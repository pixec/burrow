//! Log and trace initialisation, shared by both daemons.
//!
//! Logs always go to stderr. Traces, and metrics for a daemon that records
//! any, are exported over OTLP only when an endpoint is configured: a host with nowhere to send spans should not pay to
//! build them, and a collector that is down must never stall the daemon
//! talking to it.
//!
//! An `Exec` runs across client, orchestrator, node and guest agent, so "which
//! hop was slow" is not answerable from any one process's logs.

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Keeps the exporter alive and flushes it on shutdown.
///
/// Batched spans live in memory until the exporter ships them, so dropping
/// this without shutting down loses the last batch.
pub struct Telemetry {
    service_name: &'static str,
    endpoint: Option<String>,
    provider: Option<opentelemetry_sdk::trace::TracerProvider>,
    meters: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
}

impl Telemetry {
    /// Exports what is recorded through the global meter to the trace
    /// collector, read every `interval`. A no-op without an endpoint, which
    /// leaves the global meter recording nothing.
    pub fn export_metrics(&mut self, interval: std::time::Duration) {
        let Some(endpoint) = self.endpoint.as_deref() else {
            return;
        };
        let exporter = match opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
        {
            Ok(exporter) => exporter,
            Err(err) => {
                tracing::error!(endpoint, %err, "otlp metric exporter unavailable");
                return;
            }
        };
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
            exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .with_interval(interval)
        .build();
        let meters = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource(self.service_name))
            .build();
        opentelemetry::global::set_meter_provider(meters.clone());
        tracing::info!(endpoint, ?interval, "exporting metrics over otlp");
        self.meters = Some(meters);
    }

    /// Flushes pending spans and metrics. Worth awaiting on a clean shutdown
    /// path.
    pub fn shutdown(self) {
        if let Some(provider) = self.provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(%err, "otlp exporter did not flush cleanly");
        }
        if let Some(meters) = self.meters
            && let Err(err) = meters.shutdown()
        {
            tracing::warn!(%err, "otlp metric exporter did not flush cleanly");
        }
    }
}

fn resource(service_name: &'static str) -> Resource {
    Resource::new([
        KeyValue::new("service.name", service_name),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ])
}

/// Installs the global subscriber.
///
/// `otlp_endpoint` is the collector's gRPC address (`http://host:4317`).
/// `None` leaves tracing entirely local.
pub fn init(service_name: &'static str, otlp_endpoint: Option<&str>) -> Telemetry {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt::layer();

    let Some(endpoint) = otlp_endpoint.filter(|e| !e.is_empty()) else {
        tracing_subscriber::registry()
            .with(filter)
            .with(logs)
            .init();
        return Telemetry {
            service_name,
            endpoint: None,
            provider: None,
            meters: None,
        };
    };

    // Both ends must agree on the header format before either can join a
    // trace the other started.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    match build_provider(service_name, endpoint) {
        Ok(provider) => {
            let tracer = provider.tracer(service_name);
            tracing_subscriber::registry()
                .with(filter)
                .with(logs)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            tracing::info!(endpoint, service_name, "exporting traces over otlp");
            Telemetry {
                service_name,
                endpoint: Some(endpoint.to_string()),
                provider: Some(provider),
                meters: None,
            }
        }
        Err(err) => {
            // Deliberately not fatal. A collector that cannot be reached is an
            // observability problem; refusing to run sandboxes over it would
            // turn it into an availability one.
            tracing_subscriber::registry()
                .with(filter)
                .with(logs)
                .init();
            tracing::error!(endpoint, %err, "otlp exporter unavailable; traces are not being exported");
            Telemetry {
                service_name,
                endpoint: Some(endpoint.to_string()),
                provider: None,
                meters: None,
            }
        }
    }
}

fn build_provider(
    service_name: &'static str,
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::TracerProvider, Box<dyn std::error::Error>> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    Ok(opentelemetry_sdk::trace::TracerProvider::builder()
        // Batched, so an unreachable collector backs up in a bounded queue
        // instead of blocking whatever emitted the span.
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource(service_name))
        .build())
}

/// W3C trace-context propagation across the orchestrator-to-node hop.
///
/// Without it every process starts a fresh trace, so no span on the node is
/// linked to the request that caused it.
pub mod propagation {
    use opentelemetry::propagation::{Extractor, Injector};
    use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    struct MetadataInjector<'a>(&'a mut MetadataMap);

    impl Injector for MetadataInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            // A header that will not parse is dropped rather than escalated:
            // an unpropagated trace is a gap in a graph, not a failed request.
            if let (Ok(key), Ok(value)) = (
                MetadataKey::from_bytes(key.as_bytes()),
                MetadataValue::try_from(value.as_str()),
            ) {
                self.0.insert(key, value);
            }
        }
    }

    struct MetadataExtractor<'a>(&'a MetadataMap);

    impl Extractor for MetadataExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|value| value.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0
                .keys()
                .filter_map(|key| match key {
                    tonic::metadata::KeyRef::Ascii(key) => Some(key.as_str()),
                    tonic::metadata::KeyRef::Binary(_) => None,
                })
                .collect()
        }
    }

    /// Writes the calling span's trace context into an outgoing request.
    pub fn inject(metadata: &mut MetadataMap) {
        let context = tracing::Span::current().context();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&context, &mut MetadataInjector(metadata));
        });
    }

    /// Adopts an incoming request's trace context as the current span's parent.
    ///
    /// A request without one simply starts its own trace, which is what a
    /// direct call to a node should do.
    pub fn adopt(metadata: &MetadataMap) {
        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&MetadataExtractor(metadata))
        });
        tracing::Span::current().set_parent(parent);
    }
}
