//! Per-sandbox usage as OpenTelemetry metrics, for charts.
//!
//! The reaper publishes every sandbox's totals on its tick and the exporter
//! reads the latest of them on the same period, so each sandbox gets one point
//! per tick. The counters are the same totals the events and the ledger carry,
//! so a chart and the ledger cannot disagree about what was counted, only
//! about when it was read. The names carry their units, so a Prometheus
//! export reads `burrow_sandbox_cpu_usec_total` rather than growing a suffix.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use opentelemetry::KeyValue;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    pub sandbox_id: String,
    pub template: String,
    pub tags: HashMap<String, String>,
    pub cpu_usage_usec: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Memory the running VM holds; 0 while it is suspended or stopped.
    pub mem_mib: u64,
}

impl Reading {
    /// Every tag as an attribute of its own, so a collector can group by it,
    /// then the fixed ones, which a tag of the same name does not replace.
    fn attributes(&self, node_id: &str) -> Vec<KeyValue> {
        let mut attributes: Vec<KeyValue> = self
            .tags
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "sandbox_id" | "template" | "node_id"))
            .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
            .collect();
        attributes.push(KeyValue::new("sandbox_id", self.sandbox_id.clone()));
        attributes.push(KeyValue::new("template", self.template.clone()));
        attributes.push(KeyValue::new("node_id", node_id.to_string()));
        attributes
    }
}

/// How the node's object-store collector is faring. A collector that cannot
/// finish a pass deletes nothing, so the store grows until it can.
#[derive(Debug, Default)]
pub struct Collector {
    state: Mutex<CollectorState>,
}

#[derive(Debug, Default, Clone)]
struct CollectorState {
    /// Unix seconds; 0 before the first pass here succeeds.
    succeeded_at: i64,
    error: Option<String>,
    failures: u32,
}

impl Collector {
    pub fn succeeded(&self, at: i64) {
        *self.state.lock().unwrap() = CollectorState {
            succeeded_at: at,
            error: None,
            failures: 0,
        };
    }

    /// Records a failed pass and says how many have failed in a row.
    pub fn failed(&self, err: String) -> u32 {
        let mut state = self.state.lock().unwrap();
        state.error = Some(err);
        state.failures += 1;
        state.failures
    }

    pub fn succeeded_at(&self) -> i64 {
        self.state.lock().unwrap().succeeded_at
    }

    /// Why the latest pass failed, while it is the latest.
    pub fn error(&self) -> Option<String> {
        self.state.lock().unwrap().error.clone()
    }
}

#[derive(Clone, Default)]
pub struct SandboxMetrics {
    readings: Arc<Mutex<Vec<Reading>>>,
    pub collector: Arc<Collector>,
}

impl SandboxMetrics {
    pub fn publish(&self, readings: Vec<Reading>) {
        *self.readings.lock().unwrap() = readings;
    }

    /// Registers the instruments on the global meter. Without an exporter the
    /// global meter is a no-op and nothing is read.
    pub fn register(
        &self,
        node_id: Arc<Mutex<String>>,
        cold_boots: Arc<crate::coldboot::ColdBoots>,
    ) {
        let meter = opentelemetry::global::meter("burrowd");
        let observe = |pick: fn(&Reading) -> u64| {
            let readings = Arc::clone(&self.readings);
            let node_id = Arc::clone(&node_id);
            move |observer: &dyn opentelemetry::metrics::AsyncInstrument<u64>| {
                let node_id = node_id.lock().unwrap().clone();
                for reading in readings.lock().unwrap().iter() {
                    observer.observe(pick(reading), &reading.attributes(&node_id));
                }
            }
        };
        meter
            .u64_observable_counter("burrow.sandbox.cpu_usec")
            .with_description("Host CPU time the sandbox's VM has used")
            .with_callback(observe(|r| r.cpu_usage_usec))
            .build();
        meter
            .u64_observable_counter("burrow.sandbox.rx_bytes")
            .with_description("Bytes the sandbox has received")
            .with_callback(observe(|r| r.rx_bytes))
            .build();
        meter
            .u64_observable_counter("burrow.sandbox.tx_bytes")
            .with_description("Bytes the sandbox has sent, allowed or not")
            .with_callback(observe(|r| r.tx_bytes))
            .build();
        meter
            .u64_observable_gauge("burrow.sandbox.mem_mib")
            .with_description("Memory the sandbox's running VM holds")
            .with_callback(observe(|r| r.mem_mib))
            .build();

        let node = |pick: fn(&Collector) -> u64| {
            let collector = Arc::clone(&self.collector);
            let node_id = Arc::clone(&node_id);
            move |observer: &dyn opentelemetry::metrics::AsyncInstrument<u64>| {
                let node_id = node_id.lock().unwrap().clone();
                observer.observe(pick(&collector), &[KeyValue::new("node_id", node_id)]);
            }
        };
        meter
            .u64_observable_gauge("burrow.node.gc_succeeded_unix_s")
            .with_description(
                "When the node's object-store collector last finished a pass; 0 before the first",
            )
            .with_callback(node(|c| c.succeeded_at().max(0) as u64))
            .build();
        meter
            .u64_observable_gauge("burrow.node.gc_stalled")
            .with_description("1 while the node's latest object-store collection failed")
            .with_callback(node(|c| u64::from(c.error().is_some())))
            .build();

        let boots = |pick: fn(&crate::coldboot::ColdBoots) -> u64| {
            let cold_boots = Arc::clone(&cold_boots);
            let node_id = Arc::clone(&node_id);
            move |observer: &dyn opentelemetry::metrics::AsyncInstrument<u64>| {
                let node_id = node_id.lock().unwrap().clone();
                observer.observe(pick(&cold_boots), &[KeyValue::new("node_id", node_id)]);
            }
        };
        meter
            .u64_observable_gauge("burrow.node.cold_boots_waiting")
            .with_description("Cold boots waiting for a --cold-boots slot")
            .with_callback(boots(crate::coldboot::ColdBoots::waiting))
            .build();
        meter
            .u64_observable_gauge("burrow.node.cold_boots_running")
            .with_description("Cold boots holding a --cold-boots slot")
            .with_callback(boots(crate::coldboot::ColdBoots::running))
            .build();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_collector_is_stalled_from_a_failed_pass_until_one_succeeds() {
        let collector = Collector::default();
        assert_eq!((collector.succeeded_at(), collector.error()), (0, None));
        collector.succeeded(100);
        assert_eq!(collector.failed("unreadable manifest".into()), 1);
        assert_eq!(collector.failed("unreadable manifest".into()), 2);
        assert_eq!(collector.succeeded_at(), 100);
        assert_eq!(collector.error().as_deref(), Some("unreadable manifest"));
        collector.succeeded(200);
        assert_eq!((collector.succeeded_at(), collector.error()), (200, None));
        assert_eq!(collector.failed("again".into()), 1);
    }

    #[test]
    fn tags_become_attributes_and_cannot_replace_the_fixed_ones() {
        let reading = Reading {
            sandbox_id: "sbx_1".into(),
            template: "alpine".into(),
            tags: HashMap::from([
                ("customer".into(), "acme".into()),
                ("template".into(), "spoofed".into()),
            ]),
            ..Default::default()
        };
        let attributes: HashMap<String, String> = reading
            .attributes("node_a")
            .into_iter()
            .map(|kv| (kv.key.to_string(), kv.value.to_string()))
            .collect();
        assert_eq!(attributes["customer"], "acme");
        assert_eq!(attributes["template"], "alpine");
        assert_eq!(attributes["node_id"], "node_a");
        assert_eq!(attributes["sandbox_id"], "sbx_1");
        assert_eq!(attributes.len(), 4);
    }
}
