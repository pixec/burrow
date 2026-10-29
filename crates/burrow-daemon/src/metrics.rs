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
    pub metadata: HashMap<String, String>,
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
            .metadata
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

#[derive(Clone, Default)]
pub struct SandboxMetrics {
    readings: Arc<Mutex<Vec<Reading>>>,
}

impl SandboxMetrics {
    pub fn publish(&self, readings: Vec<Reading>) {
        *self.readings.lock().unwrap() = readings;
    }

    /// Registers the instruments on the global meter. Without an exporter the
    /// global meter is a no-op and nothing is read.
    pub fn register(&self, node_id: Arc<Mutex<String>>) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_become_attributes_and_cannot_replace_the_fixed_ones() {
        let reading = Reading {
            sandbox_id: "sbx_1".into(),
            template: "alpine".into(),
            metadata: HashMap::from([
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
