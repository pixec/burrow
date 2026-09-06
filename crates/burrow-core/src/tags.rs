//! Sandbox tags: the `metadata` map, and the limits every path applies to it.
//!
//! Shared by the orchestrator and the node so the two cannot disagree about
//! what a tag is. Tags are echoed back in every response and written to both
//! tiers' stores, so they are bounded at the door rather than trusted for
//! being small in practice.
//!
//! Node labels are the same shape under a different name, so they share the
//! limits rather than growing a second nearly-identical set.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;

use tonic::Status;

pub const MAX_TAGS: usize = 16;
pub const MAX_KEY_BYTES: usize = 64;
pub const MAX_VALUE_BYTES: usize = 256;

/// Rejects a tag set that exceeds the limits or carries control characters.
///
/// Tags are rendered into operator output (CLI tables, logs, audit lines),
/// where an embedded newline or escape sequence forges lines the operator
/// reads as the system's own.
pub fn validate(tags: &HashMap<String, String>) -> Result<(), Status> {
    validate_pairs("tag", tags)
}

/// Rejects a node label set, under the tag limits.
///
/// Labels reach `burrow nodes ls` and placement errors, the same exposure a
/// tag has.
pub fn validate_labels(labels: &HashMap<String, String>) -> Result<(), Status> {
    validate_pairs("label", labels)
}

fn validate_pairs(kind: &str, pairs: &HashMap<String, String>) -> Result<(), Status> {
    if pairs.len() > MAX_TAGS {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_TAGS} {kind}s, got {}",
            pairs.len()
        )));
    }
    for (key, value) in pairs {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(Status::invalid_argument(format!(
                "{kind} key {key:?} must be 1..={MAX_KEY_BYTES} bytes"
            )));
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(Status::invalid_argument(format!(
                "{kind} {key:?} value is {} bytes (max {MAX_VALUE_BYTES})",
                value.len()
            )));
        }
        if has_control(key) {
            return Err(Status::invalid_argument(format!(
                "{kind} key {key:?} contains a control character"
            )));
        }
        if has_control(value) {
            return Err(Status::invalid_argument(format!(
                "{kind} {key:?} value contains a control character"
            )));
        }
    }
    Ok(())
}

/// Parses `key=value` labels into a validated map.
///
/// A pair with no `=` is refused rather than read as a key with an empty
/// value: a node must not silently carry a label it was not given.
pub fn parse_labels<S: AsRef<str>>(pairs: &[S]) -> Result<HashMap<String, String>, Status> {
    let mut labels = HashMap::new();
    for pair in pairs {
        let pair = pair.as_ref();
        let Some((key, value)) = pair.split_once('=') else {
            return Err(Status::invalid_argument(format!(
                "label {pair:?} is not key=value"
            )));
        };
        labels.insert(key.to_string(), value.to_string());
    }
    validate_labels(&labels)?;
    Ok(labels)
}

fn has_control(value: &str) -> bool {
    value.bytes().any(|b| b < 0x20 || b == 0x7F)
}

/// Splits a `key=value` list filter, on the first `=`.
///
/// `None` for an empty filter, which means "every sandbox". A key with no `=`
/// is refused rather than read as a key-only match, which would list
/// sandboxes the caller did not ask about.
pub fn parse_filter(filter: &str) -> Result<Option<(&str, &str)>, Status> {
    if filter.is_empty() {
        return Ok(None);
    }
    match filter.split_once('=') {
        Some(("", _)) => Err(Status::invalid_argument(
            "tag filter needs a key before the '='",
        )),
        Some((key, value)) => Ok(Some((key, value))),
        None => Err(Status::invalid_argument(format!(
            "tag filter {filter:?} is not key=value"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn an_ordinary_tag_set_is_accepted() {
        assert!(validate(&tags(&[("env", "staging"), ("team", "infra")])).is_ok());
        // An empty value is a real tag: presence is the signal.
        assert!(validate(&tags(&[("gpu", "")])).is_ok());
        assert!(validate(&HashMap::new()).is_ok());
    }

    #[test]
    fn the_limits_are_enforced_at_both_ends() {
        let too_many: HashMap<String, String> = (0..=MAX_TAGS)
            .map(|i| (format!("k{i}"), String::new()))
            .collect();
        assert!(validate(&too_many).is_err());

        assert!(validate(&tags(&[("", "v")])).is_err());

        let long_key = "k".repeat(MAX_KEY_BYTES + 1);
        assert!(validate(&tags(&[(&long_key, "v")])).is_err());
        assert!(validate(&tags(&[(&long_key[1..], "v")])).is_ok());

        let long_value = "v".repeat(MAX_VALUE_BYTES + 1);
        assert!(validate(&tags(&[("k", &long_value)])).is_err());
        assert!(validate(&tags(&[("k", &long_value[1..])])).is_ok());
    }

    /// Tags land in operator-facing output; a value carrying a newline or an
    /// escape sequence writes lines the operator reads as the system's own.
    #[test]
    fn control_characters_are_refused() {
        for bad in ["a\nb", "a\rb", "a\tb", "a\0b", "a\x1b[31mb", "a\x7fb"] {
            assert!(validate(&tags(&[("env", bad)])).is_err(), "{bad:?} value");
            assert!(validate(&tags(&[(bad, "v")])).is_err(), "{bad:?} key");
        }
    }

    /// Labels are checked like tags, and say "label" when they are refused:
    /// an operator told their node was rejected for a bad "tag" would look in
    /// the wrong place.
    #[test]
    fn labels_are_held_to_the_tag_limits_under_their_own_name() {
        assert!(validate_labels(&tags(&[("rack", "b7")])).is_ok());
        let err = validate_labels(&tags(&[("rack", "b\n7")])).unwrap_err();
        assert!(err.message().contains("label"), "{}", err.message());
        assert!(validate_labels(&tags(&[("", "b7")])).is_err());

        let too_many: HashMap<String, String> = (0..=MAX_TAGS)
            .map(|i| (format!("k{i}"), String::new()))
            .collect();
        assert!(validate_labels(&too_many).is_err());
    }

    #[test]
    fn labels_parse_from_key_equals_value() {
        let labels = parse_labels(&["rack=b7", "tenant=acme"]).unwrap();
        assert_eq!(labels["rack"], "b7");
        assert_eq!(labels["tenant"], "acme");
        // Only the first '=' separates, so a value may carry one.
        assert_eq!(parse_labels(&["k=a=b"]).unwrap()["k"], "a=b");
        // Presence is a real label.
        assert_eq!(parse_labels(&["gpu="]).unwrap()["gpu"], "");
        assert!(parse_labels(&["rack"]).is_err());
        assert!(parse_labels(&["=b7"]).is_err());
        assert!(parse_labels(&["rack=b\n7"]).is_err());
        assert!(parse_labels::<String>(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_filter_splits_on_the_first_equals() {
        assert_eq!(parse_filter("").unwrap(), None);
        assert_eq!(
            parse_filter("env=staging").unwrap(),
            Some(("env", "staging"))
        );
        // A value may contain '='; only the first separates.
        assert_eq!(parse_filter("k=a=b").unwrap(), Some(("k", "a=b")));
        // Matching an empty value is a real query.
        assert_eq!(parse_filter("gpu=").unwrap(), Some(("gpu", "")));

        assert!(parse_filter("env").is_err());
        assert!(parse_filter("=staging").is_err());
    }
}
