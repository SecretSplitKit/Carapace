//! Secret-redacted operational events.

use serde_json::{json, Value};

/// Build one stable, structured operational event.
///
/// Callers must supply only fixed event identifiers and bounded numeric fields. This
/// function does not accept free-form error text, paths, or identity values.
pub(crate) fn event(event_id: &'static str, reference: Option<u64>) -> Value {
    json!({
        "component": "carapace-api",
        "event_id": event_id,
        "reference": reference,
    })
}

/// Write one event as a single JSON line to the local process log.
pub(crate) fn log(event_id: &'static str, reference: Option<u64>) {
    eprintln!("{}", event(event_id, reference));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_contract_has_only_redacted_stable_fields() {
        let value = event("api.internal_error", Some(7));
        assert_eq!(value["component"], "carapace-api");
        assert_eq!(value["event_id"], "api.internal_error");
        assert_eq!(value["reference"], 7);
        assert_eq!(value.as_object().unwrap().len(), 3);
    }
}
