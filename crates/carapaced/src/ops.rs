//! Structured, secret-redacted daemon operational events.

/// One stable event that cannot carry paths, identities, or free-form errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) event_id: &'static str,
    pub(crate) reference: Option<u64>,
}

impl Event {
    pub(crate) fn line(self) -> String {
        match self.reference {
            Some(reference) => format!(
                "{{\"component\":\"carapaced\",\"event_id\":\"{}\",\"reference\":{reference}}}",
                self.event_id
            ),
            None => format!(
                "{{\"component\":\"carapaced\",\"event_id\":\"{}\",\"reference\":null}}",
                self.event_id
            ),
        }
    }
}

pub(crate) fn log(event_id: &'static str, reference: Option<u64>) {
    eprintln!(
        "{}",
        Event {
            event_id,
            reference
        }
        .line()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_contract_is_stable_and_redacted_by_type() {
        let line = Event {
            event_id: "recovery.manifest_rederive_failed",
            reference: Some(7),
        }
        .line();
        assert_eq!(
            line,
            "{\"component\":\"carapaced\",\"event_id\":\"recovery.manifest_rederive_failed\",\"reference\":7}"
        );
        for forbidden in ["/", "\\", "error", "identity", "vault_id"] {
            assert!(!line.contains(forbidden));
        }
    }
}
