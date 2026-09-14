//! Public claimant metadata is authenticated independently of secret share contents.
use super::*;

pub type ClaimantAddress = ([u8; 32], Vec<String>, Option<String>);

pub struct ClaimantPackage {
    pub roster: Vec<[u8; 32]>,
    pub trustees: Vec<ClaimantTrusteeHint>,
    pub announce_refs: Vec<AnnounceRef>,
    pub sponsor_sig: [u8; 64],
}

fn signing_bytes(
    open: &RecoveryOpen,
    roster: &[[u8; 32]],
    trustees: &[ClaimantAddress],
    refs: &[AnnounceRef],
) -> Vec<u8> {
    use carapace_wire::{encode, Value};
    encode(&Value::Array(vec![
        Value::Text("carapace/v1/claimant-package".into()),
        Value::Bytes(open.encode_frame()),
        Value::Array(
            roster
                .iter()
                .map(|user| Value::Bytes(user.to_vec()))
                .collect(),
        ),
        Value::Array(
            trustees
                .iter()
                .map(|(node, addrs, relay)| {
                    Value::Array(vec![
                        Value::Bytes(node.to_vec()),
                        Value::Array(addrs.iter().cloned().map(Value::Text).collect()),
                        relay.clone().map(Value::Text).unwrap_or(Value::Null),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            refs.iter()
                .map(|r| {
                    Value::Array(vec![
                        Value::Bytes(r.vid.to_vec()),
                        Value::Uint(r.epoch),
                        Value::Bytes(r.digest.to_vec()),
                    ])
                })
                .collect(),
        ),
    ]))
}

pub fn verify_claimant_package(
    open: &RecoveryOpen,
    roster: &[[u8; 32]],
    trustees: &[ClaimantAddress],
    refs: &[AnnounceRef],
    signature: &[u8; 64],
) -> Result<()> {
    ensure!(
        roster.len() <= 255 && trustees.len() <= 64 && refs.len() <= 4096,
        "claimant package exceeds limits"
    );
    ensure!(
        trustees.iter().all(|(_, addrs, _)| addrs.len() <= 16),
        "too many trustee address hints"
    );
    carapace_recovery::verify_recovery_open(open, roster)
        .map_err(|error| anyhow::anyhow!("invalid recovery open: {error:?}"))?;
    VerifyingKey::from_bytes(&open.by)?
        .verify_strict(
            &signing_bytes(open, roster, trustees, refs),
            &Signature::from_bytes(signature),
        )
        .context("claimant package metadata signature is invalid")
}

impl Daemon {
    pub fn verify_recovery_handoff(&self, metadata: &[u8], sealed: &[u8]) -> Result<()> {
        let digest = carapace_crypto::state_seal::open(
            &self.k_root,
            b"claimant-handoff",
            b"version-2",
            sealed,
        )?;
        ensure!(
            digest.as_slice() == blake3::hash(metadata).as_bytes(),
            "restart handoff was replaced or modified"
        );
        Ok(())
    }

    pub fn claimant_package(&self, open: &RecoveryOpen) -> Result<ClaimantPackage> {
        let grant = self
            .held_grant(&open.subject)
            .context("sponsor holds no recovery grant")?;
        let share = verify_share_grant(&grant)
            .map_err(|error| anyhow::anyhow!("invalid held grant: {error:?}"))?;
        ensure!(
            open.by == self.user_id()
                && grant.subject == open.subject
                && grant.by == open.subject
                && u64::from(share.recovery_set_id) == open.rsid,
            "recovery open does not match sponsor's grant"
        );
        let trustees = self.claimant_trustee_hints(&open.subject)?;
        let roster: Vec<_> = trustees.iter().map(|t| t.user).collect();
        let addresses: Vec<_> = trustees
            .iter()
            .map(|t| (t.node, t.addrs.clone(), t.relay_url.clone()))
            .collect();
        let announce_refs = max_epoch_refs(&grant.refs);
        let sponsor_sig = self
            .user_key
            .sign(&signing_bytes(open, &roster, &addresses, &announce_refs))
            .to_bytes();
        Ok(ClaimantPackage {
            roster,
            trustees,
            announce_refs,
            sponsor_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_metadata_signature_binds_refs_roster_and_addresses() {
        let key = SigningKey::from_bytes(&[101; 32]);
        let open = open_recovery(
            &key,
            [1; 16],
            [2; 32],
            7,
            "claimant".into(),
            [3; 32],
            [4; 32],
            "reason".into(),
            1,
        );
        let roster = vec![key.verifying_key().to_bytes()];
        let trustees = vec![([5; 32], vec!["127.0.0.1:99".into()], None)];
        let refs = vec![AnnounceRef {
            vid: [6; 32],
            epoch: 7,
            digest: [8; 32],
        }];
        let sig = key
            .sign(&signing_bytes(&open, &roster, &trustees, &refs))
            .to_bytes();
        verify_claimant_package(&open, &roster, &trustees, &refs, &sig).unwrap();
        assert!(verify_claimant_package(&open, &roster, &trustees, &[], &sig).is_err());
        assert!(verify_claimant_package(&open, &roster, &[], &refs, &sig).is_err());
        let mut substituted = roster;
        substituted.push([9; 32]);
        assert!(verify_claimant_package(&open, &substituted, &trustees, &refs, &sig).is_err());
    }
}
