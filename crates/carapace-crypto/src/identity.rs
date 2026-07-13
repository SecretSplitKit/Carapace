//! Ed25519 identity: user key (from `K_userid`), per-device node keys, and the
//! user->node delegation chain (protocol §4).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain prefix for a device delegation, signed by the user key.
pub const DELEG_PREFIX: &[u8] = b"carapace/v1/deleg";

/// Build the user's Ed25519 signing key from the 32-byte `K_userid` seed.
pub fn user_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// The exact bytes signed for a delegation:
/// `"carapace/v1/deleg" ‖ node_id ‖ not_after.to_be_bytes(8)`.
pub fn delegation_message(node_id: &VerifyingKey, not_after: u64) -> Vec<u8> {
    let node_bytes = node_id.to_bytes();
    let mut msg = Vec::with_capacity(DELEG_PREFIX.len() + node_bytes.len() + 8);
    msg.extend_from_slice(DELEG_PREFIX);
    msg.extend_from_slice(&node_bytes);
    msg.extend_from_slice(&not_after.to_be_bytes());
    msg
}

/// Sign a device delegation certifying `node_id` for the user until `not_after`.
pub fn sign_delegation(
    user_key: &SigningKey,
    node_id: &VerifyingKey,
    not_after: u64,
) -> Signature {
    user_key.sign(&delegation_message(node_id, not_after))
}

/// Verify a delegation chain: that `user_pub` really delegated to `node_id`
/// until `not_after`, and (if given) that the delegation has not expired at
/// `now`. `verify_strict` rejects the malleable/edge public keys dalek warns on.
pub fn verify_delegation(
    user_pub: &VerifyingKey,
    node_id: &VerifyingKey,
    not_after: u64,
    sig: &Signature,
    now: Option<u64>,
) -> Result<(), DelegationError> {
    if let Some(now) = now {
        if now > not_after {
            return Err(DelegationError::Expired { not_after, now });
        }
    }
    user_pub
        .verify_strict(&delegation_message(node_id, not_after), sig)
        .map_err(|_| DelegationError::BadSignature)
}

/// Generic Ed25519 verify against a raw message (documents, etc.).
/// Uses `verify_strict` to match every other signature path and to reject
/// signature malleability and small-order / mixed-order public keys.
pub fn verify(pubkey: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    pubkey.verify_strict(msg, sig).is_ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum DelegationError {
    BadSignature,
    Expired { not_after: u64, now: u64 },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::BadSignature => write!(f, "delegation signature invalid"),
            DelegationError::Expired { not_after, now } => {
                write!(f, "delegation expired: not_after={not_after} now={now}")
            }
        }
    }
}

impl std::error::Error for DelegationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_roundtrip_and_expiry() {
        let user = SigningKey::from_bytes(&[0x01; 32]);
        let node = SigningKey::from_bytes(&[0x03; 32]);
        let node_pub = node.verifying_key();
        let not_after = 1_798_761_600u64;

        let sig = sign_delegation(&user, &node_pub, not_after);
        let user_pub = user.verifying_key();

        assert!(verify_delegation(&user_pub, &node_pub, not_after, &sig, None).is_ok());
        // valid before expiry
        assert!(verify_delegation(&user_pub, &node_pub, not_after, &sig, Some(not_after - 1)).is_ok());
        // rejected after expiry
        assert_eq!(
            verify_delegation(&user_pub, &node_pub, not_after, &sig, Some(not_after + 1)),
            Err(DelegationError::Expired { not_after, now: not_after + 1 })
        );
        // wrong signer rejected
        let impostor = SigningKey::from_bytes(&[0x02; 32]).verifying_key();
        assert_eq!(
            verify_delegation(&impostor, &node_pub, not_after, &sig, None),
            Err(DelegationError::BadSignature)
        );
        // tampered not_after rejected
        assert_eq!(
            verify_delegation(&user_pub, &node_pub, not_after + 1, &sig, None),
            Err(DelegationError::BadSignature)
        );
    }

    // W2: the generic document `verify` now uses `verify_strict` (consistent
    // with every other signature path). Guard its basic accept/reject contract.
    #[test]
    fn generic_verify_accepts_valid_rejects_tampered() {
        let key = SigningKey::from_bytes(&[0x07; 32]);
        let vk = key.verifying_key();
        let sig = key.sign(b"doc bytes");
        assert!(verify(&vk, b"doc bytes", &sig));
        // wrong message
        assert!(!verify(&vk, b"other bytes", &sig));
        // signature over a different message
        let sig2 = key.sign(b"other bytes");
        assert!(!verify(&vk, b"doc bytes", &sig2));
    }
}
