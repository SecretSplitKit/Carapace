//! Unfriending (protocol §9.3 steps 1-2). A [`FriendshipEnd`] is effective for
//! the sender the instant it is signed; the deletion flow then issues
//! [`DeleteRequest`]s for everything placed on the ex-friend and answers incoming
//! ones with [`DeleteAck`]s. Acks are **bookkeeping, not proof**: deletion is
//! unprovable in any system that ever handed out bytes (the ex-friend held only
//! ciphertext, and any share is neutralized by the re-split of §9.3 step 3,
//! see [`crate::resplit`]).

use carapace_wire::{DeleteAck, DeleteRequest, FriendshipEnd, Message, Signed};
use ed25519_dalek::SigningKey;

use crate::FriendError;

/// `DeleteRequest.scope` = replicas (a specific vault's replica placement).
pub const SCOPE_REPLICAS: u64 = 0;
/// `DeleteRequest.scope` = shares (any share/grant placed on the peer).
pub const SCOPE_SHARES: u64 = 1;
/// `DeleteRequest.scope` = all (drop everything placed on the peer).
pub const SCOPE_ALL: u64 = 2;

/// What this user placed on the peer being unfriended - the input to
/// [`build_delete_requests`].
#[derive(Clone, Debug, Default)]
pub struct Placement {
    /// Vaults the ex-friend held a replica of (one replica `DeleteRequest` each).
    pub replica_vids: Vec<[u8; 32]>,
    /// Whether the ex-friend held any share/queued grant (one `SCOPE_SHARES` request).
    pub held_shares: bool,
}

/// Terminate a friendship unilaterally (§9.3): a node-signed [`FriendshipEnd`]
/// naming the unfriended `user`, effective for the sender on send.
pub fn end_friendship(node_key: &SigningKey, user: [u8; 32], ts: u64) -> FriendshipEnd {
    let mut end = FriendshipEnd {
        user,
        ts,
        by: [0; 32],
        sig: [0; 64],
    };
    end.sign(node_key);
    end
}

/// Build one signed [`DeleteRequest`] at the given `scope` (`vid` is required for
/// [`SCOPE_REPLICAS`] and ignored otherwise).
pub fn build_delete_request(
    node_key: &SigningKey,
    scope: u64,
    vid: Option<[u8; 32]>,
) -> DeleteRequest {
    let mut req = DeleteRequest {
        scope,
        vid: if scope == SCOPE_REPLICAS { vid } else { None },
        by: [0; 32],
        sig: [0; 64],
    };
    req.sign(node_key);
    req
}

/// Build the full set of signed [`DeleteRequest`]s for everything placed on the
/// ex-friend (§9.3 step 1): one replica request per held vault, plus a shares
/// request if the ex-friend held any share.
pub fn build_delete_requests(node_key: &SigningKey, placed: &Placement) -> Vec<DeleteRequest> {
    let mut out = Vec::new();
    for vid in &placed.replica_vids {
        out.push(build_delete_request(node_key, SCOPE_REPLICAS, Some(*vid)));
    }
    if placed.held_shares {
        out.push(build_delete_request(node_key, SCOPE_SHARES, None));
    }
    out
}

/// The BLAKE3 reference an ack carries: the hash of the `DeleteRequest`'s frame
/// payload (the deterministic `det_cbor([6, body])`, i.e. the frame minus its
/// 4-byte length prefix) - matching Appendix B.8.11.
fn delete_request_reference(req: &DeleteRequest) -> [u8; 32] {
    let frame = req.encode_frame();
    *blake3::hash(&frame[4..]).as_bytes()
}

/// Answer a [`DeleteRequest`] with a signed [`DeleteAck`] (§9.3 step 1,
/// bookkeeping only). The ack references the request by BLAKE3 of its payload.
pub fn build_delete_ack(node_key: &SigningKey, req: &DeleteRequest, ts: u64) -> DeleteAck {
    let mut ack = DeleteAck {
        reference: delete_request_reference(req),
        ts,
        by: [0; 32],
        sig: [0; 64],
    };
    ack.sign(node_key);
    ack
}

/// Verify a [`DeleteAck`]'s signature and that it references `req` (its BLAKE3
/// reference matches the request payload). A mismatch is [`FriendError::IdentityMismatch`].
pub fn verify_delete_ack(ack: &DeleteAck, req: &DeleteRequest) -> Result<(), FriendError> {
    ack.verify()?;
    if ack.reference != delete_request_reference(req) {
        return Err(FriendError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn friendship_end_is_signed_and_effective() {
        let node = SigningKey::from_bytes(&[3; 32]);
        let end = end_friendship(&node, [9; 32], 1_700_000_000);
        end.verify().unwrap();
        assert_eq!(end.by, node.verifying_key().to_bytes());
        assert_eq!(end.user, [9; 32]);
    }

    #[test]
    fn delete_requests_cover_all_placements() {
        let node = SigningKey::from_bytes(&[3; 32]);
        let placed = Placement {
            replica_vids: vec![[0xA0; 32], [0xB0; 32]],
            held_shares: true,
        };
        let reqs = build_delete_requests(&node, &placed);
        assert_eq!(reqs.len(), 3);
        // Two replica requests carry their vids; the shares request carries none.
        assert_eq!(reqs[0].scope, SCOPE_REPLICAS);
        assert_eq!(reqs[0].vid, Some([0xA0; 32]));
        assert_eq!(reqs[1].vid, Some([0xB0; 32]));
        assert_eq!(reqs[2].scope, SCOPE_SHARES);
        assert_eq!(reqs[2].vid, None);
        for r in &reqs {
            r.verify().unwrap();
        }
    }

    #[test]
    fn no_shares_no_shares_request() {
        let node = SigningKey::from_bytes(&[3; 32]);
        let placed = Placement {
            replica_vids: vec![],
            held_shares: false,
        };
        assert!(build_delete_requests(&node, &placed).is_empty());
    }

    #[test]
    fn ack_references_request_payload() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let peer = SigningKey::from_bytes(&[4; 32]);
        let req = build_delete_request(&owner, SCOPE_REPLICAS, Some([0xC0; 32]));
        let ack = build_delete_ack(&peer, &req, 1_700_000_000);
        verify_delete_ack(&ack, &req).unwrap();
    }

    #[test]
    fn ack_for_wrong_request_rejected() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let peer = SigningKey::from_bytes(&[4; 32]);
        let req_a = build_delete_request(&owner, SCOPE_REPLICAS, Some([0xC0; 32]));
        let req_b = build_delete_request(&owner, SCOPE_ALL, None);
        let ack = build_delete_ack(&peer, &req_a, 1);
        assert!(matches!(
            verify_delete_ack(&ack, &req_b),
            Err(FriendError::IdentityMismatch)
        ));
    }

    #[test]
    fn tampered_ack_signature_rejected() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let peer = SigningKey::from_bytes(&[4; 32]);
        let req = build_delete_request(&owner, SCOPE_SHARES, None);
        let mut ack = build_delete_ack(&peer, &req, 1);
        ack.ts ^= 1; // change signed content without re-signing
        assert!(matches!(
            verify_delete_ack(&ack, &req),
            Err(FriendError::Wire(_))
        ));
    }
}
