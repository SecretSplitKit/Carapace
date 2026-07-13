//! The friendship handshake (protocol §9.2). A requester presents a ticket token
//! in a node-signed [`FriendRequest`] that embeds their own user-signed
//! [`ContactCard`]; the acceptor redeems the token (single-use, §6), then replies
//! with a node-signed [`FriendAccept`] embedding their own card and the
//! mutually-signed [`Friendship`] record.
//!
//! # W1 discipline
//!
//! Every embedded object is verified against its *own* signature, never trusted
//! because the outer node signed the bytes: [`verify_friend_request`] and
//! [`verify_friend_accept`] check the embedded card's self-signature **and** that
//! the message's signing node is delegated by that card's user. A hostile node
//! cannot smuggle a forged card or a node it does not control past these checks.
//!
//! # Producing a dual-signed Friendship
//!
//! A [`Friendship`] carries both users' signatures over the same core
//! (`a`, `b`, `established`, with `a < b` bytewise). The acceptor picks
//! `established`, so the requester cannot pre-sign; instead [`accept_friend_request`]
//! takes the requester's countersignature as a signing *oracle*
//! (`FnOnce(&[u8]) -> [u8; 64]`). In a live session this oracle is the
//! interactive round-trip to the requester's device; the acceptor never holds the
//! requester's private key. The result is a genuinely dual-signed record.

use carapace_wire::{
    signing_bytes, ContactCard, FriendAccept, FriendRequest, Friendship, Map, Signed, Value,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::card::card_delegates_node;
use crate::ticket::TicketBook;
use crate::FriendError;

/// Build a node-signed [`FriendRequest`] presenting `token` and embedding the
/// requester's own user-signed card. Signed by `node_key` (a device delegated in
/// `card`); `card` must be the requester's own current card.
pub fn build_friend_request(
    node_key: &SigningKey,
    card: ContactCard,
    token: [u8; 16],
) -> FriendRequest {
    let mut req = FriendRequest {
        token,
        card,
        by: [0; 32],
        sig: [0; 64],
    };
    req.sign(node_key);
    req
}

/// Verify a [`FriendRequest`] under the W1 discipline and return the requester's
/// user pubkey. Checks: the outer node signature, the embedded card's own
/// self-signature (both via [`Signed::verify`]), and that the signing node
/// (`by`) is delegated by the embedded card's user and unexpired at `now`.
pub fn verify_friend_request(req: &FriendRequest, now: u64) -> Result<[u8; 32], FriendError> {
    // Outer node sig + embedded card self-sig (recurses via verify_embedded).
    req.verify()?;
    if !card_delegates_node(&req.card, &req.by, now) {
        return Err(FriendError::Delegation);
    }
    Ok(req.card.user)
}

/// Accept a verified [`FriendRequest`]: redeem its ticket token (single-use, §6),
/// build the mutually-signed [`Friendship`] (`established` chosen here), and wrap
/// it with the acceptor's own card in a node-signed [`FriendAccept`].
///
/// - `book` is the acceptor's ticket book; the token is redeemed exactly once.
/// - `acceptor_node_key` signs the outer `FriendAccept` (must be delegated in
///   `acceptor_card`).
/// - `acceptor_user_key` signs the acceptor's half of the friendship.
/// - `requester_countersign` supplies the requester's user-key signature over the
///   friendship core (the interactive round-trip; the acceptor never holds the
///   requester's private key).
///
/// Returns the `FriendAccept` to send and the completed `Friendship`.
#[allow(clippy::too_many_arguments)]
pub fn accept_friend_request<F>(
    req: &FriendRequest,
    book: &mut TicketBook,
    now: u64,
    acceptor_node_key: &SigningKey,
    acceptor_user_key: &SigningKey,
    acceptor_card: &ContactCard,
    established: u64,
    requester_countersign: F,
) -> Result<(FriendAccept, Friendship), FriendError>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    let requester_user = verify_friend_request(req, now)?;
    // Single-use: the token must be one we issued, unexpired, and unredeemed.
    book.redeem(&req.token, now)?;

    let acceptor_user = acceptor_user_key.verifying_key().to_bytes();
    let core = friendship_core_bytes(least_and_greatest(acceptor_user, requester_user), established);

    let acceptor_sig = acceptor_user_key.sign(&core).to_bytes();
    let requester_sig = requester_countersign(&core);

    // Assign each signature to the a/b slot by bytewise order of the two users.
    let (a, b) = least_and_greatest(acceptor_user, requester_user);
    let (sig_a, sig_b) = if a == acceptor_user {
        (acceptor_sig, requester_sig)
    } else {
        (requester_sig, acceptor_sig)
    };
    let friendship = Friendship {
        a,
        b,
        established,
        sig_a,
        sig_b,
    };
    // Prove BOTH signatures are valid over the canonical core before shipping.
    friendship.verify()?;

    let mut accept = FriendAccept {
        card: acceptor_card.clone(),
        friendship: friendship.clone(),
        by: [0; 32],
        sig: [0; 64],
    };
    accept.sign(acceptor_node_key);
    Ok((accept, friendship))
}

/// Verify a [`FriendAccept`] on the requester's side under the W1 discipline and
/// return the completed [`Friendship`]. Checks: the outer node signature, the
/// embedded acceptor card's self-signature and the embedded friendship's two
/// signatures (both via [`Signed::verify`] -> `verify_embedded`), that the signing
/// node is delegated by the acceptor's card at `now`, and that the friendship
/// actually binds `expected_requester` to the acceptor's user.
pub fn verify_friend_accept(
    accept: &FriendAccept,
    now: u64,
    expected_requester: &[u8; 32],
) -> Result<Friendship, FriendError> {
    // Outer node sig + embedded card self-sig + friendship dual-sig.
    accept.verify()?;
    if !card_delegates_node(&accept.card, &accept.by, now) {
        return Err(FriendError::Delegation);
    }
    let acceptor_user = accept.card.user;
    let fr = &accept.friendship;
    // The friendship must bind exactly {acceptor_user, expected_requester}.
    let bound = [fr.a, fr.b];
    if !(bound.contains(&acceptor_user) && bound.contains(expected_requester))
        || acceptor_user == *expected_requester
    {
        return Err(FriendError::IdentityMismatch);
    }
    Ok(accept.friendship.clone())
}

/// Sort two user pubkeys bytewise into `(a, b)` with `a <= b` (§9.2 ordering).
fn least_and_greatest(x: [u8; 32], y: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if x <= y {
        (x, y)
    } else {
        (y, x)
    }
}

/// The exact bytes both users sign for a `Friendship` (Appendix B doc-type 0,
/// errata E1): `"carapace-sig-v1" ‖ det_cbor([0, {0:a, 1:b, 2:established}])`.
/// Reconstructed here so the acceptor can hand them to the countersign oracle;
/// it matches `Friendship`'s own signing construction byte-for-byte. Exposed so a
/// networked requester can produce its half-signature over the identical core
/// after learning the acceptor-chosen `established` (the interactive round-trip).
pub fn friendship_core_bytes((a, b): ([u8; 32], [u8; 32]), established: u64) -> Vec<u8> {
    let mut m = Map::new();
    m.u(0, Value::Bytes(a.to_vec()));
    m.u(1, Value::Bytes(b.to_vec()));
    m.u(2, Value::Uint(established));
    signing_bytes(Friendship::DOC_TYPE, &m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{build_card, node_entry};
    use crate::ticket::build_ticket;
    use carapace_wire::Offers;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_000;
    const NOT_AFTER: u64 = 5_000_000_000;
    const ESTABLISHED: u64 = 1_700_000_000;

    fn offers() -> Offers {
        Offers {
            storage_bytes: 0,
            relay: false,
            trustee: false,
        }
    }

    fn card_for(user: &SigningKey, node: &SigningKey) -> ContactCard {
        let ne = node_entry(user, node, NOT_AFTER, vec![], None);
        build_card(user, "peer".into(), [7; 32], vec![ne], offers(), 1)
    }

    struct Party {
        user: SigningKey,
        node: SigningKey,
        card: ContactCard,
    }

    fn party(seed: u8) -> Party {
        let user = SigningKey::from_bytes(&[seed; 32]);
        let node = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
        let card = card_for(&user, &node);
        Party { user, node, card }
    }

    /// Drive the full A<->B handshake, returning the requester's completed
    /// friendship (and the accept the acceptor produced).
    fn run_handshake(
        requester: &Party,
        acceptor: &Party,
        book: &mut TicketBook,
        token: [u8; 16],
        now: u64,
    ) -> Result<(Friendship, FriendAccept), FriendError> {
        let req = build_friend_request(&requester.node, requester.card.clone(), token);
        let (accept, acceptor_friendship) = accept_friend_request(
            &req,
            book,
            now,
            &acceptor.node,
            &acceptor.user,
            &acceptor.card,
            ESTABLISHED,
            |core| requester.user.sign(core).to_bytes(),
        )?;
        // Requester side: verify the accept and recover the same friendship.
        let requester_friendship = verify_friend_accept(
            &accept,
            now,
            &requester.user.verifying_key().to_bytes(),
        )?;
        assert_eq!(requester_friendship, acceptor_friendship);
        Ok((requester_friendship, accept))
    }

    #[test]
    fn full_handshake_produces_dual_signed_friendship() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let ticket = build_ticket(&acceptor.user, [0x21; 32], vec![], vec![], NOW + 3600).unwrap();
        let mut book = TicketBook::new();
        book.issue(&ticket);

        let (friendship, _accept) =
            run_handshake(&requester, &acceptor, &mut book, ticket.token, NOW).unwrap();
        // Genuinely dual-signed and correctly ordered.
        friendship.verify().unwrap();
        assert!(friendship.a <= friendship.b);
        let want = [
            requester.user.verifying_key().to_bytes(),
            acceptor.user.verifying_key().to_bytes(),
        ];
        assert!(want.contains(&friendship.a) && want.contains(&friendship.b));
        assert_eq!(friendship.established, ESTABLISHED);
    }

    #[test]
    fn ticket_is_single_use_across_handshakes() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let ticket = build_ticket(&acceptor.user, [0x21; 32], vec![], vec![], NOW + 3600).unwrap();
        let mut book = TicketBook::new();
        book.issue(&ticket);

        run_handshake(&requester, &acceptor, &mut book, ticket.token, NOW).unwrap();
        // A second attempt with the same token is refused (single-use).
        let second = party(0x30);
        assert!(matches!(
            run_handshake(&second, &acceptor, &mut book, ticket.token, NOW),
            Err(FriendError::TicketConsumed)
        ));
    }

    #[test]
    fn unknown_token_rejected() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let mut book = TicketBook::new(); // never issued
        assert!(matches!(
            run_handshake(&requester, &acceptor, &mut book, [0xAB; 16], NOW),
            Err(FriendError::TicketUnknown)
        ));
    }

    #[test]
    fn expired_token_rejected() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let ticket = build_ticket(&acceptor.user, [0x21; 32], vec![], vec![], NOW + 10).unwrap();
        let mut book = TicketBook::new();
        book.issue(&ticket);
        assert!(matches!(
            run_handshake(&requester, &acceptor, &mut book, ticket.token, NOW + 1000),
            Err(FriendError::TicketExpired)
        ));
    }

    #[test]
    fn forged_embedded_card_in_request_rejected() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let ticket = build_ticket(&acceptor.user, [0x21; 32], vec![], vec![], NOW + 3600).unwrap();
        let mut book = TicketBook::new();
        book.issue(&ticket);

        // Break the embedded card's self-signature, then re-sign only the OUTER
        // frame with the requester's node. The outer sig is valid but the inner
        // card no longer verifies - W1 must catch it.
        let mut req = build_friend_request(&requester.node, requester.card.clone(), ticket.token);
        req.card.display = "forged".into();
        req.sign(&requester.node);
        assert!(matches!(
            verify_friend_request(&req, NOW),
            Err(FriendError::Wire(_))
        ));
    }

    #[test]
    fn undelegated_node_in_request_rejected() {
        let requester = party(0x10);
        // Sign the request with a node NOT delegated in the requester's card.
        let rogue_node = SigningKey::from_bytes(&[0x77; 32]);
        let req = build_friend_request(&rogue_node, requester.card.clone(), [1; 16]);
        assert!(matches!(
            verify_friend_request(&req, NOW),
            Err(FriendError::Delegation)
        ));
    }

    #[test]
    fn tampered_friendship_in_accept_rejected() {
        let requester = party(0x10);
        let acceptor = party(0x20);
        let ticket = build_ticket(&acceptor.user, [0x21; 32], vec![], vec![], NOW + 3600).unwrap();
        let mut book = TicketBook::new();
        book.issue(&ticket);
        let (_fr, mut accept) =
            run_handshake(&requester, &acceptor, &mut book, ticket.token, NOW).unwrap();
        // Tamper the embedded friendship, re-sign only the outer node frame.
        accept.friendship.established ^= 1;
        accept.sign(&acceptor.node);
        assert!(matches!(
            verify_friend_accept(&accept, NOW, &requester.user.verifying_key().to_bytes()),
            Err(FriendError::Wire(_))
        ));
    }
}
