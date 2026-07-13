//! Friend-request tickets (protocol §6). A ticket is a single-use, expiring,
//! self-identifying [`InviteTicket`] rendered as a `carapace:<base32-CBOR>` URI
//! and handed over any channel the two people already trust. A ticket alone
//! grants only the ability to *ask*; acceptance is the mutual signing of a
//! [`carapace_wire::Friendship`] (§9.2, see [`crate::handshake`]).

use std::collections::{HashMap, HashSet};

use carapace_wire::{decode, InviteTicket, Message};
use ed25519_dalek::SigningKey;

use crate::FriendError;

/// Mint and sign a single-use [`InviteTicket`] with a fresh random token. The
/// signature is by `user_key` (the ticket is self-identifying: field 0 is both
/// the user pubkey and the signer). `expires` is a unix-seconds deadline.
pub fn build_ticket(
    user_key: &SigningKey,
    node: [u8; 32],
    addrs: Vec<String>,
    relay_urls: Vec<String>,
    expires: u64,
) -> Result<InviteTicket, FriendError> {
    let mut token = [0u8; 16];
    getrandom::getrandom(&mut token).map_err(|_| FriendError::Rng)?;
    let mut ticket = InviteTicket {
        user: [0; 32],
        node,
        addrs,
        relay_urls,
        token,
        expires,
        sig: [0; 64],
    };
    ticket.sign(user_key);
    Ok(ticket)
}

/// Verify a ticket's signature (against its own field-0 user key) and its expiry
/// against `now`. A ticket whose signature is bad is [`FriendError::Wire`]; one
/// past its deadline is [`FriendError::TicketExpired`].
pub fn verify_ticket(ticket: &InviteTicket, now: u64) -> Result<(), FriendError> {
    ticket.verify()?;
    if now > ticket.expires {
        return Err(FriendError::TicketExpired);
    }
    Ok(())
}

/// Parse a `carapace:<base32-CBOR>` invite URI and verify its signature + expiry
/// (§6). Rejects a malformed prefix, bad base32, non-`InviteTicket` CBOR, a bad
/// signature, or an expired deadline. A tampered payload fails the signature check
/// because verification re-encodes deterministically (never trusts spliced bytes).
pub fn parse_uri(uri: &str, now: u64) -> Result<InviteTicket, FriendError> {
    let b32 = uri.strip_prefix("carapace:").ok_or(FriendError::BadUri)?;
    let payload = base32_lower_decode(b32).ok_or(FriendError::BadUri)?;
    let mut arr = decode(&payload).map_err(|_| FriendError::BadUri)?.into_list().map_err(|_| FriendError::BadUri)?;
    if arr.len() != 2 {
        return Err(FriendError::BadUri);
    }
    let body = arr.pop().unwrap().into_map().map_err(|_| FriendError::BadUri)?;
    let ty = arr.pop().unwrap().into_uint().map_err(|_| FriendError::BadUri)?;
    if ty != InviteTicket::TYPE {
        return Err(FriendError::BadUri);
    }
    let ticket = InviteTicket::from_map(body).map_err(|_| FriendError::BadUri)?;
    verify_ticket(&ticket, now)?;
    Ok(ticket)
}

/// Single-use bookkeeping for the tickets a user issues (§6). The issuer records
/// each minted token and refuses a token that is unknown, expired, or already
/// redeemed - so a ticket presented in a `FriendRequest` can be honored exactly once.
#[derive(Default)]
pub struct TicketBook {
    issued: HashMap<[u8; 16], u64>,
    consumed: HashSet<[u8; 16]>,
}

impl TicketBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a freshly issued ticket so its token can later be redeemed once.
    pub fn issue(&mut self, ticket: &InviteTicket) {
        self.issued.insert(ticket.token, ticket.expires);
    }

    /// Redeem a presented token: it must have been issued, be unexpired at `now`,
    /// and not already consumed. On success the token is marked consumed so a
    /// replay is refused.
    pub fn redeem(&mut self, token: &[u8; 16], now: u64) -> Result<(), FriendError> {
        let expires = *self.issued.get(token).ok_or(FriendError::TicketUnknown)?;
        if self.consumed.contains(token) {
            return Err(FriendError::TicketConsumed);
        }
        if now > expires {
            return Err(FriendError::TicketExpired);
        }
        self.consumed.insert(*token);
        Ok(())
    }

    /// Drop tokens that expired at or before `now` (S7). An expired token can no
    /// longer be redeemed (`redeem` rejects it on expiry), so both its issued
    /// record and any consumed marker are dead weight; prune them so the book does
    /// not grow without bound. Every consumed token was first issued, so pruning
    /// the issued record and then dropping orphaned consumed markers is sufficient.
    pub fn prune(&mut self, now: u64) {
        self.issued.retain(|_, &mut expires| now <= expires);
        self.consumed.retain(|t| self.issued.contains_key(t));
    }
}

/// Decode RFC 4648 base32 (lowercase, no padding) as produced by
/// [`InviteTicket::uri`]. Returns `None` on any character outside the alphabet.
fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_000;

    fn a_ticket(now: u64) -> (SigningKey, InviteTicket) {
        let user = SigningKey::from_bytes(&[1; 32]);
        let ticket = build_ticket(
            &user,
            [2; 32],
            vec!["198.51.100.7:7400".into()],
            vec!["relay.example:443".into()],
            now + 3600,
        )
        .unwrap();
        (user, ticket)
    }

    #[test]
    fn uri_round_trips_and_verifies() {
        let (_user, ticket) = a_ticket(NOW);
        let uri = ticket.uri();
        assert!(uri.starts_with("carapace:"));
        let parsed = parse_uri(&uri, NOW).unwrap();
        assert_eq!(parsed, ticket);
    }

    #[test]
    fn expired_ticket_rejected_on_parse() {
        let (_user, ticket) = a_ticket(NOW);
        let uri = ticket.uri();
        // now past the deadline
        assert!(matches!(
            parse_uri(&uri, NOW + 100_000),
            Err(FriendError::TicketExpired)
        ));
    }

    #[test]
    fn tampered_uri_rejected() {
        let (_user, ticket) = a_ticket(NOW);
        let uri = ticket.uri();
        // flip one base32 char inside the signature region of the payload
        let mut chars: Vec<char> = uri.chars().collect();
        let i = chars.len() - 3;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        // Either the signature fails to verify or the CBOR no longer parses;
        // both surface as a rejected URI.
        assert!(parse_uri(&tampered, NOW).is_err());
    }

    #[test]
    fn bad_prefix_rejected() {
        let (_user, ticket) = a_ticket(NOW);
        let uri = ticket.uri().replace("carapace:", "http:");
        assert!(matches!(parse_uri(&uri, NOW), Err(FriendError::BadUri)));
    }

    #[test]
    fn ticket_book_single_use() {
        let (_user, ticket) = a_ticket(NOW);
        let mut book = TicketBook::new();
        // Unknown token before issuing.
        assert!(matches!(
            book.redeem(&ticket.token, NOW),
            Err(FriendError::TicketUnknown)
        ));
        book.issue(&ticket);
        book.redeem(&ticket.token, NOW).unwrap();
        // Replay refused.
        assert!(matches!(
            book.redeem(&ticket.token, NOW),
            Err(FriendError::TicketConsumed)
        ));
    }

    // S7: expired tokens are pruned from both issued and consumed, and pruning is
    // safe (a still-valid token survives, a redeemed-then-expired token is gone).
    #[test]
    fn ticket_book_prunes_expired() {
        let user = SigningKey::from_bytes(&[9; 32]);
        let live = build_ticket(&user, [2; 32], vec![], vec![], NOW + 3600).unwrap();
        let stale = build_ticket(&user, [3; 32], vec![], vec![], NOW + 10).unwrap();
        let mut book = TicketBook::new();
        book.issue(&live);
        book.issue(&stale);
        book.redeem(&stale.token, NOW).unwrap(); // consumed, then it expires

        book.prune(NOW + 100); // past `stale.expires`, before `live.expires`
        assert!(!book.issued.contains_key(&stale.token), "expired issued record dropped");
        assert!(!book.consumed.contains(&stale.token), "orphaned consumed marker dropped");
        // The live ticket is untouched and still redeemable exactly once.
        assert!(book.issued.contains_key(&live.token));
        book.redeem(&live.token, NOW + 100).unwrap();
    }

    #[test]
    fn ticket_book_expiry() {
        let (_user, ticket) = a_ticket(NOW);
        let mut book = TicketBook::new();
        book.issue(&ticket);
        assert!(matches!(
            book.redeem(&ticket.token, ticket.expires + 1),
            Err(FriendError::TicketExpired)
        ));
    }
}
