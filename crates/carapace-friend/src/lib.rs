//! carapace-friend: the friendship graph and its lifecycle (protocol §9, §6).
//!
//! This crate sits above the frozen wire types ([`carapace_wire`]) and the
//! recovery layer ([`carapace_recovery`]) and drives the human-facing flows:
//!
//! - [`card`]: this user's own self-signed [`carapace_wire::ContactCard`] plus
//!   the address book of friends' latest verified cards (§9.1), with the §6
//!   monotonic-version rollback discipline.
//! - [`ticket`]: build/verify [`carapace_wire::InviteTicket`]s and the
//!   `carapace:<base32-CBOR>` URI, plus single-use token bookkeeping (§6).
//! - [`handshake`]: the ticket -> `FriendRequest` -> `FriendAccept` exchange
//!   that yields a mutually-signed [`carapace_wire::Friendship`] (§9.2), with
//!   the Phase 0 W1 discipline (verify embedded card self-signatures and node
//!   delegations, never trust spliced bytes).
//! - [`unfriend`]: `FriendshipEnd` and the deletion flow (§9.3 steps 1-2).
//! - [`resplit`]: the re-split-on-unfriend completion state machine (§9.3
//!   step 3): stand up a new recovery set, wait for it to go live, and only
//!   then instruct the old honest trustees to destroy their shares.

pub mod card;
pub mod handshake;
pub mod resplit;
pub mod ticket;
pub mod unfriend;

pub use card::{build_card, node_entry, CardStore};
pub use handshake::{
    accept_friend_request, build_friend_request, friendship_core_bytes, verify_friend_accept,
    verify_friend_request,
};
pub use resplit::{Resplit, ResplitPhase, ResplitProgress};
pub use ticket::{build_ticket, parse_uri, verify_ticket, TicketBook};
pub use unfriend::{build_delete_ack, build_delete_requests, end_friendship, verify_delete_ack};

/// Every failure mode of the friendship layer.
#[derive(Debug)]
pub enum FriendError {
    /// A wire-layer encode/decode or signature-verification error.
    Wire(carapace_wire::Error),
    /// A recovery-layer error (split, grant, attestation).
    Recovery(carapace_recovery::RecoveryError),
    /// The invite URI was malformed (bad prefix, bad base32, or bad CBOR).
    BadUri,
    /// The ticket's expiry is in the past relative to the supplied clock.
    TicketExpired,
    /// The presented token was never issued by this book.
    TicketUnknown,
    /// The presented token was already redeemed (single-use replay).
    TicketConsumed,
    /// An embedded card's signing node is not delegated by the card's user
    /// (or the delegation has expired) - the W1 discipline refused it.
    Delegation,
    /// A signed object's `by` did not match the identity it must be bound to.
    IdentityMismatch,
    /// A card offered to the address book was not strictly newer than the
    /// newest already held from that signer (a rollback or stale duplicate).
    Rollback {
        /// Highest version already accepted from this signer.
        seen: u64,
        /// Version of the rejected card.
        got: u64,
    },
    /// The OS CSPRNG failed while minting a ticket token.
    Rng,
    /// A re-split step was attempted before the new recovery set is live: the
    /// old shares MUST NOT be destroyed until `>= M + slack` attestations land.
    NewSetNotLive,
    /// A message referenced a trustee that is not part of this re-split.
    UnknownTrustee,
    /// A message referenced the wrong recovery-set id or subject.
    WrongSet,
    /// Persisted state bytes were truncated, over-long, or otherwise malformed
    /// and could not be decoded back into a valid machine.
    Corrupt,
}

impl core::fmt::Display for FriendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "wire error: {e}"),
            Self::Recovery(e) => write!(f, "recovery error: {e}"),
            Self::BadUri => f.write_str("malformed carapace: invite URI"),
            Self::TicketExpired => f.write_str("ticket has expired"),
            Self::TicketUnknown => f.write_str("ticket token was never issued"),
            Self::TicketConsumed => f.write_str("ticket token was already redeemed"),
            Self::Delegation => f.write_str("embedded card's signing node is not delegated"),
            Self::IdentityMismatch => f.write_str("signed object bound to the wrong identity"),
            Self::Rollback { seen, got } => {
                write!(f, "card rollback rejected: seen version {seen}, got {got}")
            }
            Self::Rng => f.write_str("CSPRNG failed while minting a token"),
            Self::NewSetNotLive => {
                f.write_str("new recovery set is not live yet; cannot destroy old shares")
            }
            Self::UnknownTrustee => f.write_str("trustee is not part of this re-split"),
            Self::WrongSet => f.write_str("message referenced the wrong subject or recovery set"),
            Self::Corrupt => f.write_str("persisted re-split state was malformed"),
        }
    }
}

impl std::error::Error for FriendError {}

impl From<carapace_wire::Error> for FriendError {
    fn from(e: carapace_wire::Error) -> Self {
        Self::Wire(e)
    }
}

impl From<carapace_recovery::RecoveryError> for FriendError {
    fn from(e: carapace_recovery::RecoveryError) -> Self {
        Self::Recovery(e)
    }
}
