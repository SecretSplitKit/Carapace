//! Hello + pairwise anti-entropy (§6). On a `carapace/1` stream the two nodes
//! exchange a `Hello`, then reconcile their latest signed documents
//! (`ContactCard`, `VaultAnnounce` for Phase 1) by monotonic version.
//!
//! Rollback protection (§6): a document whose version/epoch is `<=` the highest
//! already seen from that signer is rejected. Signatures are always verified
//! before a document is admitted.

use crate::endpoint::ALPN;
use crate::frame::{read_frame_raw, read_msg, write_msg};
use anyhow::Result;
use carapace_wire::messages::Message;
use carapace_wire::{ContactCard, Hello, Signed, VaultAnnounce};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use std::collections::HashMap;
use std::sync::Arc;

/// The one wire suite this build speaks. §2: the suite is bound to the ALPN
/// (`carapace/1`); a future suite gets a new ALPN and a new protocol number, so a
/// peer advertising anything else here is speaking a suite we MUST reject rather
/// than negotiate down to.
pub const PROTOCOL_VERSION: u64 = 1;

/// A peer advertised a `Hello.protocol` this build does not speak (§2). Unknown
/// suite ids are rejected outright, never negotiated down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedProtocol {
    /// The protocol number the peer advertised.
    pub got: u64,
    /// The only protocol number this build accepts.
    pub expected: u64,
}

impl std::fmt::Display for UnsupportedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported protocol {}: this build speaks only carapace/{} \
             (unknown suite ids are rejected, not negotiated down)",
            self.got, self.expected
        )
    }
}

impl std::error::Error for UnsupportedProtocol {}

/// §2: enforce that `peer` speaks our exact suite. The suite is pinned to the ALPN
/// `carapace/1`, so any other protocol number is a hard reject.
fn check_protocol(peer: &Hello) -> Result<(), UnsupportedProtocol> {
    if peer.protocol == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(UnsupportedProtocol {
            got: peer.protocol,
            expected: PROTOCOL_VERSION,
        })
    }
}

/// Why an offered document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The document's self-signature did not verify.
    BadSignature,
    /// The document's version/epoch was `<=` the highest already seen from this
    /// signer (a rollback attempt or a stale duplicate).
    Rollback {
        /// Highest version/epoch already accepted from this signer.
        seen: u64,
        /// Version/epoch of the rejected document.
        got: u64,
    },
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::BadSignature => write!(f, "document signature invalid"),
            Reject::Rollback { seen, got } => {
                write!(f, "rollback rejected: seen version {seen}, got {got}")
            }
        }
    }
}

impl std::error::Error for Reject {}

/// The newest signed documents seen per signer, with monotonic-version rollback
/// protection. Cards are keyed by signer; announces by `(signer, vid)` since a
/// signer maintains an independent monotonic epoch line per vault.
#[derive(Default)]
pub struct DocStore {
    cards: HashMap<[u8; 32], ContactCard>,
    announces: HashMap<([u8; 32], [u8; 32]), VaultAnnounce>,
}

impl DocStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer a `ContactCard`. Verifies the signature, then enforces
    /// `version > highest seen from this signer`. Returns `Ok(true)` if it was
    /// newer and stored, `Ok(false)` if identical-or-older is *not* possible
    /// (any non-newer version is a rollback and errors).
    pub fn offer_card(&mut self, card: &ContactCard) -> Result<bool, Reject> {
        card.verify().map_err(|_| Reject::BadSignature)?;
        if let Some(existing) = self.cards.get(&card.by) {
            if card.version <= existing.version {
                return Err(Reject::Rollback {
                    seen: existing.version,
                    got: card.version,
                });
            }
        }
        self.cards.insert(card.by, card.clone());
        Ok(true)
    }

    /// Offer a `VaultAnnounce`. Verifies the signature, then enforces
    /// `epoch > highest seen from this signer for this vault`.
    pub fn offer_announce(&mut self, ann: &VaultAnnounce) -> Result<bool, Reject> {
        ann.verify().map_err(|_| Reject::BadSignature)?;
        let key = (ann.by, ann.vid);
        if let Some(existing) = self.announces.get(&key) {
            if ann.epoch <= existing.epoch {
                return Err(Reject::Rollback {
                    seen: existing.epoch,
                    got: ann.epoch,
                });
            }
        }
        self.announces.insert(key, ann.clone());
        Ok(true)
    }

    /// The newest card seen from `signer`, if any.
    pub fn card(&self, signer: &[u8; 32]) -> Option<&ContactCard> {
        self.cards.get(signer)
    }

    /// The newest announce seen for `vid` (from any signer).
    pub fn announce_for_vid(&self, vid: &[u8; 32]) -> Option<&VaultAnnounce> {
        self.announces.values().find(|a| &a.vid == vid)
    }

    /// All known announces.
    pub fn announces(&self) -> impl Iterator<Item = &VaultAnnounce> {
        self.announces.values()
    }
}

/// The document set a node advertises during anti-entropy, plus its `Hello`.
#[derive(Debug, Clone)]
pub struct SyncHandler {
    /// This node's `Hello`.
    pub hello: Hello,
    /// Self-signed `ContactCard`s to advertise.
    pub cards: Arc<Vec<ContactCard>>,
    /// Node-signed `VaultAnnounce`s to advertise.
    pub announces: Arc<Vec<VaultAnnounce>>,
}

impl SyncHandler {
    async fn serve(&self, conn: Connection) -> Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        // Exchange Hello: read the peer's, validate its suite (§2 - an unknown
        // protocol number is rejected, never negotiated down), then send ours.
        let peer_hello = read_msg::<Hello>(&mut recv).await?;
        check_protocol(&peer_hello)?;
        write_msg(&mut send, &self.hello).await?;
        // Push our latest signed documents; the peer applies its own rollback
        // rule on receipt.
        for card in self.cards.iter() {
            write_msg(&mut send, card).await?;
        }
        for ann in self.announces.iter() {
            write_msg(&mut send, ann).await?;
        }
        send.finish()?;
        // Hold the connection open until the peer is done reading.
        conn.closed().await;
        Ok(())
    }
}

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.serve(conn)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// Client side of anti-entropy: send `Hello`, read the peer's `Hello`, then read
/// its advertised documents into `store`, applying the rollback rule. Returns
/// the number of documents accepted as newer.
pub async fn pull_documents(
    conn: &Connection,
    hello: &Hello,
    store: &mut DocStore,
) -> Result<usize> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, hello).await?;
    // §2: reject a peer advertising a suite we do not speak instead of proceeding.
    let peer_hello = read_msg::<Hello>(&mut recv).await?;
    check_protocol(&peer_hello)?;

    let mut accepted = 0usize;
    while let Some((ty, body)) = read_frame_raw(&mut recv).await? {
        match ty {
            ContactCard::TYPE => {
                let card = ContactCard::from_map(body)?;
                // A rollback/stale doc is rejected but does not abort the sync.
                if store.offer_card(&card).unwrap_or(false) {
                    accepted += 1;
                }
            }
            VaultAnnounce::TYPE => {
                let ann = VaultAnnounce::from_map(body)?;
                if store.offer_announce(&ann).unwrap_or(false) {
                    accepted += 1;
                }
            }
            // Phase 1 reconciles only cards and announces; ignore others.
            _ => {}
        }
    }
    send.finish()?;
    Ok(accepted)
}

/// The ALPN this sync protocol speaks (re-exported for `Router` registration).
pub const SYNC_ALPN: &[u8] = ALPN;

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(protocol: u64) -> Hello {
        Hello {
            protocol,
            card_version: 1,
            roles: 1,
        }
    }

    // §2: a peer advertising an unknown suite id is rejected, not accepted.
    #[test]
    fn unknown_protocol_is_rejected() {
        assert!(check_protocol(&hello(PROTOCOL_VERSION)).is_ok());
        assert_eq!(
            check_protocol(&hello(99)),
            Err(UnsupportedProtocol {
                got: 99,
                expected: PROTOCOL_VERSION,
            }),
            "protocol 99 must be rejected outright"
        );
        assert_eq!(
            check_protocol(&hello(0)),
            Err(UnsupportedProtocol {
                got: 0,
                expected: PROTOCOL_VERSION,
            }),
            "protocol 0 is not negotiated down to a supported suite"
        );
    }
}
