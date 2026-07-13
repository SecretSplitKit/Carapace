//! Contact card + address book (protocol §9.1). A user keeps one self-signed,
//! versioned [`ContactCard`] describing themselves; the set of your friends'
//! current verified cards **is** your address book. Card versions are monotonic
//! per signer and admitted under the same rollback discipline as §6 anti-entropy.

use std::collections::HashMap;

use carapace_wire::{ContactCard, NodeEntry, Offers, Signed};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::FriendError;

/// Build a signed [`NodeEntry`] for `node_key`, delegated by `user_key` until
/// `not_after` (spec §4.3). The delegation signature binds the node to the user.
pub fn node_entry(
    user_key: &SigningKey,
    node_key: &SigningKey,
    not_after: u64,
    addrs: Vec<String>,
    relay_url: Option<String>,
) -> NodeEntry {
    let node_pub = node_key.verifying_key();
    let deleg =
        carapace_crypto::identity::sign_delegation(user_key, &node_pub, not_after).to_bytes();
    NodeEntry {
        node_id: node_pub.to_bytes(),
        deleg,
        not_after,
        addrs,
        relay_url,
    }
}

/// Build and self-sign a [`ContactCard`] at `version` (§9.1). The card is signed
/// with the user key; each node entry must already carry a user-signed delegation
/// (see [`node_entry`]).
pub fn build_card(
    user_key: &SigningKey,
    display: String,
    enc_pub: [u8; 32],
    nodes: Vec<NodeEntry>,
    offers: Offers,
    version: u64,
) -> ContactCard {
    let mut card = ContactCard {
        user: user_key.verifying_key().to_bytes(),
        display,
        enc_pub,
        nodes,
        offers,
        version,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(user_key);
    card
}

/// True iff `card` (assumed already self-signature-verified) carries a
/// `NodeEntry` for `node_id` whose user-signed delegation is valid and unexpired
/// at `now`. This is the W1 discipline: a node speaks for a user only while a
/// live delegation in that user's card says so.
#[must_use]
pub fn card_delegates_node(card: &ContactCard, node_id: &[u8; 32], now: u64) -> bool {
    let Ok(user_pub) = VerifyingKey::from_bytes(&card.user) else {
        return false;
    };
    card.nodes.iter().any(|n| {
        if &n.node_id != node_id {
            return false;
        }
        let (Ok(node_pub), Ok(sig)) = (
            VerifyingKey::from_bytes(&n.node_id),
            ed25519_dalek::Signature::try_from(&n.deleg[..]),
        ) else {
            return false;
        };
        carapace_crypto::identity::verify_delegation(
            &user_pub,
            &node_pub,
            n.not_after,
            &sig,
            Some(now),
        )
        .is_ok()
    })
}

/// This user's own card plus the address book of friends' latest verified cards,
/// keyed by user pubkey. Enforces monotonic card versions on offer (§6 rollback).
pub struct CardStore {
    own: ContactCard,
    user_key: SigningKey,
    friends: HashMap<[u8; 32], ContactCard>,
}

impl CardStore {
    /// Start a store around this user's own signed card and its user key (used to
    /// re-sign on [`CardStore::bump_own`]).
    #[must_use]
    pub fn new(own: ContactCard, user_key: SigningKey) -> Self {
        Self {
            own,
            user_key,
            friends: HashMap::new(),
        }
    }

    /// This user's own current card.
    #[must_use]
    pub fn own(&self) -> &ContactCard {
        &self.own
    }

    /// Replace the own card's mutable contents and bump its version, re-signing.
    /// The version strictly increases so friends admit it under their rollback rule.
    pub fn bump_own(&mut self, edit: impl FnOnce(&mut ContactCard)) {
        edit(&mut self.own);
        self.own.version += 1;
        self.own.sign(&self.user_key);
    }

    /// Offer a friend's card into the address book. Verifies the self-signature,
    /// then enforces `version > highest already seen from this signer`. Returns
    /// `Ok(true)` if it was newer and stored; a non-newer version is a
    /// [`FriendError::Rollback`].
    pub fn offer(&mut self, card: &ContactCard) -> Result<bool, FriendError> {
        card.verify()?;
        if let Some(existing) = self.friends.get(&card.user) {
            if card.version <= existing.version {
                return Err(FriendError::Rollback {
                    seen: existing.version,
                    got: card.version,
                });
            }
        }
        self.friends.insert(card.user, card.clone());
        Ok(true)
    }

    /// The newest verified card held for `user`, if any.
    #[must_use]
    pub fn friend(&self, user: &[u8; 32]) -> Option<&ContactCard> {
        self.friends.get(user)
    }

    /// Iterate every friend's current card (the address book).
    pub fn friends(&self) -> impl Iterator<Item = &ContactCard> {
        self.friends.values()
    }

    /// Drop a friend's card from the address book (on unfriend, §9.3 step 1).
    pub fn remove(&mut self, user: &[u8; 32]) -> Option<ContactCard> {
        self.friends.remove(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_wire::Offers;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_000;
    const NOT_AFTER: u64 = 5_000_000_000;

    fn offers() -> Offers {
        Offers {
            storage_bytes: 0,
            relay: false,
            trustee: false,
        }
    }

    fn a_card(user: &SigningKey, node: &SigningKey, version: u64) -> ContactCard {
        let ne = node_entry(user, node, NOT_AFTER, vec![], None);
        build_card(user, "me".into(), [7; 32], vec![ne], offers(), version)
    }

    #[test]
    fn built_card_verifies_and_delegates_node() {
        let user = SigningKey::from_bytes(&[1; 32]);
        let node = SigningKey::from_bytes(&[2; 32]);
        let card = a_card(&user, &node, 1);
        card.verify().unwrap();
        assert!(card_delegates_node(
            &card,
            &node.verifying_key().to_bytes(),
            NOW
        ));
        // A node not in the card is not delegated.
        assert!(!card_delegates_node(&card, &[9; 32], NOW));
    }

    #[test]
    fn delegation_expiry_is_enforced() {
        let user = SigningKey::from_bytes(&[1; 32]);
        let node = SigningKey::from_bytes(&[2; 32]);
        let ne = node_entry(&user, &node, 100, vec![], None);
        let card = build_card(&user, "me".into(), [7; 32], vec![ne], offers(), 1);
        assert!(card_delegates_node(
            &card,
            &node.verifying_key().to_bytes(),
            50
        ));
        assert!(!card_delegates_node(
            &card,
            &node.verifying_key().to_bytes(),
            200
        ));
    }

    #[test]
    fn address_book_is_monotonic() {
        let me = SigningKey::from_bytes(&[1; 32]);
        let my_node = SigningKey::from_bytes(&[2; 32]);
        let mut store = CardStore::new(a_card(&me, &my_node, 1), me.clone());

        let friend = SigningKey::from_bytes(&[3; 32]);
        let fnode = SigningKey::from_bytes(&[4; 32]);
        let v1 = a_card(&friend, &fnode, 1);
        let v2 = a_card(&friend, &fnode, 2);

        assert!(store.offer(&v1).unwrap());
        assert_eq!(
            store
                .friend(&friend.verifying_key().to_bytes())
                .unwrap()
                .version,
            1
        );
        assert!(store.offer(&v2).unwrap());
        // A replay of v1 (<= seen) is a rollback.
        assert!(matches!(
            store.offer(&v1),
            Err(FriendError::Rollback { seen: 2, got: 1 })
        ));
        // Same version is also a rollback.
        assert!(matches!(
            store.offer(&v2),
            Err(FriendError::Rollback { .. })
        ));
    }

    #[test]
    fn bump_own_increments_and_resigns() {
        let me = SigningKey::from_bytes(&[1; 32]);
        let my_node = SigningKey::from_bytes(&[2; 32]);
        let mut store = CardStore::new(a_card(&me, &my_node, 1), me.clone());
        assert_eq!(store.own().version, 1);
        store.bump_own(|c| c.display = "renamed".into());
        assert_eq!(store.own().version, 2);
        assert_eq!(store.own().display, "renamed");
        store.own().verify().unwrap();
    }

    #[test]
    fn forged_friend_card_is_refused() {
        let me = SigningKey::from_bytes(&[1; 32]);
        let my_node = SigningKey::from_bytes(&[2; 32]);
        let mut store = CardStore::new(a_card(&me, &my_node, 1), me);
        let friend = SigningKey::from_bytes(&[3; 32]);
        let fnode = SigningKey::from_bytes(&[4; 32]);
        let mut card = a_card(&friend, &fnode, 1);
        card.display = "tampered".into(); // break the self-signature
        assert!(matches!(store.offer(&card), Err(FriendError::Wire(_))));
    }
}
