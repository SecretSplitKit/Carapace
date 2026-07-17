//! Framing (B.2), signing discipline (B.3), and the typed message registry
//! (B.5 / B.6) for Carapace. Every struct's `to_map`/`from_map` places fields
//! at the CDDL field numbers; key 22 = `by` (signer pubkey), key 23 = `sig`.

use crate::value::{decode, encode, Key, Map, Value};
use crate::Error;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Signing-domain prefix (B.3).
pub const DOMAIN: &[u8] = b"carapace-sig-v1";
/// Device-delegation domain prefix (spec §4.3).
pub const DELEG_DOMAIN: &[u8] = b"carapace/v1/deleg";

/// Sign a device delegation: `Ed25519(user_key, "carapace/v1/deleg" ‖ node ‖ not_after_be8)`.
pub fn sign_delegation(user_key: &SigningKey, node_pub: &[u8; 32], not_after: u64) -> [u8; 64] {
    let mut msg = DELEG_DOMAIN.to_vec();
    msg.extend_from_slice(node_pub);
    msg.extend_from_slice(&not_after.to_be_bytes());
    user_key.sign(&msg).to_bytes()
}
/// Maximum control-frame payload (B.2): 1 MiB.
pub const MAX_PAYLOAD: usize = 1 << 20;

// ---------------- framing (B.2) -----------------------------------------

/// Encode `det_cbor([type_id, body])` and prepend the 4-byte big-endian length.
pub fn frame(type_id: u64, body: &Map) -> Vec<u8> {
    let payload = encode(&Value::Array(vec![
        Value::Uint(type_id),
        Value::Map(body.clone()),
    ]));
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend(payload);
    out
}

/// Decode a frame into `(msg_type, body_map)`, enforcing the payload cap and
/// strict deterministic decoding. Rejects oversized or non-canonical frames.
pub fn decode_frame(bytes: &[u8]) -> Result<(u64, Map), Error> {
    let len_bytes = bytes.get(0..4).ok_or(Error::Truncated)?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Oversized);
    }
    let payload = bytes.get(4..).ok_or(Error::Truncated)?;
    if payload.len() != len {
        return Err(Error::Truncated);
    }
    let mut arr = decode(payload)?.into_list()?;
    if arr.len() != 2 {
        return Err(Error::BadFrame);
    }
    let body = arr.pop().unwrap().into_map()?;
    let mt = arr.pop().unwrap().into_uint()?;
    Ok((mt, body))
}

// ---------------- signing discipline (B.3) ------------------------------

/// The bytes an Ed25519 signature is computed over:
/// `DOMAIN ‖ det_cbor([type_id, body_without_key_23])`.
pub fn signing_bytes(type_id: u64, body: &Map) -> Vec<u8> {
    let mut m = body.clone();
    m.remove(23);
    let mut out = DOMAIN.to_vec();
    out.extend(encode(&Value::Array(vec![
        Value::Uint(type_id),
        Value::Map(m),
    ])));
    out
}

// ---------------- traits -------------------------------------------------

/// A framed message with a stable registry type id and map<->struct mapping.
pub trait Message: Sized {
    /// Registry type id (B.5).
    const TYPE: u64;
    /// Encode the body as a canonical map (fields at their CDDL numbers).
    fn to_map(&self) -> Map;
    /// Decode the body from a map, rejecting unknown keys.
    fn from_map(m: Map) -> Result<Self, Error>;

    /// Encode as a full length-prefixed frame.
    fn encode_frame(&self) -> Vec<u8> {
        frame(Self::TYPE, &self.to_map())
    }
    /// Decode from a full frame (validates the type id).
    fn decode_frame(bytes: &[u8]) -> Result<Self, Error> {
        let (mt, body) = decode_frame(bytes)?;
        if mt != Self::TYPE {
            return Err(Error::WrongType {
                expected: Self::TYPE,
                got: mt,
            });
        }
        Self::from_map(body)
    }
}

/// A message carrying `by` (key 22) and `sig` (key 23) under the B.3 rule.
pub trait Signed: Message {
    /// Signer public key (key 22).
    fn by(&self) -> [u8; 32];
    /// Set the signer public key.
    fn set_by(&mut self, v: [u8; 32]);
    /// Signature (key 23).
    fn sig(&self) -> [u8; 64];
    /// Set the signature.
    fn set_sig(&mut self, v: [u8; 64]);

    /// Sign in place: set `by` from the key and fill `sig` per B.3.
    fn sign(&mut self, key: &SigningKey) {
        self.set_by(key.verifying_key().to_bytes());
        let sig = key.sign(&signing_bytes(Self::TYPE, &self.to_map()));
        self.set_sig(sig.to_bytes());
    }

    /// Verify signatures of any embedded signed objects (e.g. an inner
    /// `ContactCard`/`Friendship`). Default: nothing embedded. The outer node
    /// signature only binds the embedded *bytes*; it does not certify that
    /// those bytes carry a valid self-signature, so `verify` recurses here.
    fn verify_embedded(&self) -> Result<(), Error> {
        Ok(())
    }

    /// Verify by re-encoding deterministically (never against spliced bytes),
    /// then recurse into every embedded signed object. A hostile node cannot
    /// smuggle an unverified inner `ContactCard`/`Friendship` past `verify`.
    fn verify(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.by())?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig());
        vk.verify_strict(&signing_bytes(Self::TYPE, &self.to_map()), &sig)?;
        self.verify_embedded()
    }
}

macro_rules! impl_signed {
    ($t:ty) => {
        impl Signed for $t {
            fn by(&self) -> [u8; 32] {
                self.by
            }
            fn set_by(&mut self, v: [u8; 32]) {
                self.by = v;
            }
            fn sig(&self) -> [u8; 64] {
                self.sig
            }
            fn set_sig(&mut self, v: [u8; 64]) {
                self.sig = v;
            }
        }
    };
}

// ---------------- small value helpers -----------------------------------

fn vb(x: &[u8]) -> Value {
    Value::Bytes(x.to_vec())
}
fn pubs(v: &[[u8; 32]]) -> Value {
    Value::Array(v.iter().map(|p| vb(p)).collect())
}
fn from_pubs(v: Value) -> Result<Vec<[u8; 32]>, Error> {
    v.into_list()?
        .into_iter()
        .map(|x| x.into_array_n())
        .collect()
}

/// A version vector: device pubkey -> counter.
pub type Vv = Vec<([u8; 32], u64)>;

fn vv_to_value(vv: &Vv) -> Value {
    let mut m = Map::new();
    for (k, v) in vv {
        m.push(Key::Bytes(k.to_vec()), Value::Uint(*v));
    }
    Value::Map(m)
}
fn vv_from_value(v: Value) -> Result<Vv, Error> {
    let mut out = Vv::new();
    for (k, val) in v.into_map()?.into_entries() {
        match k {
            Key::Bytes(b) => out.push((
                b.try_into().map_err(|_| Error::WrongLength)?,
                val.into_uint()?,
            )),
            Key::Uint(_) => return Err(Error::InvalidMapKey),
        }
    }
    Ok(out)
}

// ================= nested (non-framed) sub-structures ====================

/// A device entry in a ContactCard (CDDL `NodeEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEntry {
    /// node_id (device Ed25519 pubkey).
    pub node_id: [u8; 32],
    /// delegation signature by the user key (spec §4.3).
    pub deleg: [u8; 64],
    /// delegation not_after (unix seconds).
    pub not_after: u64,
    /// reachable addresses ("host:port").
    pub addrs: Vec<String>,
    /// relay URL, or none.
    pub relay_url: Option<String>,
}

impl NodeEntry {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, vb(&self.node_id));
        m.u(1, vb(&self.deleg));
        m.u(2, Value::Uint(self.not_after));
        m.u(
            3,
            Value::Array(self.addrs.iter().map(|s| Value::Text(s.clone())).collect()),
        );
        m.u(
            4,
            match &self.relay_url {
                Some(s) => Value::Text(s.clone()),
                None => Value::Null,
            },
        );
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let node_id = m.take(0)?.into_array_n()?;
        let deleg = m.take(1)?.into_array_n()?;
        let not_after = m.take(2)?.into_uint()?;
        let addrs = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(|x| x.into_text())
            .collect::<Result<_, _>>()?;
        let relay_url = m.take(4)?.into_opt_text()?;
        m.finish()?;
        Ok(NodeEntry {
            node_id,
            deleg,
            not_after,
            addrs,
            relay_url,
        })
    }
}

/// Storage/relay/trustee offers advertised in a ContactCard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offers {
    /// offered storage in bytes.
    pub storage_bytes: u64,
    /// whether relay is offered.
    pub relay: bool,
    /// whether trustee service is offered.
    pub trustee: bool,
}

impl Offers {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, Value::Uint(self.storage_bytes));
        m.u(1, Value::Bool(self.relay));
        m.u(2, Value::Bool(self.trustee));
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let storage_bytes = m.take(0)?.into_uint()?;
        let relay = m.take(1)?.into_bool()?;
        let trustee = m.take(2)?.into_bool()?;
        m.finish()?;
        Ok(Offers {
            storage_bytes,
            relay,
            trustee,
        })
    }
}

/// A co-trustee reference in a ShareGrant (CDDL `CoTrustee`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoTrustee {
    /// co-trustee user pubkey.
    pub user: [u8; 32],
    /// co-trustee node pubkey.
    pub node: [u8; 32],
    /// relay URL, or none.
    pub relay_url: Option<String>,
}

impl CoTrustee {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, vb(&self.user));
        m.u(1, vb(&self.node));
        m.u(
            2,
            match &self.relay_url {
                Some(s) => Value::Text(s.clone()),
                None => Value::Null,
            },
        );
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let user = m.take(0)?.into_array_n()?;
        let node = m.take(1)?.into_array_n()?;
        let relay_url = m.take(2)?.into_opt_text()?;
        m.finish()?;
        Ok(CoTrustee {
            user,
            node,
            relay_url,
        })
    }
}

/// A vault-announcement reference in a ShareGrant (CDDL `AnnounceRef`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnounceRef {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// manifest digest.
    pub digest: [u8; 32],
}

impl AnnounceRef {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, vb(&self.digest));
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let digest = m.take(2)?.into_array_n()?;
        m.finish()?;
        Ok(AnnounceRef { vid, epoch, digest })
    }
}

/// An HPKE-sealed grant recipient in a FileGrant (CDDL `Sealed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// recipient user pubkey.
    pub to: [u8; 32],
    /// opaque HPKE ciphertext of the det-CBOR GrantBody.
    pub ct: Vec<u8>,
}

impl Sealed {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, vb(&self.to));
        m.u(1, vb(&self.ct));
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let to = m.take(0)?.into_array_n()?;
        let ct = m.take(1)?.into_bytes()?;
        m.finish()?;
        Ok(Sealed { to, ct })
    }
}

// ================= framed messages (B.5) ================================

/// Type 1: Hello (unsigned; connection is NodeID-authenticated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// protocol version.
    pub protocol: u64,
    /// sender's own ContactCard version.
    pub card_version: u64,
    /// roles bitfield: 1=storage 2=trustee 4=relay.
    pub roles: u64,
}
impl Message for Hello {
    const TYPE: u64 = 1;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, Value::Uint(self.protocol));
        m.u(1, Value::Uint(self.card_version));
        m.u(2, Value::Uint(self.roles));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let protocol = m.take(0)?.into_uint()?;
        let card_version = m.take(1)?.into_uint()?;
        let roles = m.take(2)?.into_uint()?;
        m.finish()?;
        Ok(Hello {
            protocol,
            card_version,
            roles,
        })
    }
}

/// Type 2: ContactCard (signed by the user key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    /// user pubkey.
    pub user: [u8; 32],
    /// display name.
    pub display: String,
    /// X25519 encryption pubkey.
    pub enc_pub: [u8; 32],
    /// device entries.
    pub nodes: Vec<NodeEntry>,
    /// advertised offers.
    pub offers: Offers,
    /// monotonic version.
    pub version: u64,
    /// signer pubkey (= user).
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl ContactCard {
    fn to_value(&self) -> Value {
        Value::Map(self.to_map())
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        Self::from_map(v.into_map()?)
    }
}
impl Message for ContactCard {
    const TYPE: u64 = 2;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.user));
        m.u(1, Value::Text(self.display.clone()));
        m.u(2, vb(&self.enc_pub));
        m.u(
            3,
            Value::Array(self.nodes.iter().map(|n| n.to_value()).collect()),
        );
        m.u(4, self.offers.to_value());
        m.u(5, Value::Uint(self.version));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let user = m.take(0)?.into_array_n()?;
        let display = m.take(1)?.into_text()?;
        let enc_pub = m.take(2)?.into_array_n()?;
        let nodes = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(NodeEntry::from_value)
            .collect::<Result<_, _>>()?;
        let offers = Offers::from_value(m.take(4)?)?;
        let version = m.take(5)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ContactCard {
            user,
            display,
            enc_pub,
            nodes,
            offers,
            version,
            by,
            sig,
        })
    }
}
impl_signed!(ContactCard);

/// Type 3: FriendRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendRequest {
    /// ticket token.
    pub token: [u8; 16],
    /// requester's ContactCard (carries its own sig).
    pub card: ContactCard,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for FriendRequest {
    const TYPE: u64 = 3;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.token));
        m.u(1, self.card.to_value());
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let token = m.take(0)?.into_array_n()?;
        let card = ContactCard::from_value(m.take(1)?)?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(FriendRequest {
            token,
            card,
            by,
            sig,
        })
    }
}
impl Signed for FriendRequest {
    fn by(&self) -> [u8; 32] {
        self.by
    }
    fn set_by(&mut self, v: [u8; 32]) {
        self.by = v;
    }
    fn sig(&self) -> [u8; 64] {
        self.sig
    }
    fn set_sig(&mut self, v: [u8; 64]) {
        self.sig = v;
    }
    fn verify_embedded(&self) -> Result<(), Error> {
        self.card.verify()
    }
}

/// Type 4: FriendAccept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendAccept {
    /// acceptor's ContactCard.
    pub card: ContactCard,
    /// mutually-signed Friendship.
    pub friendship: Friendship,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for FriendAccept {
    const TYPE: u64 = 4;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, self.card.to_value());
        m.u(1, self.friendship.to_value());
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let card = ContactCard::from_value(m.take(0)?)?;
        let friendship = Friendship::from_value(m.take(1)?)?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(FriendAccept {
            card,
            friendship,
            by,
            sig,
        })
    }
}
impl Signed for FriendAccept {
    fn by(&self) -> [u8; 32] {
        self.by
    }
    fn set_by(&mut self, v: [u8; 32]) {
        self.by = v;
    }
    fn sig(&self) -> [u8; 64] {
        self.sig
    }
    fn set_sig(&mut self, v: [u8; 64]) {
        self.sig = v;
    }
    fn verify_embedded(&self) -> Result<(), Error> {
        self.card.verify()?;
        self.friendship.verify()
    }
}

/// Type 5: FriendshipEnd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendshipEnd {
    /// the unfriended user.
    pub user: [u8; 32],
    /// timestamp.
    pub ts: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for FriendshipEnd {
    const TYPE: u64 = 5;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.user));
        m.u(1, Value::Uint(self.ts));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let user = m.take(0)?.into_array_n()?;
        let ts = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(FriendshipEnd { user, ts, by, sig })
    }
}
impl_signed!(FriendshipEnd);

/// Type 6: DeleteRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteRequest {
    /// scope: 0=replicas 1=shares 2=all.
    pub scope: u64,
    /// vid (present when scope=0).
    pub vid: Option<[u8; 32]>,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for DeleteRequest {
    const TYPE: u64 = 6;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, Value::Uint(self.scope));
        m.u(
            1,
            match &self.vid {
                Some(v) => vb(v),
                None => Value::Null,
            },
        );
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let scope = m.take(0)?.into_uint()?;
        let vid = match m.take(1)? {
            Value::Null => None,
            other => Some(other.into_array_n()?),
        };
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(DeleteRequest {
            scope,
            vid,
            by,
            sig,
        })
    }
}
impl_signed!(DeleteRequest);

/// Type 7: DeleteAck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteAck {
    /// BLAKE3 of the DeleteRequest payload.
    pub reference: [u8; 32],
    /// timestamp.
    pub ts: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for DeleteAck {
    const TYPE: u64 = 7;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.reference));
        m.u(1, Value::Uint(self.ts));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let reference = m.take(0)?.into_array_n()?;
        let ts = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(DeleteAck {
            reference,
            ts,
            by,
            sig,
        })
    }
}
impl_signed!(DeleteAck);

/// Type 8: VaultAnnounce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultAnnounce {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch (monotonic).
    pub epoch: u64,
    /// replica NodeIDs.
    pub replicas: Vec<[u8; 32]>,
    /// manifest digest (iroh blob hash).
    pub digest: [u8; 32],
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for VaultAnnounce {
    const TYPE: u64 = 8;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, pubs(&self.replicas));
        m.u(3, vb(&self.digest));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let replicas = from_pubs(m.take(2)?)?;
        let digest = m.take(3)?.into_array_n()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(VaultAnnounce {
            vid,
            epoch,
            replicas,
            digest,
            by,
            sig,
        })
    }
}
impl_signed!(VaultAnnounce);

/// Type 9: ManifestOffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestOffer {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// manifest digest.
    pub digest: [u8; 32],
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ManifestOffer {
    const TYPE: u64 = 9;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, vb(&self.digest));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let digest = m.take(2)?.into_array_n()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ManifestOffer {
            vid,
            epoch,
            digest,
            by,
            sig,
        })
    }
}
impl_signed!(ManifestOffer);

/// Type 10: ReplicaInvite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaInvite {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// approximate bytes.
    pub approx_bytes: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ReplicaInvite {
    const TYPE: u64 = 10;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, Value::Uint(self.approx_bytes));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let approx_bytes = m.take(2)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ReplicaInvite {
            vid,
            epoch,
            approx_bytes,
            by,
            sig,
        })
    }
}
impl_signed!(ReplicaInvite);

/// Type 11: ReplicaAccept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaAccept {
    /// vault id.
    pub vid: [u8; 32],
    /// quota bytes.
    pub quota_bytes: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ReplicaAccept {
    const TYPE: u64 = 11;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.quota_bytes));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let vid = m.take(0)?.into_array_n()?;
        let quota_bytes = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ReplicaAccept {
            vid,
            quota_bytes,
            by,
            sig,
        })
    }
}
impl_signed!(ReplicaAccept);

/// Type 12: ShareGrant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareGrant {
    /// subject user.
    pub subject: [u8; 32],
    /// chela.share JSON, verbatim.
    pub share_json: String,
    /// recovery delay (seconds).
    pub recovery_delay: u64,
    /// co-trustees.
    pub cotrustees: Vec<CoTrustee>,
    /// announcement references.
    pub refs: Vec<AnnounceRef>,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ShareGrant {
    const TYPE: u64 = 12;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.subject));
        m.u(1, Value::Text(self.share_json.clone()));
        m.u(2, Value::Uint(self.recovery_delay));
        m.u(
            3,
            Value::Array(self.cotrustees.iter().map(|c| c.to_value()).collect()),
        );
        m.u(
            4,
            Value::Array(self.refs.iter().map(|r| r.to_value()).collect()),
        );
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let subject = m.take(0)?.into_array_n()?;
        let share_json = m.take(1)?.into_text()?;
        let recovery_delay = m.take(2)?.into_uint()?;
        let cotrustees = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(CoTrustee::from_value)
            .collect::<Result<_, _>>()?;
        let refs = m
            .take(4)?
            .into_list()?
            .into_iter()
            .map(AnnounceRef::from_value)
            .collect::<Result<_, _>>()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ShareGrant {
            subject,
            share_json,
            recovery_delay,
            cotrustees,
            refs,
            by,
            sig,
        })
    }
}
impl_signed!(ShareGrant);

/// Type 13: ShareAttestChallenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareAttestChallenge {
    /// subject user.
    pub subject: [u8; 32],
    /// recovery-set id.
    pub rsid: u64,
    /// challenge nonce.
    pub nonce: [u8; 16],
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ShareAttestChallenge {
    const TYPE: u64 = 13;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.subject));
        m.u(1, Value::Uint(self.rsid));
        m.u(2, vb(&self.nonce));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let subject = m.take(0)?.into_array_n()?;
        let rsid = m.take(1)?.into_uint()?;
        let nonce = m.take(2)?.into_array_n()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ShareAttestChallenge {
            subject,
            rsid,
            nonce,
            by,
            sig,
        })
    }
}
impl_signed!(ShareAttestChallenge);

/// Type 14: ShareAttestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareAttestation {
    /// subject user.
    pub subject: [u8; 32],
    /// recovery-set id.
    pub rsid: u64,
    /// card number.
    pub card_number: u64,
    /// echoed nonce.
    pub nonce: [u8; 16],
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ShareAttestation {
    const TYPE: u64 = 14;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.subject));
        m.u(1, Value::Uint(self.rsid));
        m.u(2, Value::Uint(self.card_number));
        m.u(3, vb(&self.nonce));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let subject = m.take(0)?.into_array_n()?;
        let rsid = m.take(1)?.into_uint()?;
        let card_number = m.take(2)?.into_uint()?;
        let nonce = m.take(3)?.into_array_n()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ShareAttestation {
            subject,
            rsid,
            card_number,
            nonce,
            by,
            sig,
        })
    }
}
impl_signed!(ShareAttestation);

/// Type 15: ShareDestroy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareDestroy {
    /// subject user.
    pub subject: [u8; 32],
    /// recovery-set id.
    pub rsid: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ShareDestroy {
    const TYPE: u64 = 15;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.subject));
        m.u(1, Value::Uint(self.rsid));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let subject = m.take(0)?.into_array_n()?;
        let rsid = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ShareDestroy {
            subject,
            rsid,
            by,
            sig,
        })
    }
}
impl_signed!(ShareDestroy);

/// Type 16: ShareDestroyAck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareDestroyAck {
    /// subject user.
    pub subject: [u8; 32],
    /// recovery-set id.
    pub rsid: u64,
    /// timestamp.
    pub ts: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for ShareDestroyAck {
    const TYPE: u64 = 16;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.subject));
        m.u(1, Value::Uint(self.rsid));
        m.u(2, Value::Uint(self.ts));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let subject = m.take(0)?.into_array_n()?;
        let rsid = m.take(1)?.into_uint()?;
        let ts = m.take(2)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ShareDestroyAck {
            subject,
            rsid,
            ts,
            by,
            sig,
        })
    }
}
impl_signed!(ShareDestroyAck);

/// Type 17: FileGrant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileGrant {
    /// grant id.
    pub grant_id: [u8; 16],
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// audience (user keys).
    pub audience: Vec<[u8; 32]>,
    /// sealed grant bodies per recipient.
    pub sealed: Vec<Sealed>,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for FileGrant {
    const TYPE: u64 = 17;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.grant_id));
        m.u(1, vb(&self.vid));
        m.u(2, Value::Uint(self.epoch));
        m.u(3, pubs(&self.audience));
        m.u(
            4,
            Value::Array(self.sealed.iter().map(|s| s.to_value()).collect()),
        );
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let grant_id = m.take(0)?.into_array_n()?;
        let vid = m.take(1)?.into_array_n()?;
        let epoch = m.take(2)?.into_uint()?;
        let audience = from_pubs(m.take(3)?)?;
        let sealed = m
            .take(4)?
            .into_list()?
            .into_iter()
            .map(Sealed::from_value)
            .collect::<Result<_, _>>()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(FileGrant {
            grant_id,
            vid,
            epoch,
            audience,
            sealed,
            by,
            sig,
        })
    }
}
impl_signed!(FileGrant);

/// Type 18: AuditNotice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditNotice {
    /// vault id.
    pub vid: [u8; 32],
    /// audit code.
    pub code: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for AuditNotice {
    const TYPE: u64 = 18;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.code));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let vid = m.take(0)?.into_array_n()?;
        let code = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(AuditNotice { vid, code, by, sig })
    }
}
impl_signed!(AuditNotice);

/// Type 19: RecoveryOpen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOpen {
    /// ceremony id.
    pub ceremony_id: [u8; 16],
    /// subject user.
    pub subject: [u8; 32],
    /// recovery-set id.
    pub rsid: u64,
    /// claimant display.
    pub claimant_display: String,
    /// fresh ceremony X25519 pubkey.
    pub ceremony_enc: [u8; 32],
    /// claimant's new node id.
    pub new_node: [u8; 32],
    /// reason.
    pub reason: String,
    /// opened-at timestamp.
    pub opened_at: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for RecoveryOpen {
    const TYPE: u64 = 19;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.ceremony_id));
        m.u(1, vb(&self.subject));
        m.u(2, Value::Uint(self.rsid));
        m.u(3, Value::Text(self.claimant_display.clone()));
        m.u(4, vb(&self.ceremony_enc));
        m.u(5, vb(&self.new_node));
        m.u(6, Value::Text(self.reason.clone()));
        m.u(7, Value::Uint(self.opened_at));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let ceremony_id = m.take(0)?.into_array_n()?;
        let subject = m.take(1)?.into_array_n()?;
        let rsid = m.take(2)?.into_uint()?;
        let claimant_display = m.take(3)?.into_text()?;
        let ceremony_enc = m.take(4)?.into_array_n()?;
        let new_node = m.take(5)?.into_array_n()?;
        let reason = m.take(6)?.into_text()?;
        let opened_at = m.take(7)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(RecoveryOpen {
            ceremony_id,
            subject,
            rsid,
            claimant_display,
            ceremony_enc,
            new_node,
            reason,
            opened_at,
            by,
            sig,
        })
    }
}
impl_signed!(RecoveryOpen);

/// Type 20: CeremonyApprove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyApprove {
    /// ceremony id.
    pub ceremony_id: [u8; 16],
    /// timestamp.
    pub ts: u64,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for CeremonyApprove {
    const TYPE: u64 = 20;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.ceremony_id));
        m.u(1, Value::Uint(self.ts));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let ceremony_id = m.take(0)?.into_array_n()?;
        let ts = m.take(1)?.into_uint()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(CeremonyApprove {
            ceremony_id,
            ts,
            by,
            sig,
        })
    }
}
impl_signed!(CeremonyApprove);

/// Type 21: CeremonyAbort (signed by the SUBJECT USER key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyAbort {
    /// ceremony id.
    pub ceremony_id: [u8; 16],
    /// signer pubkey (= subject user).
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for CeremonyAbort {
    const TYPE: u64 = 21;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.ceremony_id));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let ceremony_id = m.take(0)?.into_array_n()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(CeremonyAbort {
            ceremony_id,
            by,
            sig,
        })
    }
}
impl_signed!(CeremonyAbort);

/// Type 22: CeremonyShare (HPKE-sealed chela.share JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyShare {
    /// ceremony id.
    pub ceremony_id: [u8; 16],
    /// opaque HPKE-sealed share.
    pub sealed: Vec<u8>,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl Message for CeremonyShare {
    const TYPE: u64 = 22;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.ceremony_id));
        m.u(1, vb(&self.sealed));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let ceremony_id = m.take(0)?.into_array_n()?;
        let sealed = m.take(1)?.into_bytes()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(CeremonyShare {
            ceremony_id,
            sealed,
            by,
            sig,
        })
    }
}
impl_signed!(CeremonyShare);

/// Type 23: InviteTicket (self-identifying; no `by`, signer = field 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteTicket {
    /// user pubkey (also the signer).
    pub user: [u8; 32],
    /// node pubkey.
    pub node: [u8; 32],
    /// addresses.
    pub addrs: Vec<String>,
    /// relay URLs.
    pub relay_urls: Vec<String>,
    /// token.
    pub token: [u8; 16],
    /// expiry timestamp.
    pub expires: u64,
    /// signature by the field-0 user key.
    pub sig: [u8; 64],
}
impl InviteTicket {
    /// Sign in place with the field-0 user key.
    pub fn sign(&mut self, key: &SigningKey) {
        self.user = key.verifying_key().to_bytes();
        let sig = key.sign(&signing_bytes(Self::TYPE, &self.to_map()));
        self.sig = sig.to_bytes();
    }
    /// Verify against the field-0 user key.
    pub fn verify(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.user)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        vk.verify_strict(&signing_bytes(Self::TYPE, &self.to_map()), &sig)?;
        Ok(())
    }
    /// Render as the `carapace:` invite URI (lowercase unpadded base32 of the payload).
    pub fn uri(&self) -> String {
        let payload = encode(&Value::Array(vec![
            Value::Uint(Self::TYPE),
            Value::Map(self.to_map()),
        ]));
        format!("carapace:{}", base32_lower_unpadded(&payload))
    }
}
impl Message for InviteTicket {
    const TYPE: u64 = 23;
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.user));
        m.u(1, vb(&self.node));
        m.u(
            2,
            Value::Array(self.addrs.iter().map(|s| Value::Text(s.clone())).collect()),
        );
        m.u(
            3,
            Value::Array(
                self.relay_urls
                    .iter()
                    .map(|s| Value::Text(s.clone()))
                    .collect(),
            ),
        );
        m.u(4, vb(&self.token));
        m.u(5, Value::Uint(self.expires));
        m.u(23, vb(&self.sig));
        m
    }
    fn from_map(mut m: Map) -> Result<Self, Error> {
        let user = m.take(0)?.into_array_n()?;
        let node = m.take(1)?.into_array_n()?;
        let addrs = m
            .take(2)?
            .into_list()?
            .into_iter()
            .map(|x| x.into_text())
            .collect::<Result<_, _>>()?;
        let relay_urls = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(|x| x.into_text())
            .collect::<Result<_, _>>()?;
        let token = m.take(4)?.into_array_n()?;
        let expires = m.take(5)?.into_uint()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(InviteTicket {
            user,
            node,
            addrs,
            relay_urls,
            token,
            expires,
            sig,
        })
    }
}

/// RFC 4648 base32 (no padding), lowercased, for the invite URI.
fn base32_lower_unpadded(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

// ================= documents (B.5; bare, no frame) =======================

/// Friendship document (doc-type 0), dual-signed by both parties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Friendship {
    /// party a (bytewise a < b).
    pub a: [u8; 32],
    /// party b.
    pub b: [u8; 32],
    /// established timestamp.
    pub established: u64,
    /// signature by a's key.
    pub sig_a: [u8; 64],
    /// signature by b's key.
    pub sig_b: [u8; 64],
}
impl Friendship {
    /// Friendship doc-type id used in the signing wrapper.
    pub const DOC_TYPE: u64 = 0;

    fn core_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.a));
        m.u(1, vb(&self.b));
        m.u(2, Value::Uint(self.established));
        m
    }
    fn core_signing_bytes(&self) -> Vec<u8> {
        signing_bytes(Self::DOC_TYPE, &self.core_map())
    }
    /// Build a mutually-signed Friendship from two keys, sorting a<b bytewise.
    pub fn create(k1: &SigningKey, k2: &SigningKey, established: u64) -> Self {
        let p1 = k1.verifying_key().to_bytes();
        let p2 = k2.verifying_key().to_bytes();
        let (a, ka, b, kb) = if p1 <= p2 {
            (p1, k1, p2, k2)
        } else {
            (p2, k2, p1, k1)
        };
        let mut fr = Friendship {
            a,
            b,
            established,
            sig_a: [0; 64],
            sig_b: [0; 64],
        };
        let msg = fr.core_signing_bytes();
        fr.sig_a = ka.sign(&msg).to_bytes();
        fr.sig_b = kb.sign(&msg).to_bytes();
        fr
    }
    /// Verify both signatures against a and b.
    pub fn verify(&self) -> Result<(), Error> {
        let msg = self.core_signing_bytes();
        VerifyingKey::from_bytes(&self.a)?
            .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&self.sig_a))?;
        VerifyingKey::from_bytes(&self.b)?
            .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&self.sig_b))?;
        Ok(())
    }
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.a));
        m.u(1, vb(&self.b));
        m.u(2, Value::Uint(self.established));
        m.u(3, vb(&self.sig_a));
        m.u(4, vb(&self.sig_b));
        m
    }
    fn to_value(&self) -> Value {
        Value::Map(self.to_map())
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let a = m.take(0)?.into_array_n()?;
        let b = m.take(1)?.into_array_n()?;
        let established = m.take(2)?.into_uint()?;
        let sig_a = m.take(3)?.into_array_n()?;
        let sig_b = m.take(4)?.into_array_n()?;
        m.finish()?;
        Ok(Friendship {
            a,
            b,
            established,
            sig_a,
            sig_b,
        })
    }
    /// Encode as a bare document (no frame, no length prefix).
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&self.to_value())
    }
    /// Decode from a bare document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(decode(bytes)?)
    }
}

/// A chunk reference in a GrantFile (CDDL `GrantChunk`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantChunk {
    /// chunk id.
    pub chunk_id: [u8; 32],
    /// chunk key.
    pub chunk_key: [u8; 32],
    /// nonce.
    pub nonce: [u8; 24],
    /// plaintext length.
    pub len: u64,
}
/// S1: a `GrantChunk` carries a disclosed chunk's convergent key and nonce in the
/// clear. Scrub both on drop so a decoded `GrantBody` (the HPKE plaintext) does not
/// leave copies of the keys in freed memory after reconstruction.
impl Drop for GrantChunk {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.chunk_key.zeroize();
        self.nonce.zeroize();
    }
}

impl GrantChunk {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, vb(&self.chunk_id));
        m.u(1, vb(&self.chunk_key));
        m.u(2, vb(&self.nonce));
        m.u(3, Value::Uint(self.len));
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let chunk_id = m.take(0)?.into_array_n()?;
        let chunk_key = m.take(1)?.into_array_n()?;
        let nonce = m.take(2)?.into_array_n()?;
        let len = m.take(3)?.into_uint()?;
        m.finish()?;
        Ok(GrantChunk {
            chunk_id,
            chunk_key,
            nonce,
            len,
        })
    }
}

/// A file entry in a GrantBody (CDDL `GrantFile`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantFile {
    /// path.
    pub path: String,
    /// file hash.
    pub file_hash: [u8; 32],
    /// size.
    pub size: u64,
    /// chunks.
    pub chunks: Vec<GrantChunk>,
}
impl GrantFile {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, Value::Text(self.path.clone()));
        m.u(1, vb(&self.file_hash));
        m.u(2, Value::Uint(self.size));
        m.u(
            3,
            Value::Array(self.chunks.iter().map(|c| c.to_value()).collect()),
        );
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let path = m.take(0)?.into_text()?;
        let file_hash = m.take(1)?.into_array_n()?;
        let size = m.take(2)?.into_uint()?;
        let chunks = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(GrantChunk::from_value)
            .collect::<Result<_, _>>()?;
        m.finish()?;
        Ok(GrantFile {
            path,
            file_hash,
            size,
            chunks,
        })
    }
}

/// GrantBody document (unsigned; HPKE plaintext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBody {
    /// files granted.
    pub files: Vec<GrantFile>,
}
impl GrantBody {
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(
            0,
            Value::Array(self.files.iter().map(|f| f.to_value()).collect()),
        );
        m
    }
    /// Encode as a bare document.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&Value::Map(self.to_map()))
    }
    /// Decode from a bare document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut m = decode(bytes)?.into_map()?;
        let files = m
            .take(0)?
            .into_list()?
            .into_iter()
            .map(GrantFile::from_value)
            .collect::<Result<_, _>>()?;
        m.finish()?;
        Ok(GrantBody { files })
    }
}

/// A file entry in a Manifest (CDDL `FileEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// path.
    pub path: String,
    /// mode.
    pub mode: u64,
    /// mtime.
    pub mtime: u64,
    /// size.
    pub size: u64,
    /// chunks (id, pt_hash, len). `pt_hash = BLAKE3(chunk plaintext)` lets a
    /// `K_content` holder re-derive the chunk key/nonce from the manifest alone
    /// (Option B, spec §4), so owner sync and recovery need no `FileGrant`.
    pub chunks: Vec<([u8; 32], [u8; 32], u64)>,
    /// file hash.
    pub file_hash: [u8; 32],
    /// version vector.
    pub version: Vv,
    /// deleted flag.
    pub deleted: bool,
}
impl FileEntry {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.u(0, Value::Text(self.path.clone()));
        m.u(1, Value::Uint(self.mode));
        m.u(2, Value::Uint(self.mtime));
        m.u(3, Value::Uint(self.size));
        m.u(
            4,
            Value::Array(
                self.chunks
                    .iter()
                    .map(|(id, pt_hash, len)| {
                        let mut cm = Map::new();
                        cm.u(0, vb(id));
                        cm.u(1, vb(pt_hash));
                        cm.u(2, Value::Uint(*len));
                        Value::Map(cm)
                    })
                    .collect(),
            ),
        );
        m.u(5, vb(&self.file_hash));
        m.u(6, vv_to_value(&self.version));
        m.u(7, Value::Bool(self.deleted));
        Value::Map(m)
    }
    fn from_value(v: Value) -> Result<Self, Error> {
        let mut m = v.into_map()?;
        let path = m.take(0)?.into_text()?;
        let mode = m.take(1)?.into_uint()?;
        let mtime = m.take(2)?.into_uint()?;
        let size = m.take(3)?.into_uint()?;
        let chunks = m
            .take(4)?
            .into_list()?
            .into_iter()
            .map(|x| {
                let mut cm = x.into_map()?;
                let id = cm.take(0)?.into_array_n()?;
                let pt_hash = cm.take(1)?.into_array_n()?;
                let len = cm.take(2)?.into_uint()?;
                cm.finish()?;
                Ok((id, pt_hash, len))
            })
            .collect::<Result<_, Error>>()?;
        let file_hash = m.take(5)?.into_array_n()?;
        let version = vv_from_value(m.take(6)?)?;
        let deleted = m.take(7)?.into_bool()?;
        m.finish()?;
        Ok(FileEntry {
            path,
            mode,
            mtime,
            size,
            chunks,
            file_hash,
            version,
            deleted,
        })
    }
}

/// Manifest document (unsigned; AEAD plaintext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// authors.
    pub authors: Vec<[u8; 32]>,
    /// file entries.
    pub files: Vec<FileEntry>,
    /// version vector.
    pub vv: Vv,
}
impl Manifest {
    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, pubs(&self.authors));
        m.u(
            3,
            Value::Array(self.files.iter().map(|f| f.to_value()).collect()),
        );
        m.u(4, vv_to_value(&self.vv));
        m
    }
    /// Encode as a bare document.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&Value::Map(self.to_map()))
    }
    /// Decode from a bare document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut m = decode(bytes)?.into_map()?;
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let authors = from_pubs(m.take(2)?)?;
        let files = m
            .take(3)?
            .into_list()?
            .into_iter()
            .map(FileEntry::from_value)
            .collect::<Result<_, _>>()?;
        let vv = vv_from_value(m.take(4)?)?;
        m.finish()?;
        Ok(Manifest {
            vid,
            epoch,
            authors,
            files,
            vv,
        })
    }
}

/// ManifestEnvelope document (doc-type 24), signed per B.3 with doc-type 24.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEnvelope {
    /// vault id.
    pub vid: [u8; 32],
    /// epoch.
    pub epoch: u64,
    /// AEAD nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext of the det-CBOR Manifest.
    pub ct: Vec<u8>,
    /// signer pubkey.
    pub by: [u8; 32],
    /// signature.
    pub sig: [u8; 64],
}
impl ManifestEnvelope {
    /// ManifestEnvelope doc-type id used in the signing wrapper.
    pub const DOC_TYPE: u64 = 24;

    fn to_map(&self) -> Map {
        let mut m = Map::new();
        m.u(0, vb(&self.vid));
        m.u(1, Value::Uint(self.epoch));
        m.u(2, vb(&self.nonce));
        m.u(3, vb(&self.ct));
        m.u(22, vb(&self.by));
        m.u(23, vb(&self.sig));
        m
    }
    /// Sign in place per B.3 with doc-type 24.
    pub fn sign(&mut self, key: &SigningKey) {
        self.by = key.verifying_key().to_bytes();
        let sig = key.sign(&signing_bytes(Self::DOC_TYPE, &self.to_map()));
        self.sig = sig.to_bytes();
    }
    /// Verify per B.3 with doc-type 24.
    pub fn verify(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.by)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        vk.verify_strict(&signing_bytes(Self::DOC_TYPE, &self.to_map()), &sig)?;
        Ok(())
    }
    /// Encode as a bare document (no frame, no length prefix).
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&Value::Map(self.to_map()))
    }
    /// Decode from a bare document.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut m = decode(bytes)?.into_map()?;
        let vid = m.take(0)?.into_array_n()?;
        let epoch = m.take(1)?.into_uint()?;
        let nonce = m.take(2)?.into_array_n()?;
        let ct = m.take(3)?.into_bytes()?;
        let by = m.take(22)?.into_array_n()?;
        let sig = m.take(23)?.into_array_n()?;
        m.finish()?;
        Ok(ManifestEnvelope {
            vid,
            epoch,
            nonce,
            ct,
            by,
            sig,
        })
    }
}
