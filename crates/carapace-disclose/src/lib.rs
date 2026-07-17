//! carapace-disclose: selective disclosure (Carapace protocol §7.4).
//!
//! An owner discloses exactly chosen files to an explicit audience by handing out
//! exactly those files' chunk keys, sealed per-recipient. This crate:
//!
//! - [`build_grant`] assembles a [`GrantBody`] (per-file `{id, key, nonce, len}`)
//!   and HPKE-seals it to each audience member's `enc_pub` (from their
//!   `ContactCard`, an X25519 key derived from their `K_disclose`, §4) inside a
//!   signed [`FileGrant`] (type 17);
//! - [`open_grant`] lets an audience member HPKE-open the [`Sealed`] entry
//!   addressed to them and recover the [`GrantBody`];
//! - [`open_file`] / [`write_grant`] decrypt and reconstruct *exactly* the
//!   granted files from their fetched ciphertext chunks (nothing more);
//! - [`DisclosureTable`] records, owner-side, which audience user may fetch which
//!   ChunkID, so a storage peer can enforce §7.4 fetch authorization: a chunk is
//!   served to an audience member only if an owner-signed grant covers that
//!   ChunkID **and** the requester is authenticated as a member of that grant's
//!   audience (adversarial review D3 — a leaked grant document alone authorizes
//!   nothing).
//!
//! # Snapshot + irrevocable semantics (§7.4, NORMATIVE)
//!
//! A grant is a **snapshot by construction**: it carries the convergent chunk
//! keys of one epoch's plaintext. An edit produces new plaintext, hence new
//! convergent keys and new ChunkIDs (§5), so a grant never extends to future
//! content — there is nothing for it to extend *to*. A grant is likewise
//! **irrevocable for the content it discloses**: a recipient may keep the opened
//! bytes forever, so "revoke" means only "issue no future version." No function
//! here can recall disclosed content, and a caller MUST NOT present disclosure as
//! recallable.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use carapace_crypto::content;
use carapace_crypto::kdf::INFO_DISCLOSE;
use carapace_crypto::seal::{self, HpkeError, HpkePrivateKey, HpkePublicKey};
use carapace_wire::messages::Signed;
use carapace_wire::{
    decode, encode, Error as WireError, FileGrant, GrantBody, GrantFile, Map, Sealed, Value,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// The X25519 encapsulated key (DHKEM output) is prefixed onto the HPKE
/// ciphertext inside each [`Sealed`] entry (which carries no separate encap
/// field) and split back off on open. RFC 9180 X25519 encaps are 32 bytes.
const ENCAP_LEN: usize = 32;

/// HPKE aad binding a sealed grant body to its exact grant identity: `vid ||
/// epoch(le) || grant_id`. Binding all three (not just `vid`) stops a recipient's
/// [`Sealed`] ciphertext from being lifted verbatim into a *different* signed
/// grant for the same vault (a different epoch or grant_id) and still opening —
/// the aad would no longer match (S2). Length: 32 + 8 + 16 = 56.
pub fn grant_aad(vid: &[u8; 32], epoch: u64, grant_id: &[u8; 16]) -> [u8; 56] {
    let mut aad = [0u8; 56];
    aad[..32].copy_from_slice(vid);
    aad[32..40].copy_from_slice(&epoch.to_le_bytes());
    aad[40..].copy_from_slice(grant_id);
    aad
}

/// An audience member the owner seals a grant to.
#[derive(Clone, Debug)]
pub struct Recipient {
    /// The member's Ed25519 user identity: the [`FileGrant`] audience entry and
    /// the [`Sealed::to`] tag.
    pub user: [u8; 32],
    /// The member's X25519 HPKE public key (their `ContactCard.enc_pub`, derived
    /// from `K_disclose`) that the grant body is sealed to.
    pub enc_pub: [u8; 32],
}

/// Errors from building, opening, or reconstructing a disclosure.
#[derive(Debug)]
pub enum DiscloseError {
    /// A recipient's `enc_pub` was not a valid X25519 public key.
    BadRecipientKey,
    /// HPKE seal failed.
    Seal(HpkeError),
    /// HPKE open failed (wrong recipient key, tampered ciphertext, or wrong aad).
    Open(HpkeError),
    /// This grant has no sealed body addressed to the opening user.
    NotAudience,
    /// A sealed entry was too short to carry the encapsulated key.
    Truncated,
    /// The sealed/opened body was not a well-formed `GrantBody`.
    Decode(carapace_wire::Error),
    /// A requested file's ciphertext chunk was not supplied.
    MissingChunk([u8; 32]),
    /// A chunk failed to decrypt/authenticate under its grant key (aad = vid).
    Chunk(content::ChunkError),
    /// A reconstructed file did not match its `fileHash`.
    FileHashMismatch(String),
    /// A granted file path was absolute or escaped the output root.
    UnsafePath(String),
    /// Filesystem I/O during reconstruction failed.
    Io(std::io::Error),
}

impl std::fmt::Display for DiscloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscloseError::BadRecipientKey => {
                write!(f, "recipient enc_pub is not a valid X25519 key")
            }
            DiscloseError::Seal(e) => write!(f, "grant seal failed: {e}"),
            DiscloseError::Open(e) => write!(f, "grant open failed: {e}"),
            DiscloseError::NotAudience => write!(f, "grant has no sealed body for this user"),
            DiscloseError::Truncated => write!(f, "sealed grant too short for encapsulated key"),
            DiscloseError::Decode(e) => write!(f, "grant body decode failed: {e:?}"),
            DiscloseError::MissingChunk(id) => write!(f, "missing granted chunk {}", hex(id)),
            DiscloseError::Chunk(e) => write!(f, "granted chunk failed to open: {e}"),
            DiscloseError::FileHashMismatch(p) => {
                write!(f, "reconstructed file hash mismatch: {p}")
            }
            DiscloseError::UnsafePath(p) => write!(f, "unsafe granted path: {p}"),
            DiscloseError::Io(e) => write!(f, "reconstruction io: {e}"),
        }
    }
}

impl std::error::Error for DiscloseError {}

impl From<std::io::Error> for DiscloseError {
    fn from(e: std::io::Error) -> Self {
        DiscloseError::Io(e)
    }
}

/// Assemble and sign a [`FileGrant`] disclosing `body` to each recipient.
///
/// The det-CBOR `body` is HPKE-sealed once per recipient to that recipient's
/// `enc_pub` (info = `K_disclose` label, aad = [`grant_aad`] over `vid`, `epoch`,
/// and `grant_id`, so the seal is bound to this exact grant). The `grant_id` is
/// supplied by the caller (a fresh 16-byte nonce). The
/// grant is signed by `node_key` under the type-17 signing discipline.
///
/// The whole audience receives the *same* disclosed set; to disclose different
/// files to different people, issue separate grants.
pub fn build_grant(
    node_key: &SigningKey,
    vid: [u8; 32],
    epoch: u64,
    grant_id: [u8; 16],
    body: &GrantBody,
    recipients: &[Recipient],
) -> Result<FileGrant, DiscloseError> {
    // The serialized body holds every disclosed chunk key in the clear; scrub it
    // once every recipient's ciphertext is produced.
    let body_bytes = Zeroizing::new(body.to_bytes());

    let aad = grant_aad(&vid, epoch, &grant_id);
    let mut audience = Vec::with_capacity(recipients.len());
    let mut sealed = Vec::with_capacity(recipients.len());
    for r in recipients {
        let pk =
            HpkePublicKey::from_bytes(&r.enc_pub).map_err(|_| DiscloseError::BadRecipientKey)?;
        let (enc, ct) =
            seal::seal(&pk, INFO_DISCLOSE, &aad, &body_bytes).map_err(DiscloseError::Seal)?;
        // Prefix the encapsulated key onto the ciphertext; split it back on open.
        let mut sealed_ct = enc;
        sealed_ct.extend_from_slice(&ct);
        audience.push(r.user);
        sealed.push(Sealed {
            to: r.user,
            ct: sealed_ct,
        });
    }

    let mut grant = FileGrant {
        grant_id,
        vid,
        epoch,
        audience,
        sealed,
        by: [0; 32],
        sig: [0; 64],
    };
    grant.sign(node_key);
    Ok(grant)
}

/// HPKE-open the sealed body addressed to `my_user` and recover the [`GrantBody`].
///
/// The caller supplies its own `K_disclose`-derived HPKE private key. The aad is
/// [`grant_aad`] over `grant.vid`, `grant.epoch`, and `grant.grant_id`, so a body
/// sealed under one vault (or a different epoch/grant_id) will not open here. Does
/// not verify the grant's signature — the caller MUST
/// [`Signed::verify`] it (owner-signed) before trusting the disclosure.
pub fn open_grant(
    grant: &FileGrant,
    my_user: [u8; 32],
    my_priv: &HpkePrivateKey,
) -> Result<GrantBody, DiscloseError> {
    let sealed = grant
        .sealed
        .iter()
        .find(|s| s.to == my_user)
        .ok_or(DiscloseError::NotAudience)?;
    if sealed.ct.len() < ENCAP_LEN {
        return Err(DiscloseError::Truncated);
    }
    let (enc, ct) = sealed.ct.split_at(ENCAP_LEN);
    let aad = grant_aad(&grant.vid, grant.epoch, &grant.grant_id);
    // The opened plaintext carries every disclosed chunk key; scrub it on drop.
    let pt = Zeroizing::new(
        seal::open(my_priv, enc, INFO_DISCLOSE, &aad, ct).map_err(DiscloseError::Open)?,
    );
    GrantBody::from_bytes(&pt).map_err(DiscloseError::Decode)
}

/// Decrypt one disclosed file's ordered chunks into its plaintext, verifying the
/// result against the grant's `fileHash`. `fetch(chunk_id)` supplies each chunk's
/// (still-sealed) ciphertext; `vid` is the aad the chunks were sealed under (§5).
pub fn open_file(
    file: &GrantFile,
    vid: &[u8; 32],
    fetch: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, DiscloseError> {
    let mut out = Vec::with_capacity(file.size as usize);
    for c in &file.chunks {
        let ct = fetch(&c.chunk_id).ok_or(DiscloseError::MissingChunk(c.chunk_id))?;
        let pt =
            content::open_chunk(&c.chunk_key, &c.nonce, &ct, vid).map_err(DiscloseError::Chunk)?;
        out.extend_from_slice(&pt);
    }
    if *blake3::hash(&out).as_bytes() != file.file_hash {
        return Err(DiscloseError::FileHashMismatch(file.path.clone()));
    }
    Ok(out)
}

/// Reconstruct *every* granted file under `out_dir` at its validated relative
/// path, returning the written paths. Only the files named in `body` are written;
/// a grant never carries anything beyond what it discloses. `fetch` supplies each
/// chunk's ciphertext.
pub fn write_grant(
    body: &GrantBody,
    vid: &[u8; 32],
    out_dir: &Path,
    fetch: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Vec<PathBuf>, DiscloseError> {
    let mut written = Vec::with_capacity(body.files.len());
    for file in &body.files {
        let bytes = open_file(file, vid, &fetch)?;
        // A grant is a cross-user document; treat its paths as hostile (reject
        // absolute paths and `..` escape) exactly as vault reconstruction does.
        let dest = safe_join(out_dir, &file.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &bytes)?;
        written.push(dest);
    }
    Ok(written)
}

/// Every ChunkID disclosed by `body` (across all its files).
pub fn granted_chunk_ids(body: &GrantBody) -> HashSet<[u8; 32]> {
    body.files
        .iter()
        .flat_map(|f| f.chunks.iter().map(|c| c.chunk_id))
        .collect()
}

/// Owner-side record of which audience users may fetch which ChunkIDs, built from
/// the grants the owner has issued. The blob-fetch gate consults it to enforce
/// §7.4 / D3: a granted chunk is served to a requester only when the requester is
/// authenticated (elsewhere, via NodeID + delegation) as one of the users an
/// owner-signed grant covering that chunk names in its audience.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct DisclosureTable {
    /// ChunkID -> the set of audience user pubkeys any issued grant authorizes
    /// for that chunk.
    by_chunk: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl DisclosureTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an issued grant: every audience user may fetch every ChunkID the
    /// (cleartext) `body` discloses. Call once per grant at issuance, when the
    /// owner still holds the plaintext body.
    pub fn record(&mut self, grant: &FileGrant, body: &GrantBody) {
        for id in granted_chunk_ids(body) {
            let entry = self.by_chunk.entry(id).or_default();
            for user in &grant.audience {
                entry.insert(*user);
            }
        }
    }

    /// Whether some issued grant covering `chunk_id` names `user` in its audience.
    /// The caller must have *already authenticated* that the requesting node is a
    /// device of `user` (NodeID + delegation); this supplies the "grant covers the
    /// ChunkID AND `user` is in that grant's audience" half of §7.4/D3.
    pub fn is_audience(&self, chunk_id: &[u8; 32], user: &[u8; 32]) -> bool {
        self.by_chunk
            .get(chunk_id)
            .is_some_and(|users| users.contains(user))
    }

    /// Serialize the whole table to deterministic det-CBOR for at-rest
    /// persistence. This state is NOT recoverable from the owner's persisted
    /// `FileGrant`s (those carry only HPKE-sealed bodies; the ChunkID->audience
    /// mapping lives in the cleartext `GrantBody`, which the owner never
    /// retains), so the table itself must survive a reboot or disclosed-to
    /// friends get denied after restart, breaking §7.4 "disclosure is forever."
    ///
    /// Lossless: every `(chunk, audience-user)` authorization round-trips, so the
    /// audience-arm fetch-gate decides identically after restart. The contents are
    /// PLAIN - ChunkIDs and audience user PUBKEYS only, no secret - so the persistence
    /// funnel stores these bytes in the clear (a PLAIN redb row, not a SEAL row); nothing
    /// here needs sealing. Entries and per-chunk users are sorted, so equal tables encode
    /// to identical bytes (stable input to the redb persistence funnel).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut chunks: Vec<(&[u8; 32], &HashSet<[u8; 32]>)> = self.by_chunk.iter().collect();
        chunks.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let entries = chunks
            .into_iter()
            .map(|(id, users)| {
                let mut u: Vec<[u8; 32]> = users.iter().copied().collect();
                u.sort_unstable();
                Value::Array(vec![
                    Value::Bytes(id.to_vec()),
                    Value::Array(u.into_iter().map(|x| Value::Bytes(x.to_vec())).collect()),
                ])
            })
            .collect();
        let mut m = Map::new();
        m.u(0, Value::Array(entries));
        encode(&Value::Map(m))
    }

    /// Reconstruct a table from [`DisclosureTable::to_bytes`] output. The
    /// reconstructed table authorizes exactly the same `(chunk, user)` pairs as
    /// the original.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DiscloseError> {
        let mut m = decode(bytes)
            .and_then(Value::into_map)
            .map_err(DiscloseError::Decode)?;
        let entries = m
            .take(0)
            .and_then(Value::into_list)
            .map_err(DiscloseError::Decode)?;
        m.finish().map_err(DiscloseError::Decode)?;
        let mut by_chunk = HashMap::with_capacity(entries.len());
        for e in entries {
            let mut it = e.into_list().map_err(DiscloseError::Decode)?.into_iter();
            let id = it
                .next()
                .ok_or(DiscloseError::Decode(WireError::TypeMismatch))?
                .into_array_n::<32>()
                .map_err(DiscloseError::Decode)?;
            let users_v = it
                .next()
                .ok_or(DiscloseError::Decode(WireError::TypeMismatch))?
                .into_list()
                .map_err(DiscloseError::Decode)?;
            if it.next().is_some() {
                return Err(DiscloseError::Decode(WireError::TypeMismatch));
            }
            let mut users = HashSet::with_capacity(users_v.len());
            for u in users_v {
                users.insert(u.into_array_n::<32>().map_err(DiscloseError::Decode)?);
            }
            by_chunk.insert(id, users);
        }
        Ok(DisclosureTable { by_chunk })
    }
}

/// Join a grant-supplied relative path onto `base`, rejecting absolute paths and
/// any `..` escape (a foreign grant may be hostile). Mirrors the vault's
/// reconstruction guard.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf, DiscloseError> {
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains('\\') {
            return Err(DiscloseError::UnsafePath(rel.to_string()));
        }
        out.push(part);
    }
    if out == base {
        return Err(DiscloseError::UnsafePath(rel.to_string()));
    }
    Ok(out)
}

fn hex(b: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_crypto::kdf;
    use carapace_wire::GrantChunk;

    /// Seal a plaintext chunk under a vault's content key and return the wire
    /// GrantChunk plus its ciphertext, exactly as an owner would after ingest.
    fn seal_one(k_content: &[u8; 32], vid: &[u8; 32], pt: &[u8]) -> (GrantChunk, Vec<u8>) {
        let sealed = content::seal_chunk(k_content, vid, pt).unwrap();
        (
            GrantChunk {
                chunk_id: sealed.chunk_id,
                chunk_key: *sealed.chunk_key,
                nonce: *sealed.nonce,
                len: pt.len() as u64,
            },
            sealed.ciphertext,
        )
    }

    fn file_of(path: &str, pt: &[u8], gc: GrantChunk) -> GrantFile {
        GrantFile {
            path: path.to_string(),
            file_hash: *blake3::hash(pt).as_bytes(),
            size: pt.len() as u64,
            chunks: vec![gc],
        }
    }

    // Round-trip: owner seals F1,F2 (not F3) to friend B; B opens and reconstructs
    // exactly F1,F2; a non-audience user cannot open; F3's keys never appear.
    #[test]
    fn selective_grant_round_trips_to_audience_only() {
        let owner_node = SigningKey::from_bytes(&[0x03; 32]);
        let vid = [0xC0; 32];
        let k_content = *kdf::k_content(&*kdf::k_vaultroot(&[0x11; 32], &vid));

        let (f1p, f2p, f3p) = (
            b"file one".as_ref(),
            b"file two".as_ref(),
            b"file three".as_ref(),
        );
        let (g1, ct1) = seal_one(&k_content, &vid, f1p);
        let (g2, ct2) = seal_one(&k_content, &vid, f2p);
        let (g3, _ct3) = seal_one(&k_content, &vid, f3p);

        // Disclose only F1, F2.
        let body = GrantBody {
            files: vec![
                file_of("a/f1.txt", f1p, g1.clone()),
                file_of("f2.txt", f2p, g2.clone()),
            ],
        };

        // Audience B's disclosure keypair, addressed by its enc_pub.
        let (b_priv, b_pub) = seal::derive_keypair(&*kdf::k_disclose(&[0x22; 32]));
        let b_user = [0xBB; 32];
        let b_enc: [u8; 32] = b_pub.to_bytes().try_into().unwrap();

        let grant = build_grant(
            &owner_node,
            vid,
            7,
            [0x90; 16],
            &body,
            &[Recipient {
                user: b_user,
                enc_pub: b_enc,
            }],
        )
        .unwrap();
        grant.verify().expect("grant is owner-signed");

        // B opens and reconstructs exactly F1, F2.
        let opened = open_grant(&grant, b_user, &b_priv).unwrap();
        assert_eq!(opened.files.len(), 2);
        let chunks: HashMap<[u8; 32], Vec<u8>> =
            HashMap::from([(g1.chunk_id, ct1), (g2.chunk_id, ct2)]);
        let out = tempfile::tempdir().unwrap();
        let written = write_grant(&opened, &vid, out.path(), |id| chunks.get(id).cloned()).unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(fs::read(out.path().join("a/f1.txt")).unwrap(), f1p);
        assert_eq!(fs::read(out.path().join("f2.txt")).unwrap(), f2p);

        // F3's ChunkID/key are nowhere in the disclosure — B cannot derive them.
        let ids = granted_chunk_ids(&opened);
        assert!(
            !ids.contains(&g3.chunk_id),
            "F3 must not be covered by the grant"
        );

        // S2: lifting B's sealed ciphertext into a grant with a different epoch or
        // grant_id (same vid) fails to open — the aad binds the exact grant identity.
        let mut forged_epoch = grant.clone();
        forged_epoch.epoch = grant.epoch + 1;
        assert!(matches!(
            open_grant(&forged_epoch, b_user, &b_priv),
            Err(DiscloseError::Open(_))
        ));
        let mut forged_id = grant.clone();
        forged_id.grant_id = [0xEE; 16];
        assert!(matches!(
            open_grant(&forged_id, b_user, &b_priv),
            Err(DiscloseError::Open(_))
        ));

        // A non-audience user (different disclosure key) cannot open the grant.
        let (c_priv, _c_pub) = seal::derive_keypair(&*kdf::k_disclose(&[0x33; 32]));
        assert!(matches!(
            open_grant(&grant, [0xCC; 32], &c_priv),
            Err(DiscloseError::NotAudience)
        ));
        // Even guessing B's user tag, C's wrong key fails the HPKE open.
        assert!(matches!(
            open_grant(&grant, b_user, &c_priv),
            Err(DiscloseError::Open(_))
        ));
    }

    // The disclosure table authorizes exactly the recorded audience for exactly
    // the disclosed chunks (the D3 "grant covers ChunkID and user is audience"
    // half); an unrecorded chunk or a non-audience user is refused.
    #[test]
    fn disclosure_table_gates_by_chunk_and_audience() {
        let vid = [0xC0; 32];
        let k_content = *kdf::k_content(&*kdf::k_vaultroot(&[0x11; 32], &vid));
        let (g1, _) = seal_one(&k_content, &vid, b"one");
        let (g3, _) = seal_one(&k_content, &vid, b"three");
        let body = GrantBody {
            files: vec![file_of("f1", b"one", g1.clone())],
        };

        let owner_node = SigningKey::from_bytes(&[0x03; 32]);
        let b_user = [0xBB; 32];
        let grant = build_grant(
            &owner_node,
            vid,
            1,
            [0x90; 16],
            &body,
            &[Recipient {
                user: b_user,
                enc_pub: [0x05; 32],
            }],
        )
        .unwrap();

        let mut table = DisclosureTable::new();
        table.record(&grant, &body);
        assert!(
            table.is_audience(&g1.chunk_id, &b_user),
            "audience B may fetch the granted chunk"
        );
        assert!(
            !table.is_audience(&g1.chunk_id, &[0xCC; 32]),
            "a non-audience user is refused"
        );
        assert!(
            !table.is_audience(&g3.chunk_id, &b_user),
            "an ungranted chunk is refused"
        );
    }

    // Persistence: a table serialized and reloaded authorizes EXACTLY the same
    // (audience, chunk) pairs as the original, so the audience-arm fetch gate
    // decides identically after a reboot (§7.4 "disclosure is forever"). Two
    // grants give overlapping and distinct chunks across two audiences to
    // exercise multi-user-per-chunk.
    #[test]
    fn disclosure_table_round_trips_losslessly() {
        let vid = [0xC0; 32];
        let k_content = *kdf::k_content(&*kdf::k_vaultroot(&[0x11; 32], &vid));
        let owner = SigningKey::from_bytes(&[0x03; 32]);
        let (b_user, c_user, d_user) = ([0xBB; 32], [0xCC; 32], [0xDD; 32]);

        let (g1, _) = seal_one(&k_content, &vid, b"one");
        let (g2, _) = seal_one(&k_content, &vid, b"two");
        let (g3, _) = seal_one(&k_content, &vid, b"three");
        let (ungranted, _) = seal_one(&k_content, &vid, b"nope");

        // Grant 1: {B, C} get files carrying chunks g1, g2.
        let body1 = GrantBody {
            files: vec![
                file_of("f1", b"one", g1.clone()),
                file_of("f2", b"two", g2.clone()),
            ],
        };
        let grant1 = build_grant(
            &owner,
            vid,
            1,
            [0x90; 16],
            &body1,
            &[
                Recipient {
                    user: b_user,
                    enc_pub: [0x05; 32],
                },
                Recipient {
                    user: c_user,
                    enc_pub: [0x06; 32],
                },
            ],
        )
        .unwrap();

        // Grant 2: {D} gets a file carrying chunks g2 (overlap) and g3.
        let body2 = GrantBody {
            files: vec![GrantFile {
                path: "f23".into(),
                file_hash: [0; 32],
                size: 0,
                chunks: vec![g2.clone(), g3.clone()],
            }],
        };
        let grant2 = build_grant(
            &owner,
            vid,
            1,
            [0x91; 16],
            &body2,
            &[Recipient {
                user: d_user,
                enc_pub: [0x07; 32],
            }],
        )
        .unwrap();

        let mut table = DisclosureTable::new();
        table.record(&grant1, &body1);
        table.record(&grant2, &body2);

        let reloaded = DisclosureTable::from_bytes(&table.to_bytes()).unwrap();

        // Full-state equality (HashMap/HashSet Eq is order-independent) proves the
        // reconstruction is lossless.
        assert_eq!(table, reloaded, "reloaded table differs from original");

        // And the gate decides identically across every relevant (chunk, user):
        // sweep the cartesian product of every referenced chunk and user, plus an
        // ungranted chunk and a never-seen user.
        let chunks = [g1.chunk_id, g2.chunk_id, g3.chunk_id, ungranted.chunk_id];
        let users = [b_user, c_user, d_user, [0xEE; 32]];
        for chunk in &chunks {
            for user in &users {
                assert_eq!(
                    table.is_audience(chunk, user),
                    reloaded.is_audience(chunk, user),
                    "gate decision diverged after reload for chunk/user",
                );
            }
        }

        // Spot-check the intended authorizations survived: B and C reach g1/g2,
        // D reaches g2/g3, nobody reaches an ungranted chunk, and D is not on g1.
        assert!(reloaded.is_audience(&g1.chunk_id, &b_user));
        assert!(reloaded.is_audience(&g2.chunk_id, &c_user));
        assert!(reloaded.is_audience(&g2.chunk_id, &d_user)); // overlap merged
        assert!(reloaded.is_audience(&g3.chunk_id, &d_user));
        assert!(!reloaded.is_audience(&g1.chunk_id, &d_user));
        assert!(!reloaded.is_audience(&ungranted.chunk_id, &b_user));

        // Determinism: recording in the opposite order yields identical bytes
        // (sorted encoding), so the redb funnel sees a stable value.
        let mut table_rev = DisclosureTable::new();
        table_rev.record(&grant2, &body2);
        table_rev.record(&grant1, &body1);
        assert_eq!(
            table.to_bytes(),
            table_rev.to_bytes(),
            "encoding must be independent of record order",
        );
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/out");
        assert!(safe_join(base, "../etc/passwd").is_err());
        assert!(safe_join(base, "/abs").is_ok()); // leading '/' -> empty first part, kept relative
        assert_eq!(
            safe_join(base, "a/b.txt").unwrap(),
            Path::new("/out/a/b.txt")
        );
        assert!(safe_join(base, "").is_err());
    }
}
