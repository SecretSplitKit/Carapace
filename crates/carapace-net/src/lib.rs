//! carapace-net: iroh integration for Carapace (protocol §6).
//!
//! - [`endpoint`]: bind an iroh `Endpoint` on ALPN `carapace/1` from a carapace
//!   node key (NodeID == carapace node id), plus connect/accept plumbing.
//! - [`frame`]: length-prefixed deterministic-CBOR control frames over iroh
//!   bidi streams (reusing `carapace-wire` framing, 1 MiB cap).
//! - [`sync`]: `Hello` + pairwise anti-entropy of the latest signed documents
//!   (`ContactCard`, `VaultAnnounce`) with monotonic-version rollback rejection.
//! - [`blobs`]: an iroh-blobs-backed [`carapace_vault::ChunkStore`]; a sealed
//!   chunk's blob hash equals its ChunkID by construction.
//! - [`relay`]: the embedded self-hosted relay a capable node runs so friends
//!   can relay through it (§6, "zero third-party infrastructure").
//!
//! Every wire encoding routes through `carapace-wire`; every crypto primitive
//! through `carapace-crypto`; vault logic through `carapace-vault`.

pub mod blobs;
pub mod endpoint;
pub mod frame;
pub mod relay;
pub mod sync;

pub use blobs::{authorizing_event_sender, IrohBlobStore};
pub use endpoint::{CarapaceEndpoint, PeerHints, ALPN};
pub use frame::{read_frame_raw, read_msg, write_msg};
pub use relay::{AllowList, CarapaceRelay, RelayAccessPolicy};
pub use sync::{
    pull_documents, DocStore, Reject, SyncHandler, UnsupportedProtocol, PROTOCOL_VERSION,
};
