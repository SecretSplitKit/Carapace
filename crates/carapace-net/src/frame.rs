//! Length-prefixed deterministic-CBOR framing over iroh bidi streams (§6, B.2).
//!
//! Every Carapace control message is a `carapace-wire` frame: a 4-byte
//! big-endian length followed by `det_cbor([type_id, body])`, capped at 1 MiB.
//! We reuse `carapace_wire`'s `frame`/`decode_frame` for the encoding and only
//! add the async stream plumbing here.

use anyhow::{bail, Result};
use carapace_wire::{Map, Message, MAX_PAYLOAD};
use iroh::endpoint::{ReadExactError, RecvStream, SendStream};

/// Write a typed message as a single length-prefixed frame.
pub async fn write_msg<M: Message>(send: &mut SendStream, msg: &M) -> Result<()> {
    let bytes = msg.encode_frame();
    send.write_all(&bytes).await?;
    Ok(())
}

/// Read one raw frame, returning `(type_id, body)`, or `None` on a clean stream
/// end at a frame boundary. Enforces the 1 MiB payload cap (dropping the
/// connection on an oversized or non-canonical frame, per §6).
pub async fn read_frame_raw(recv: &mut RecvStream) -> Result<Option<(u64, Map)>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        // Peer finished the stream exactly at a frame boundary: clean EOF.
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PAYLOAD {
        bail!("carapace frame payload {len} exceeds 1 MiB cap");
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;

    // Reassemble the full framed bytes so the wire crate re-validates the cap,
    // strict deterministic decoding, and the `[uint, map]` shape.
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&payload);
    let (ty, body) = carapace_wire::decode_frame(&full)?;
    Ok(Some((ty, body)))
}

/// Read the next frame and decode it as `M`, erroring on EOF or a type mismatch.
pub async fn read_msg<M: Message>(recv: &mut RecvStream) -> Result<M> {
    let (ty, body) = read_frame_raw(recv)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream ended before expected {} frame", M::TYPE))?;
    if ty != M::TYPE {
        bail!("expected message type {}, got {}", M::TYPE, ty);
    }
    Ok(M::from_map(body)?)
}
