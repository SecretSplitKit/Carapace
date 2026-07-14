//! W2 recovery ceremony wired end-to-end over the daemon control stream (§8.5 + §8.4).
//!
//! The acceptance test drives a full ceremony from a KEY-LESS claimant to a recovered
//! `K_root` that EQUALS the original: an owner splits `M`-of-`N` to trustees (W3 grants
//! delivered); a sponsor trustee opens a ceremony for the subject with a fresh claimant
//! device; the open fans out to the co-trustees (each raises the alarm); `M` trustees
//! approve; before the delay NO share releases; after advancing the INJECTED clock past
//! `first_seen + recovery_delay` the `M` approving trustees release HPKE-sealed shares;
//! the claimant collects `M`, recovers `K_root`, and it matches. Plus: a subject-key
//! `CeremonyAbort` cancels permanently (takeover flagged, no release); a non-trustee
//! cannot open; sub-`M` never releases; and a share never crosses the wire unsealed.
//!
//! Every test is BOUNDED (§11 lesson): the 72 h abort delay is exercised with a fast
//! INJECTED clock (`set_test_clock`) - never a real sleep - all dials are bounded by the
//! daemon connect timeout, and every daemon is torn down at the end.

use anyhow::{Context, Result};
use carapace_wire::AnnounceRef;
use carapaced::{max_epoch_refs, ClaimantDevice, Daemon, RecoveryScope, State};
use ed25519_dalek::{Signature, VerifyingKey};

/// The owner's abort window carried in every grant (§8.5 default): 72 hours.
const DELAY: u64 = 72 * 3600;
/// A fixed injected wall clock the ceremony starts at (bounded tests never use real time).
const T0: u64 = 1_800_000_000;
/// The far-future delegation expiry the recovered device re-signs under (matches the
/// daemon's `DELEG_NOT_AFTER`, 2100-01-01Z).
const DELEG_NOT_AFTER: u64 = 4_102_444_800;

fn seeds(node: u8, root: u8) -> State {
    State::from_seeds([node; 32], [root; 32])
}

/// `a` befriends `peer` (peer issues the ticket): both sides record the friendship + the
/// other's card, so `a` can deliver grants and `peer` authorizes `a`'s owner-signed grant.
async fn a_befriends(a: &Daemon, peer: &Daemon) -> Result<()> {
    let ticket = peer.issue_ticket()?;
    a.befriend(peer.addr()?, &ticket, None).await?;
    Ok(())
}

/// True iff `needle` appears as a contiguous byte run inside `haystack`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Stand up an owner `A` and three trustees `B, C, D`, befriend them, and split `A`'s
/// `K_root` 2-of-3 with W3 grants delivered. Returns the four daemons and the root key.
async fn setup() -> Result<(Daemon, Daemon, Daemon, Daemon, [u8; 32])> {
    let root = 0xA0;
    let a = Daemon::start(seeds(0x01, root)).await?;
    let b = Daemon::start(seeds(0x11, 0xB0)).await?;
    let c = Daemon::start(seeds(0x21, 0xC0)).await?;
    let d = Daemon::start(seeds(0x31, 0xD0)).await?;
    for t in [&b, &c, &d] {
        a_befriends(&a, t).await?;
    }
    let trustees = [b.user_id(), c.user_id(), d.user_id()];
    let report = a
        .recovery_split_grant(7, RecoveryScope::Root, 2, &trustees, DELAY, false)
        .await?;
    assert_eq!(report.delivered.len(), 3, "all three grants must deliver");
    // Each trustee holds a grant for the owner-subject: that is what makes it a trustee.
    let subject = a.user_id();
    for t in [&b, &c, &d] {
        assert!(
            t.held_grant(&subject).is_some(),
            "trustee must hold a grant"
        );
    }
    Ok((a, b, c, d, [root; 32]))
}

async fn teardown(daemons: [Daemon; 4]) {
    for d in daemons {
        d.shutdown().await;
    }
}

/// THE acceptance test: a key-less claimant recovers `K_root` through the full ceremony,
/// and it equals the original.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn full_ceremony_recovers_k_root() -> Result<()> {
    let (a, b, c, d, k_root) = setup().await?;
    let subject = a.user_id();
    let roster = [b.user_id(), c.user_id(), d.user_id()];

    // Every trustee's ceremony clock starts at T0 (so first_seen = T0 on track).
    for t in [&b, &c, &d] {
        t.set_test_clock(T0);
    }

    // A fresh key-less claimant device generates its ceremony keypair + node key.
    let claimant = ClaimantDevice::new()?;

    // Sponsor B opens the ceremony for subject A with the claimant's fresh key.
    let (open, id) = b.ceremony_sponsor_open(
        subject,
        "the heir".into(),
        claimant.ceremony_enc(),
        claimant.new_node(),
        "owner lost all devices".into(),
        T0,
    )?;

    // §8.5 step 2 fan-out: relay the open to the co-trustees. Each raises the alarm.
    b.deliver_recovery_open(&c.addr()?, &open).await?;
    b.deliver_recovery_open(&d.addr()?, &open).await?;
    for t in [&b, &c, &d] {
        let st = t.ceremony_statuses();
        let row = st
            .iter()
            .find(|r| r.ceremony_id == id)
            .context("no alarm row")?;
        assert!(row.trustee, "a trustee tracks the full ceremony");
        assert_eq!(row.phase, "open", "no approvals + no delay yet -> open");
    }

    // §8.5 step 4: B and C approve (after out-of-band verification), each broadcasting
    // its signed approval to the co-trustees so every tracked state reaches M.
    let ap_b = b.ceremony_approve(id, T0 + 10)?;
    b.send_ceremony_approve(&c.addr()?, &ap_b).await?;
    b.send_ceremony_approve(&d.addr()?, &ap_b).await?;
    let ap_c = c.ceremony_approve(id, T0 + 20)?;
    c.send_ceremony_approve(&b.addr()?, &ap_c).await?;
    c.send_ceremony_approve(&d.addr()?, &ap_c).await?;

    // B and C now hold 2 approvals AND approved themselves; D holds 2 but did not approve.
    for t in [&b, &c] {
        let st = t.ceremony_statuses();
        let row = st.iter().find(|r| r.ceremony_id == id).unwrap();
        assert_eq!(row.approvals, 2, "both approvals propagated");
        assert!(row.approved, "this trustee approved");
    }

    // §8.5 step 5, delay NOT satisfied: even with M approvals, no share releases.
    for t in [&b, &c, &d] {
        t.set_test_clock(T0 + DELAY - 1);
    }
    let early = claimant
        .collect_raw(&open, &[b.addr()?, c.addr()?, d.addr()?])
        .await?;
    assert!(
        early.is_empty(),
        "no share may release before the delay elapses"
    );
    for t in [&b, &c] {
        let row = t.ceremony_statuses();
        let r = row.iter().find(|r| r.ceremony_id == id).unwrap();
        assert_eq!(r.phase, "open", "pre-delay phase is still open");
    }

    // Advance the injected clock past first_seen + recovery_delay: the gate opens.
    for t in [&b, &c, &d] {
        t.set_test_clock(T0 + DELAY);
    }
    let shares = claimant
        .collect_raw(&open, &[b.addr()?, c.addr()?, d.addr()?])
        .await?;
    assert_eq!(
        shares.len(),
        2,
        "exactly the two APPROVING trustees release; D (no approval) does not"
    );

    // A share is NEVER sent unsealed: the trustee's plaintext share JSON must not appear
    // in the ciphertext.
    let plaintext = b.held_grant(&subject).unwrap().share_json;
    for cs in &shares {
        assert!(
            cs.sealed.len() > 32,
            "sealed = encapped key(32) || ciphertext"
        );
        assert!(
            !contains_subslice(&cs.sealed, plaintext.as_bytes()),
            "the share must be HPKE-sealed, never sent in the clear"
        );
    }

    // §8.5 step 6 / §8.4: the claimant opens the M shares and recovers K_root.
    let recovered = claimant.recover_from(&shares, &roster)?;
    assert_eq!(
        recovered.k_root.as_slice(),
        &k_root,
        "the recovered K_root EQUALS the original"
    );

    // The recovered identity re-derives the SAME user key (friendships/cards stay valid)
    // and re-signs a valid delegation for the new device (§8.4).
    assert_eq!(
        recovered.user_id, subject,
        "re-derived user key equals the original owner's"
    );
    let user_vk = VerifyingKey::from_bytes(&recovered.user_id).unwrap();
    let node_vk = VerifyingKey::from_bytes(&recovered.new_node).unwrap();
    let sig = Signature::from_bytes(&recovered.node_deleg);
    carapace_crypto::identity::verify_delegation(
        &user_vk,
        &node_vk,
        DELEG_NOT_AFTER,
        &sig,
        Some(T0 + DELAY),
    )
    .context("re-signed node delegation must verify")?;

    teardown([a, b, c, d]).await;
    Ok(())
}

/// A subject-signed `CeremonyAbort` cancels the ceremony permanently and flags it as an
/// attempted takeover: no share releases even past the delay with M approvals.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn subject_abort_cancels_and_flags_takeover() -> Result<()> {
    let (a, b, c, d, _k_root) = setup().await?;
    let subject = a.user_id();
    for t in [&b, &c, &d] {
        t.set_test_clock(T0);
    }
    let claimant = ClaimantDevice::new()?;
    let (open, id) = b.ceremony_sponsor_open(
        subject,
        "impostor".into(),
        claimant.ceremony_enc(),
        claimant.new_node(),
        "takeover attempt".into(),
        T0,
    )?;
    b.deliver_recovery_open(&c.addr()?, &open).await?;
    b.deliver_recovery_open(&d.addr()?, &open).await?;

    // Both B and C approve (M reached) - the ceremony would otherwise release.
    let ap_b = b.ceremony_approve(id, T0 + 10)?;
    for t in [&c, &d] {
        b.send_ceremony_approve(&t.addr()?, &ap_b).await?;
    }
    let ap_c = c.ceremony_approve(id, T0 + 20)?;
    for t in [&b, &d] {
        c.send_ceremony_approve(&t.addr()?, &ap_c).await?;
    }

    // The owner (still holds the subject user key) signs the authoritative abort and
    // broadcasts it to the trustees.
    let ab = a.ceremony_abort(id)?;
    assert_eq!(ab.by, subject, "abort is signed by the subject user key");
    for t in [&b, &c, &d] {
        a.send_ceremony_abort(&t.addr()?, &ab).await?;
    }

    // Every trustee flags the ceremony as a takeover; the phase is aborted.
    for t in [&b, &c, &d] {
        let row = t.ceremony_statuses();
        let r = row.iter().find(|r| r.ceremony_id == id).unwrap();
        assert!(
            r.takeover,
            "a valid subject abort flags an attempted takeover"
        );
        assert_eq!(r.phase, "aborted", "aborted permanently");
    }

    // Past the delay, with M approvals, NOTHING releases.
    for t in [&b, &c, &d] {
        t.set_test_clock(T0 + DELAY);
    }
    let shares = claimant
        .collect_raw(&open, &[b.addr()?, c.addr()?, d.addr()?])
        .await?;
    assert!(
        shares.is_empty(),
        "an aborted ceremony never releases a share"
    );

    teardown([a, b, c, d]).await;
    Ok(())
}

/// Only a trustee may open (§8.5 step 1): a daemon holding no grant for the subject is
/// refused when it tries to sponsor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_trustee_cannot_open() -> Result<()> {
    let a = Daemon::start(seeds(0x02, 0xA5)).await?;
    let stranger = Daemon::start(seeds(0x42, 0xE5)).await?;
    let claimant = ClaimantDevice::new()?;
    let err = stranger
        .ceremony_sponsor_open(
            a.user_id(),
            "impostor".into(),
            claimant.ceremony_enc(),
            claimant.new_node(),
            "no grant here".into(),
            T0,
        )
        .expect_err("a non-trustee must not be able to open a ceremony");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("only a trustee may sponsor"),
        "unexpected error: {msg}"
    );
    a.shutdown().await;
    stranger.shutdown().await;
    Ok(())
}

/// §8.4 max-epoch selection: given announce refs gathered across several trustees for
/// the same vault, a recovering claimant takes the HIGHEST epoch (a stale source cannot
/// roll recovery back to an old manifest).
#[test]
fn max_epoch_takes_the_highest_per_vault() {
    let vid_a = [0x0A; 32];
    let vid_b = [0x0B; 32];
    let refs = vec![
        AnnounceRef {
            vid: vid_a,
            epoch: 3,
            digest: [1; 32],
        }, // one trustee: stale
        AnnounceRef {
            vid: vid_a,
            epoch: 7,
            digest: [2; 32],
        }, // another: current
        AnnounceRef {
            vid: vid_a,
            epoch: 5,
            digest: [3; 32],
        },
        AnnounceRef {
            vid: vid_b,
            epoch: 1,
            digest: [4; 32],
        },
    ];
    let picked = max_epoch_refs(&refs);
    assert_eq!(picked.len(), 2, "one winning ref per vault");
    let a = picked.iter().find(|r| r.vid == vid_a).unwrap();
    assert_eq!(a.epoch, 7, "the max epoch wins for vault A");
    assert_eq!(a.digest, [2; 32], "and its digest, not a stale one");
    let b = picked.iter().find(|r| r.vid == vid_b).unwrap();
    assert_eq!(b.epoch, 1);
    // Empty input yields no target.
    assert!(max_epoch_refs(&[]).is_empty());
}

/// Sub-`M` approvals never release, even past the delay: with one approval of a 2-of-3,
/// no trustee's state reaches the threshold, so the claimant collects nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sub_m_never_releases() -> Result<()> {
    let (a, b, c, d, _k) = setup().await?;
    let subject = a.user_id();
    for t in [&b, &c, &d] {
        t.set_test_clock(T0);
    }
    let claimant = ClaimantDevice::new()?;
    let (open, id) = b.ceremony_sponsor_open(
        subject,
        "heir".into(),
        claimant.ceremony_enc(),
        claimant.new_node(),
        "lost devices".into(),
        T0,
    )?;
    b.deliver_recovery_open(&c.addr()?, &open).await?;
    b.deliver_recovery_open(&d.addr()?, &open).await?;

    // Only ONE approval (B). 1 < M = 2.
    let ap_b = b.ceremony_approve(id, T0 + 10)?;
    for t in [&c, &d] {
        b.send_ceremony_approve(&t.addr()?, &ap_b).await?;
    }

    // Even long past the delay, nothing releases (no trustee state reaches M).
    for t in [&b, &c, &d] {
        t.set_test_clock(T0 + DELAY + 1_000_000);
    }
    let shares = claimant
        .collect_raw(&open, &[b.addr()?, c.addr()?, d.addr()?])
        .await?;
    assert!(
        shares.is_empty(),
        "sub-M approvals must never release a share"
    );

    teardown([a, b, c, d]).await;
    Ok(())
}
