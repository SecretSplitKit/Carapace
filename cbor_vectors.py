#!/usr/bin/env python3
"""Carapace Appendix B — reference deterministic-CBOR encoder + test-vector
generator. This script is the source of truth for the vectors in
carapace-appendix-b-cbor.md; re-run it to regenerate or extend them.

Encoding profile (RFC 8949 §4.2.1 Core Deterministic, restricted):
  - unsigned integers only (no negatives needed by any message), shortest form
  - definite-length strings/arrays/maps only
  - map keys: unsigned ints < 24 (single-byte encodings) or byte strings;
    sorted bytewise-lexicographically on their encoded form
  - bool/null as simple values; floats PROHIBITED
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------- deterministic CBOR encoder (reference) ----------------

def enc_uint(n, major=0):
    assert n >= 0
    m = major << 5
    if n < 24:      return bytes([m | n])
    if n < 0x100:   return bytes([m | 24]) + n.to_bytes(1, "big")
    if n < 0x10000: return bytes([m | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000: return bytes([m | 26]) + n.to_bytes(4, "big")
    return bytes([m | 27]) + n.to_bytes(8, "big")

def enc(v):
    if isinstance(v, bool):            # before int (bool is int subclass)
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return enc_uint(v, 0)
    if isinstance(v, bytes):
        return enc_uint(len(v), 2) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return enc_uint(len(b), 3) + b
    if isinstance(v, list):
        return enc_uint(len(v), 4) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((enc(k), enc(val)) for k, val in v.items()),
                       key=lambda kv: kv[0])
        return enc_uint(len(v), 5) + b"".join(k + val for k, val in items)
    raise TypeError(type(v))

# ---------------- signing discipline ----------------

DOMAIN = b"carapace-sig-v1"

def sign_body(msg_type, body, key):
    """sig = Ed25519(key, DOMAIN || det_cbor([msg_type, body_without_sig]))"""
    body_wo = {k: v for k, v in body.items() if k != 23}
    return key.sign(DOMAIN + enc([msg_type, body_wo]))

def frame(msg_type, body):
    payload = enc([msg_type, body])
    return len(payload).to_bytes(4, "big") + payload

# ---------------- fixed test material ----------------

def k(seed_byte):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)

USER_A  = k(0x01); USER_A_PUB  = USER_A.public_key().public_bytes_raw()
USER_B  = k(0x02); USER_B_PUB  = USER_B.public_key().public_bytes_raw()
NODE_A1 = k(0x03); NODE_A1_PUB = NODE_A1.public_key().public_bytes_raw()
NODE_B1 = k(0x04); NODE_B1_PUB = NODE_B1.public_key().public_bytes_raw()
ENC_A   = bytes([0x05]) * 32          # X25519 pub placeholder (fixed)
T0      = 1767225600                  # 2026-01-01T00:00:00Z
CEREMONY_ID = bytes([0xA0]) * 16
NONCE16 = bytes([0xB0]) * 16
VID     = bytes([0xC0]) * 32
DIGEST  = bytes([0xD0]) * 32
TOKEN   = bytes([0xE0]) * 16

def deleg(user_key, node_pub, not_after):
    return user_key.sign(b"carapace/v1/deleg" + node_pub +
                         not_after.to_bytes(8, "big"))

# ---------------- messages ----------------

vectors = []

def emit(name, msg_type, body, note=""):
    f = frame(msg_type, body)
    vectors.append((name, msg_type, body, f, note))

# 1. Hello (unsigned; connection already NodeID-authenticated)
emit("Hello", 1, {0: 1, 1: 7, 2: 0b111},
     "protocol=1, card_version=7, roles bitfield storage|trustee|relay")

# 21. CeremonyAbort — signed by USER key (the point of the message)
body = {0: CEREMONY_ID, 22: USER_A_PUB}
body[23] = sign_body(21, body, USER_A)
emit("CeremonyAbort", 21, body, "by/sig = USER key, unforgeable by impostor")

# 2. ContactCard — signed by USER key
node_entry = {0: NODE_A1_PUB, 1: deleg(USER_A, NODE_A1_PUB, T0 + 31536000),
              2: T0 + 31536000, 3: ["192.0.2.10:7400"],
              4: "relay.example.net:443"}
body = {0: USER_A_PUB, 1: "AtHeart", 2: ENC_A, 3: [node_entry],
        4: {0: 10737418240, 1: True, 2: True}, 5: 7, 22: USER_A_PUB}
body[23] = sign_body(2, body, USER_A)
emit("ContactCard", 2, body, "offers: 10 GiB storage, relay, trustee")

# 8. VaultAnnounce — signed by node key
body = {0: VID, 1: 42, 2: [NODE_B1_PUB], 3: DIGEST, 22: NODE_A1_PUB}
body[23] = sign_body(8, body, NODE_A1)
emit("VaultAnnounce", 8, body, "epoch=42, one replica (node B1)")

# 14. ShareAttestation — signed by node key of trustee
body = {0: USER_A_PUB, 1: 0x02C9, 2: 5, 3: NONCE16, 22: NODE_B1_PUB}
body[23] = sign_body(14, body, NODE_B1)
emit("ShareAttestation", 14, body,
     "rsid=0x2C9, card_number=5 (Chela SPEC's example values); echoes nonce")

# 5. FriendshipEnd
body = {0: USER_B_PUB, 1: T0, 22: NODE_A1_PUB}
body[23] = sign_body(5, body, NODE_A1)
emit("FriendshipEnd", 5, body, "A unfriends B at T0")

# 23. InviteTicket — signed by USER key; also rendered as carapace: URI
body = {0: USER_A_PUB, 1: NODE_A1_PUB, 2: ["192.0.2.10:7400"],
        3: ["relay.example.net:443"], 4: TOKEN, 5: T0 + 604800}
body[23] = sign_body(23, body, USER_A)
emit("InviteTicket", 23, body, "expires T0+7d; URI = carapace:<base32>")

import base64
ticket_uri = "carapace:" + base64.b32encode(enc([23, body])).decode().rstrip("=").lower()

# ================= PART 2: remaining 16 frame types + 4 documents =========
import blake3

# additional fixed material
ENC_B        = bytes([0x08]) * 32
GRANT_ID     = bytes([0x90]) * 16
CEREMONY_ENC = bytes([0x06]) * 32
NEW_NODE     = bytes([0x07]) * 32
FILEHASH     = bytes([0xAA]) * 32
CHUNKID      = bytes([0xC1]) * 32
PTHASH       = bytes([0xB1]) * 32     # BLAKE3(chunk plaintext), stored in the manifest (Option B)
CHUNKKEY     = bytes([0x77]) * 32
CHUNKNONCE   = bytes([0x88]) * 24
ENV_NONCE    = bytes([0x99]) * 24
HPKE_CT      = bytes([0xEE]) * 48   # placeholder: HPKE ct is opaque at framing layer
ENV_CT       = bytes([0xEE]) * 64   # placeholder: AEAD ct is opaque at framing layer

# --- documents -------------------------------------------------------------
# Friendship (doc_type 0): a < b bytewise on encoded pubkeys
a_pub, b_pub = sorted([USER_A_PUB, USER_B_PUB])          # USER_B (0x81..) < USER_A (0x8a..)
key_of = {USER_A_PUB: USER_A, USER_B_PUB: USER_B}
fr_core = {0: a_pub, 1: b_pub, 2: T0}
sig_a = key_of[a_pub].sign(DOMAIN + enc([0, fr_core]))
sig_b = key_of[b_pub].sign(DOMAIN + enc([0, fr_core]))
FRIENDSHIP = {0: a_pub, 1: b_pub, 2: T0, 3: sig_a, 4: sig_b}

# USER_B's ContactCard (needed by FriendRequest)
node_entry_b = {0: NODE_B1_PUB, 1: deleg(USER_B, NODE_B1_PUB, T0 + 31536000),
                2: T0 + 31536000, 3: ["198.51.100.7:7400"], 4: None}
CARD_B = {0: USER_B_PUB, 1: "UserB", 2: ENC_B, 3: [node_entry_b],
          4: {0: 5368709120, 1: False, 2: True}, 5: 3, 22: USER_B_PUB}
CARD_B[23] = sign_body(2, CARD_B, USER_B)

# USER_A's ContactCard — identical to the B.8.3 vector
node_entry_a = {0: NODE_A1_PUB, 1: deleg(USER_A, NODE_A1_PUB, T0 + 31536000),
                2: T0 + 31536000, 3: ["192.0.2.10:7400"],
                4: "relay.example.net:443"}
CARD_A = {0: USER_A_PUB, 1: "AtHeart", 2: ENC_A, 3: [node_entry_a],
          4: {0: 10737418240, 1: True, 2: True}, 5: 7, 22: USER_A_PUB}
CARD_A[23] = sign_body(2, CARD_A, USER_A)

# Chela SPEC §8.3 worked-example share, verbatim single-line JSON
CHELA_SHARE_JSON = ('{"type":"chela.share","card_code":"CHELA-02C9-5-2-3-6",'
 '"recovery_set_id":"02C9","card_number":5,"threshold":2,"total":3,'
 '"word_count":6,"scheme":"bip39-wordlist","payload_kind":"text",'
 '"words":["cactus","float","ghost","shine","baby","talk"]}')

part2 = []
def emit2(name, msg_type, body, note=""):
    part2.append((name, msg_type, body, frame(msg_type, body), note))

# 3. FriendRequest — B asks A, using A's ticket token
body = {0: TOKEN, 1: CARD_B, 22: NODE_B1_PUB}
body[23] = sign_body(3, body, NODE_B1)
emit2("FriendRequest", 3, body, "B->A with A's ticket token; embeds CARD_B (own sig)")

# 4. FriendAccept — A accepts, embeds CARD_A + mutually-signed Friendship
body = {0: CARD_A, 1: FRIENDSHIP, 22: NODE_A1_PUB}
body[23] = sign_body(4, body, NODE_A1)
emit2("FriendAccept", 4, body, "embeds CARD_A + Friendship (a=USER_B, b=USER_A by bytewise sort)")

# 6. DeleteRequest — A asks B to delete replicas of VID
body = {0: 0, 1: VID, 22: NODE_A1_PUB}
body[23] = sign_body(6, body, NODE_A1)
emit2("DeleteRequest", 6, body, "scope=0 (replicas), vid")
del_req_payload = enc([6, body])

# 7. DeleteAck — ref = BLAKE3 of the DeleteRequest payload (frame minus length)
body = {0: blake3.blake3(del_req_payload).digest(), 1: T0, 22: NODE_B1_PUB}
body[23] = sign_body(7, body, NODE_B1)
emit2("DeleteAck", 7, body, "ref = BLAKE3(DeleteRequest payload) — computed, real")

# 9. ManifestOffer
body = {0: VID, 1: 42, 2: DIGEST, 22: NODE_A1_PUB}
body[23] = sign_body(9, body, NODE_A1)
emit2("ManifestOffer", 9, body, "")

# 10. ReplicaInvite
body = {0: VID, 1: 42, 2: 1073741824, 22: NODE_A1_PUB}
body[23] = sign_body(10, body, NODE_A1)
emit2("ReplicaInvite", 10, body, "approx_bytes = 1 GiB")

# 11. ReplicaAccept
body = {0: VID, 1: 2147483648, 22: NODE_B1_PUB}
body[23] = sign_body(11, body, NODE_B1)
emit2("ReplicaAccept", 11, body, "quota_bytes = 2 GiB")

# 12. ShareGrant — carries the Chela SPEC §8.3 worked-example share verbatim
body = {0: USER_A_PUB, 1: CHELA_SHARE_JSON, 2: 259200,
        3: [{0: USER_B_PUB, 1: NODE_B1_PUB, 2: "relay.example.net:443"}],
        4: [{0: VID, 1: 42, 2: DIGEST}], 22: NODE_A1_PUB}
body[23] = sign_body(12, body, NODE_A1)
emit2("ShareGrant", 12, body,
      "share = Chela SPEC §8.3 example (rsid 02C9, 'cactus float ghost shine baby talk'); delay 72 h")

# 13. ShareAttestChallenge
body = {0: USER_A_PUB, 1: 0x02C9, 2: NONCE16, 22: NODE_A1_PUB}
body[23] = sign_body(13, body, NODE_A1)
emit2("ShareAttestChallenge", 13, body, "")

# 15. ShareDestroy
body = {0: USER_A_PUB, 1: 0x02C9, 22: NODE_A1_PUB}
body[23] = sign_body(15, body, NODE_A1)
emit2("ShareDestroy", 15, body, "")

# 16. ShareDestroyAck
body = {0: USER_A_PUB, 1: 0x02C9, 2: T0, 22: NODE_B1_PUB}
body[23] = sign_body(16, body, NODE_B1)
emit2("ShareDestroyAck", 16, body, "")

# 17. FileGrant — sealed ct is an opaque placeholder (HPKE has RFC 9180 vectors)
body = {0: GRANT_ID, 1: VID, 2: 42, 3: [USER_B_PUB],
        4: [{0: USER_B_PUB, 1: HPKE_CT}], 22: NODE_A1_PUB}
body[23] = sign_body(17, body, NODE_A1)
emit2("FileGrant", 17, body, "audience = USER_B; ct = 0xEE placeholder (opaque at framing layer)")

# 18. AuditNotice
body = {0: VID, 1: 1, 22: NODE_A1_PUB}
body[23] = sign_body(18, body, NODE_A1)
emit2("AuditNotice", 18, body, "code=1")

# 19. RecoveryOpen — sponsored by trustee NODE_B1
body = {0: CEREMONY_ID, 1: USER_A_PUB, 2: 0x02C9, 3: "Heir of A",
        4: CEREMONY_ENC, 5: NEW_NODE, 6: "device lost", 7: T0,
        22: NODE_B1_PUB}
body[23] = sign_body(19, body, NODE_B1)
emit2("RecoveryOpen", 19, body, "sponsor = trustee NODE_B1")

# 20. CeremonyApprove
body = {0: CEREMONY_ID, 1: T0 + 3600, 22: NODE_B1_PUB}
body[23] = sign_body(20, body, NODE_B1)
emit2("CeremonyApprove", 20, body, "")

# 22. CeremonyShare — sealed share is an opaque placeholder
body = {0: CEREMONY_ID, 1: HPKE_CT, 22: NODE_B1_PUB}
body[23] = sign_body(22, body, NODE_B1)
emit2("CeremonyShare", 22, body, "sealed = 0xEE placeholder (opaque at framing layer)")

# --- unsigned / document vectors -------------------------------------------
GRANTBODY = {0: [{0: "notes/plan.txt", 1: FILEHASH, 2: 1234,
                  3: [{0: CHUNKID, 1: CHUNKKEY, 2: CHUNKNONCE, 3: 1234}]}]}
MANIFEST = {0: VID, 1: 42, 2: [USER_A_PUB],
            3: [{0: "notes/plan.txt", 1: 33188, 2: T0, 3: 1234,
                 4: [{0: CHUNKID, 1: PTHASH, 2: 1234}], 5: FILEHASH,
                 6: {NODE_A1_PUB: 3}, 7: False}],
            4: {NODE_A1_PUB: 3}}
env = {0: VID, 1: 42, 2: ENV_NONCE, 3: ENV_CT, 22: NODE_A1_PUB}
env[23] = NODE_A1.sign(DOMAIN + enc([24, {k2: v for k2, v in env.items() if k2 != 23}]))
docs = [
    ("Friendship (doc_type 0)", FRIENDSHIP, enc(FRIENDSHIP),
     "sig_a by USER_B (a), sig_b by USER_A (b), over DOMAIN||det_cbor([0,{0:a,1:b,2:ts}])"),
    ("GrantBody (unsigned; HPKE plaintext)", GRANTBODY, enc(GRANTBODY), ""),
    ("Manifest (unsigned; AEAD plaintext)", MANIFEST, enc(MANIFEST), "vv keyed by NODE_A1 pub"),
    ("ManifestEnvelope (doc_type 24)", env, enc(env), "ct = 0xEE placeholder; sig discipline as B.3 with doc_type 24"),
]

# --- verify everything ------------------------------------------------------
pubmap2 = {USER_A_PUB: USER_A, USER_B_PUB: USER_B,
           NODE_A1_PUB: NODE_A1, NODE_B1_PUB: NODE_B1}
for name, mt, body, f, note in part2:
    body_wo = {k2: v for k2, v in body.items() if k2 != 23}
    pubmap2[body[22]].public_key().verify(body[23], DOMAIN + enc([mt, body_wo]))
    # nested docs
    if mt == 3:
        c = body[1]; cwo = {k2: v for k2, v in c.items() if k2 != 23}
        pubmap2[c[22]].public_key().verify(c[23], DOMAIN + enc([2, cwo]))
    if mt == 4:
        c = body[0]; cwo = {k2: v for k2, v in c.items() if k2 != 23}
        pubmap2[c[22]].public_key().verify(c[23], DOMAIN + enc([2, cwo]))
        fr = body[1]
        core = {0: fr[0], 1: fr[1], 2: fr[2]}
        pubmap2[fr[0]].public_key().verify(fr[3], DOMAIN + enc([0, core]))
        pubmap2[fr[1]].public_key().verify(fr[4], DOMAIN + enc([0, core]))
pubmap2[env[22]].public_key().verify(
    env[23], DOMAIN + enc([24, {k2: v for k2, v in env.items() if k2 != 23}]))
core = {0: FRIENDSHIP[0], 1: FRIENDSHIP[1], 2: FRIENDSHIP[2]}
pubmap2[FRIENDSHIP[0]].public_key().verify(FRIENDSHIP[3], DOMAIN + enc([0, core]))
pubmap2[FRIENDSHIP[1]].public_key().verify(FRIENDSHIP[4], DOMAIN + enc([0, core]))

# --- emit markdown fragment for the appendix --------------------------------
def hexwrap(b, indent=""):
    h = b.hex()
    return "\n".join(indent + h[i:i+64] for i in range(0, len(h), 64))

sec = 8  # continues B.8.7
lines = []
for name, mt, body, f, note in part2:
    lines.append(f"### B.8.{sec} {name} (type {mt})" + (f" — {note}" if note else ""))
    lines.append("")
    lines.append("```")
    lines.append(hexwrap(f))
    lines.append("```")
    lines.append("")
    sec += 1
lines.append(f"### B.8.{sec} Documents (not frames; encoded bare, no length prefix)")
lines.append("")
for name, body, e, note in docs:
    lines.append(f"**{name}**" + (f" — {note}" if note else ""))
    lines.append("")
    lines.append("```")
    lines.append(hexwrap(e))
    lines.append("```")
    lines.append("")
with open("appendix_b8_fragment.md", "w") as fh:
    fh.write("\n".join(lines))

print(f"\nPART 2: {len(part2)} frames + {len(docs)} documents generated, all signatures verified OK")
print("fragment written to appendix_b8_fragment.md")

# ---------------- output ----------------

print("== test keys ==")
for label, kp in [("USER_A", USER_A), ("USER_B", USER_B),
                  ("NODE_A1", NODE_A1), ("NODE_B1", NODE_B1)]:
    print(f"{label}: seed={kp.private_bytes_raw().hex()}")
    print(f"{label}: pub ={kp.public_key().public_bytes_raw().hex()}")
print(f"T0={T0}")
print()
for name, mt, body, f, note in vectors:
    print(f"== {name} (type {mt}) ==  {note}")
    print(f"frame ({len(f)} bytes):")
    h = f.hex()
    for i in range(0, len(h), 64):
        print("  " + h[i:i+64])
    print()
print("== InviteTicket URI ==")
print(ticket_uri)

# sanity: verify every signature verifies
from cryptography.exceptions import InvalidSignature
pubmap = {USER_A_PUB: USER_A, USER_B_PUB: USER_B,
          NODE_A1_PUB: NODE_A1, NODE_B1_PUB: NODE_B1}
for name, mt, body, f, note in vectors:
    if 23 in body:
        # signer = key 22 (by) when present, else field 0 (self-identifying docs)
        signer = pubmap[body.get(22, body[0])].public_key()
        body_wo = {k2: v for k2, v in body.items() if k2 != 23}
        signer.verify(body[23], DOMAIN + enc([mt, body_wo]))
print("\nall signatures verified OK")
