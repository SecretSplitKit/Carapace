# Carapace Protocol — Appendix B: Wire Encoding (deterministic CBOR)

*Normative companion to the Carapace Protocol spec (v0.10). Every byte
sequence in §8 was generated and signature-verified by the included
reference script (`cbor_vectors.py`) — regenerate rather than hand-edit.*

---

## B.1 Encoding profile (normative)

All Carapace control messages and documents are encoded in **CBOR
(RFC 8949) under the Core Deterministic Encoding requirements (§4.2.1)**,
further restricted so that two independent implementations cannot disagree:

1. **Integers:** unsigned only (no message field is ever negative), shortest
   form (major type 0).
2. **Lengths:** definite-length only, for strings, arrays, and maps.
   Indefinite-length items MUST be rejected.
3. **Map keys:** unsigned integers `< 24` (encoding to a single byte) or
   byte strings (version-vector keys only). Keys are sorted
   **bytewise-lexicographically on their encoded form**. (With all integer
   keys `< 24`, this equals numeric order; the `< 24` restriction exists so
   RFC 7049-canonical and RFC 8949-deterministic encoders agree.)
4. **Floats: prohibited.** No message uses them; a decoder MUST reject any
   float, as well as tags, bignums, and simple values other than
   `false`/`true`/`null`.
5. **Text strings:** valid UTF-8, NFC-normalized where they name paths.
6. Unknown map keys in a *known* message type MUST be rejected (there is no
   extension-by-unknown-field; protocol evolution uses new message types or
   a new suite id).

## B.2 Framing and envelope

Messages on ALPN `carapace/1` (iroh QUIC streams):

```
frame     = len(4 bytes, big-endian) ‖ payload
payload   = det_cbor( [ msg_type: uint, body: map ] )
```

Max control-frame payload: **1 MiB** (chunk data never travels in frames —
bulk bytes use iroh-blobs). A peer MUST drop the connection on an oversized
or non-deterministic frame.

## B.3 Signing discipline

Signed messages carry two conventional keys in `body`:

- key **22** — `by`: the signer's public key (32-byte Ed25519). Per message
  this is either a **node** key (delegation checked via the signer's newest
  ContactCard) or a **user** key; the registry (§B.5) says which.
- key **23** — `sig`: 64-byte Ed25519 signature.

```
sig = Ed25519-sign( signer_key,
        "carapace-sig-v1" ‖ det_cbor([ msg_type, body_without_key_23 ]) )
```

`body_without_key_23` is the body map with only the `sig` entry removed
(`by` **is** covered). The `msg_type` inside the signed structure provides
domain separation between message kinds; the ASCII prefix separates
Carapace signatures from every other Ed25519 use (device delegations use
the distinct prefix `carapace/v1/deleg`, spec §4.3). Self-identifying
documents that omit `by` (InviteTicket) sign identically, with the signer
given by field 0.

Verification MUST re-encode deterministically and compare — never verify
against received bytes with the sig spliced out by offset arithmetic
(prevents malleability via alternate encodings; B.1 makes the two
equivalent, this rule makes sloppy decoders safe).

## B.4 Common types (CDDL, RFC 8610)

```cddl
pub32   = bstr .size 32     ; Ed25519 or X25519 public key
hash32  = bstr .size 32     ; BLAKE3-256
sig64   = bstr .size 64
id16    = bstr .size 16
nonce24 = bstr .size 24
ts      = uint              ; unix seconds, UTC
addr    = text              ; "host:port" or "ip:port"
vv      = { * pub32 => uint }              ; version vector, keyed by deviceID
by      = (22: pub32)
sig     = (23: sig64)
```

## B.5 Message-type registry

| type | message | signer (`by`) | channel |
|---|---|---|---|
| 1 | Hello | — (unsigned; conn is NodeID-authenticated) | stream |
| 2 | ContactCard | **user** | sync |
| 3 | FriendRequest | node | stream |
| 4 | FriendAccept | node | stream |
| 5 | FriendshipEnd | node | stream |
| 6 | DeleteRequest | node | stream |
| 7 | DeleteAck | node | stream |
| 8 | VaultAnnounce | node | sync |
| 9 | ManifestOffer | node | stream |
| 10 | ReplicaInvite | node | stream |
| 11 | ReplicaAccept | node | stream |
| 12 | ShareGrant | node | stream |
| 13 | ShareAttestChallenge | node | sync |
| 14 | ShareAttestation | node | sync |
| 15 | ShareDestroy | node | stream |
| 16 | ShareDestroyAck | node | stream |
| 17 | FileGrant | node | stream |
| 18 | AuditNotice | node | stream |
| 19 | RecoveryOpen | node (sponsor trustee) | stream |
| 20 | CeremonyApprove | node (trustee) | stream |
| 21 | CeremonyAbort | **user** (the whole point) | stream |
| 22 | CeremonyShare | node (trustee) | stream |
| 23 | InviteTicket | **user** (field 0; no `by`) | out-of-band URI/QR |

Documents that never travel as frames but are det-CBOR for hashing/signing:
`Manifest` (inside the envelope AEAD), `ManifestEnvelope` (an iroh blob),
`Friendship`, `GrantBody` (inside HPKE). Schemas in §B.6. Signed documents
use the B.3 discipline with **doc-type ids** in place of `msg_type`:
`0` = Friendship, `24` = ManifestEnvelope. Unsigned documents (`Manifest`,
`GrantBody`) are encoded as bare maps — no `[type, body]` wrapper — since
they are only ever hashed or AEAD-encrypted, never signature-verified
standalone.

## B.6 Message schemas (CDDL)

```cddl
Hello           = { 0: uint,              ; protocol version (1)
                    1: uint,              ; sender's own ContactCard version
                    2: uint }             ; roles bitfield: 1=storage 2=trustee 4=relay

NodeEntry       = { 0: pub32,             ; node_id
                    1: sig64,             ; delegation by user key (spec §4.3)
                    2: ts,                ; delegation not_after
                    3: [* addr],
                    4: text / null }      ; relay_url
ContactCard     = { 0: pub32,             ; user_pubkey
                    1: text,              ; display
                    2: pub32,             ; enc_pubkey (X25519)
                    3: [* NodeEntry],
                    4: { 0: uint,         ; offers.storage_bytes
                         1: bool,         ; offers.relay
                         2: bool },       ; offers.trustee
                    5: uint,              ; version (monotonic)
                    by, sig }             ; by = user_pubkey (self)

FriendRequest   = { 0: id16,              ; ticket token
                    1: ContactCard,       ; requester's card (with its own sig)
                    by, sig }
FriendAccept    = { 0: ContactCard,       ; acceptor's card
                    1: Friendship,
                    by, sig }
Friendship      = { 0: pub32, 1: pub32,   ; a, b (bytewise a < b)
                    2: ts,                ; established
                    3: sig64, 4: sig64 }  ; sig_a, sig_b over
                                          ; "carapace-sig-v1" ‖ det_cbor([0,{0:a,1:b,2:ts}])
FriendshipEnd   = { 0: pub32,             ; the unfriended user
                    1: ts, by, sig }
DeleteRequest   = { 0: uint,              ; scope: 0=replicas 1=shares 2=all
                    1: hash32 / null,     ; vid, when scope=0
                    by, sig }
DeleteAck       = { 0: hash32,            ; BLAKE3 of the DeleteRequest payload
                    1: ts, by, sig }

VaultAnnounce   = { 0: hash32,            ; vid
                    1: uint,              ; epoch (monotonic)
                    2: [* pub32],         ; replica NodeIDs
                    3: hash32,            ; manifestDigest (iroh blob hash)
                    by, sig }
ManifestOffer   = { 0: hash32, 1: uint, 2: hash32, by, sig }
ReplicaInvite   = { 0: hash32, 1: uint,   ; vid, epoch
                    2: uint, by, sig }    ; approx_bytes
ReplicaAccept   = { 0: hash32, 1: uint, by, sig }   ; vid, quota_bytes

ShareGrant      = { 0: pub32,             ; subject user
                    1: text,              ; chela.share JSON, verbatim (SPEC §6.2)
                    2: uint,              ; recovery_delay (seconds)
                    3: [* CoTrustee],
                    4: [* AnnounceRef],
                    by, sig }
CoTrustee       = { 0: pub32, 1: pub32, 2: text / null }  ; user, node, relay_url
AnnounceRef     = { 0: hash32, 1: uint, 2: hash32 }       ; vid, epoch, digest
ShareAttestChallenge = { 0: pub32, 1: uint,    ; subject, rsid
                         2: id16, by, sig }    ; nonce
ShareAttestation     = { 0: pub32, 1: uint, 2: uint,   ; subject, rsid, card_number
                         3: id16, by, sig }             ; echoed nonce
ShareDestroy    = { 0: pub32, 1: uint, by, sig }        ; subject, rsid
ShareDestroyAck = { 0: pub32, 1: uint, 2: ts, by, sig }

FileGrant       = { 0: id16,              ; grant_id
                    1: hash32, 2: uint,   ; vid, epoch
                    3: [* pub32],         ; audience (user keys)
                    4: [* Sealed],
                    by, sig }
Sealed          = { 0: pub32, 1: bstr }   ; to, HPKE ct of det_cbor GrantBody
GrantBody       = { 0: [* GrantFile] }
GrantFile       = { 0: text, 1: hash32, 2: uint,        ; path, fileHash, size
                    3: [* GrantChunk] }
GrantChunk      = { 0: hash32, 1: bstr .size 32,        ; ChunkID, chunk_key
                    2: nonce24, 3: uint }               ; nonce, len
AuditNotice     = { 0: hash32, 1: uint, by, sig }       ; vid, code

RecoveryOpen    = { 0: id16,              ; ceremony_id
                    1: pub32, 2: uint,    ; subject, rsid
                    3: text,              ; claimant display
                    4: pub32,             ; ceremony_enc_pubkey (fresh X25519)
                    5: pub32,             ; claimant new node_id
                    6: text, 7: ts,       ; reason, opened_at
                    by, sig }
CeremonyApprove = { 0: id16, 1: ts, by, sig }
CeremonyAbort   = { 0: id16, by, sig }    ; by = SUBJECT USER key
CeremonyShare   = { 0: id16, 1: bstr, by, sig }  ; HPKE-sealed chela.share JSON

InviteTicket    = { 0: pub32, 1: pub32,   ; user, node
                    2: [* addr], 3: [* text],  ; addrs, relay urls
                    4: id16, 5: ts, sig }      ; token, expires; signer = field 0
                    ; URI: "carapace:" ‖ lowercase-unpadded-base32(payload)

Manifest        = { 0: hash32, 1: uint,   ; vid, epoch
                    2: [* pub32],         ; authors
                    3: [* FileEntry],
                    4: vv }
FileEntry       = { 0: text, 1: uint, 2: ts, 3: uint,   ; path, mode, mtime, size
                    4: [* { 0: hash32, 1: uint }],      ; chunks (id, len)
                    5: hash32,                          ; fileHash
                    6: vv, 7: bool }                    ; version, deleted
ManifestEnvelope = { 0: hash32, 1: uint,  ; vid, epoch
                     2: nonce24, 3: bstr, ; nonce, ct (AEAD of det_cbor Manifest)
                     by, sig }
```

## B.7 Fixed test material

All vectors use Ed25519 keys from repeated-byte seeds (RFC 8032 keygen) and
the timestamp `T0 = 1767225600` (2026-01-01T00:00:00Z):

```
USER_A  seed 01×32  pub 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
USER_B  seed 02×32  pub 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
NODE_A1 seed 03×32  pub ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1
NODE_B1 seed 04×32  pub ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c
ceremony_id = a0×16   nonce16 = b0×16   vid = c0×32   digest = d0×32
token = e0×16   enc_pubkey placeholder = 05×32
```

## B.8 Test vectors (generated + signature-verified)

### B.8.1 Hello — annotated

`{0:1, 1:7, 2:7}` (protocol 1, card version 7, roles storage|trustee|relay):

```
00000009            frame length = 9
  82                array(2)
  01                  msg_type = 1 (Hello)
  a3                  map(3)
  00 01                 0: 1
  01 07                 1: 7
  02 07                 2: 7
```

Full frame: `000000098201a3000101070207`

### B.8.2 CeremonyAbort — annotated (signed by USER_A)

```
0000007b            frame length = 123
  82 15             array(2), msg_type = 21
  a3                map(3)
  00 50 a0…a0         0: ceremony_id (16 bytes)
  16 5820 8a88…6f5c   22: by = USER_A pub (32 bytes)
  17 5840 31da…010c   23: sig (64 bytes)
```

Full frame:
```
0000007b8215a30050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a01658208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c17584031
da69180840d4ed14c28b2909447807606af8e61e3f51c7d4840427bf490a4e8f
f9c362d25be5e24bb2b1a5bfaf47dd5f5efe61909717a84e70c53ee192010c
```

Signing input = `"carapace-sig-v1"` ‖ `8215a20050a0…a01658208a88…6f5c`
(the same structure with map(2), sig entry removed). This vector was
re-verified from the raw frame bytes alone.

### B.8.3 ContactCard (USER_A; one node with delegation; offers 10 GiB + relay + trustee; version 7)

```
000001628202a80058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c01674174486561727402582005050505050505050505
050505050505050505050505050505050505050505050381a5005820ed4928c6
28d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d101584048
5ff570b5fc2c8d68074e514d98c04e9312363ae19b6ac6c90b3c163f0323b91a
3301cc6a6883979931bf5a11fad8252fe46c32994ce48c50a588c64bbda50402
1a6b36ec8003816f3139322e302e322e31303a37343030047572656c61792e65
78616d706c652e6e65743a34343304a3001b000000028000000001f502f50507
1658208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c175840d49e2be24f9469dfeca6d4aabb647b1167385004f6913bc214ee
16d2ba72caeb29921c7a33cb023ae08ddb94d0911732287634194719448cc8ca
1dcf48adfa04
```

(Contains a real embedded delegation: `Ed25519(USER_A, "carapace/v1/deleg"
‖ NODE_A1 ‖ not_after=T0+1y)`.)

### B.8.4 VaultAnnounce (vid c0×32, epoch 42, one replica NODE_B1, signed NODE_A1)

```
000000d68208a6005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c001182a02815820ca93ac1705187071d67b83c7ff0efe
8108e8ec4530575d7726879333dbdabe7c035820d0d0d0d0d0d0d0d0d0d0d0d0
d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6ea
e90338905995612959273a5c63f93636c14614ac8737d117584098d70de83d73
a3ad022c8a77a4dd3cb755d16cc32de88191949c87adc0d2330f712a9cb1931e
7aacfe829d07787605c30cdcf0c8e96af161700edb9d6c78db0c
```

### B.8.5 ShareAttestation (subject USER_A, rsid 0x2C9, card 5 — Chela SPEC's worked-example values; signed NODE_B1)

```
000000a4820ea60058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c011902c902050350b0b0b0b0b0b0b0b0b0b0b0b0b0b0
b0b0165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d77268793
33dbdabe7c17584053e1da91761449cfe6df6e24e6457ed0d7c3cb3d274d6be0
0a479e1b546f45da4585ba75ce3524cec5f362c49948d8dbc8680d11c60ed97e
73edfc258408760f
```

### B.8.6 FriendshipEnd (A unfriends B at T0, signed NODE_A1)

```
000000928205a40058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee
37a25df60f5b8fc9b394011a6955b900165820ed4928c628d1c2c6eae9033890
5995612959273a5c63f93636c14614ac8737d11758404438dc88fbf8e5d6ee2a
2f72dea2b37e2dd2ce38ca1279dd56f586c92f4c54eebbe78dfa1b6d988bdc3d
3cc4039021ffa3537fac5735e38aaf4d01d5ba205b06
```

### B.8.7 InviteTicket (USER_A, expires T0+7d) + URI

```
000000ce8217a70058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c015820ed4928c628d1c2c6eae9033890599561295927
3a5c63f93636c14614ac8737d102816f3139322e302e322e31303a3734303003
817572656c61792e6578616d706c652e6e65743a3434330450e0e0e0e0e0e0e0
e0e0e0e0e0e0e0e0e0051a695ef3801758408b60451bc8e104bc219db807ff34
5e9fdd565a6f2c09b3bb4dbd98864f451762272bb3555dd35ac47558424cf78f
e00deb791b1e05360617e41e539d50c3e503
```

URI form (`carapace:` + lowercase unpadded base32 of the payload):

```
carapace:qil2oacyecfiry65oqe7dfp5klns2pf2lvzmuzyjx4ozieq36n2iqanub5xvyakyedwuskggfdi4frxk5ebtreczsvqsswjhhjogh6jwg3aumffmq435caubn4ytsmrogaxdelrrga5donbqgabyc5lsmvwgc6jomv4gc3lqnrss43tfoq5dinbtariobyha4dqobyha4dqobyha4dqoabi2nfpphaaxlbaiwycfdpeocbf4ego3qb77grpj7xkwljxsycntxng33gegj5croyrhfozvkxotllchkwccjt3y7yan5n4rwhqfgydbpza6koovbq7fam
```

### B.8.8 FriendRequest (type 3) — B->A with A's ticket token; embeds CARD_B (own sig)

```
000001c78203a40050e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e001a80058208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940165
5573657242025820080808080808080808080808080808080808080808080808
08080808080808080381a5005820ca93ac1705187071d67b83c7ff0efe8108e8
ec4530575d7726879333dbdabe7c0158400c175a09882a78847927eb4681f140
15f8106be9e3e6dcde66da9f337ee9446e4f40a271b81fa772abcc1be499573d
b7970de86fff0020eecb34c932a6a4ee0b021a6b36ec800381713139382e3531
2e3130302e373a3734303004f604a3001b000000014000000001f402f5050316
58208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9
b394175840b1cc162b3315b2520f220f4442762c210d902627c28c4fd227056a
86a59abd18ad3f2ef451c66a1ba6e96869539ea638449c243f49d8afe80bc5fa
ebd9074201165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d77
26879333dbdabe7c1758409b9fb465ee6a466ce96e6a4e51b2d903bb15eb4f19
ab036d192d994bb601b0cb1f309711692ad9794fe45eab0992ce9966d236056c
6f145e13959184353c7401
```

### B.8.9 FriendAccept (type 4) — embeds CARD_A + Friendship (a=USER_B, b=USER_A by bytewise sort)

```
0000029e8204a400a80058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf
1d94121bf3748801b40f6f5c0167417448656172740258200505050505050505
0505050505050505050505050505050505050505050505050381a5005820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10158
40485ff570b5fc2c8d68074e514d98c04e9312363ae19b6ac6c90b3c163f0323
b91a3301cc6a6883979931bf5a11fad8252fe46c32994ce48c50a588c64bbda5
04021a6b36ec8003816f3139322e302e322e31303a37343030047572656c6179
2e6578616d706c652e6e65743a34343304a3001b000000028000000001f502f5
05071658208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488
01b40f6f5c175840d49e2be24f9469dfeca6d4aabb647b1167385004f6913bc2
14ee16d2ba72caeb29921c7a33cb023ae08ddb94d0911732287634194719448c
c8ca1dcf48adfa0401a50058208139770ea87d175f56a35466c34c7ecccb8d8a
91b4ee37a25df60f5b8fc9b3940158208a88e3dd7409f195fd52db2d3cba5d72
ca6709bf1d94121bf3748801b40f6f5c021a6955b90003584054adbcbdf4b4d9
b1b403e481dac5fb51f30d5bd31a023909fde78361e1bcacdb4bb3aa1e4e3919
6947376ef1385c3b4f905f030d5174b32f8e77224bf4c49204045840748d76e5
312c306b7c2e327bec74663f52ebfb17cffb1ac3cbc5f3b89b2b071de77cdef1
12ce0815df3f0207c6c9302f96f11930b02e7914f88171a3bfc24a02165820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d117
5840588fe9445deb9d7e88f64eb4e180a90c28ea7c52dd7d2563e3f2d29d8dbf
8c1204cf8fa5015fe450457d7b9173d149e57329c09b90d72da8805117537f8b
ae00
```

### B.8.10 DeleteRequest (type 6) — scope=0 (replicas), vid

```
0000008e8206a40000015820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c0c0c0165820ed4928c628d1c2c6eae903389059956129
59273a5c63f93636c14614ac8737d117584033f7c73152f90eb53ca324268e2d
07ffb9754e05937002e118d0368152f9b96b7c9a2dd09150b19e740669f6b6ef
0ae10c8d6bbcf231e535bdc65c3ff94ec30a
```

### B.8.11 DeleteAck (type 7) — ref = BLAKE3(DeleteRequest payload) — computed, real

```
000000928207a4005820c59bd17212732dcc524e6abe0e56929bd30840783a6d
91945958a176047c8d57011a6955b900165820ca93ac1705187071d67b83c7ff
0efe8108e8ec4530575d7726879333dbdabe7c175840fa186e53c2f810280178
ed1905c757a588cd05046f80e65d765b499d6a89c07d48a9f0017b900ab27307
e14291647f096ca4787ea5f4e8a58c77e73e965ea40d
```

### B.8.12 ManifestOffer (type 9)

```
000000b28209a5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c001182a025820d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0
d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6eae9033890
5995612959273a5c63f93636c14614ac8737d117584024486e534a2240261f8c
4bb6e457416daef356c2a5d6e3e6bdfd6af121f3d58e4d9d6e6e3fcec97f0c39
04f3e5528b9a8a89c61522ae3498709fc7c6efb5ef0b
```

### B.8.13 ReplicaInvite (type 10) — approx_bytes = 1 GiB

```
00000095820aa5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c001182a021a40000000165820ed4928c628d1c2c6eae9
0338905995612959273a5c63f93636c14614ac8737d1175840a0da16973f2412
e13795cacc3e30beac5f1be3546295ef59b770eeb345c7b6bfe3b9929123b3eb
62eb2c47c588bab0d116133c8979424aed5bd6fd653c9edf0e
```

### B.8.14 ReplicaAccept (type 11) — quota_bytes = 2 GiB

```
00000092820ba4005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c0011a80000000165820ca93ac1705187071d67b83c7ff
0efe8108e8ec4530575d7726879333dbdabe7c1758403efe09ef1b654fd28154
2395c261569a9e005a20d75bc6d83202f78a1268b7911017c35597bef221e4ff
d95535fa6e30d70c44cd159e7dc171816752ca9f6508
```

### B.8.15 ShareGrant (type 12) — share = Chela SPEC §8.3 example (rsid 02C9, 'cactus float ghost shine baby talk'); delay 72 h

```
00000231820ca70058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c0178f07b2274797065223a226368656c612e73686172
65222c22636172645f636f6465223a224348454c412d303243392d352d322d33
2d36222c227265636f766572795f7365745f6964223a2230324339222c226361
72645f6e756d626572223a352c227468726573686f6c64223a322c22746f7461
6c223a332c22776f72645f636f756e74223a362c22736368656d65223a226269
7033392d776f72646c697374222c227061796c6f61645f6b696e64223a227465
7874222c22776f726473223a5b22636163747573222c22666c6f6174222c2267
686f7374222c227368696e65222c2262616279222c2274616c6b225d7d021a00
03f4800381a30058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37
a25df60f5b8fc9b394015820ca93ac1705187071d67b83c7ff0efe8108e8ec45
30575d7726879333dbdabe7c027572656c61792e6578616d706c652e6e65743a
3434330481a3005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c001182a025820d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0
d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6eae903389059
95612959273a5c63f93636c14614ac8737d1175840613c0b1653c908d1572b5e
61c272c46f0aeb7ec24e6eb9bf9b05bd8c51ef9bf4f1136338fe8edf262848c0
18f5634ec1e46d1c9d4b23f26a0adc0992b8b03d02
```

### B.8.16 ShareAttestChallenge (type 13)

```
000000a2820da50058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c011902c90250b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac
8737d1175840b584c05fd5ed01388139f1b212265615a61e996e12bbd8ee0f65
c2840a3d7262ee5731905c3fb556f9c5afb7413597b91fed8655801c08f9cfd1
e7d3c4f0b00f
```

### B.8.17 ShareDestroy (type 15)

```
00000090820fa40058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c011902c9165820ed4928c628d1c2c6eae90338905995
612959273a5c63f93636c14614ac8737d11758406b581bbff910d447df4bb5d1
99f9d46eb4c58481f7d7133c4eb0be86905acd0984f3f4a8049c518dd3140188
273942d922a6d225cd9a2df2a989177be4642e04
```

### B.8.18 ShareDestroyAck (type 16)

```
000000968210a50058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94
121bf3748801b40f6f5c011902c9021a6955b900165820ca93ac1705187071d6
7b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c1758409173c66cf3e3
c3f623fc0a3c478259bb8dd83daee1d37b9ad334413f9bc3d7667cdeec423d8d
f3b5c3ad795eb3aa0fc9571e022baf842b4a871dc54681654d08
```

### B.8.19 FileGrant (type 17) — audience = USER_B; ct = 0xEE placeholder (opaque at framing layer)

```
0000011e8211a7005090909090909090909090909090909090015820c0c0c0c0
c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c002182a03
8158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8f
c9b3940481a20058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37
a25df60f5b8fc9b394015830eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee165820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d117
58401a167632482c5f46cc63acaaba34fdd2ad36193d9e118c668b4b9c8fd827
05a41ae33947b647cd98115f7e225e72af861517c6b76243167d7d95276a251b
580b
```

### B.8.20 AuditNotice (type 18) — code=1

```
0000008e8212a4005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c0c0c0c0c0c0c00101165820ed4928c628d1c2c6eae903389059956129
59273a5c63f93636c14614ac8737d1175840bfdf67136920696baea7f54b20de
69d3f0fc6728b75ca06c6a5537a8ab85f7afd9fb44b0e7851b3f105f68b15465
b70b813ebae0005a0e78b9ed40f5d8ba570a
```

### B.8.21 RecoveryOpen (type 19) — sponsor = trustee NODE_B1

```
000001068213aa0050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c021902c9
036948656972206f662041045820060606060606060606060606060606060606
0606060606060606060606060606055820070707070707070707070707070707
0707070707070707070707070707070707066b646576696365206c6f7374071a
6955b900165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726
879333dbdabe7c17584009387f49a6e037fa018b53c379df96259c4ee89204a8
1f8a7d55a4da412dea0757880ed639f8d748fc0610bc9b5abf00d9f3e5c249b5
404dd59c4f3016c05202
```

### B.8.22 CeremonyApprove (type 20)

```
000000818214a40050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0011a6955c71016
5820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbda
be7c175840056ae598adf4964c920a39aa294f804f64ccf7d357d1fbe2afe257
41d77e6be1b5ffe00dd703dee1324d17b3233c7a9064e5f63076c9ce05fb9870
1b81870801
```

### B.8.23 CeremonyShare (type 22) — sealed = 0xEE placeholder (opaque at framing layer)

```
000000ae8216a40050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0015830eeeeeeee
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
eeeeeeeeeeeeeeeeeeeeeeee165820ca93ac1705187071d67b83c7ff0efe8108
e8ec4530575d7726879333dbdabe7c17584068047fcb207c3312490947b5b98e
28bb1dca0c103614957d8689038178e94acdda8aa8287762796a1b44d2f52e3a
b615fa8c58fdc3cde6ea4e9ce5b22163850b
```

### B.8.24 Documents (not frames; encoded bare, no length prefix)

**Friendship (doc_type 0)** — sig_a by USER_B (a), sig_b by USER_A (b), over DOMAIN||det_cbor([0,{0:a,1:b,2:ts}])

```
a50058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b3940158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3
748801b40f6f5c021a6955b90003584054adbcbdf4b4d9b1b403e481dac5fb51
f30d5bd31a023909fde78361e1bcacdb4bb3aa1e4e39196947376ef1385c3b4f
905f030d5174b32f8e77224bf4c49204045840748d76e5312c306b7c2e327bec
74663f52ebfb17cffb1ac3cbc5f3b89b2b071de77cdef112ce0815df3f0207c6
c9302f96f11930b02e7914f88171a3bfc24a02
```

**GrantBody (unsigned; HPKE plaintext)**

```
a10081a4006e6e6f7465732f706c616e2e747874015820aaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa021904d20381a40058
20c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1
c101582077777777777777777777777777777777777777777777777777777777
7777777702581888888888888888888888888888888888888888888888888803
1904d2
```

**Manifest (unsigned; AEAD plaintext)** — vv keyed by NODE_A1 pub

```
a5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c001182a028158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d
94121bf3748801b40f6f5c0381a8006e6e6f7465732f706c616e2e7478740119
81a4021a6955b900031904d20481a2005820c1c1c1c1c1c1c1c1c1c1c1c1c1c1
c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1011904d2055820aaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa06a15820ed4928
c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10307f4
04a15820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614
ac8737d103
```

**ManifestEnvelope (doc_type 24)** — ct = 0xEE placeholder; sig discipline as B.3 with doc_type 24

```
a6005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0
c0c0c0c001182a02581899999999999999999999999999999999999999999999
9999035840eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
eeeeeeeeee165820ed4928c628d1c2c6eae90338905995612959273a5c63f936
36c14614ac8737d11758409a09aef7dfe9e726ab600eddb756e5cbe4289d1918
ed71766259d2b2b7df9344f386c1c7d193273b8167e1524b4fb686186aedda07
7419c7e76542e8f018ee00
```

## B.9 Conformance for this appendix

An implementation is wire-conformant when it (1) byte-reproduces every §B.8
frame from the §B.7 inputs, (2) verifies every §B.8 signature via the B.3
re-encode rule, and (3) rejects each of: an indefinite-length item, a float,
an unknown map key, unsorted map keys, a non-shortest-form integer, and a
frame whose signature was computed over any encoding other than the
deterministic one.

Coverage is complete: **all 23 frame types** (B.8.1–B.8.23) and **all 4
documents** (B.8.24) have vectors, every signature generated with the fixed
§B.7 keys and machine-verified — including the nested cases (a signed
ContactCard inside FriendRequest/FriendAccept, and the dual-signed
Friendship, whose `a`/`b` ordering the vector fixes concretely: USER_B
sorts before USER_A bytewise). Two deliberate placeholders: HPKE
ciphertexts (`FileGrant.sealed[].ct`, `CeremonyShare.sealed`) and the
envelope AEAD `ct` are fixed `0xEE` bytes — opaque at the framing layer;
RFC 9180 and the AEAD RFCs carry their own vectors. The `DeleteAck.ref` is
a *real* BLAKE3 of the B.8.10 DeleteRequest payload, binding the two
vectors together. The `ShareGrant` vector embeds, verbatim, the worked
example share from **Chela SPEC §8.3** (`rsid 02C9`, "cactus float ghost
shine baby talk") — a cross-spec tie: a client that passes both documents'
vectors interoperates at the share-carrier boundary by construction.
`cbor_vectors.py` regenerates everything; treat it, not this file, as the
vector source of truth.

## B.10 Crypto primitive vectors (KDF tree, chunking, convergent seal)

These pin the §4 key tree, the §5 FastCDC chunker, and the §5 convergent seal
byte-for-byte, so an independent client can check its KDF, chunker, and seal
without any CBOR framing. Not generated by `cbor_vectors.py` (they are not CBOR
messages); pinned instead by the `carapace-crypto` `appendix_b_pins` tests,
which are the source of truth and reproduce every value below.

**Deterministic buffer fill.** Where a vector needs a pseudo-random buffer it is
filled by **BLAKE3 in extendable-output (XOF) mode** over an ASCII seed string —
`buf = BLAKE3-XOF(seed)[0:N]`. Any conformant BLAKE3 reproduces it exactly; no
shared PRNG is assumed.

### B.10.1 KDF tree — `K_root = 00×32`, `vid = c0×32`

Empty-salt HKDF-SHA-256 (`Hkdf::new(None, ikm)`) with the exact §4 `info`
strings. Inputs: `K_root` = the 32 zero bytes, `vid` = `c0` repeated 32 times.

```
K_vaultroot(vid) = 92d90be86652064e1c52a1749cbdaccd6a94d24e9cccdb0dcfec38e7165517c6
K_content(vid)   = f545200aa775f683c955d9123468b87e5405b962ffd69c7ac3bfe87279172192
K_manifest(vid)  = 6bfe69d0e457994892e0e95919947398aa80427f09abae3caf02700c5b4fe775
K_audit(vid)     = 6f05d55b61a919442b9e8551e2cbd37f37634a1047c47bd5e62b77a6648d0689
K_userid         = 956dc4696762c4c1aa2d3bfd5e7fcb3b384c6bec47e43dafa73e11e2170f235c
K_disclose       = a6bf0efac0cbf63b32c00cb9f5e2ac601a259a95ced890192b082cd8dcc802c0
```

`K_vaultroot` uses `info = "carapace/v1/vault/" ‖ vid`; `K_content`/`K_manifest`/
`K_audit` derive from `K_vaultroot` with `info = "content"`/`"manifest"`/`"por"`;
`K_userid`/`K_disclose` derive from `K_root` with `info =
"carapace/v1/user-identity"`/`"carapace/v1/disclosure"`.

### B.10.2 Chunk boundaries — FastCDC v2016, Gear, Normalization Level 1

Input: `buf = BLAKE3-XOF("carapace/v1/fastcdc-test-vector")[0 : 8·1024·1024]` (8
MiB). Params MIN 256 KiB / AVG 1 MiB / MAX 4 MiB, **Normalization Level 1** (the
value this vector pins). Cut points `(offset, length)`, in order:

```
( 0,       2017596)
( 2017596,  415201)
( 2432797, 1562602)
( 3995399, 1116653)
( 5112052,  769948)
( 5882000, 1032702)
( 6914702,  818610)
( 7733312,  655296)
```

8 chunks; contiguous (each offset = the previous offset+length) and covering the
full 8388608 bytes. A chunker that reproduces this list matches Carapace dedup; a
different variant or normalization level will not.

### B.10.3 Convergent seal — `K_content = 11×32`, `vid = c0×32`, 64-byte plaintext

Inputs: `K_content` = `11` repeated 32 times, `vid` = `c0` repeated 32 times,
`plaintext` = the 64 bytes `00 01 02 … 3f`. The full §5 pipeline:

```
pt_hash   = BLAKE3(plaintext)
          = 4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98
chunk_key = HKDF(K_content, "chunk-key"   ‖ pt_hash)
          = d5518b9b9091ba13696dee33fe2d10054b3cbf414847c9b9efe5d7645745c4c1
nonce     = HKDF(K_content, "chunk-nonce" ‖ pt_hash)[0:24]
          = 24043a8b48396741746260c1c4d02dc6a8380e3dac02488a
C         = XChaCha20-Poly1305(chunk_key, nonce, plaintext, aad = vid)   # 80 bytes
          = a3760f56f5ef0ff11e8c630e96c9968ec9cf7d86f4f9ab93e9c5bcd680c15f7e
            af4f9e7626aa467153d9e93420ebcab39d3fc67e4eb8786d4526770731454155
            55b00319b262a208310acfafe7f396c1
ChunkID   = BLAKE3-256(C)
          = 344368f7a16c3a40a851be8917f174f84b362c8376c998b9bd1eec87b88db7e1
```

`C` is 80 bytes = 64 plaintext + 16 Poly1305 tag; `ChunkID` is the iroh blob
hash. A client that reproduces `C` and `ChunkID` from the three inputs
implements the convergent seal identically.
