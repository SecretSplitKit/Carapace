//! Appendix B conformance: byte-reproduce every §B.8 golden vector from the
//! §B.7 fixed inputs (B.9.1), verify every signature via the re-encode rule
//! (B.9.2), and reject each non-canonical form (B.9.3).

use carapace_wire::messages::*;
use carapace_wire::value::{decode, Map, Value};
use carapace_wire::Error;
use ed25519_dalek::{Signer, SigningKey};

// ---------------- B.7 fixed test material -------------------------------

const T0: u64 = 1_767_225_600;
const YEAR: u64 = 31_536_000;

fn sk(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}
fn pk(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn rep<const N: usize>(b: u8) -> [u8; N] {
    [b; N]
}

fn assert_frame(golden: &str, got: Vec<u8>) {
    assert_eq!(golden, hex::encode(&got), "frame byte mismatch");
}

fn card_a() -> ContactCard {
    let user_a = sk(0x01);
    let node_a1 = pk(&sk(0x03));
    let node = NodeEntry {
        node_id: node_a1,
        deleg: sign_delegation(&user_a, &node_a1, T0 + YEAR),
        not_after: T0 + YEAR,
        addrs: vec!["192.0.2.10:7400".into()],
        relay_url: Some("relay.example.net:443".into()),
    };
    let mut card = ContactCard {
        user: pk(&user_a),
        display: "AtHeart".into(),
        enc_pub: rep(0x05),
        nodes: vec![node],
        offers: Offers {
            storage_bytes: 10_737_418_240,
            relay: true,
            trustee: true,
        },
        version: 7,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(&user_a);
    card
}

fn card_b() -> ContactCard {
    let user_b = sk(0x02);
    let node_b1 = pk(&sk(0x04));
    let node = NodeEntry {
        node_id: node_b1,
        deleg: sign_delegation(&user_b, &node_b1, T0 + YEAR),
        not_after: T0 + YEAR,
        addrs: vec!["198.51.100.7:7400".into()],
        relay_url: None,
    };
    let mut card = ContactCard {
        user: pk(&user_b),
        display: "UserB".into(),
        enc_pub: rep(0x08),
        nodes: vec![node],
        offers: Offers {
            storage_bytes: 5_368_709_120,
            relay: false,
            trustee: true,
        },
        version: 3,
        by: [0; 32],
        sig: [0; 64],
    };
    card.sign(&user_b);
    card
}

const CHELA_SHARE_JSON: &str = concat!(
    r#"{"type":"chela.share","card_code":"CHELA-02C9-5-2-3-6","#,
    r#""recovery_set_id":"02C9","card_number":5,"threshold":2,"total":3,"#,
    r#""word_count":6,"scheme":"bip39-wordlist","payload_kind":"text","#,
    r#""words":["cactus","float","ghost","shine","baby","talk"]}"#
);

// ================= B.9.1 + B.9.2: reproduce & verify =====================

#[test]
fn b8_1_hello() {
    let m = Hello {
        protocol: 1,
        card_version: 7,
        roles: 0b111,
    };
    assert_frame("000000098201a3000101070207", m.encode_frame());
    // round-trips
    assert_eq!(m, Hello::decode_frame(&m.encode_frame()).unwrap());
}

#[test]
fn b8_2_ceremony_abort() {
    let user_a = sk(0x01);
    let mut m = CeremonyAbort {
        ceremony_id: rep(0xA0),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&user_a);
    assert_frame(
        "0000007b8215a30050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a01658208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c17584031da69180840d4ed14c28b2909447807606af8e61e3f51c7d4840427bf490a4e8ff9c362d25be5e24bb2b1a5bfaf47dd5f5efe61909717a84e70c53ee192010c",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_3_contact_card() {
    let m = card_a();
    assert_frame(
        "000001628202a80058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01674174486561727402582005050505050505050505050505050505050505050505050505050505050505050381a5005820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1015840485ff570b5fc2c8d68074e514d98c04e9312363ae19b6ac6c90b3c163f0323b91a3301cc6a6883979931bf5a11fad8252fe46c32994ce48c50a588c64bbda504021a6b36ec8003816f3139322e302e322e31303a37343030047572656c61792e6578616d706c652e6e65743a34343304a3001b000000028000000001f502f505071658208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c175840d49e2be24f9469dfeca6d4aabb647b1167385004f6913bc214ee16d2ba72caeb29921c7a33cb023ae08ddb94d0911732287634194719448cc8ca1dcf48adfa04",
        m.encode_frame(),
    );
    m.verify().unwrap();
    assert_eq!(m, ContactCard::decode_frame(&m.encode_frame()).unwrap());
}

#[test]
fn b8_4_vault_announce() {
    let node_a1 = sk(0x03);
    let mut m = VaultAnnounce {
        vid: rep(0xC0),
        epoch: 42,
        replicas: vec![pk(&sk(0x04))],
        digest: rep(0xD0),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "000000d68208a6005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a02815820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c035820d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d117584098d70de83d73a3ad022c8a77a4dd3cb755d16cc32de88191949c87adc0d2330f712a9cb1931e7aacfe829d07787605c30cdcf0c8e96af161700edb9d6c78db0c",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_5_share_attestation() {
    let node_b1 = sk(0x04);
    let mut m = ShareAttestation {
        subject: pk(&sk(0x01)),
        rsid: 0x02C9,
        card_number: 5,
        nonce: rep(0xB0),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000000a4820ea60058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c011902c902050350b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c17584053e1da91761449cfe6df6e24e6457ed0d7c3cb3d274d6be00a479e1b546f45da4585ba75ce3524cec5f362c49948d8dbc8680d11c60ed97e73edfc258408760f",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_6_friendship_end() {
    let node_a1 = sk(0x03);
    let mut m = FriendshipEnd {
        user: pk(&sk(0x02)),
        ts: T0,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "000000928205a40058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394011a6955b900165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d11758404438dc88fbf8e5d6ee2a2f72dea2b37e2dd2ce38ca1279dd56f586c92f4c54eebbe78dfa1b6d988bdc3d3cc4039021ffa3537fac5735e38aaf4d01d5ba205b06",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_7_invite_ticket() {
    let user_a = sk(0x01);
    let mut m = InviteTicket {
        user: pk(&user_a),
        node: pk(&sk(0x03)),
        addrs: vec!["192.0.2.10:7400".into()],
        relay_urls: vec!["relay.example.net:443".into()],
        token: rep(0xE0),
        expires: T0 + 604_800,
        sig: [0; 64],
    };
    m.sign(&user_a);
    assert_frame(
        "000000ce8217a70058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d102816f3139322e302e322e31303a3734303003817572656c61792e6578616d706c652e6e65743a3434330450e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0051a695ef3801758408b60451bc8e104bc219db807ff345e9fdd565a6f2c09b3bb4dbd98864f451762272bb3555dd35ac47558424cf78fe00deb791b1e05360617e41e539d50c3e503",
        m.encode_frame(),
    );
    m.verify().unwrap();
    assert_eq!(
        m.uri(),
        "carapace:qil2oacyecfiry65oqe7dfp5klns2pf2lvzmuzyjx4ozieq36n2iqanub5xvyakyedwuskggfdi4frxk5ebtreczsvqsswjhhjogh6jwg3aumffmq435caubn4ytsmrogaxdelrrga5donbqgabyc5lsmvwgc6jomv4gc3lqnrss43tfoq5dinbtariobyha4dqobyha4dqobyha4dqoabi2nfpphaaxlbaiwycfdpeocbf4ego3qb77grpj7xkwljxsycntxng33gegj5croyrhfozvkxotllchkwccjt3y7yan5n4rwhqfgydbpza6koovbq7fam"
    );
}

#[test]
fn b8_8_friend_request() {
    let node_b1 = sk(0x04);
    let mut m = FriendRequest {
        token: rep(0xE0),
        card: card_b(),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000001c78203a40050e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e001a80058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940165557365724202582008080808080808080808080808080808080808080808080808080808080808080381a5005820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0158400c175a09882a78847927eb4681f14015f8106be9e3e6dcde66da9f337ee9446e4f40a271b81fa772abcc1be499573db7970de86fff0020eecb34c932a6a4ee0b021a6b36ec800381713139382e35312e3130302e373a3734303004f604a3001b000000014000000001f402f505031658208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394175840b1cc162b3315b2520f220f4442762c210d902627c28c4fd227056a86a59abd18ad3f2ef451c66a1ba6e96869539ea638449c243f49d8afe80bc5faebd9074201165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c1758409b9fb465ee6a466ce96e6a4e51b2d903bb15eb4f19ab036d192d994bb601b0cb1f309711692ad9794fe45eab0992ce9966d236056c6f145e13959184353c7401",
        m.encode_frame(),
    );
    m.verify().unwrap();
    m.card.verify().unwrap();
}

#[test]
fn b8_9_friend_accept() {
    let user_a = sk(0x01);
    let user_b = sk(0x02);
    let node_a1 = sk(0x03);
    let friendship = Friendship::create(&user_a, &user_b, T0);
    // a = USER_B, b = USER_A by bytewise sort.
    assert_eq!(friendship.a, pk(&user_b));
    assert_eq!(friendship.b, pk(&user_a));
    let mut m = FriendAccept {
        card: card_a(),
        friendship,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "0000029e8204a400a80058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01674174486561727402582005050505050505050505050505050505050505050505050505050505050505050381a5005820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1015840485ff570b5fc2c8d68074e514d98c04e9312363ae19b6ac6c90b3c163f0323b91a3301cc6a6883979931bf5a11fad8252fe46c32994ce48c50a588c64bbda504021a6b36ec8003816f3139322e302e322e31303a37343030047572656c61792e6578616d706c652e6e65743a34343304a3001b000000028000000001f502f505071658208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c175840d49e2be24f9469dfeca6d4aabb647b1167385004f6913bc214ee16d2ba72caeb29921c7a33cb023ae08ddb94d0911732287634194719448cc8ca1dcf48adfa0401a50058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c021a6955b90003584054adbcbdf4b4d9b1b403e481dac5fb51f30d5bd31a023909fde78361e1bcacdb4bb3aa1e4e39196947376ef1385c3b4f905f030d5174b32f8e77224bf4c49204045840748d76e5312c306b7c2e327bec74663f52ebfb17cffb1ac3cbc5f3b89b2b071de77cdef112ce0815df3f0207c6c9302f96f11930b02e7914f88171a3bfc24a02165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1175840588fe9445deb9d7e88f64eb4e180a90c28ea7c52dd7d2563e3f2d29d8dbf8c1204cf8fa5015fe450457d7b9173d149e57329c09b90d72da8805117537f8bae00",
        m.encode_frame(),
    );
    m.verify().unwrap();
    m.card.verify().unwrap();
    m.friendship.verify().unwrap();
}

#[test]
fn b8_10_delete_request() {
    let node_a1 = sk(0x03);
    let mut m = DeleteRequest {
        scope: 0,
        vid: Some(rep(0xC0)),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "0000008e8206a40000015820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d117584033f7c73152f90eb53ca324268e2d07ffb9754e05937002e118d0368152f9b96b7c9a2dd09150b19e740669f6b6ef0ae10c8d6bbcf231e535bdc65c3ff94ec30a",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_11_delete_ack() {
    let node_a1 = sk(0x03);
    let node_b1 = sk(0x04);
    // ref = BLAKE3 of the B.8.10 DeleteRequest payload (frame minus length).
    let mut req = DeleteRequest {
        scope: 0,
        vid: Some(rep(0xC0)),
        by: [0; 32],
        sig: [0; 64],
    };
    req.sign(&node_a1);
    let payload = &req.encode_frame()[4..];
    let reference = *blake3::hash(payload).as_bytes();
    let mut m = DeleteAck {
        reference,
        ts: T0,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000000928207a4005820c59bd17212732dcc524e6abe0e56929bd30840783a6d91945958a176047c8d57011a6955b900165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c175840fa186e53c2f810280178ed1905c757a588cd05046f80e65d765b499d6a89c07d48a9f0017b900ab27307e14291647f096ca4787ea5f4e8a58c77e73e965ea40d",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_12_manifest_offer() {
    let node_a1 = sk(0x03);
    let mut m = ManifestOffer {
        vid: rep(0xC0),
        epoch: 42,
        digest: rep(0xD0),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "000000b28209a5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a025820d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d117584024486e534a2240261f8c4bb6e457416daef356c2a5d6e3e6bdfd6af121f3d58e4d9d6e6e3fcec97f0c3904f3e5528b9a8a89c61522ae3498709fc7c6efb5ef0b",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_13_replica_invite() {
    let node_a1 = sk(0x03);
    let mut m = ReplicaInvite {
        vid: rep(0xC0),
        epoch: 42,
        approx_bytes: 1_073_741_824,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "00000095820aa5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a021a40000000165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1175840a0da16973f2412e13795cacc3e30beac5f1be3546295ef59b770eeb345c7b6bfe3b9929123b3eb62eb2c47c588bab0d116133c8979424aed5bd6fd653c9edf0e",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_14_replica_accept() {
    let node_b1 = sk(0x04);
    let mut m = ReplicaAccept {
        vid: rep(0xC0),
        quota_bytes: 2_147_483_648,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "00000092820ba4005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0011a80000000165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c1758403efe09ef1b654fd281542395c261569a9e005a20d75bc6d83202f78a1268b7911017c35597bef221e4ffd95535fa6e30d70c44cd159e7dc171816752ca9f6508",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_15_share_grant() {
    let node_a1 = sk(0x03);
    let mut m = ShareGrant {
        subject: pk(&sk(0x01)),
        share_json: CHELA_SHARE_JSON.into(),
        recovery_delay: 259_200,
        cotrustees: vec![CoTrustee {
            user: pk(&sk(0x02)),
            node: pk(&sk(0x04)),
            relay_url: Some("relay.example.net:443".into()),
        }],
        refs: vec![AnnounceRef {
            vid: rep(0xC0),
            epoch: 42,
            digest: rep(0xD0),
        }],
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "00000231820ca70058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0178f07b2274797065223a226368656c612e7368617265222c22636172645f636f6465223a224348454c412d303243392d352d322d332d36222c227265636f766572795f7365745f6964223a2230324339222c22636172645f6e756d626572223a352c227468726573686f6c64223a322c22746f74616c223a332c22776f72645f636f756e74223a362c22736368656d65223a2262697033392d776f72646c697374222c227061796c6f61645f6b696e64223a2274657874222c22776f726473223a5b22636163747573222c22666c6f6174222c2267686f7374222c227368696e65222c2262616279222c2274616c6b225d7d021a0003f4800381a30058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394015820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c027572656c61792e6578616d706c652e6e65743a3434330481a3005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a025820d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1175840613c0b1653c908d1572b5e61c272c46f0aeb7ec24e6eb9bf9b05bd8c51ef9bf4f1136338fe8edf262848c018f5634ec1e46d1c9d4b23f26a0adc0992b8b03d02",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_16_share_attest_challenge() {
    let node_a1 = sk(0x03);
    let mut m = ShareAttestChallenge {
        subject: pk(&sk(0x01)),
        rsid: 0x02C9,
        nonce: rep(0xB0),
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "000000a2820da50058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c011902c90250b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1175840b584c05fd5ed01388139f1b212265615a61e996e12bbd8ee0f65c2840a3d7262ee5731905c3fb556f9c5afb7413597b91fed8655801c08f9cfd1e7d3c4f0b00f",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_17_share_destroy() {
    let node_a1 = sk(0x03);
    let mut m = ShareDestroy {
        subject: pk(&sk(0x01)),
        rsid: 0x02C9,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "00000090820fa40058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c011902c9165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d11758406b581bbff910d447df4bb5d199f9d46eb4c58481f7d7133c4eb0be86905acd0984f3f4a8049c518dd3140188273942d922a6d225cd9a2df2a989177be4642e04",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_18_share_destroy_ack() {
    let node_b1 = sk(0x04);
    let mut m = ShareDestroyAck {
        subject: pk(&sk(0x01)),
        rsid: 0x02C9,
        ts: T0,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000000968210a50058208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c011902c9021a6955b900165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c1758409173c66cf3e3c3f623fc0a3c478259bb8dd83daee1d37b9ad334413f9bc3d7667cdeec423d8df3b5c3ad795eb3aa0fc9571e022baf842b4a871dc54681654d08",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_19_file_grant() {
    let node_a1 = sk(0x03);
    let mut m = FileGrant {
        grant_id: rep(0x90),
        vid: rep(0xC0),
        epoch: 42,
        audience: vec![pk(&sk(0x02))],
        sealed: vec![Sealed {
            to: pk(&sk(0x02)),
            ct: vec![0xEE; 48],
        }],
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "0000011e8211a7005090909090909090909090909090909090015820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c002182a038158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940481a20058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394015830eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d11758401a167632482c5f46cc63acaaba34fdd2ad36193d9e118c668b4b9c8fd82705a41ae33947b647cd98115f7e225e72af861517c6b76243167d7d95276a251b580b",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_20_audit_notice() {
    let node_a1 = sk(0x03);
    let mut m = AuditNotice {
        vid: rep(0xC0),
        code: 1,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_a1);
    assert_frame(
        "0000008e8212a4005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00101165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1175840bfdf67136920696baea7f54b20de69d3f0fc6728b75ca06c6a5537a8ab85f7afd9fb44b0e7851b3f105f68b15465b70b813ebae0005a0e78b9ed40f5d8ba570a",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_21_recovery_open() {
    let node_b1 = sk(0x04);
    let mut m = RecoveryOpen {
        ceremony_id: rep(0xA0),
        subject: pk(&sk(0x01)),
        rsid: 0x02C9,
        claimant_display: "Heir of A".into(),
        ceremony_enc: rep(0x06),
        new_node: rep(0x07),
        reason: "device lost".into(),
        opened_at: T0,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000001068213aa0050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c021902c9036948656972206f66204104582006060606060606060606060606060606060606060606060606060606060606060558200707070707070707070707070707070707070707070707070707070707070707066b646576696365206c6f7374071a6955b900165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c17584009387f49a6e037fa018b53c379df96259c4ee89204a81f8a7d55a4da412dea0757880ed639f8d748fc0610bc9b5abf00d9f3e5c249b5404dd59c4f3016c05202",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_22_ceremony_approve() {
    let node_b1 = sk(0x04);
    let mut m = CeremonyApprove {
        ceremony_id: rep(0xA0),
        ts: T0 + 3600,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000000818214a40050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0011a6955c710165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c175840056ae598adf4964c920a39aa294f804f64ccf7d357d1fbe2afe25741d77e6be1b5ffe00dd703dee1324d17b3233c7a9064e5f63076c9ce05fb98701b81870801",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

#[test]
fn b8_23_ceremony_share() {
    let node_b1 = sk(0x04);
    let mut m = CeremonyShare {
        ceremony_id: rep(0xA0),
        sealed: vec![0xEE; 48],
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&node_b1);
    assert_frame(
        "000000ae8216a40050a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0015830eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee165820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c17584068047fcb207c3312490947b5b98e28bb1dca0c103614957d8689038178e94acdda8aa8287762796a1b44d2f52e3ab615fa8c58fdc3cde6ea4e9ce5b22163850b",
        m.encode_frame(),
    );
    m.verify().unwrap();
}

// ---------------- B.8.24 documents (bare) --------------------------------

#[test]
fn b8_24_friendship_doc() {
    let user_a = sk(0x01);
    let user_b = sk(0x02);
    let fr = Friendship::create(&user_a, &user_b, T0);
    assert_eq!(
        "a50058208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c021a6955b90003584054adbcbdf4b4d9b1b403e481dac5fb51f30d5bd31a023909fde78361e1bcacdb4bb3aa1e4e39196947376ef1385c3b4f905f030d5174b32f8e77224bf4c49204045840748d76e5312c306b7c2e327bec74663f52ebfb17cffb1ac3cbc5f3b89b2b071de77cdef112ce0815df3f0207c6c9302f96f11930b02e7914f88171a3bfc24a02",
        hex::encode(fr.to_bytes())
    );
    fr.verify().unwrap();
    assert_eq!(fr, Friendship::from_bytes(&fr.to_bytes()).unwrap());
}

#[test]
fn b8_24_grant_body_doc() {
    let g = GrantBody {
        files: vec![GrantFile {
            path: "notes/plan.txt".into(),
            file_hash: rep(0xAA),
            size: 1234,
            chunks: vec![GrantChunk {
                chunk_id: rep(0xC1),
                chunk_key: rep(0x77),
                nonce: rep(0x88),
                len: 1234,
            }],
        }],
    };
    assert_eq!(
        "a10081a4006e6e6f7465732f706c616e2e747874015820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa021904d20381a4005820c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c10158207777777777777777777777777777777777777777777777777777777777777777025818888888888888888888888888888888888888888888888888031904d2",
        hex::encode(g.to_bytes())
    );
    assert_eq!(g, GrantBody::from_bytes(&g.to_bytes()).unwrap());
}

#[test]
fn b8_24_manifest_doc() {
    let node_a1 = pk(&sk(0x03));
    let m = Manifest {
        vid: rep(0xC0),
        epoch: 42,
        authors: vec![pk(&sk(0x01))],
        files: vec![FileEntry {
            path: "notes/plan.txt".into(),
            mode: 33188,
            mtime: T0,
            size: 1234,
            chunks: vec![(rep(0xC1), rep(0xB1), 1234)],
            file_hash: rep(0xAA),
            version: vec![(node_a1, 3)],
            deleted: false,
        }],
        vv: vec![(node_a1, 3)],
    };
    assert_eq!(
        "a5005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a028158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0381a8006e6e6f7465732f706c616e2e747874011981a4021a6955b900031904d20481a3005820c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1015820b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1021904d2055820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa06a15820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10307f404a15820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d103",
        hex::encode(m.to_bytes())
    );
    assert_eq!(m, Manifest::from_bytes(&m.to_bytes()).unwrap());
}

#[test]
fn b8_24_manifest_envelope_doc() {
    let node_a1 = sk(0x03);
    let mut env = ManifestEnvelope {
        vid: rep(0xC0),
        epoch: 42,
        nonce: rep(0x99),
        ct: vec![0xEE; 64],
        by: [0; 32],
        sig: [0; 64],
    };
    env.sign(&node_a1);
    assert_eq!(
        "a6005820c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001182a025818999999999999999999999999999999999999999999999999035840eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee165820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d11758409a09aef7dfe9e726ab600eddb756e5cbe4289d1918ed71766259d2b2b7df9344f386c1c7d193273b8167e1524b4fb686186aedda077419c7e76542e8f018ee00",
        hex::encode(env.to_bytes())
    );
    env.verify().unwrap();
    assert_eq!(env, ManifestEnvelope::from_bytes(&env.to_bytes()).unwrap());
}

// ================= B.9.3: reject every non-canonical form ================

#[test]
fn reject_indefinite_length() {
    // 0x9f .. 0xff = indefinite-length array.
    assert_eq!(decode(&[0x9f, 0xff]), Err(Error::IndefiniteLength));
    // indefinite-length byte string 0x5f .. 0xff.
    assert_eq!(decode(&[0x5f, 0xff]), Err(Error::IndefiniteLength));
}

#[test]
fn reject_float() {
    // 0xfa 00000000 = single-precision float 0.0.
    assert_eq!(decode(&[0xfa, 0x00, 0x00, 0x00, 0x00]), Err(Error::Float));
    // 0xfb .. = double.
    assert_eq!(decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Float));
    // 0xf9 .. = half.
    assert_eq!(decode(&[0xf9, 0, 0]), Err(Error::Float));
}

#[test]
fn reject_unknown_key() {
    // A Hello map with an extra key 3 must be rejected by the typed decoder.
    let mut body = Map::new();
    body.u(0, Value::Uint(1));
    body.u(1, Value::Uint(7));
    body.u(2, Value::Uint(7));
    body.u(3, Value::Uint(0));
    let f = frame(Hello::TYPE, &body);
    assert_eq!(Hello::decode_frame(&f), Err(Error::UnknownKey(3)));
}

#[test]
fn reject_unsorted_keys() {
    // map(2) with keys 1 then 0 (descending) — not strictly increasing.
    assert_eq!(
        decode(&[0xa2, 0x01, 0x07, 0x00, 0x01]),
        Err(Error::UnsortedMapKeys)
    );
    // duplicate key 0 also caught (equal, not strictly greater).
    assert_eq!(
        decode(&[0xa2, 0x00, 0x01, 0x00, 0x02]),
        Err(Error::UnsortedMapKeys)
    );
}

#[test]
fn reject_non_shortest_int() {
    // uint 23 encoded with a 1-byte argument (0x18 0x17): value < 24.
    assert_eq!(decode(&[0x18, 0x17]), Err(Error::NonCanonicalInt));
    // uint 255 encoded with a 2-byte argument: value < 0x100.
    assert_eq!(decode(&[0x19, 0x00, 0xff]), Err(Error::NonCanonicalInt));
    // uint 0 encoded with an 8-byte argument.
    assert_eq!(
        decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::NonCanonicalInt)
    );
}

#[test]
fn reject_negative_int_and_tag() {
    assert_eq!(decode(&[0x20]), Err(Error::NegativeInt)); // -1
    assert_eq!(decode(&[0xc0, 0x00]), Err(Error::Tag)); // tag 0
}

#[test]
fn reject_oversized_frame() {
    // Length header claims > 1 MiB.
    let mut bytes = ((MAX_PAYLOAD as u32) + 1).to_be_bytes().to_vec();
    bytes.push(0x00);
    assert_eq!(decode_frame(&bytes), Err(Error::Oversized));
}

#[test]
fn reject_sig_over_nondeterministic_encoding() {
    // Same logical CeremonyAbort body, but the signature is computed over a
    // NON-canonical CBOR encoding (map key 0 written as the 2-byte 0x18 0x00
    // instead of the shortest 0x00). Our verify() re-encodes deterministically,
    // so the signature must be rejected.
    let user_a = sk(0x01);
    let cid = rep::<16>(0xA0);
    let by = pk(&user_a);

    // Non-canonical: 0x82 0x15 (array2, type 21), 0xa2 (map2),
    //   key 0 as 0x1800 (non-shortest), value = cid,
    //   key 22 (0x16) as 0x5820 || by.
    let mut nc = Vec::new();
    nc.extend_from_slice(b"carapace-sig-v1");
    nc.extend_from_slice(&[0x82, 0x15, 0xa2, 0x18, 0x00, 0x50]);
    nc.extend_from_slice(&cid);
    nc.extend_from_slice(&[0x16, 0x58, 0x20]);
    nc.extend_from_slice(&by);
    let bad_sig = user_a.sign(&nc).to_bytes();

    // Sanity: that signature IS valid over the non-canonical bytes.
    user_a
        .verifying_key()
        .verify_strict(&nc, &ed25519_dalek::Signature::from_bytes(&bad_sig))
        .unwrap();

    let m = CeremonyAbort {
        ceremony_id: cid,
        by,
        sig: bad_sig,
    };
    assert_eq!(m.verify(), Err(Error::Signature));
}

// ---------------- extra: strict decode sanity ----------------------------

#[test]
fn frame_rejects_trailing_bytes() {
    let m = Hello {
        protocol: 1,
        card_version: 7,
        roles: 7,
    };
    let mut f = m.encode_frame();
    f.push(0xff);
    assert_eq!(decode_frame(&f), Err(Error::Truncated));
}

#[test]
fn wrong_type_rejected() {
    let m = Hello {
        protocol: 1,
        card_version: 7,
        roles: 7,
    };
    assert_eq!(
        CeremonyAbort::decode_frame(&m.encode_frame()),
        Err(Error::WrongType {
            expected: 21,
            got: 1
        })
    );
}

// ---------------- audit regressions --------------------------------------

// C1: a tower of nested single-element arrays (each 1 byte, 0x81) is far under
// the 1 MiB frame cap yet would recurse tens of thousands deep. The decoder
// must error (B.9: "must error, not panic"), never overflow the stack.
#[test]
fn reject_deeply_nested_value() {
    let mut deep = vec![0x81u8; 100_000];
    deep.push(0x00); // innermost value
    assert_eq!(decode(&deep), Err(Error::TooDeep));
}

#[test]
fn reject_deeply_nested_frame() {
    // Same attack through the network entry point.
    let mut payload = vec![0x81u8; 50_000];
    payload.push(0x00);
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    assert_eq!(decode_frame(&frame), Err(Error::TooDeep));
}

// The legitimate schemas nest only a handful of levels; a moderate, valid tower
// well within the cap still decodes so the depth guard isn't over-tight.
#[test]
fn accept_moderately_nested_value() {
    let mut deep = vec![0x81u8; 30];
    deep.push(0x00);
    assert!(decode(&deep).is_ok());
}

// S2: a length/count that cannot fit the remaining buffer must error rather
// than mis-decode. On 32-bit targets this also guards the `u64 as usize`
// truncation; on 64-bit it is caught before any allocation attempt.
#[test]
fn reject_length_exceeding_buffer() {
    // 0x5b = byte string, 8-byte length = 2^40, with no payload following.
    let b = [0x5b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(decode(&b), Err(Error::Truncated));
}

// W1: the outer node signature covers the embedded card *bytes* but not the
// card's own self-signature. `verify()` must recurse and reject a request that
// embeds a card with a broken self-signature (identity-spoof foot-gun).
#[test]
fn friend_request_rejects_unsigned_embedded_card() {
    let user_a = sk(0x01);
    let mut card = card_b(); // validly self-signed by USER_B...
    card.sig = [0xAA; 64]; // ...then its self-signature is broken.
    let mut m = FriendRequest {
        token: rep(0xE0),
        card,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&user_a); // outer signature is valid over the tampered card bytes
    assert_eq!(m.verify(), Err(Error::Signature));
}

#[test]
fn friend_accept_rejects_unsigned_embedded_objects() {
    let user_a = sk(0x01);
    let user_b = sk(0x02);
    let mut friendship = Friendship::create(&user_a, &user_b, T0);
    friendship.sig_b = [0xAA; 64]; // break one of the mutual signatures
    let mut m = FriendAccept {
        card: card_a(),
        friendship,
        by: [0; 32],
        sig: [0; 64],
    };
    m.sign(&user_a);
    assert_eq!(m.verify(), Err(Error::Signature));
}
