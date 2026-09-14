#![no_main]

use carapace_wire::{
    CeremonyAbort, CeremonyApprove, CeremonyShare, Message, RecoveryOpen, ShareGrant,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RecoveryOpen::decode_frame(data);
    let _ = CeremonyApprove::decode_frame(data);
    let _ = CeremonyAbort::decode_frame(data);
    let _ = CeremonyShare::decode_frame(data);
    let _ = ShareGrant::decode_frame(data);
    let _ = carapace_recovery::CeremonyState::from_bytes(data);
});
