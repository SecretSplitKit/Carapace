#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = carapace_wire::decode(data);
    let _ = carapace_wire::decode_frame(data);
});
