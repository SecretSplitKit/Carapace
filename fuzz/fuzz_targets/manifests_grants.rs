#![no_main]

use carapace_wire::{GrantBody, Manifest, ManifestEnvelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Manifest::from_bytes(data);
    let _ = ManifestEnvelope::from_bytes(data);
    let _ = GrantBody::from_bytes(data);
    let _ = carapace_disclose::DisclosureTable::from_bytes(data);
});
