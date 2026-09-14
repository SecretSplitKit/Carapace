#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    let _ = carapace_restore::validate_path(path);

    let sizes: Vec<u64> = data
        .chunks(8)
        .take(1024)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(bytes)
        })
        .collect();
    let declared = sizes
        .iter()
        .fold(0u64, |sum, item| sum.saturating_add(*item));
    let _ = carapace_restore::checked_file_layout(path, declared, &sizes);
    let _ = carapace_restore::validate_operation([(path, declared)]);
});
