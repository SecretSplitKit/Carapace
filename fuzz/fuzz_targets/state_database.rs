#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let db_path = dir.path().join("state.redb");
    if std::fs::write(&db_path, data).is_err() {
        return;
    }
    let state = carapaced::State::from_seeds_in(dir.path(), [0x11; 32], [0x22; 32]);
    let _ = carapaced::inspect_state_database(&state, &db_path);
});
