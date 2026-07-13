//! `carapace` CLI entry point. See `lib.rs` for the argument grammar and
//! `carapace-api`'s handlers for the request/response shapes this drives.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match carapace::run(&args) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("carapace: {e:#}");
            std::process::exit(1);
        }
    }
}
