//! gh-restricted binary entry point

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    devaipod_upcalls::gh_restricted::run(args)
}
