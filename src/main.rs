//! The fence: it holds a fenced service's network namespace to rules refusing every
//! private address, and holds nothing else.
//!
//! Run with no arguments, it reads the host addresses it is handed, puts the rules in
//! place, reads them back, and then waits for as long as the namespace is wanted. It
//! exits where any of that fails, so the service written behind it never starts in a
//! namespace the rules do not hold. Run as `fence health`, it asks the kernel whether
//! the rules are still in force. Run as `fence addresses`, it prints the addresses of the
//! host whose network it is on and installs nothing.

mod addresses;
mod applying;
mod rules;

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => fence(),
        Some("health") => match applying::holding(&applying::NFT) {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("fence: {why}");
                ExitCode::FAILURE
            }
        },
        Some("addresses") => match addresses::asked(|path| std::fs::read_to_string(path)) {
            Ok(held) => {
                for address in held {
                    println!("{address}");
                }
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("fence: {why}");
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!(
                "fence: {other:?} is not a command; run it with none, with `health` or with \
                 `addresses`"
            );
            ExitCode::from(2)
        }
    }
}

/// Put the rules in place, then hold the namespace.
fn fence() -> ExitCode {
    let said = std::env::var(rules::HOST_ADDRESSES).ok();
    let hosts = match rules::host_addresses(said.as_deref()) {
        Ok(hosts) => hosts,
        Err(why) => {
            eprintln!("fence: {why}");
            return ExitCode::from(2);
        }
    };
    if let Err(why) = applying::applied(&applying::NFT, &rules::ruleset(&hosts)) {
        eprintln!("fence: {why}");
        return ExitCode::FAILURE;
    }
    eprintln!("fence: the namespace refuses every private address");
    loop {
        std::thread::park();
    }
}
