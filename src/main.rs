//! The fence: it holds a fenced service's network namespace to rules refusing every
//! private address, and holds nothing else.
//!
//! Run with no arguments, it reads the host addresses it is handed, puts the rules in
//! place, reads them back, and then waits for as long as the namespace is wanted. It
//! exits where any of that fails, so the service written behind it never starts in a
//! namespace the rules do not hold. Run as `fence health`, it asks the kernel whether
//! the rules are still in force. Run as `fence nftables`, it puts the same rules in place
//! under a table of its own, reads them back and takes them away again, and prints
//! `held` where all of that succeeded and why not where it did not. Run as `fence
//! addresses`, it prints the addresses of the host whose network it is on and installs
//! nothing. Run as `fence render-group`, it prints the id of the group owning the host's
//! render devices, or nothing where there are none, and installs nothing. Run as `fence
//! ask <method> <port> <path>`, it asks the service on `127.0.0.1` at that port, prints
//! its status, its `content-type` and its body, and installs nothing.

mod addresses;
mod applying;
mod ask;
mod render_group;
mod rules;

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => fence(),
        Some("health") => match applying::holding(&applying::NFT, rules::TABLE) {
            Ok(()) => ExitCode::SUCCESS,
            Err(why) => {
                eprintln!("fence: {why}");
                ExitCode::FAILURE
            }
        },
        Some("nftables") => match applying::probed(&applying::NFT) {
            Ok(()) => {
                println!("{}", applying::HELD);
                ExitCode::SUCCESS
            }
            Err(why) => {
                println!("{why}");
                ExitCode::FAILURE
            }
        },
        Some("addresses") => match addresses::asked(&|path| std::fs::read_to_string(path), &|| {
            listed(&addresses::IP)
        }) {
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
        Some("render-group") => match render_group::asked(&render_group::listed) {
            Ok(group) => {
                if let Some(group) = group {
                    println!("{group}");
                }
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("fence: {why}");
                ExitCode::FAILURE
            }
        },
        Some("ask") => {
            let given: Vec<String> = std::env::args().skip(2).collect();
            let answered = ask::named(
                given.first().map(String::as_str),
                given.get(1).map(String::as_str),
                given.get(2).map(String::as_str),
            )
            .and_then(|request| ask::asked(&request));
            match answered {
                Ok(answer) => {
                    let mut out = std::io::stdout().lock();
                    match std::io::Write::write_all(&mut out, &ask::printed(&answer)) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(_) => ExitCode::FAILURE,
                    }
                }
                Err(why) => {
                    eprintln!("fence: {why}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!(
                "fence: {other:?} is not a command; run it with none, with `health`, with \
                 `nftables`, with `addresses`, with `render-group` or with `ask`"
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
    if let Err(why) = applying::applied(
        &applying::NFT,
        rules::TABLE,
        &rules::ruleset(rules::TABLE, &hosts),
    ) {
        eprintln!("fence: {why}");
        return ExitCode::FAILURE;
    }
    eprintln!("fence: the namespace refuses every private address");
    loop {
        std::thread::park();
    }
}

/// What `program` wrote, where it ran and succeeded.
fn listed(program: &[&str]) -> Result<String, String> {
    let (name, args) = program.split_first().ok_or("no program was named")?;
    let output = std::process::Command::new(name)
        .args(args)
        .output()
        .map_err(|why| why.to_string())?;
    if !output.status.success() {
        return Err(format!("it exited {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|_| "it wrote what is not text".to_owned())
}
