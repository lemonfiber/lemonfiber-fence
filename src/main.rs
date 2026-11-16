//! The fence: it holds a service's network namespace to rules, and holds nothing else.
//!
//! Run with no arguments, it reads the host addresses it is handed, puts the rules
//! refusing every private address in place, reads them back, and then waits for as long
//! as the namespace is wanted. Run as `fence stack`, it does the same with the rules
//! passing only what is inside the stack's networks, read from the subnets and gateways
//! it is handed beside the host's addresses, and then answers the namespace's DNS
//! questions itself, passing on only those for the stack's names it is handed. It exits where any of that fails, so the
//! service written behind it never starts in a namespace the rules do not hold. Run as
//! `fence health`, it asks the kernel whether either ruleset is still in force whole. Run
//! as `fence nftables`, it puts the rules refusing every private address in place under a
//! table of its own, reads them back and takes them away again, and prints
//! `held` where all of that succeeded and why not where it did not. Run as `fence
//! addresses`, it prints the addresses of the host whose network it is on and installs
//! nothing. Run as `fence render-group`, it prints the id of the group owning the host's
//! render devices, or nothing where there are none, and installs nothing. Run as `fence
//! ask <method> <port> <path>`, it asks the service on `127.0.0.1` at that port, prints
//! its status, its `content-type` and its body, and installs nothing.

mod addresses;
mod applying;
mod ask;
mod names;
mod render_group;
mod resolving;
mod rules;

use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        None => fence(),
        Some("stack") => held_inside(),
        Some("health") => match applying::holding_either(&applying::NFT, rules::TABLE) {
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
                "fence: {other:?} is not a command; run it with none, with `stack`, with \
                 `health`, with `nftables`, with `addresses`, with `render-group` or with \
                 `ask`"
            );
            ExitCode::from(2)
        }
    }
}

/// Put the rules refusing every private address in place, then hold the namespace.
fn fence() -> ExitCode {
    match handed(rules::HOST_ADDRESSES).and_then(|said| rules::host_addresses(said.as_deref())) {
        Ok(hosts) => holding(
            &rules::ruleset(rules::TABLE, &hosts),
            applying::Held::Refusing,
            "the namespace refuses every private address",
        ),
        Err(why) => refused(&why),
    }
}

/// Put the rules passing only what is inside the stack's networks in place, then hold the
/// namespace.
fn held_inside() -> ExitCode {
    let hosts =
        handed(rules::HOST_ADDRESSES).and_then(|said| rules::host_addresses(said.as_deref()));
    let networks = handed(rules::NETWORKS).and_then(|said| rules::networks(said.as_deref()));
    let names = handed(names::NAMES).and_then(|said| names::names(said.as_deref()));
    match hosts.and_then(|hosts| Ok((hosts, networks?, names?))) {
        Ok((hosts, networks, names)) => {
            if let Err(why) = applying::applied(
                &applying::NFT,
                rules::TABLE,
                &rules::within(rules::TABLE, &networks, &hosts),
                applying::Held::Inside,
            ) {
                eprintln!("fence: {why}");
                return ExitCode::FAILURE;
            }
            eprintln!(
                "fence: the namespace reaches nothing outside the stack's networks, and \
                 resolves only the stack's names"
            );
            let Err(why) = resolving::answering(resolving::ANSWERING, names);
            eprintln!("fence: cannot answer on {}: {why}", resolving::ANSWERING);
            ExitCode::FAILURE
        }
        Err(why) => refused(&why),
    }
}

/// What the setting `name` holds, where it is set.
///
/// # Errors
///
/// Where it is set to what is not text.
fn handed(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(said) => Ok(Some(said)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not text")),
    }
}

/// Say why the fence does not start, and end with the exit of a fence handed what it
/// cannot read.
fn refused(why: &str) -> ExitCode {
    eprintln!("fence: {why}");
    ExitCode::from(2)
}

/// Put `ruleset` in place as `held` holds it, say `said` once it is, and hold the
/// namespace.
fn holding(ruleset: &str, held: applying::Held, said: &str) -> ExitCode {
    if let Err(why) = applying::applied(&applying::NFT, rules::TABLE, ruleset, held) {
        eprintln!("fence: {why}");
        return ExitCode::FAILURE;
    }
    eprintln!("fence: {said}");
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
