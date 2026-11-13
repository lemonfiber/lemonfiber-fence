//! Putting the ruleset in place, asking whether it still holds, and asking whether a
//! namespace can hold it at all.
//!
//! The rules go in through `nft`, the one program the image carries beside the fence,
//! and are read back before the fence calls itself ready: a ruleset `nft` accepted and
//! the kernel does not hold is a fence that refuses nothing.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::rules::{ruleset, PROBE};

/// What running `nft` came to: whether it succeeded, and what it printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// Whether it exited zero.
    pub succeeded: bool,
    /// What it wrote to standard output.
    pub stdout: String,
    /// What it wrote to standard error.
    pub stderr: String,
}

/// Something that runs `nft` with these arguments and this input.
pub trait Nft {
    /// Run `nft` with `args`, handing it `input` on standard input.
    ///
    /// # Errors
    ///
    /// Why `nft` could not be run at all.
    fn run(&self, args: &[&str], input: &str) -> Result<Ran, String>;
}

/// A program run as `nft`: the one the image carries, by default.
pub struct Installed {
    /// The program, found on the path.
    pub program: &'static str,
}

/// The program the image carries.
pub const NFT: Installed = Installed { program: "nft" };

impl Nft for Installed {
    fn run(&self, args: &[&str], input: &str) -> Result<Ran, String> {
        let mut child = Command::new(self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(failed(self.program))?;
        let written = child
            .stdin
            .take()
            .map(|mut stdin| stdin.write_all(input.as_bytes()));
        written.transpose().map_err(failed(self.program))?;
        let output = child.wait_with_output().map_err(failed(self.program))?;
        Ok(Ran {
            succeeded: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// What running `program` came to where it could not be run, written, or waited on.
fn failed(program: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |why| format!("{program} could not be run: {why}")
}

/// What `fence nftables` prints where the namespace it ran in held the rules.
pub const HELD: &str = "held";

/// Put `rules` in place and read `table` back.
///
/// # Errors
///
/// Why the rules are not in force: `nft` could not run, refused the ruleset, or the
/// table is not there once it accepted it.
pub fn applied(nft: &dyn Nft, table: &str, rules: &str) -> Result<(), String> {
    let ran = nft.run(&["-f", "-"], rules)?;
    if !ran.succeeded {
        return Err(format!("nft refused the ruleset: {}", ran.stderr.trim()));
    }
    holding(nft, table)
}

/// Whether the namespace this runs in can hold the fence's rules: the fence's ruleset
/// put in place under [`PROBE`], read back, and taken away again.
///
/// # Errors
///
/// Why it cannot: `nft` could not run, refused the ruleset, the kernel does not list
/// what it accepted, or the table could not be taken away again.
pub fn probed(nft: &dyn Nft) -> Result<(), String> {
    applied(nft, PROBE, &ruleset(PROBE, &[]))?;
    let ran = nft.run(&["delete", "table", "inet", PROBE], "")?;
    if !ran.succeeded {
        return Err(format!(
            "the table {PROBE} could not be taken away again: {}",
            ran.stderr.trim()
        ));
    }
    Ok(())
}

/// What the kernel's listing of the fence's table holds while the rules are in force.
const IN_FORCE: [&str; 5] = [
    "set refused_v4",
    "set refused_v6",
    "chain output",
    "ip daddr @refused_v4 reject",
    "ip6 daddr @refused_v6 reject",
];

/// Whether `table` is in force, read from the kernel.
///
/// # Errors
///
/// Why it is not: `nft` could not run, the table is missing, or it lacks one of its
/// sets, its chain, or a rule refusing either set.
pub fn holding(nft: &dyn Nft, table: &str) -> Result<(), String> {
    let ran = nft.run(&["list", "table", "inet", table], "")?;
    if !ran.succeeded {
        return Err(format!(
            "the table {table} is not in force: {}",
            ran.stderr.trim()
        ));
    }
    match IN_FORCE.iter().find(|held| !ran.stdout.contains(*held)) {
        Some(missing) => Err(format!("the table {table} lacks {missing}")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
