//! The addresses of the host whose network the fence is run on, read from the kernel's
//! own tables: every IPv4 address it answers on as its own, and every IPv6 address any of
//! its interfaces holds.
//!
//! lemonfiber runs `fence addresses` once on the host's network, with every capability
//! dropped, to learn the addresses it hands each fence. What is printed is each address
//! once, one to a line, in order.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where the kernel lists its IPv4 routing tables, each address it holds marked local.
pub const FIB_TRIE: &str = "/proc/net/fib_trie";

/// Where the kernel lists every IPv6 address its interfaces hold.
pub const IF_INET6: &str = "/proc/net/if_inet6";

/// What a leaf of the IPv4 tables begins with, before its address.
const LEAF: &str = "|-- ";

/// The scope and type the line under a leaf ends with where the address is the host's own.
const LOCAL: &str = " host LOCAL";

/// The hexadecimal digits the kernel writes an IPv6 address in.
const IPV6_DIGITS: usize = 32;

/// Every address `fib_trie` marks as the host's own, and every address `if_inet6` lists,
/// each once and in order.
///
/// # Errors
///
/// Naming the first line of `if_inet6` that does not begin with an address, or where
/// neither holds any address: an answer lemonfiber would hand on has to be one it can
/// trust whole.
pub fn read(fib_trie: &str, if_inet6: Option<&str>) -> Result<Vec<IpAddr>, String> {
    let mut held: BTreeSet<IpAddr> = local_v4(fib_trie).into_iter().map(IpAddr::V4).collect();
    for line in if_inet6.unwrap_or_default().lines() {
        held.insert(IpAddr::V6(v6(line)?));
    }
    if held.is_empty() {
        return Err("the host's tables hold no address of its own".to_owned());
    }
    Ok(held.into_iter().collect())
}

/// The host's addresses, as `reading` answers for [`FIB_TRIE`] and [`IF_INET6`]: a host
/// with no IPv6 has no `IF_INET6`, and that is no address rather than a failure.
///
/// # Errors
///
/// Where either cannot be read for any other reason, or as [`read`] refuses what they
/// hold.
pub fn asked(reading: impl Fn(&str) -> std::io::Result<String>) -> Result<Vec<IpAddr>, String> {
    let fib_trie =
        reading(FIB_TRIE).map_err(|why| format!("{FIB_TRIE} could not be read: {why}"))?;
    let if_inet6 = match reading(IF_INET6) {
        Ok(text) => Some(text),
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => None,
        Err(why) => return Err(format!("{IF_INET6} could not be read: {why}")),
    };
    read(&fib_trie, if_inet6.as_deref())
}

/// Each address a leaf of `fib_trie` holds whose next line marks it the host's own, but
/// the unspecified one, which a table can mark local and no connection can reach.
fn local_v4(fib_trie: &str) -> Vec<Ipv4Addr> {
    let lines: Vec<&str> = fib_trie.lines().map(str::trim).collect();
    lines
        .windows(2)
        .filter_map(|pair| match pair {
            [leaf, marked] if marked.ends_with(LOCAL) => leaf.strip_prefix(LEAF)?.parse().ok(),
            _ => None,
        })
        .filter(|address: &Ipv4Addr| !address.is_unspecified())
        .collect()
}

/// The address `line` of `if_inet6` begins with.
fn v6(line: &str) -> Result<Ipv6Addr, String> {
    let digits = line.split_whitespace().next().unwrap_or_default();
    if digits.len() != IPV6_DIGITS {
        return Err(format!("{line:?} does not begin with an IPv6 address"));
    }
    u128::from_str_radix(digits, 16)
        .map(Ipv6Addr::from)
        .map_err(|_| format!("{line:?} does not begin with an IPv6 address"))
}

#[cfg(test)]
mod tests;
