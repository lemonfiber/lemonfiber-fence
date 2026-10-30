//! The addresses of the host whose network the fence is run on, read twice and held to
//! agree: once from the kernel's own tables, every IPv4 address any routing table marks
//! local and every IPv6 address an interface holds, and once as `ip -o addr` lists the
//! addresses of every interface. Either answer alone could miss an address the other
//! holds, and an address missed is one the fence would let a fenced service reach, so
//! where the two differ, or either holds a line this does not read, nothing is answered.
//!
//! A local route covering a whole range is held to lie inside a range the fence refuses
//! anyway, since the fence is handed addresses and not ranges. The one exception is a
//! local route covering every address in a table of its own: that is policy routing
//! handing what it marks to a transparent proxy, not an address the host holds, and the
//! fence refusing it would refuse every address there is.
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

/// The program listing every interface's addresses, one to a line.
pub const IP: [&str; 3] = ["/sbin/ip", "-o", "addr"];

/// What a node of the IPv4 tables begins with, before the prefix it covers.
const NODE: &str = "+-- ";

/// What a leaf of the IPv4 tables begins with, before its address.
const LEAF: &str = "|-- ";

/// What an entry of a leaf begins with, before its prefix length.
const ENTRY: char = '/';

/// The names the kernel gives the two tables it names, each followed by a colon.
const NAMED_TABLES: [&str; 2] = ["Local", "Main"];

/// What the kernel writes before the number of a table it does not name.
const NUMBERED_TABLE: &str = "Id ";

/// Each scope an entry of the IPv4 tables may have.
const SCOPES: [&str; 5] = ["universe", "site", "link", "host", "nowhere"];

/// Each type an entry of the IPv4 tables may have.
const TYPES: [&str; 12] = [
    "UNSPEC",
    "UNICAST",
    "LOCAL",
    "BROADCAST",
    "ANYCAST",
    "MULTICAST",
    "BLACKHOLE",
    "UNREACHABLE",
    "PROHIBIT",
    "THROW",
    "NAT",
    "XRESOLVE",
];

/// The type of an entry naming an address the host answers on as its own.
const LOCAL: &str = "LOCAL";

/// What the type of service an entry carries begins with, where it carries one.
const TOS: &str = "tos=";

/// The hexadecimal digits the kernel writes an IPv6 address in.
const IPV6_DIGITS: usize = 32;

/// What follows the address of a point-to-point interface in `ip -o addr`, which lists
/// it without a prefix.
const PEER: &str = "peer";

/// The family `ip -o addr` lists an IPv4 address under.
const INET: &str = "inet";

/// The family `ip -o addr` lists an IPv6 address under.
const INET6: &str = "inet6";

/// The host's addresses, as `reading` answers for [`FIB_TRIE`] and [`IF_INET6`] and
/// `listing` answers for [`IP`]: a host with no IPv6 has no `IF_INET6`, and that is no
/// address rather than a failure.
///
/// # Errors
///
/// Where any of them cannot be read for any other reason, or as [`read`] refuses what
/// they hold.
pub fn asked(
    reading: &dyn Fn(&str) -> std::io::Result<String>,
    listing: &dyn Fn() -> Result<String, String>,
) -> Result<Vec<IpAddr>, String> {
    let fib_trie =
        reading(FIB_TRIE).map_err(|why| format!("{FIB_TRIE} could not be read: {why}"))?;
    let if_inet6 = match reading(IF_INET6) {
        Ok(text) => Some(text),
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => None,
        Err(why) => return Err(format!("{IF_INET6} could not be read: {why}")),
    };
    let listed = listing().map_err(|why| format!("{} could not be run: {why}", IP.join(" ")))?;
    read(&fib_trie, if_inet6.as_deref(), &listed)
}

/// Every address `fib_trie` and `if_inet6` hold as the host's own, each once and in
/// order, where `listed` holds exactly the same.
///
/// # Errors
///
/// Naming the first line any of them holds that this does not read, a local range the
/// fence would not refuse, the addresses one source holds and the other does not, or
/// where they hold no address at all: an answer lemonfiber hands on has to be one it can
/// trust whole.
pub fn read(fib_trie: &str, if_inet6: Option<&str>, listed: &str) -> Result<Vec<IpAddr>, String> {
    let mut tabled: BTreeSet<IpAddr> = local_v4(fib_trie)?.into_iter().map(IpAddr::V4).collect();
    for line in if_inet6.unwrap_or_default().lines() {
        tabled.insert(IpAddr::V6(v6(line)?));
    }
    let listed: BTreeSet<IpAddr> = listed.lines().map(listing).collect::<Result<_, _>>()?;
    if tabled != listed {
        let only = |one: &BTreeSet<IpAddr>, other: &BTreeSet<IpAddr>| {
            one.difference(other)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(format!(
            "the kernel's tables and {} disagree: only the tables hold [{}], and only the \
             listing holds [{}]",
            IP.join(" "),
            only(&tabled, &listed),
            only(&listed, &tabled)
        ));
    }
    if tabled.is_empty() {
        return Err("the host's tables hold no address of its own".to_owned());
    }
    Ok(tabled.into_iter().collect())
}

/// Which kind of table a header names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    /// One of the two the kernel names.
    Named,
    /// One the kernel only numbers.
    Numbered,
}

/// Each address an entry of `fib_trie` marks local with a full prefix, with every other
/// local range held to lie inside a range the fence refuses.
fn local_v4(fib_trie: &str) -> Result<BTreeSet<Ipv4Addr>, String> {
    let mut local = BTreeSet::new();
    let mut table = None;
    let mut leaf = None;
    for line in fib_trie.lines() {
        let said = line.trim();
        if let Some(name) = said.strip_suffix(':') {
            table = Some(tabled(name).ok_or_else(|| unread(line))?);
            leaf = None;
        } else if let Some(node) = said.strip_prefix(NODE) {
            noded(node).ok_or_else(|| unread(line))?;
            leaf = None;
        } else if let Some(address) = said.strip_prefix(LEAF) {
            leaf = Some(address.parse::<Ipv4Addr>().map_err(|_| unread(line))?);
        } else {
            let (prefix, kind) = entry(said).ok_or_else(|| unread(line))?;
            let (Some(address), Some(table)) = (leaf, table) else {
                return Err(unread(line));
            };
            if kind != LOCAL {
                continue;
            }
            let proxied = prefix == 0 && table == Table::Numbered;
            if prefix == 32 {
                local.insert(address);
            } else if !(proxied || refused(address, prefix)) {
                return Err(format!(
                    "the host answers on every address of {address}/{prefix} as its own, and \
                     the fence is handed addresses rather than a range"
                ));
            }
        }
    }
    Ok(local)
}

/// The kind of table `name` is, where it is one the kernel writes.
fn tabled(name: &str) -> Option<Table> {
    if NAMED_TABLES.contains(&name) {
        return Some(Table::Named);
    }
    let number = name.strip_prefix(NUMBERED_TABLE)?;
    number.parse::<u32>().ok().map(|_| Table::Numbered)
}

/// Whether `node` is a prefix followed by the three counts the kernel writes after it.
fn noded(node: &str) -> Option<()> {
    let mut words = node.split_whitespace();
    let (network, prefix) = words.next()?.split_once('/')?;
    network.parse::<Ipv4Addr>().ok()?;
    let counts: Vec<&str> = words.collect();
    let known = prefix.parse::<u8>().is_ok_and(|prefix| prefix <= 32)
        && counts.len() == 3
        && counts.iter().all(|count| count.parse::<u64>().is_ok());
    known.then_some(())
}

/// The prefix length of the entry `said` and its type, where it is an entry the kernel
/// writes.
fn entry(said: &str) -> Option<(u8, &str)> {
    let mut words = said.split_whitespace();
    let prefix = words.next()?.strip_prefix(ENTRY)?.parse::<u8>().ok()?;
    let scope = words.next()?;
    let kind = words.next()?;
    let tos = words.next();
    let known = prefix <= 32
        && SCOPES.contains(&scope)
        && TYPES.contains(&kind)
        && tos.is_none_or(|tos| {
            tos.strip_prefix(TOS)
                .is_some_and(|value| value.parse::<u8>().is_ok())
        })
        && words.next().is_none();
    known.then_some((prefix, kind))
}

/// Whether every address of `network`/`prefix` lies inside a range the fence refuses.
fn refused(network: Ipv4Addr, prefix: u8) -> bool {
    lemonfiber_outward::INTERNAL_V4
        .iter()
        .any(|&(range, length)| {
            prefix >= length && masked(network, length) == masked(range, length)
        })
}

/// `address` with every bit past the first `prefix` cleared.
fn masked(address: Ipv4Addr, prefix: u8) -> u32 {
    u32::from(address)
        .checked_shr(32 - u32::from(prefix))
        .unwrap_or_default()
}

/// The address one line of `ip -o addr` lists.
fn listing(line: &str) -> Result<IpAddr, String> {
    let mut words = line.split_whitespace();
    let index = words.next().and_then(|index| index.strip_suffix(':'));
    let named = words.next();
    let family = words.next();
    let address = words
        .next()
        .and_then(|address| match address.split_once('/') {
            Some((address, prefix)) => prefix.parse::<u8>().is_ok().then_some(address),
            None => (words.next() == Some(PEER)).then_some(address),
        });
    let parsed = match (index, named, family, address) {
        (Some(index), Some(_), Some(family), Some(address)) if index.parse::<u32>().is_ok() => {
            match family {
                INET => address.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                INET6 => address.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
                _ => None,
            }
        }
        _ => None,
    };
    parsed.ok_or_else(|| unread(line))
}

/// The address `line` of `if_inet6` begins with.
fn v6(line: &str) -> Result<Ipv6Addr, String> {
    let digits = line.split_whitespace().next().unwrap_or_default();
    if digits.len() != IPV6_DIGITS {
        return Err(unread(line));
    }
    u128::from_str_radix(digits, 16)
        .map(Ipv6Addr::from)
        .map_err(|_| unread(line))
}

/// Why `line` stops the answer.
fn unread(line: &str) -> String {
    format!("{line:?} is not a line the host's addresses are read from")
}

#[cfg(test)]
mod tests;
