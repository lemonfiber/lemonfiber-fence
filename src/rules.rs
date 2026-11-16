//! The ruleset the fence holds its namespace to.
//!
//! Every new connection the namespace opens to an address no stranger's page should
//! reach is refused: every range the core's check on a name refuses, read from the same
//! list, every IPv6 range whose addresses carry an IPv4 one, and the host's own
//! addresses. A connection on the namespace's own loopback interface to any address but
//! the resolver's is let through, since it reaches nothing but the namespace itself, so
//! a service whose parts talk to each other over it still runs. The engine's resolver is
//! let through on its port alone, so names still resolve, and so are the answers to
//! connections other services opened, so the service behind the fence still answers
//! whoever asks it.
//!
//! A fence holding its service inside the stack holds the opposite rules: a new
//! connection passes only to an address inside one of the namespace's own networks that
//! is neither that network's gateway nor the host's, out of its own loopback interface and
//! to the resolver as above, and every other is refused. A network's own address and its
//! IPv4 broadcast address are refused beside its gateway, since each reaches the gateway
//! too. IPv6 neighbour discovery passes only to a link-local or solicited-node address and
//! only with the hop limit no router has lowered, so it never leaves the namespace's own
//! link. Every question asked of the resolver on its port is sent to the fence's own
//! answer instead, before the filter sees it, but one the fence passes on itself, from a
//! socket carrying its mark. The filter refuses every packet opening or continuing a
//! connection to the resolver that does not carry that mark, on the packet and on its
//! connection, before it passes the answers to connections already open, so a socket
//! reusing a flow the fence opened is refused too, while the answers sent back over a
//! connection pass.
//!
//! Both rulesets refuse every address the namespace's own routes class as broadcast,
//! multicast or anycast.
//!
//! The chain runs before the engine moves the resolver's port, which it does at
//! `dstnat`, so the port it matches is the one the service asked for.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::resolving::{MARK, PORT};

/// The table the fence installs, by the name it is listed under.
pub const TABLE: &str = "lemonfiber_fence";

/// The table `fence nftables` installs and takes away again, so asking whether a
/// namespace can hold the rules never touches a fence's own.
pub const PROBE: &str = "lemonfiber_fence_probe";

/// The namespace's own loopback interface.
const LOOPBACK: &str = "lo";

/// The address of the engine's own resolver inside a container's namespace.
const RESOLVER: &str = "127.0.0.11";

/// The setting naming the host's own addresses.
pub const HOST_ADDRESSES: &str = "LEMONFIBER_FENCE_HOST_ADDRESSES";

/// The setting naming the subnet and gateway of each of the namespace's own networks, for
/// a fence holding its service inside the stack.
pub const NETWORKS: &str = "LEMONFIBER_FENCE_NETWORKS";

/// What separates a network's subnet from its gateway in [`NETWORKS`].
const GATEWAY_AFTER: char = '=';

/// The IPv6 neighbour discovery messages a namespace sends to reach an address on its own
/// link, which open no connection: neighbour solicitation and advertisement, by their
/// `ICMPv6` types.
const NEIGHBOURS: &str = "135, 136";

/// The destinations a neighbour discovery message may name: the link-local range and the
/// solicited-node multicast range, neither of which a router forwards.
const NEIGHBOUR_DESTINATIONS: &str = "fe80::/10, ff02::1:ff00:0/104";

/// The hop limit every neighbour discovery message carries, which no router has lowered.
const NEIGHBOUR_HOP_LIMIT: u8 = 255;

/// The kinds of address that reach more than the one host they name, as the namespace's own
/// routes class them.
const SHARED: &str = "broadcast, multicast, anycast";

/// The longest IPv4 prefix whose first and last addresses are the network's own and its
/// broadcast address, rather than two hosts.
const SHARED_ENDS_V4: u8 = 30;

/// The longest IPv6 prefix whose first address is the subnet-router anycast address, rather
/// than a host.
const SHARED_FIRST_V6: u8 = 126;

/// The priority the chain sending the namespace's questions to the fence's own answer runs
/// at among the nat chains: before the engine moves the resolver's port, at `dstnat`. Every
/// nat chain runs where the kernel's own address translation does, so the filter chain
/// holding a service inside the stack runs after them, at `filter`, and sees each question
/// already sent on and the resolver's port already moved.
const REDIRECTED_FIRST: i32 = -160;

/// The IPv6 addresses no range of the core's list covers: the unspecified address and
/// loopback, which it classes by the IPv4 address the compatible range carries.
const UNCOVERED_V6: [&str; 2] = ["::/128", "::1/128"];

/// The host addresses the fence is handed, read from `said`: each a plain IPv4 or IPv6
/// address, separated by commas or whitespace.
///
/// # Errors
///
/// Where nothing is said, where it names no address, or naming the first entry that is
/// not an address: a fence that does not know the host's own addresses cannot refuse
/// them, so it refuses to start rather than fence without them.
pub fn host_addresses(said: Option<&str>) -> Result<Vec<IpAddr>, String> {
    let said = said.ok_or_else(|| {
        format!("{HOST_ADDRESSES} is not set, so the host's own addresses are not known")
    })?;
    let hosts = said
        .split(|one: char| one == ',' || one.is_whitespace())
        .filter(|one| !one.is_empty())
        .map(|one| {
            one.parse()
                .map_err(|_| format!("{one:?} is not an IP address the fence can refuse"))
        })
        .collect::<Result<Vec<IpAddr>, String>>()?;
    if hosts.is_empty() {
        return Err(format!("{HOST_ADDRESSES} holds no address"));
    }
    Ok(hosts)
}

/// One of the namespace's own networks: the subnet the engine gave it and its gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// The subnet's first address.
    pub address: IpAddr,
    /// How many leading bits of an address name the subnet.
    pub prefix: u8,
    /// The address the engine routes the network through.
    pub gateway: IpAddr,
}

impl Network {
    /// The subnet, as nftables reads one.
    fn subnet(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }

    /// The addresses inside the subnet that reach its gateway: the gateway, the subnet's
    /// own address where it is the IPv4 network or IPv6 subnet-router anycast address, and
    /// the IPv4 broadcast address.
    fn barred(&self) -> Vec<IpAddr> {
        let mut barred = vec![self.gateway];
        match self.address {
            IpAddr::V4(first) if self.prefix <= SHARED_ENDS_V4 => {
                let host_bits = u32::MAX >> self.prefix;
                barred.push(self.address);
                barred.push(IpAddr::from(std::net::Ipv4Addr::from(
                    u32::from(first) | host_bits,
                )));
            }
            IpAddr::V6(_) if self.prefix <= SHARED_FIRST_V6 => barred.push(self.address),
            _ => {}
        }
        barred
    }
}

/// The networks the fence is handed, read from `said`: each a subnet and its gateway
/// joined by `=`, such as `172.20.0.0/16=172.20.0.1`, separated by commas or whitespace.
///
/// # Errors
///
/// Where nothing is said, where it names no network, or naming the first entry that is not
/// a subnet holding its gateway: a fence that does not know which addresses are inside the
/// stack cannot pass only those, so it refuses to start rather than guess.
pub fn networks(said: Option<&str>) -> Result<Vec<Network>, String> {
    let said = said.ok_or_else(|| {
        format!("{NETWORKS} is not set, so the networks inside the stack are not known")
    })?;
    let held = said
        .split(|one: char| one == ',' || one.is_whitespace())
        .filter(|one| !one.is_empty())
        .map(|one| {
            network(one).ok_or_else(|| format!("{one:?} is not a subnet holding its gateway"))
        })
        .collect::<Result<Vec<Network>, String>>()?;
    if held.is_empty() {
        return Err(format!("{NETWORKS} holds no network"));
    }
    Ok(held)
}

/// `one` as a network, where it is a subnet's first address, its prefix and a gateway of
/// the same family inside it.
fn network(one: &str) -> Option<Network> {
    let (subnet, gateway) = one.split_once(GATEWAY_AFTER)?;
    let (address, prefix) = subnet.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let gateway: IpAddr = gateway.parse().ok()?;
    let held = Network {
        address,
        prefix,
        gateway,
    };
    (masked(address, prefix) == Some(address) && masked(gateway, prefix) == Some(address))
        .then_some(held)
}

/// `address` with every bit past the first `prefix` cleared, where `prefix` fits its family.
fn masked(address: IpAddr, prefix: u8) -> Option<IpAddr> {
    match address {
        IpAddr::V4(one) if prefix <= 32 => {
            let kept = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            Some(IpAddr::from(std::net::Ipv4Addr::from(
                u32::from(one) & kept,
            )))
        }
        IpAddr::V6(one) if prefix <= 128 => {
            let kept = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            Some(IpAddr::from(std::net::Ipv6Addr::from(
                u128::from(one) & kept,
            )))
        }
        _ => None,
    }
}

/// The ruleset a fence holding its service inside the stack installs under `table`:
/// a new connection passes to an address inside one of `networks` that neither reaches its
/// gateway, nor is one of `hosts`, nor a broadcast, multicast or anycast address, out of the
/// namespace's own loopback interface to any address but the resolver's, and to the
/// resolver on the port it was asked on, and every other is refused.
#[must_use]
pub fn within(table: &str, networks: &[Network], hosts: &[IpAddr]) -> String {
    let inside = |v4: bool| {
        listed(
            networks
                .iter()
                .filter(|one| one.address.is_ipv4() == v4)
                .map(Network::subnet),
        )
    };
    let barred = |v4: bool| {
        listed(
            networks
                .iter()
                .flat_map(Network::barred)
                .chain(hosts.iter().copied())
                .filter(|one| one.is_ipv4() == v4)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|one| one.to_string()),
        )
    };
    format!(
        "table inet {table}\n\
         delete table inet {table}\n\
         table inet {table} {{\n\
         {}{}{}{}\
         \tchain output {{\n\
         \t\ttype filter hook output priority filter; policy accept;\n\
         \t\tmeta mark {MARK:#x} ct mark set meta mark\n\
         \t\tip daddr {RESOLVER} ct direction original meta mark != {MARK:#x} reject\n\
         \t\tip daddr {RESOLVER} ct direction original ct mark != {MARK:#x} reject\n\
         \t\tct state established,related accept\n\
         \t\toif \"{LOOPBACK}\" ip daddr != {RESOLVER} accept\n\
         \t\toif \"{LOOPBACK}\" meta nfproto ipv6 accept\n\
         \t\tmeta mark {MARK:#x} ct mark {MARK:#x} ip daddr {RESOLVER} \
         meta l4proto {{ tcp, udp }} ct original proto-dst 53 accept\n\
         \t\tip daddr @barred_v4 reject\n\
         \t\tip6 daddr @barred_v6 reject\n\
         \t\tip6 daddr {{ {NEIGHBOUR_DESTINATIONS} }} icmpv6 type {{ {NEIGHBOURS} }} \
         ip6 hoplimit {NEIGHBOUR_HOP_LIMIT} accept\n\
         \t\tfib daddr type {{ {SHARED} }} reject\n\
         \t\tip daddr @inside_v4 accept\n\
         \t\tip6 daddr @inside_v6 accept\n\
         \t\treject\n\
         \t}}\n\
         \tchain resolving {{\n\
         \t\ttype nat hook output priority {REDIRECTED_FIRST}; policy accept;\n\
         \t\tmeta mark != {MARK:#x} ip daddr {RESOLVER} udp dport 53 redirect to :{PORT}\n\
         \t\tmeta mark != {MARK:#x} ip daddr {RESOLVER} tcp dport 53 redirect to :{PORT}\n\
         \t}}\n\
         }}\n",
        set("inside_v4", "ipv4_addr", &inside(true)),
        set("inside_v6", "ipv6_addr", &inside(false)),
        set("barred_v4", "ipv4_addr", &barred(true)),
        set("barred_v6", "ipv6_addr", &barred(false)),
    )
}

/// Each of `elements`, as one set's elements.
fn listed(elements: impl Iterator<Item = String>) -> String {
    elements.collect::<Vec<_>>().join(", ")
}

/// The set `name` of addresses of `kind`, holding `elements` where there are any.
fn set(name: &str, kind: &str, elements: &str) -> String {
    let held = if elements.is_empty() {
        String::new()
    } else {
        format!("\t\telements = {{ {elements} }}\n")
    };
    format!(
        "\tset {name} {{\n\
         \t\ttype {kind}\n\
         \t\tflags interval\n\
         \t\tauto-merge\n\
         {held}\
         \t}}\n"
    )
}

/// The ruleset, as `nft -f` reads it, installing `table` and refusing `hosts` beside
/// every fixed range and every broadcast, multicast and anycast address.
#[must_use]
pub fn ruleset(table: &str, hosts: &[IpAddr]) -> String {
    let v4 = elements(
        lemonfiber_outward::INTERNAL_V4
            .iter()
            .map(|(network, prefix)| format!("{network}/{prefix}")),
        hosts.iter().filter(|one| one.is_ipv4()),
    );
    let v6 = elements(
        lemonfiber_outward::INTERNAL_V6
            .iter()
            .chain(&lemonfiber_outward::CARRYING_V6)
            .map(|(network, prefix)| format!("{network}/{prefix}"))
            .chain(UNCOVERED_V6.iter().map(|one| (*one).to_owned())),
        hosts.iter().filter(|one| one.is_ipv6()),
    );
    format!(
        "table inet {table}\n\
         delete table inet {table}\n\
         table inet {table} {{\n\
         \tset refused_v4 {{\n\
         \t\ttype ipv4_addr\n\
         \t\tflags interval\n\
         \t\tauto-merge\n\
         \t\telements = {{ {v4} }}\n\
         \t}}\n\
         \tset refused_v6 {{\n\
         \t\ttype ipv6_addr\n\
         \t\tflags interval\n\
         \t\tauto-merge\n\
         \t\telements = {{ {v6} }}\n\
         \t}}\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tct state established,related accept\n\
         \t\toif \"{LOOPBACK}\" ip daddr != {RESOLVER} accept\n\
         \t\toif \"{LOOPBACK}\" meta nfproto ipv6 accept\n\
         \t\tip daddr {RESOLVER} udp dport 53 accept\n\
         \t\tip daddr {RESOLVER} tcp dport 53 accept\n\
         \t\tfib daddr type {{ {SHARED} }} reject\n\
         \t\tip daddr @refused_v4 reject\n\
         \t\tip6 daddr @refused_v6 reject\n\
         \t}}\n\
         }}\n"
    )
}

/// The ranges `fixed` and every address of `hosts`, as one set's elements.
fn elements<'a>(
    fixed: impl Iterator<Item = String>,
    hosts: impl Iterator<Item = &'a IpAddr>,
) -> String {
    fixed
        .chain(hosts.map(ToString::to_string))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests;
