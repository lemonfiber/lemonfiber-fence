//! The ruleset the fence holds its namespace to.
//!
//! Every new connection the namespace opens to an address no stranger's page should
//! reach is refused: the machine itself, the networks beside it and the clouds'
//! metadata addresses. The engine's resolver is let through, so names still resolve,
//! and so are the answers to connections other services opened, so the service behind
//! the fence still answers whoever asks it.

use std::net::IpAddr;

/// The table the fence installs, by the name it is listed under.
pub const TABLE: &str = "lemonfiber_fence";

/// The address of the engine's own resolver inside a container's namespace.
const RESOLVER: &str = "127.0.0.11";

/// Every IPv4 range the fence refuses: loopback, this network, the private ranges,
/// carrier-grade NAT, link-local and the metadata addresses within it, multicast and
/// the reserved and broadcast range above it.
const REFUSED_V4: [&str; 9] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Every IPv6 range the fence refuses: the unspecified and loopback addresses, IPv4
/// carried in IPv6, unique-local, link-local and multicast.
const REFUSED_V6: [&str; 6] = [
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// The host addresses the fence is handed, read from `said`: each a plain IPv4 or IPv6
/// address, separated by commas or whitespace.
///
/// # Errors
///
/// Names the first entry that is not an address, so a fence handed something it cannot
/// refuse refuses to start rather than starting without it.
pub fn host_addresses(said: &str) -> Result<Vec<IpAddr>, String> {
    said.split(|one: char| one == ',' || one.is_whitespace())
        .filter(|one| !one.is_empty())
        .map(|one| {
            one.parse()
                .map_err(|_| format!("{one:?} is not an IP address the fence can refuse"))
        })
        .collect()
}

/// The ruleset, as `nft -f` reads it, refusing `hosts` beside every fixed range.
#[must_use]
pub fn ruleset(hosts: &[IpAddr]) -> String {
    let v4 = elements(&REFUSED_V4, hosts.iter().filter(|one| one.is_ipv4()));
    let v6 = elements(&REFUSED_V6, hosts.iter().filter(|one| one.is_ipv6()));
    format!(
        "table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         table inet {TABLE} {{\n\
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
         \t\ttype filter hook output priority 0; policy accept;\n\
         \t\tct state established,related accept\n\
         \t\tip daddr {RESOLVER} accept\n\
         \t\tip daddr @refused_v4 reject\n\
         \t\tip6 daddr @refused_v6 reject\n\
         \t}}\n\
         }}\n"
    )
}

/// The ranges `fixed` and every address of `hosts`, as one set's elements.
fn elements<'a>(fixed: &[&str], hosts: impl Iterator<Item = &'a IpAddr>) -> String {
    fixed
        .iter()
        .map(|one| (*one).to_owned())
        .chain(hosts.map(ToString::to_string))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests;
