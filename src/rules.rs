//! The ruleset the fence holds its namespace to.
//!
//! Every new connection the namespace opens to an address no stranger's page should
//! reach is refused: every range the core's check on a name refuses, read from the same
//! list, every IPv6 range whose addresses carry an IPv4 one, and the host's own
//! addresses. The engine's resolver is let through on its port alone, so names still
//! resolve, and so are the answers to connections other services opened, so the
//! service behind the fence still answers whoever asks it.
//!
//! The chain runs before the engine moves the resolver's port, which it does at
//! `dstnat`, so the port it matches is the one the service asked for.

use std::net::IpAddr;

/// The table the fence installs, by the name it is listed under.
pub const TABLE: &str = "lemonfiber_fence";

/// The address of the engine's own resolver inside a container's namespace.
const RESOLVER: &str = "127.0.0.11";

/// The setting naming the host's own addresses.
pub const HOST_ADDRESSES: &str = "LEMONFIBER_FENCE_HOST_ADDRESSES";

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

/// The ruleset, as `nft -f` reads it, refusing `hosts` beside every fixed range.
#[must_use]
pub fn ruleset(hosts: &[IpAddr]) -> String {
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
         \t\ttype filter hook output priority mangle; policy accept;\n\
         \t\tct state established,related accept\n\
         \t\tip daddr {RESOLVER} udp dport 53 accept\n\
         \t\tip daddr {RESOLVER} tcp dport 53 accept\n\
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
