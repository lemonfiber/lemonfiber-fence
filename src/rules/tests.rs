use std::net::IpAddr;

use super::{host_addresses, networks, ruleset, within, Network, PROBE, TABLE};

fn addresses(said: &[&str]) -> Vec<IpAddr> {
    said.iter().filter_map(|one| one.parse().ok()).collect()
}

#[test]
fn host_addresses_are_read_past_commas_and_whitespace() {
    assert_eq!(
        host_addresses(Some(" 203.0.113.7, 2001:db8::7\n198.51.100.1,,")),
        Ok(addresses(&["203.0.113.7", "2001:db8::7", "198.51.100.1"]))
    );
}

/// A fence handed no host address would let the service reach the host at an address
/// no range covers, so it refuses to start rather than fence without one.
#[test]
fn no_host_address_refuses_to_start() {
    assert_eq!(
        host_addresses(None),
        Err(
            "LEMONFIBER_FENCE_HOST_ADDRESSES is not set, so the host's own addresses are not known"
                .to_owned()
        )
    );
    assert_eq!(
        host_addresses(Some(" , ")),
        Err("LEMONFIBER_FENCE_HOST_ADDRESSES holds no address".to_owned())
    );
}

#[test]
fn an_entry_that_is_not_an_address_refuses_the_whole_list() {
    let refused = host_addresses(Some("203.0.113.7, router.lan"));
    assert_eq!(
        refused,
        Err("\"router.lan\" is not an IP address the fence can refuse".to_owned())
    );
    assert!(host_addresses(Some("10.0.0.0/8")).is_err());
}

/// Every range the core's check on a name refuses is refused here too, read from the
/// same list, and so is every range whose addresses carry an IPv4 one.
#[test]
fn every_range_nothing_reaches_is_refused_from_the_one_list() {
    let rules = ruleset(TABLE, &[]);
    for (network, prefix) in lemonfiber_outward::INTERNAL_V4 {
        assert!(
            rules.contains(&format!("{network}/{prefix}")),
            "{network}/{prefix}:\n{rules}"
        );
    }
    for (network, prefix) in lemonfiber_outward::INTERNAL_V6
        .iter()
        .chain(&lemonfiber_outward::CARRYING_V6)
    {
        assert!(
            rules.contains(&format!("{network}/{prefix}")),
            "{network}/{prefix}:\n{rules}"
        );
    }
    for range in [
        "2002::/16",
        "2001::/32",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "::/96",
        "100::/64",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "::1/128",
    ] {
        assert!(rules.contains(range), "{range} is not refused:\n{rules}");
    }
}

/// The resolver is let through on its port alone, before the engine moves it, and
/// nothing else to it; answers pass before anything is refused.
#[test]
fn only_the_resolvers_port_passes_and_answers_pass_first() {
    let rules = ruleset(TABLE, &[]);
    assert!(
        rules.contains("type filter hook output priority mangle;"),
        "{rules}"
    );
    assert!(!rules.contains("ip daddr 127.0.0.11 accept"), "{rules}");
    let answered = rules.find("ct state established,related accept");
    let udp = rules.find("ip daddr 127.0.0.11 udp dport 53 accept");
    let tcp = rules.find("ip daddr 127.0.0.11 tcp dport 53 accept");
    let refused = rules.find("ip daddr @refused_v4 reject");
    assert!(answered.is_some() && answered < udp, "{rules}");
    assert!(udp.is_some() && tcp.is_some() && tcp < refused, "{rules}");
    assert!(rules.contains("ip6 daddr @refused_v6 reject"), "{rules}");
}

/// Every address the namespace's own routes class as broadcast, multicast or anycast is
/// refused, wherever it lies.
#[test]
fn every_broadcast_multicast_and_anycast_address_is_refused() {
    let rules = ruleset(TABLE, &[]);
    let shared = rules.find("\t\tfib daddr type { broadcast, multicast, anycast } reject\n");
    let tcp = rules.find("ip daddr 127.0.0.11 tcp dport 53 accept");
    assert!(shared.is_some() && tcp < shared, "{rules}");
}

#[test]
fn each_host_address_joins_the_set_of_its_family() {
    let rules = ruleset(TABLE, &addresses(&["203.0.113.7", "2001:db8::7"]));
    let v4 = rules
        .split("set refused_v6")
        .next()
        .unwrap_or_default()
        .to_owned();
    assert!(v4.ends_with(", 203.0.113.7 }\n\t}\n\t"), "{rules}");
    assert!(rules.contains(", 2001:db8::7 }"), "{rules}");
}

#[test]
fn applying_it_again_replaces_the_table_rather_than_adding_beside_it() {
    let rules = ruleset(TABLE, &[]);
    assert!(rules.starts_with(&format!(
        "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{"
    )));
}

/// A connection the namespace opens on its own loopback interface passes, but to the
/// resolver's address, which keeps its one port; one leaving the namespace is still
/// refused.
#[test]
fn the_namespaces_own_loopback_passes_but_to_the_resolver() {
    let rules = ruleset(TABLE, &[]);
    let v4 = rules.find("\toif \"lo\" ip daddr != 127.0.0.11 accept");
    let v6 = rules.find("\toif \"lo\" meta nfproto ipv6 accept");
    let refused = rules.find("ip daddr @refused_v4 reject");
    assert!(v4.is_some() && v4 < refused, "{rules}");
    assert!(v6.is_some() && v6 < refused, "{rules}");
    assert!(!rules.contains("\toif \"lo\" accept"), "{rules}");
    assert!(rules.contains("127.0.0.0/8"), "{rules}");
}

/// The ruleset `fence nftables` installs is the fence's own under a table of its own.
#[test]
fn the_probe_installs_the_fences_ruleset_under_a_table_of_its_own() {
    let probe = ruleset(PROBE, &[]);
    assert_ne!(PROBE, TABLE);
    assert!(probe.starts_with(&format!(
        "table inet {PROBE}\ndelete table inet {PROBE}\ntable inet {PROBE} {{"
    )));
    assert_eq!(
        probe.replace(PROBE, TABLE),
        ruleset(TABLE, &[]),
        "the probe holds another ruleset than the fence's"
    );
}

fn network(address: &str, prefix: u8, gateway: &str) -> Network {
    Network {
        address: address.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
        prefix,
        gateway: gateway.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
    }
}

#[test]
fn networks_are_read_as_subnets_and_gateways_past_commas_and_whitespace() {
    assert_eq!(
        networks(Some(" 172.20.0.0/16=172.20.0.1,\nfd00:1::/64=fd00:1::1 ,,")),
        Ok(vec![
            network("172.20.0.0", 16, "172.20.0.1"),
            network("fd00:1::", 64, "fd00:1::1"),
        ])
    );
}

/// A fence that does not know which addresses are inside the stack cannot pass only
/// those, so it refuses to start rather than guess.
#[test]
fn no_network_refuses_to_start() {
    assert_eq!(
        networks(None),
        Err(
            "LEMONFIBER_FENCE_NETWORKS is not set, so the networks inside the stack are not known"
                .to_owned()
        )
    );
    assert_eq!(
        networks(Some(" , ")),
        Err("LEMONFIBER_FENCE_NETWORKS holds no network".to_owned())
    );
}

/// A gateway outside its subnet, of another family, a subnet naming an address past its
/// first or a prefix wider than its family each refuse the whole list.
#[test]
fn an_entry_that_is_not_a_subnet_holding_its_gateway_refuses_the_whole_list() {
    for entry in [
        "172.20.0.0/16",
        "172.20.0.0=172.20.0.1",
        "172.20.0.0/16=172.21.0.1",
        "172.20.0.0/16=fd00::1",
        "172.20.0.5/16=172.20.0.1",
        "172.20.0.0/33=172.20.0.1",
        "fd00::/129=fd00::1",
        "stack/16=172.20.0.1",
    ] {
        assert_eq!(
            networks(Some(&format!("10.1.0.0/24=10.1.0.1, {entry}"))),
            Err(format!("{entry:?} is not a subnet holding its gateway")),
            "{entry}"
        );
    }
}

/// Inside the stack, a new connection passes only to the subnets, never to a gateway or
/// the host, and everything else is refused at the end.
#[test]
fn inside_the_stack_only_the_subnets_pass_and_gateways_and_the_host_are_refused_first() {
    let rules = within(
        TABLE,
        &[
            network("172.20.0.0", 16, "172.20.0.1"),
            network("fd00:1::", 64, "fd00:1::1"),
        ],
        &addresses(&["192.168.1.20", "2001:db8::7"]),
    );
    assert!(rules.contains("elements = { 172.20.0.0/16 }"), "{rules}");
    assert!(rules.contains("elements = { fd00:1::/64 }"), "{rules}");
    assert!(
        rules.contains("elements = { 172.20.0.0, 172.20.0.1, 172.20.255.255, 192.168.1.20 }"),
        "{rules}"
    );
    assert!(
        rules.contains("elements = { 2001:db8::7, fd00:1::, fd00:1::1 }"),
        "{rules}"
    );
    let answered = rules.find("ct state established,related accept");
    let resolver = rules.find("ct original proto-dst 53 accept");
    let barred = rules.find("ip daddr @barred_v4 reject");
    let barred_v6 = rules.find("ip6 daddr @barred_v6 reject");
    let inside = rules.find("ip daddr @inside_v4 accept");
    let inside_v6 = rules.find("ip6 daddr @inside_v6 accept");
    let last = rules.find("\t\treject\n\t}");
    assert!(answered.is_some() && answered < resolver, "{rules}");
    assert!(resolver < barred && barred < inside, "{rules}");
    assert!(barred_v6 < inside_v6 && inside_v6 < last, "{rules}");
    assert!(
        inside.is_some() && inside_v6.is_some() && last.is_some(),
        "{rules}"
    );
    assert!(!rules.contains("@refused_v4"), "{rules}");
}

/// The namespace's own loopback passes but to the resolver, as for a fenced service, and
/// a neighbour on its own link is still found over IPv6.
#[test]
fn inside_the_stack_the_loopback_and_neighbour_discovery_pass() {
    let rules = within(TABLE, &[network("172.20.0.0", 16, "172.20.0.1")], &[]);
    let last = rules.find("\t\treject\n\t}");
    let loopback = rules.find("\toif \"lo\" ip daddr != 127.0.0.11 accept");
    let neighbours = rules.find("icmpv6 type { 135, 136 }");
    assert!(loopback.is_some() && loopback < last, "{rules}");
    assert!(neighbours.is_some() && neighbours < last, "{rules}");
}

/// Neighbour discovery passes only to a link-local or solicited-node address with the hop
/// limit no router has lowered, so it is never a way off the namespace's own link.
#[test]
fn inside_the_stack_neighbour_discovery_never_leaves_the_link() {
    let rules = within(TABLE, &[network("fd00:1::", 64, "fd00:1::1")], &[]);
    let passing: Vec<&str> = rules
        .lines()
        .filter(|line| line.contains("icmpv6"))
        .map(str::trim)
        .collect();
    assert_eq!(
        passing,
        [
            "ip6 daddr { fe80::/10, ff02::1:ff00:0/104 } icmpv6 type { 135, 136 } ip6 hoplimit \
             255 accept"
        ],
        "{rules}"
    );
}

/// A network's own address and its IPv4 broadcast address reach its gateway as surely as
/// the gateway's own, so each is refused beside it; a prefix too long to hold them leaves
/// only the gateway.
#[test]
fn inside_the_stack_each_networks_own_and_broadcast_addresses_are_refused() {
    let rules = within(
        TABLE,
        &[
            network("10.4.0.0", 24, "10.4.0.1"),
            network("10.5.0.0", 31, "10.5.0.1"),
            network("fd00:2::", 64, "fd00:2::1"),
            network("fd00:3::", 127, "fd00:3::1"),
        ],
        &[],
    );
    assert!(
        rules.contains("elements = { 10.4.0.0, 10.4.0.1, 10.4.0.255, 10.5.0.1 }"),
        "{rules}"
    );
    assert!(
        rules.contains("elements = { fd00:2::, fd00:2::1, fd00:3::1 }"),
        "{rules}"
    );
}

/// Inside the stack, every broadcast, multicast and anycast address is refused before any
/// subnet passes, after neighbour discovery on the link, which multicast carries.
#[test]
fn inside_the_stack_broadcast_multicast_and_anycast_are_refused_before_the_subnets() {
    let rules = within(TABLE, &[network("172.20.0.0", 16, "172.20.0.1")], &[]);
    let neighbours = rules.find("icmpv6 type { 135, 136 }");
    let shared = rules.find("\t\tfib daddr type { broadcast, multicast, anycast } reject\n");
    let barred = rules.find("ip6 daddr @barred_v6 reject");
    let inside = rules.find("ip daddr @inside_v4 accept");
    assert!(barred.is_some() && barred < neighbours, "{rules}");
    assert!(neighbours.is_some() && neighbours < shared, "{rules}");
    assert!(shared.is_some() && shared < inside, "{rules}");
}

/// A family the stack holds no network of leaves its sets empty, which nftables reads,
/// rather than an empty list of elements, which it does not.
#[test]
fn a_family_with_no_network_declares_its_sets_without_elements() {
    let rules = within(TABLE, &[network("172.20.0.0", 16, "172.20.0.1")], &[]);
    assert!(!rules.contains("elements = {  }"), "{rules}");
    assert!(
        rules.contains(
            "\tset inside_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t}\n"
        ),
        "{rules}"
    );
    assert!(rules.starts_with(&format!(
        "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{"
    )));
}

/// Inside the stack, every question asked of the resolver on its port is sent to the fence's
/// own answer before the engine moves the port, but one from a socket carrying the fence's
/// mark, which only the fence can set. The filter runs after every nat chain, so it reads
/// the port each question was asked on rather than the one the engine moved it to.
#[test]
fn inside_the_stack_every_question_but_the_fences_own_goes_to_the_fences_answer() {
    let rules = within(TABLE, &[network("172.20.0.0", 16, "172.20.0.1")], &[]);
    assert!(
        rules.contains(
            "\tchain resolving {\n\t\ttype nat hook output priority -160; policy accept;\n\
             \t\tmeta mark != 0x4c46 ip daddr 127.0.0.11 udp dport 53 redirect to :53530\n\
             \t\tmeta mark != 0x4c46 ip daddr 127.0.0.11 tcp dport 53 redirect to :53530\n\t}\n"
        ),
        "{rules}"
    );
    assert!(!ruleset(TABLE, &[]).contains("chain resolving"));
    let resolver: Vec<&str> = rules
        .lines()
        .filter(|line| line.contains("ip daddr 127.0.0.11") && line.trim_end().ends_with("accept"))
        .map(str::trim)
        .collect();
    assert_eq!(
        resolver,
        ["meta mark 0x4c46 ct mark 0x4c46 ip daddr 127.0.0.11 \
             meta l4proto { tcp, udp } ct original proto-dst 53 accept"],
        "the resolver passes only to a socket carrying the fence's mark, on port 53 alone, so \
         a question the fence did not send on is refused even where it was not redirected"
    );
    let redirect = rules
        .split("type nat hook output priority ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|priority| priority.parse::<i32>().ok());
    assert!(
        redirect.is_some_and(|priority| priority < -100),
        "the redirect runs before the engine's own at dstnat: {rules}"
    );
    assert!(
        rules.contains("\tchain output {\n\t\ttype filter hook output priority filter;"),
        "the filter runs after every nat chain: {rules}"
    );
    assert!(
        rules.contains("\t\treject\n\t}\n\tchain resolving"),
        "{rules}"
    );
}

/// A packet to the resolver that the fence did not mark is refused before the answers to
/// open connections pass, so a socket reusing a flow the fence opened, whose redirect was
/// decided on that flow's first packet, never reaches the resolver; the fence's own flows
/// carry its mark on their connection too.
#[test]
fn inside_the_stack_an_unmarked_packet_to_the_resolver_is_refused_before_open_flows_pass() {
    let rules = within(TABLE, &[network("172.20.0.0", 16, "172.20.0.1")], &[]);
    let copied = rules.find("\t\tmeta mark 0x4c46 ct mark set meta mark\n");
    let unmarked =
        rules.find("\t\tip daddr 127.0.0.11 ct direction original meta mark != 0x4c46 reject\n");
    let unmarked_flow =
        rules.find("\t\tip daddr 127.0.0.11 ct direction original ct mark != 0x4c46 reject\n");
    let answered = rules.find("ct state established,related accept");
    assert!(copied.is_some() && copied < unmarked, "{rules}");
    assert!(unmarked.is_some() && unmarked < unmarked_flow, "{rules}");
    assert!(
        unmarked_flow.is_some() && unmarked_flow < answered,
        "{rules}"
    );
}
