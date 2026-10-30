use std::net::IpAddr;

use super::{host_addresses, ruleset, TABLE};

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
    let rules = ruleset(&[]);
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
    let rules = ruleset(&[]);
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

#[test]
fn each_host_address_joins_the_set_of_its_family() {
    let rules = ruleset(&addresses(&["203.0.113.7", "2001:db8::7"]));
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
    let rules = ruleset(&[]);
    assert!(rules.starts_with(&format!(
        "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{"
    )));
}
