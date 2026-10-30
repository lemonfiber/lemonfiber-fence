use std::net::IpAddr;

use super::{host_addresses, ruleset, TABLE};

fn addresses(said: &[&str]) -> Vec<IpAddr> {
    said.iter().filter_map(|one| one.parse().ok()).collect()
}

#[test]
fn host_addresses_are_read_past_commas_and_whitespace() {
    assert_eq!(
        host_addresses(" 203.0.113.7, 2001:db8::7\n198.51.100.1,,"),
        Ok(addresses(&["203.0.113.7", "2001:db8::7", "198.51.100.1"]))
    );
    assert_eq!(host_addresses(""), Ok(Vec::new()));
}

#[test]
fn an_entry_that_is_not_an_address_refuses_the_whole_list() {
    let refused = host_addresses("203.0.113.7, router.lan");
    assert_eq!(
        refused,
        Err("\"router.lan\" is not an IP address the fence can refuse".to_owned())
    );
    assert!(host_addresses("10.0.0.0/8").is_err());
}

#[test]
fn every_private_range_is_refused_and_the_resolver_and_answers_pass() {
    let rules = ruleset(&[]);
    for range in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "::ffff:0:0/96",
    ] {
        assert!(rules.contains(range), "{range} is not refused:\n{rules}");
    }
    let accepted = rules.find("ip daddr 127.0.0.11 accept");
    let refused = rules.find("ip daddr @refused_v4 reject");
    assert!(
        accepted.is_some() && accepted < refused,
        "the resolver is let through before anything is refused:\n{rules}"
    );
    let answered = rules.find("ct state established,related accept");
    assert!(answered.is_some() && answered < accepted, "{rules}");
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
    assert!(v4.contains("240.0.0.0/4, 203.0.113.7 }"), "{rules}");
    assert!(rules.contains("ff00::/8, 2001:db8::7 }"), "{rules}");
}

#[test]
fn applying_it_again_replaces_the_table_rather_than_adding_beside_it() {
    let rules = ruleset(&[]);
    assert!(rules.starts_with(&format!(
        "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{"
    )));
}
