use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;

use super::{asked, read, FIB_TRIE as TRIE, IF_INET6 as INET6};

const CONTAINER_TRIE: &str = include_str!("fixtures/container-fib_trie.txt");

const CONTAINER_IP: &str = include_str!("fixtures/container-ip.txt");

const ORBSTACK_TRIE: &str = include_str!("fixtures/orbstack-fib_trie.txt");

const ORBSTACK_IP: &str = include_str!("fixtures/orbstack-ip.txt");

const LOOPBACK_V6: &str = "00000000000000000000000000000001 01 80 10 80       lo\n";

const CONTAINER: [&str; 6] = [
    "10.5.5.255",
    "10.9.0.0",
    "127.0.0.1",
    "192.168.215.3",
    "203.0.113.5",
    "::1",
];

fn parsed(texts: &[&str]) -> Vec<IpAddr> {
    texts
        .iter()
        .filter_map(|one| one.parse().ok())
        .collect::<BTreeSet<IpAddr>>()
        .into_iter()
        .collect()
}

fn line(index: u32, address: &str) -> String {
    let family = if address.contains(':') {
        "inet6"
    } else {
        "inet"
    };
    format!("{index}: eth0    {family} {address}/32 scope global eth0\\       valid_lft forever\n")
}

#[test]
fn every_address_a_containers_tables_mark_local_is_read_where_the_listing_agrees() {
    assert_eq!(
        read(CONTAINER_TRIE, Some(LOOPBACK_V6), CONTAINER_IP),
        Ok(parsed(&CONTAINER))
    );
}

#[test]
fn every_address_an_orbstack_hosts_tables_mark_local_is_read_where_the_listing_agrees() {
    let read = read(ORBSTACK_TRIE, None, ORBSTACK_IP);
    assert_eq!(read.as_ref().map(Vec::len), Ok(86), "{read:?}");
}

#[test]
fn a_local_entry_anywhere_under_its_leaf_is_read() {
    let trie = "Local:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 10.5.5.255\n        /32 link BROADCAST\n        /32 host LOCAL tos=4\n";
    assert_eq!(
        read(trie, None, &line(2, "10.5.5.255")),
        Ok(parsed(&["10.5.5.255"]))
    );
}

#[test]
fn a_line_the_reader_does_not_know_is_refused_rather_than_passed_over() {
    let local = "Local:\n     |-- 10.0.0.1\n        /32 host LOCAL\n";
    let listed = line(2, "10.0.0.1");
    assert_eq!(read(local, None, &listed), Ok(parsed(&["10.0.0.1"])));
    for unknown in [
        "     ?? 203.0.113.9 something new\n",
        "Other:\n",
        "Id x:\n",
        "  +-- 10.0.0.0/33 1 0 0\n",
        "  +-- 10.0.0.0/8 1 0\n",
        "  +-- 10.0.0.0 1 0 0\n",
        "  +-- ten/8 1 0 0\n",
        "     |-- 10.0.0.256\n",
        "        /32 host LOCALISH\n",
        "        /32 everywhere LOCAL\n",
        "        /33 host LOCAL\n",
        "        /32 host LOCAL tos=x\n",
        "        /32 host LOCAL dscp=1\n",
        "        /32 host LOCAL tos=1 more\n",
        "        /32 host\n",
    ] {
        let said = read(&format!("{local}{unknown}"), None, &listed);
        assert!(said.is_err(), "{unknown:?} gave {said:?}");
    }
    let orphan = read("        /32 host LOCAL\n", None, "");
    assert!(orphan.is_err(), "{orphan:?}");
    let untabled = read("     |-- 10.0.0.1\n        /32 host LOCAL\n", None, "");
    assert!(untabled.is_err(), "{untabled:?}");
}

#[test]
fn the_tables_and_the_listing_disagreeing_is_refused_naming_each_side() {
    let local = "Local:\n     |-- 10.0.0.1\n        /32 host LOCAL\n";
    let refused = read(local, Some(LOOPBACK_V6), &line(2, "10.0.0.2"))
        .err()
        .unwrap_or_default();
    assert!(
        refused.contains("only the tables hold [10.0.0.1, ::1]")
            && refused.contains("only the listing holds [10.0.0.2]"),
        "{refused}"
    );
}

#[test]
fn a_local_range_is_read_only_where_the_fence_refuses_it_anyway() {
    let ranged = |table: &str, range: &str| {
        let (network, prefix) = range.split_once('/').unwrap_or_default();
        format!(
            "{table}:\n     |-- {network}\n        /{prefix} host LOCAL\n     |-- 10.0.0.1\n        /32 host LOCAL\n"
        )
    };
    let listed = line(2, "10.0.0.1");
    for (table, range) in [
        ("Local", "127.0.0.0/8"),
        ("Id 100", "192.0.2.0/24"),
        ("Id 984", "0.0.0.0/0"),
    ] {
        assert_eq!(
            read(&ranged(table, range), None, &listed),
            Ok(parsed(&["10.0.0.1"])),
            "{table} {range}"
        );
    }
    for (table, range) in [
        ("Id 100", "203.0.112.0/23"),
        ("Local", "0.0.0.0/0"),
        ("Main", "8.8.8.0/24"),
    ] {
        let refused = read(&ranged(table, range), None, &listed)
            .err()
            .unwrap_or_default();
        assert!(refused.contains(range), "{table} {range}: {refused}");
    }
}

#[test]
fn a_listing_line_that_is_not_an_address_is_refused_and_a_peer_address_read() {
    let local = "Local:\n     |-- 10.0.0.1\n        /32 host LOCAL\n";
    assert_eq!(
        read(
            local,
            None,
            "3: tun0    inet 10.0.0.1 peer 10.0.0.2/32 scope global tun0\n"
        ),
        Ok(parsed(&["10.0.0.1"]))
    );
    for listed in [
        "x: eth0    inet 10.0.0.1/32 scope global\n",
        "2 eth0    inet 10.0.0.1/32 scope global\n",
        "2: eth0    link 10.0.0.1/32\n",
        "2: eth0    inet 10.0.0.1/x\n",
        "2: eth0    inet 10.0.0.1 scope global\n",
        "2: eth0    inet ::1/128\n",
        "2: eth0    inet6 10.0.0.1/32\n",
        "2: eth0\n",
    ] {
        let said = read(local, None, listed);
        assert!(said.is_err(), "{listed:?} gave {said:?}");
    }
}

#[test]
fn an_ipv6_line_that_is_not_an_address_and_an_answer_holding_none_are_refused() {
    for (if_inet6, said) in [
        ("zz01 02 40 00 80 eth0\n", "is not a line"),
        (
            "2001zz00000000000000000000000001 02 40 00 80 eth0\n",
            "is not a line",
        ),
        ("", "no address"),
    ] {
        let refused = read("", Some(if_inet6), "").err().unwrap_or_default();
        assert!(refused.contains(said), "{refused}");
    }
}

#[test]
fn a_host_without_the_ipv6_table_is_asked_its_ipv4_alone_and_anything_unreadable_refused() {
    let without_v6 = |path: &str| match path {
        TRIE => Ok(CONTAINER_TRIE.to_owned()),
        _ => Err(Error::from(ErrorKind::NotFound)),
    };
    let v4_listed = || {
        Ok(CONTAINER_IP
            .lines()
            .filter(|line| !line.contains("inet6"))
            .flat_map(|line| [line, "\n"])
            .collect::<String>())
    };
    assert_eq!(
        asked(&without_v6, &v4_listed),
        Ok(parsed(CONTAINER.get(..5).unwrap_or_default()))
    );
    let both = |path: &str| match path {
        TRIE => Ok(CONTAINER_TRIE.to_owned()),
        _ => Ok(LOOPBACK_V6.to_owned()),
    };
    assert_eq!(
        asked(&both, &|| Ok(CONTAINER_IP.to_owned())),
        Ok(parsed(&CONTAINER))
    );
    let denied = |path: &str| match path {
        INET6 => Err(Error::from(ErrorKind::PermissionDenied)),
        _ => Ok(CONTAINER_TRIE.to_owned()),
    };
    assert!(asked(&denied, &v4_listed).is_err_and(|why| why.contains(INET6)));
    let unreadable = |_: &str| -> std::io::Result<String> { Err(Error::from(ErrorKind::NotFound)) };
    assert!(asked(&unreadable, &v4_listed).is_err_and(|why| why.contains(TRIE)));
    let unlisted = || Err("no such program".to_owned());
    assert!(asked(&without_v6, &unlisted).is_err_and(|why| why.contains("/sbin/ip -o addr")));
}
