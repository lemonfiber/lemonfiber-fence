use std::io::{Error, ErrorKind};
use std::net::IpAddr;

use super::{asked, read, FIB_TRIE as TRIE, IF_INET6 as INET6};

const FIB_TRIE: &str = "Main:
  +-- 0.0.0.0/0 3 0 6
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 192.168.1.0/24 2 0 2
        |-- 192.168.1.0
           /24 link UNICAST
        |-- 192.168.1.20
           /32 host LOCAL
        |-- 192.168.1.255
           /32 link BROADCAST
Id 984:
  |-- 0.0.0.0
     /0 host LOCAL
Local:
  +-- 0.0.0.0/0 3 0 6
     |-- 127.0.0.0
        /8 host LOCAL
     |-- 203.0.113.7
        /32 host LOCAL
     |-- 192.168.1.20
        /32 host LOCAL
";

const IF_INET6: &str = "00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000001 02 40 00 80     eth0
";

fn parsed(texts: &[&str]) -> Vec<IpAddr> {
    texts.iter().filter_map(|one| one.parse().ok()).collect()
}

#[test]
fn every_address_the_host_holds_as_its_own_is_read_once_and_in_order() {
    assert_eq!(
        read(FIB_TRIE, Some(IF_INET6)),
        Ok(parsed(&[
            "127.0.0.0",
            "192.168.1.20",
            "203.0.113.7",
            "::1",
            "2001:db8::1",
        ]))
    );
}

#[test]
fn a_host_without_ipv6_answers_its_ipv4_addresses() {
    assert_eq!(
        read(FIB_TRIE, None),
        Ok(parsed(&["127.0.0.0", "192.168.1.20", "203.0.113.7"]))
    );
}

#[test]
fn a_line_that_is_not_an_address_and_an_answer_holding_none_are_refused() {
    for (fib_trie, if_inet6, said) in [
        (FIB_TRIE, Some("zz01 02 40 00 80 eth0\n"), "does not begin"),
        (
            FIB_TRIE,
            Some("2001zz00000000000000000000000001 02 40 00 80 eth0\n"),
            "does not begin",
        ),
        ("", Some(""), "no address"),
        ("|-- 10.0.0.1\n/32 link BROADCAST\n", None, "no address"),
    ] {
        let refused = read(fib_trie, if_inet6).err().unwrap_or_default();
        assert!(refused.contains(said), "{refused}");
    }
}

#[test]
fn a_host_without_the_ipv6_table_is_asked_its_ipv4_alone_and_any_other_unreadable_table_refused() {
    let without_v6 = |path: &str| match path {
        TRIE => Ok(FIB_TRIE.to_owned()),
        _ => Err(Error::from(ErrorKind::NotFound)),
    };
    assert_eq!(
        asked(without_v6),
        Ok(parsed(&["127.0.0.0", "192.168.1.20", "203.0.113.7"]))
    );
    let both = |path: &str| match path {
        TRIE => Ok(FIB_TRIE.to_owned()),
        _ => Ok(IF_INET6.to_owned()),
    };
    assert_eq!(asked(both).map(|held| held.len()), Ok(5));
    let denied = |path: &str| match path {
        INET6 => Err(Error::from(ErrorKind::PermissionDenied)),
        _ => Ok(FIB_TRIE.to_owned()),
    };
    assert!(asked(denied).is_err_and(|why| why.contains(INET6)));
    let unreadable = |_: &str| -> std::io::Result<String> { Err(Error::from(ErrorKind::NotFound)) };
    assert!(asked(unreadable).is_err_and(|why| why.contains(TRIE)));
}
