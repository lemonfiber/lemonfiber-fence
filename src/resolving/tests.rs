use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{answered, framed, served, write_framed, Upstream};

static PASSED: AtomicUsize = AtomicUsize::new(0);

/// An address nothing answers on.
const LOOPBACK: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

/// One way of asking the fence a question at an address.
type Asking = fn(SocketAddr, &[u8]) -> Option<Vec<u8>>;

fn passing(asked: &[u8]) -> Option<Vec<u8>> {
    PASSED.fetch_add(1, Ordering::SeqCst);
    (!asked.is_empty()).then(|| resolved(asked))
}

fn asking(name: &str) -> Vec<u8> {
    let mut message = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        message.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        message.extend_from_slice(label.as_bytes());
    }
    message.extend_from_slice(&[0, 0, 1, 0, 1]);
    message
}

/// `asked` as a resolver answers it: the same message marked an answer.
fn resolved(asked: &[u8]) -> Vec<u8> {
    let mut answer = asked.to_vec();
    if let Some(flags) = answer.get_mut(2) {
        *flags |= 0x80;
    }
    answer
}

/// A resolver on this machine answering every question it is asked, counting them, over
/// datagrams and streams on one port.
fn resolver(asked: &Arc<AtomicUsize>) -> Option<SocketAddr> {
    let datagrams = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    let at = datagrams.local_addr().ok()?;
    let streams = TcpListener::bind(at).ok()?;
    let counted = Arc::clone(asked);
    std::thread::spawn(move || {
        let mut buffer = vec![0; 512];
        while let Ok((length, from)) = datagrams.recv_from(&mut buffer) {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = datagrams.send_to(&resolved(buffer.get(..length).unwrap_or_default()), from);
        }
    });
    let counted = Arc::clone(asked);
    std::thread::spawn(move || {
        for mut stream in streams.incoming().flatten() {
            while let Some(question) = framed(&mut stream) {
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = write_framed(&mut stream, &resolved(&question));
            }
        }
    });
    Some(at)
}

/// The fence answering on ports of its own, passing allowed questions to `upstream`
/// unmarked: where it answers datagrams, and where it answers streams.
fn fence(upstream: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
    let datagrams = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    let streams = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    let at = (datagrams.local_addr().ok()?, streams.local_addr().ok()?);
    let names = BTreeSet::from(["sonarr".to_owned()]);
    std::thread::spawn(move || {
        served(
            datagrams,
            streams,
            Upstream {
                at: upstream,
                mark: None,
            },
            names,
        )
    });
    Some(at)
}

fn asked_in_a_datagram(fence: SocketAddr, question: &[u8]) -> Option<Vec<u8>> {
    asked_in_a_datagram_within(fence, question, Duration::from_secs(5))
}

fn asked_in_a_datagram_within(
    fence: SocketAddr,
    question: &[u8],
    within: Duration,
) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    socket.set_read_timeout(Some(within)).ok()?;
    socket.send_to(question, fence).ok()?;
    let mut buffer = vec![0; 512];
    let length = socket.recv(&mut buffer).ok()?;
    buffer.truncate(length);
    Some(buffer)
}

fn asked_over_a_stream(fence: SocketAddr, question: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(fence).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write_framed(&mut stream, question).ok()?;
    framed(&mut stream)
}

#[test]
fn an_outside_name_is_answered_refused_and_never_passed_on_and_a_stack_name_is() {
    let names = BTreeSet::from(["sonarr".to_owned()]);
    let before = PASSED.load(Ordering::SeqCst);
    let refused = answered(&asking("exfil.example.net"), &names, &passing);
    assert_eq!(PASSED.load(Ordering::SeqCst), before);
    assert_eq!(refused.and_then(|answer| answer.get(3).copied()), Some(5));
    let given = answered(&asking("SonArr"), &names, &passing);
    assert_eq!(PASSED.load(Ordering::SeqCst), before + 1);
    assert_eq!(given, Some(resolved(&asking("SonArr"))));
    let unanswered = answered(&asking("sonarr"), &names, &|query| Some(query.to_vec()));
    assert_eq!(unanswered, None, "a query echoed back is no answer");
    let mut answer = asking("sonarr");
    if let Some(flags) = answer.get_mut(2) {
        *flags |= 0x80;
    }
    assert_eq!(answered(&answer, &names, &passing), None);
}

#[test]
fn a_streamed_message_is_read_after_its_length_as_it_was_written() {
    let mut written = Vec::new();
    assert!(write_framed(&mut written, &asking("sonarr")).is_ok());
    assert_eq!(written.get(..2), Some([0, 24].as_slice()));
    assert_eq!(framed(&mut written.as_slice()), Some(asking("sonarr")));
    assert_eq!(framed(&mut [0_u8, 9, 1].as_slice()), None);
    assert!(write_framed(&mut Vec::new(), &vec![0; 70_000]).is_err());
}

/// Over datagrams and over a stream alike, a stack name is answered by the resolver and an
/// outside name is answered refused by the fence, the resolver never asked it.
#[test]
fn the_fence_answers_over_datagrams_and_streams_passing_on_only_stack_names() {
    let asked = Arc::new(AtomicUsize::new(0));
    let listening = resolver(&asked).and_then(fence);
    assert!(listening.is_some(), "no socket on this machine's loopback");
    let (datagrams, streams) = listening.unwrap_or((LOOPBACK, LOOPBACK));
    let asking_at: [(Asking, SocketAddr); 2] = [
        (asked_in_a_datagram, datagrams),
        (asked_over_a_stream, streams),
    ];
    for (ask, at) in asking_at {
        let before = asked.load(Ordering::SeqCst);
        assert_eq!(
            ask(at, &asking("sonarr")),
            Some(resolved(&asking("sonarr")))
        );
        assert_eq!(asked.load(Ordering::SeqCst), before + 1);
        let refused = ask(at, &asking("leak.example.net"));
        assert_eq!(refused.and_then(|answer| answer.get(3).copied()), Some(5));
        assert_eq!(asked.load(Ordering::SeqCst), before + 1, "never passed on");
    }
}

/// Where the resolver cannot be reached, a stack name goes unanswered rather than
/// answered by anything else.
#[test]
fn a_resolver_that_cannot_be_reached_answers_nothing() {
    let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .unwrap_or(LOOPBACK);
    let unreached = Upstream {
        at: closed,
        mark: None,
    };
    assert_eq!(super::passed_stream(&asking("sonarr"), unreached), None);
}

/// The fence answers at the address it is told: an outside name is refused there, and a
/// stack name is passed on only to the engine's resolver over a marked socket, which this
/// machine does not let the test reach, so it goes unanswered. An address already taken
/// refuses to answer at all.
#[test]
fn the_fence_answers_where_it_is_told_and_passes_on_only_to_the_engines_resolver() {
    let free = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).and_then(|socket| socket.local_addr());
    assert!(free.is_ok(), "no socket on this machine's loopback");
    let at = free.unwrap_or(LOOPBACK);
    std::thread::spawn(move || super::answering(at, BTreeSet::from(["sonarr".to_owned()])));
    let refused = (0..50).find_map(|_| {
        asked_in_a_datagram_within(at, &asking("leak.example.net"), Duration::from_millis(100))
    });
    assert_eq!(refused.and_then(|answer| answer.get(3).copied()), Some(5));
    let unreached = asked_in_a_datagram_within(at, &asking("sonarr"), Duration::from_secs(1));
    assert_eq!(unreached, None);
    let taken = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0));
    let held = taken
        .as_ref()
        .ok()
        .and_then(|socket| socket.local_addr().ok());
    let Err(refusal) = super::answering(held.unwrap_or(at), BTreeSet::new());
    assert_eq!(refusal.kind(), std::io::ErrorKind::AddrInUse);
}
