//! The fence's own answer to the namespace's DNS questions, for a fence holding its service
//! inside the stack: it listens where the rules send every question asked of the engine's
//! resolver, passes on only those [`crate::names::judged`] passes, over sockets carrying
//! [`MARK`] so the rules let them reach the resolver itself, and answers every other refused.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::names::{drawn, judged, Verdict};

/// The port on the namespace's loopback the fence answers on.
pub const PORT: u16 = 53530;

/// Where on the namespace's loopback the fence answers.
pub const ANSWERING: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), PORT);

/// The mark every socket the fence passes a question on through carries.
pub const MARK: u32 = 0x4c46;

/// The engine's resolver, which the fence passes questions on to.
const RESOLVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 53);

/// How long the engine's resolver is given to answer.
const WITHIN: Duration = Duration::from_secs(5);

/// The largest message the fence reads.
const LARGEST: usize = 65_535;

/// Where questions are passed on to, and the mark the sockets passing them carry, where
/// they carry one.
#[derive(Debug, Clone, Copy)]
struct Upstream {
    /// The resolver.
    at: SocketAddr,
    /// The mark each socket passing a question on carries.
    mark: Option<u32>,
}

/// Answer the namespace's questions asked at `at` for as long as the fence runs, where
/// `names` are the names a question may ask for.
///
/// # Errors
///
/// Where the fence cannot listen at `at`, or can no longer read a question there.
pub fn answering(at: SocketAddr, names: BTreeSet<String>) -> std::io::Result<Infallible> {
    let datagrams = UdpSocket::bind(at)?;
    let streams = TcpListener::bind(at)?;
    served(
        datagrams,
        streams,
        Upstream {
            at: RESOLVER,
            mark: Some(MARK),
        },
        names,
    )
}

/// Answer each question asked on `datagrams` and over `streams`, passing on to `upstream`
/// those `names` allow, for as long as the sockets last.
///
/// # Errors
///
/// Where a question can no longer be read from `datagrams`.
fn served(
    datagrams: UdpSocket,
    streams: TcpListener,
    upstream: Upstream,
    names: BTreeSet<String>,
) -> std::io::Result<Infallible> {
    let names = Arc::new(names);
    let held = Arc::clone(&names);
    std::thread::spawn(move || {
        for stream in streams.incoming().flatten() {
            let names = Arc::clone(&held);
            std::thread::spawn(move || streamed(stream, &names, upstream));
        }
    });
    let datagrams = Arc::new(datagrams);
    let mut buffer = vec![0; LARGEST];
    loop {
        let (length, from) = datagrams.recv_from(&mut buffer)?;
        let asked = buffer.get(..length).unwrap_or_default().to_vec();
        let names = Arc::clone(&names);
        let datagrams = Arc::clone(&datagrams);
        std::thread::spawn(move || {
            if let Some(answer) =
                answered(&asked, &names, &|query| passed_datagram(query, upstream))
            {
                let _ = datagrams.send_to(&answer, from);
            }
        });
    }
}

/// The answer to `asked`: the resolver's, through `pass`, given back under the id and
/// question asked, where it is passed on and answers the query passed.
fn answered(
    asked: &[u8],
    names: &BTreeSet<String>,
    pass: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    match judged(asked, names, &mut drawn) {
        Verdict::Passed(passed) => pass(&passed.query).and_then(|answer| passed.answered(&answer)),
        Verdict::Refused(answer) => Some(answer),
        Verdict::Dropped => None,
    }
}

/// Answer each question the stream `stream` asks, each written after its length, until
/// one goes unanswered or the stream ends.
fn streamed(mut stream: TcpStream, names: &BTreeSet<String>, upstream: Upstream) -> Option<()> {
    stream.set_read_timeout(Some(WITHIN)).ok()?;
    loop {
        let asked = framed(&mut stream)?;
        let answer = answered(&asked, names, &|query| passed_stream(query, upstream))?;
        write_framed(&mut stream, &answer).ok()?;
    }
}

/// The next message `stream` writes after its length, where it writes one whole.
fn framed(stream: &mut dyn Read) -> Option<Vec<u8>> {
    let mut length = [0; 2];
    stream.read_exact(&mut length).ok()?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

/// Write `message` to `stream` after its length.
fn write_framed(stream: &mut dyn Write, message: &[u8]) -> std::io::Result<()> {
    let length = u16::try_from(message.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)
}

/// The answer of `upstream` to `asked`, passed on in a datagram from a socket of its own.
fn passed_datagram(asked: &[u8], upstream: Upstream) -> Option<Vec<u8>> {
    let socket: UdpSocket = connected(Type::DGRAM, Protocol::UDP, upstream)?.into();
    socket.set_read_timeout(Some(WITHIN)).ok()?;
    socket.send(asked).ok()?;
    let mut buffer = vec![0; LARGEST];
    let length = socket.recv(&mut buffer).ok()?;
    buffer.truncate(length);
    Some(buffer)
}

/// The answer of `upstream` to `asked`, passed on over a stream of its own.
fn passed_stream(asked: &[u8], upstream: Upstream) -> Option<Vec<u8>> {
    let mut stream: TcpStream = connected(Type::STREAM, Protocol::TCP, upstream)?.into();
    stream.set_read_timeout(Some(WITHIN)).ok()?;
    write_framed(&mut stream, asked).ok()?;
    framed(&mut stream)
}

/// A socket of `kind` connected to `upstream`, carrying its mark from before it connects,
/// which only a holder of `NET_ADMIN` can set; nothing where any of that fails.
fn connected(kind: Type, protocol: Protocol, upstream: Upstream) -> Option<Socket> {
    let socket = Socket::new(Domain::IPV4, kind, Some(protocol)).ok()?;
    if let Some(mark) = upstream.mark {
        with_mark(&socket, mark)?;
    }
    socket.connect_timeout(&upstream.at.into(), WITHIN).ok()?;
    Some(socket)
}

/// Mark `socket` with `mark`.
#[cfg(target_os = "linux")]
fn with_mark(socket: &Socket, mark: u32) -> Option<()> {
    socket.set_mark(mark).ok()
}

/// Nothing: no other system marks a socket.
#[cfg(not(target_os = "linux"))]
fn with_mark(_: &Socket, _: u32) -> Option<()> {
    None
}

#[cfg(test)]
mod tests;
