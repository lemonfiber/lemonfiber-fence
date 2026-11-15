//! One request to a service from inside its own network namespace.
//!
//! lemonfiber runs `fence ask <method> <port> <path>` once, in a throwaway container
//! joined to the namespace of a service that publishes no port on the host, to ask it a
//! request proof. It asks `127.0.0.1` at that port alone, follows no redirect, reads at
//! most [`MOST`] bytes of the answer, and prints its status, its `content-type` and its
//! body, one after the other.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// The most of an answer's body that is read.
pub const MOST: usize = 64 * 1024;

/// The most of an answer's status line and headers that is read.
const HEAD_MOST: usize = 16 * 1024;

/// How long the whole exchange may take, connecting, sending and reading together.
const PATIENCE: Duration = Duration::from_secs(30);

/// What separates an answer's headers from its body.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// The header naming what the body is.
const CONTENT_TYPE: &str = "content-type";

/// One request, as it was named on the command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The method, in capitals.
    pub method: String,
    /// The port the service listens on inside its namespace.
    pub port: u16,
    /// The path, with its query, beginning with `/`.
    pub path: String,
}

/// What the service answered.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    /// The status.
    pub status: u16,
    /// The `content-type` it named, or nothing where it named none.
    pub content_type: String,
    /// The body, cut at [`MOST`] bytes.
    pub body: Vec<u8>,
}

/// The request `method`, `port` and `path` name.
///
/// # Errors
///
/// Where any of the three is missing or is not what a request can carry.
pub fn named(
    method: Option<&str>,
    port: Option<&str>,
    path: Option<&str>,
) -> Result<Request, String> {
    let method = method
        .filter(|method| !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase()))
        .ok_or("a method in capitals is named first")?;
    let port = port
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("a port from 1 to 65535 is named second")?;
    let path = path
        .filter(|path| path.starts_with('/') && path.bytes().all(|byte| byte.is_ascii_graphic()))
        .ok_or(
            "a path beginning with / and holding no space or control character is named third",
        )?;
    Ok(Request {
        method: method.to_owned(),
        port,
        path: path.to_owned(),
    })
}

/// What the service on `127.0.0.1` at `request`'s port answered it, the whole exchange
/// within [`PATIENCE`].
///
/// # Errors
///
/// Where nothing listens there, the request cannot be sent, what came back is not an
/// answer, or the exchange outlasts [`PATIENCE`].
pub fn asked(request: &Request) -> Result<Answer, String> {
    asked_within(request, PATIENCE)
}

/// [`asked`], the whole exchange, connecting included, within `patience`.
fn asked_within(request: &Request, patience: Duration) -> Result<Answer, String> {
    let deadline = Instant::now() + patience;
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, request.port));
    let mut stream = TcpStream::connect_timeout(&at, left(deadline)?)
        .map_err(|why| format!("nothing answered on port {}: {why}", request.port))?;
    stream
        .set_write_timeout(Some(left(deadline)?))
        .map_err(|why| why.to_string())?;
    let sent = format!(
        "{} {} HTTP/1.0\r\nHost: {at}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        request.method, request.path
    );
    stream
        .write_all(sent.as_bytes())
        .map_err(|why| format!("the request could not be sent: {why}"))?;
    let mut taken = Vec::new();
    let mut chunk = [0_u8; 8192];
    while taken.len() < HEAD_MOST + MOST {
        stream
            .set_read_timeout(Some(left(deadline)?))
            .map_err(|why| why.to_string())?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) => taken.extend_from_slice(chunk.get(..length).unwrap_or_default()),
            Err(why) if why.kind() == ErrorKind::Interrupted => {}
            Err(why) => return Err(format!("the answer could not be read: {why}")),
        }
    }
    taken.truncate(HEAD_MOST + MOST);
    parsed(&taken)
}

/// What is left until `deadline`, or why nothing is.
fn left(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| "the service did not answer in the time it is given".to_owned())
}

/// The answer `taken` holds, its body cut at [`MOST`] bytes.
///
/// # Errors
///
/// Where it holds no status line and headers.
pub fn parsed(taken: &[u8]) -> Result<Answer, String> {
    let end = taken
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
        .ok_or("the answer holds no end to its headers")?;
    let head = String::from_utf8_lossy(taken.get(..end).unwrap_or_default());
    let mut lines = head.lines();
    let status = lines
        .next()
        .filter(|line| line.starts_with("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or("the answer holds no status")?;
    let content_type = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case(CONTENT_TYPE))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    let body = taken
        .get(end + HEAD_END.len()..)
        .unwrap_or_default()
        .iter()
        .take(MOST)
        .copied()
        .collect();
    Ok(Answer {
        status,
        content_type,
        body,
    })
}

/// `answer` as it is printed: its status on the first line, its `content-type` on the
/// second, and its body after them.
#[must_use]
pub fn printed(answer: &Answer) -> Vec<u8> {
    let mut printed = format!("{}\n{}\n", answer.status, answer.content_type).into_bytes();
    printed.extend_from_slice(&answer.body);
    printed
}

#[cfg(test)]
mod tests;
