use std::io::{Read, Write};
use std::net::TcpListener;

use std::time::{Duration, Instant};

use super::{asked, asked_within, named, parsed, printed, Answer, Request, MOST};

fn request(port: u16) -> Request {
    Request {
        method: "GET".to_owned(),
        port,
        path: "/openapi.json?x=1".to_owned(),
    }
}

#[test]
fn a_request_is_read_from_its_method_port_and_path() {
    assert_eq!(
        named(Some("GET"), Some("8191"), Some("/openapi.json?x=1")),
        Ok(request(8191))
    );
}

#[test]
fn a_request_that_cannot_be_sent_as_named_is_refused_saying_what_is_wanted() {
    for (method, port, path, wanted) in [
        (None, Some("8191"), Some("/"), "a method"),
        (Some("get"), Some("8191"), Some("/"), "a method"),
        (Some("GET"), Some("0"), Some("/"), "a port"),
        (Some("GET"), Some("65536"), Some("/"), "a port"),
        (Some("GET"), None, Some("/"), "a port"),
        (Some("GET"), Some("8191"), Some("health"), "a path"),
        (Some("GET"), Some("8191"), Some("/a b"), "a path"),
        (Some("GET"), Some("8191"), Some("/\r\nX: 1"), "a path"),
        (Some("GET"), Some("8191"), None, "a path"),
    ] {
        let refused = named(method, port, path);
        assert!(
            refused.as_ref().is_err_and(|why| why.starts_with(wanted)),
            "{method:?} {port:?} {path:?}: {refused:?}"
        );
    }
}

#[test]
fn an_answer_is_read_as_its_status_content_type_and_body() {
    let answered = parsed(
        &b"HTTP/1.1 200 OK\r\nServer: x\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"[..],
    );
    assert_eq!(
        answered,
        Ok(Answer {
            status: 200,
            content_type: "application/json".to_owned(),
            body: b"{\"a\":1}".to_vec(),
        })
    );
}

#[test]
fn a_redirect_is_answered_as_itself_and_not_followed() {
    let answered = parsed(&b"HTTP/1.0 302 Found\r\nLocation: http://elsewhere/\r\n\r\n"[..]);
    assert_eq!(
        answered,
        Ok(Answer {
            status: 302,
            content_type: String::new(),
            body: Vec::new(),
        })
    );
}

#[test]
fn a_body_longer_than_the_limit_is_cut_at_it() {
    let mut long = b"HTTP/1.0 200 OK\r\ncontent-type: text/plain\r\n\r\n".to_vec();
    long.extend(std::iter::repeat_n(b'a', MOST + 10));
    let answered = parsed(long.as_slice());
    assert_eq!(answered.map(|answer| answer.body.len()), Ok(MOST));
}

#[test]
fn what_is_not_an_answer_is_refused() {
    assert!(parsed(&b"HTTP/1.0 200 OK\r\n"[..]).is_err());
    assert!(parsed(&b"SSH-2.0-OpenSSH\r\n\r\n"[..]).is_err());
    assert!(parsed(&b"HTTP/1.0 abc\r\n\r\n"[..]).is_err());
}

#[test]
fn an_answer_is_printed_status_then_content_type_then_body() {
    let answer = Answer {
        status: 401,
        content_type: "application/json".to_owned(),
        body: b"{\"detail\":\"Unauthorized\"}".to_vec(),
    };
    assert_eq!(
        printed(&answer),
        b"401\napplication/json\n{\"detail\":\"Unauthorized\"}".to_vec()
    );
}

#[test]
fn the_service_on_loopback_is_asked_the_request_and_its_answer_read() {
    let listener = TcpListener::bind("127.0.0.1:0");
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else {
        return;
    };
    let port = listener
        .local_addr()
        .map(|at| at.port())
        .unwrap_or_default();
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().ok()?;
        let mut sent = Vec::new();
        let mut byte = [0_u8; 1];
        while !sent.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).ok()?;
            sent.extend_from_slice(&byte);
        }
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nheard")
            .ok()?;
        Some(String::from_utf8_lossy(&sent).into_owned())
    });
    let answered = asked(&request(port));
    let sent = served.join().ok().flatten().unwrap_or_default();
    assert!(
        sent.starts_with("GET /openapi.json?x=1 HTTP/1.0\r\n"),
        "{sent}"
    );
    assert!(sent.contains("Connection: close\r\n"), "{sent}");
    assert_eq!(
        answered,
        Ok(Answer {
            status: 200,
            content_type: "text/plain".to_owned(),
            body: b"heard".to_vec(),
        })
    );
}

/// A port nothing listens on: `tcpmux`'s, which no service on a machine running these
/// serves, and which no test here can be handed by the system as it hands out a free one.
const NOBODY: u16 = 1;

#[test]
fn nothing_listening_is_said() {
    let refused = asked(&request(NOBODY));
    assert!(
        refused
            .as_ref()
            .is_err_and(|why| why.starts_with("nothing answered on port")),
        "{refused:?}"
    );
}

#[test]
fn a_service_that_trickles_its_answer_is_given_up_on_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0");
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else {
        return;
    };
    let port = listener
        .local_addr()
        .map(|at| at.port())
        .unwrap_or_default();
    let dripping = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        for byte in b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nslow"
            .iter()
            .cycle()
            .take(200)
        {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let started = Instant::now();
    let answered = asked_within(&request(port), Duration::from_millis(300));
    let took = started.elapsed();
    assert!(answered.is_err(), "{answered:?}");
    assert!(took < Duration::from_secs(1), "gave up after {took:?}");
    let _ = dripping.join();
}
