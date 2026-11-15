use std::io::{Read, Write};
use std::net::TcpListener;

use super::{asked, named, printed, read, Answer, Request, MOST};

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
    let answered = read(
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
    let answered = read(&b"HTTP/1.0 302 Found\r\nLocation: http://elsewhere/\r\n\r\n"[..]);
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
    let answered = read(long.as_slice());
    assert_eq!(answered.map(|answer| answer.body.len()), Ok(MOST));
}

#[test]
fn what_is_not_an_answer_is_refused() {
    assert!(read(&b"HTTP/1.0 200 OK\r\n"[..]).is_err());
    assert!(read(&b"SSH-2.0-OpenSSH\r\n\r\n"[..]).is_err());
    assert!(read(&b"HTTP/1.0 abc\r\n\r\n"[..]).is_err());
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

#[test]
fn nothing_listening_is_said() {
    let listener = TcpListener::bind("127.0.0.1:0");
    let port = listener
        .as_ref()
        .ok()
        .and_then(|listener| listener.local_addr().ok())
        .map(|at| at.port())
        .unwrap_or_default();
    drop(listener);
    let refused = asked(&request(port));
    assert!(
        refused
            .as_ref()
            .is_err_and(|why| why.starts_with("nothing answered on port")),
        "{refused:?}"
    );
}
