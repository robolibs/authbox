use super::super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn did_web_fetch_rejects_insecure_http_by_default() {
    let result = fetch_did_document_http11(
        "http://example.com/.well-known/did.json",
        &WebFetchOptions::default(),
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.message,
        "Insecure HTTP is disabled for DID document fetch"
    );
}

#[test]
fn did_web_fetch_url_and_response_errors_are_explicit() {
    assert_eq!(
        parse_http_url("example.com/.well-known/did.json")
            .unwrap_err()
            .message,
        "URL is missing scheme"
    );
    assert_eq!(
        parse_http_url("http:///did.json").unwrap_err().message,
        "URL authority is empty"
    );
    assert_eq!(
        parse_http_url("http://example.com:0/did.json")
            .unwrap_err()
            .message,
        "Invalid URL port"
    );

    let unsupported =
        fetch_did_document_http11("ftp://example.com/did.json", &WebFetchOptions::default())
            .unwrap_err();
    assert_eq!(unsupported.message, "Unsupported URL scheme");
}

#[test]
fn did_web_fetch_detail_namespace_exposes_url_helpers() {
    let default_options = WebFetchOptions::default();
    assert!(!default_options.allow_insecure_http);
    assert!(!default_options.skip_tls_certificate_verification_for_testing);
    assert_eq!(default_options.max_response_bytes, 1024 * 1024);
    assert_eq!(default_options.user_agent, "authbox-did/0.1");
    assert_eq!(default_options.recv_timeout_ms, 5000);

    let default_url = web_fetch::ParsedUrl::default();
    assert_eq!(default_url.scheme, "");
    assert_eq!(default_url.host, "");
    assert_eq!(default_url.port, 0);
    assert_eq!(default_url.target, "/");

    assert_eq!(web_fetch::detail::parse_port("443").unwrap(), 443);
    assert_eq!(
        web_fetch::detail::parse_port("  +443trailing").unwrap(),
        443
    );
    assert_eq!(
        web_fetch::detail::parse_port("0").unwrap_err().message,
        "Invalid URL port"
    );
    assert_eq!(
        web_fetch::detail::parse_port("nope").unwrap_err().message,
        "Invalid URL port"
    );

    let parsed = web_fetch::detail::parse_http_url("https://[::1]:8443/did.json?x=1").unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "::1");
    assert_eq!(parsed.port, 8443);
    assert_eq!(parsed.target, "/did.json?x=1");

    let permissive_port =
        web_fetch::detail::parse_http_url("http://example.com:8080junk/did.json").unwrap();
    assert_eq!(permissive_port.host, "example.com");
    assert_eq!(permissive_port.port, 8080);
    assert_eq!(permissive_port.target, "/did.json");

    let defaulted = web_fetch::detail::parse_http_url("http://example.com").unwrap();
    assert_eq!(defaulted.scheme, "http");
    assert_eq!(defaulted.host, "example.com");
    assert_eq!(defaulted.port, 80);
    assert_eq!(defaulted.target, "/");
}

#[test]
fn did_web_fetch_resolver_factory_uses_safe_defaults() {
    let _resolver = make_web_http11_resolver();
    assert_eq!(
        did_web_document_url("did:web:example.com").unwrap(),
        "https://example.com/.well-known/did.json"
    );

    let fetcher = web_fetch::make_web_http_fetcher();
    let error = fetcher("http://example.com/.well-known/did.json").unwrap_err();
    assert_eq!(
        error.message,
        "Insecure HTTP is disabled for DID document fetch"
    );
}

#[test]
fn did_web_fetch_http1_does_not_follow_redirects_like_cpp_netpipe() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to bind local DID HTTP test server: {err}"),
    };
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        let response = "HTTP/1.1 302 Found\r\nLocation: https://other.example/did.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let err = fetch_did_document_http11(
        &format!("http://127.0.0.1:{port}/.well-known/did.json"),
        &WebFetchOptions {
            allow_insecure_http: true,
            ..WebFetchOptions::default()
        },
    )
    .unwrap_err();

    worker.join().unwrap();
    assert_eq!(err.message, "DID document endpoint returned non-200 status");
}

#[test]
fn did_web_fetch_http1_returns_non_200_error_text_matching_cpp() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to bind local DID HTTP test server: {err}"),
    };
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let err = fetch_did_document_http11(
        &format!("http://127.0.0.1:{port}/.well-known/did.json"),
        &WebFetchOptions {
            allow_insecure_http: true,
            ..WebFetchOptions::default()
        },
    )
    .unwrap_err();

    worker.join().unwrap();
    assert_eq!(err.message, "DID document endpoint returned non-200 status");
}

#[test]
fn did_web_fetch_http1_enforces_max_response_bytes() {
    let body = "x".repeat(1024);
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to bind local DID HTTP test server: {err}"),
    };
    let port = listener.local_addr().unwrap().port();
    let body_for_thread = body.clone();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_for_thread.len(),
            body_for_thread
        );
        let _ = stream.write_all(response.as_bytes());
    });

    let err = fetch_did_document_http11(
        &format!("http://127.0.0.1:{port}/.well-known/did.json"),
        &WebFetchOptions {
            allow_insecure_http: true,
            max_response_bytes: 64,
            ..WebFetchOptions::default()
        },
    )
    .unwrap_err();

    worker.join().unwrap();
    assert_eq!(err.message, "DID document response exceeded max size");
}

#[test]
fn did_web_fetch_http1_fetches_document_over_local_http() {
    let body = r#"{"id":"did:web:127.0.0.1","verificationMethod":[{"id":"did:web:127.0.0.1#0","type":"JsonWebKey2020","controller":"did:web:127.0.0.1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AA"}}],"authentication":["did:web:127.0.0.1#0"]}"#;
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(err) => panic!("failed to bind local DID HTTP test server: {err}"),
    };
    let port = listener.local_addr().unwrap().port();
    let body_for_thread = body.to_string();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let read = stream.read(&mut request).unwrap();
        let request_text = String::from_utf8_lossy(&request[..read]);
        assert!(request_text.starts_with("GET /.well-known/did.json HTTP/1.1\r\n"));
        assert!(request_text.contains("Host: 127.0.0.1:"));

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_for_thread.len(),
            body_for_thread
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let fetched = fetch_did_document_http11(
        &format!("http://127.0.0.1:{port}/.well-known/did.json"),
        &WebFetchOptions {
            allow_insecure_http: true,
            ..WebFetchOptions::default()
        },
    )
    .unwrap();

    worker.join().unwrap();
    assert_eq!(fetched, body);
}
