use super::{DidError, DidErrorCode, DidResult};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebFetchOptions {
    pub allow_insecure_http: bool,
    pub skip_tls_certificate_verification_for_testing: bool,
    pub max_response_bytes: usize,
    pub user_agent: String,
    pub recv_timeout_ms: u32,
}

impl Default for WebFetchOptions {
    fn default() -> Self {
        Self {
            allow_insecure_http: false,
            skip_tls_certificate_verification_for_testing: false,
            max_response_bytes: 1024 * 1024,
            user_agent: "authbox-did/0.1".to_string(),
            recv_timeout_ms: 5000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub target: String,
}

impl Default for ParsedUrl {
    fn default() -> Self {
        Self {
            scheme: String::new(),
            host: String::new(),
            port: 0,
            target: "/".to_string(),
        }
    }
}

pub mod detail {
    use super::{DidResult, ParsedUrl};

    pub fn parse_port(text: &str) -> DidResult<u16> {
        super::parse_port(text)
    }

    pub fn parse_http_url(url: &str) -> DidResult<ParsedUrl> {
        super::parse_http_url(url)
    }
}

pub fn parse_http_url(url: &str) -> DidResult<ParsedUrl> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid_url_error("URL is missing scheme"));
    };
    let (authority, target) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return Err(invalid_url_error("URL authority is empty"));
    }

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return Err(invalid_url_error("Invalid IPv6 authority"));
        };
        let host = &stripped[..close];
        let after = &stripped[close + 1..];
        let port = if after.is_empty() {
            default_port(scheme)
        } else if let Some(port) = after.strip_prefix(':') {
            parse_port(port)?
        } else {
            return Err(invalid_url_error("Invalid authority after IPv6 host"));
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            (authority.to_string(), default_port(scheme))
        } else {
            (host.to_string(), parse_port(port)?)
        }
    } else {
        (authority.to_string(), default_port(scheme))
    };
    if host.is_empty() {
        return Err(invalid_url_error("URL host is empty"));
    }
    let target = if target.is_empty() {
        "/".to_string()
    } else {
        format!("/{target}")
    };
    Ok(ParsedUrl {
        scheme: scheme.to_string(),
        host,
        port,
        target,
    })
}

pub fn make_web_http_fetcher() -> impl Fn(&str) -> DidResult<String> + Clone {
    make_web_http_fetcher_with_options(WebFetchOptions::default())
}

pub fn make_web_http_fetcher_with_options(
    options: WebFetchOptions,
) -> impl Fn(&str) -> DidResult<String> + Clone {
    move |url| fetch_did_document_http11(url, &options)
}

pub fn make_web_http11_resolver() -> super::Resolver {
    make_web_http11_resolver_with_options(WebFetchOptions::default())
}

pub fn make_web_http11_resolver_with_options(options: WebFetchOptions) -> super::Resolver {
    super::Resolver::with_fetcher(make_web_http_fetcher_with_options(options))
}

pub fn fetch_did_document_http11(url: &str, options: &WebFetchOptions) -> DidResult<String> {
    let parsed = parse_http_url(url)?;
    if parsed.scheme == "http" {
        if !options.allow_insecure_http {
            return Err(fetch_error(
                "Insecure HTTP is disabled for DID document fetch",
            ));
        }
    } else if parsed.scheme == "https" {
        return fetch_https_did_document(url, options);
    } else {
        return Err(fetch_error("Unsupported URL scheme"));
    }

    let timeout = Duration::from_millis(u64::from(options.recv_timeout_ms));
    let mut stream = connect_tcp(&parsed, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| fetch_error(format!("set read timeout failed: {err}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| fetch_error(format!("set write timeout failed: {err}")))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\nUser-Agent: {}\r\n\r\n",
        parsed.target,
        host_header(&parsed),
        options.user_agent
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| fetch_error(format!("socket send failed: {err}")))?;
    stream
        .flush()
        .map_err(|err| fetch_error(format!("socket flush failed: {err}")))?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() > options.max_response_bytes {
                    return Err(fetch_error("DID document response exceeded max size"));
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(fetch_error(format!("socket recv failed: {err}"))),
        }
    }
    decode_http_response(&response, options.max_response_bytes)
}

fn fetch_https_did_document(url: &str, options: &WebFetchOptions) -> DidResult<String> {
    let timeout = Duration::from_millis(u64::from(options.recv_timeout_ms));
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(options.skip_tls_certificate_verification_for_testing)
        .user_agent(options.user_agent.clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| fetch_error(err.to_string()))?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .map_err(|err| fetch_error(err.to_string()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(fetch_error("DID document endpoint returned non-200 status"));
    }

    let limit = options.max_response_bytes.saturating_add(1) as u64;
    let mut body = Vec::new();
    response
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|err| fetch_error(err.to_string()))?;
    if body.len() > options.max_response_bytes {
        return Err(fetch_error("DID document response exceeded max size"));
    }
    String::from_utf8(body).map_err(|_| fetch_error("DID document response body is not UTF-8"))
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
}

fn parse_port(port: &str) -> DidResult<u16> {
    let mut chars = port.trim_start().chars().peekable();
    let negative = match chars.peek().copied() {
        Some('+') => {
            chars.next();
            false
        }
        Some('-') => {
            chars.next();
            true
        }
        _ => false,
    };

    let mut saw_digit = false;
    let mut value: u32 = 0;
    while let Some(ch) = chars.peek().copied() {
        let Some(digit) = ch.to_digit(10) else {
            break;
        };
        saw_digit = true;
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| invalid_url_error("Invalid URL port"))?;
        chars.next();
    }

    if !saw_digit || negative || value == 0 || value > u16::MAX as u32 {
        return Err(invalid_url_error("Invalid URL port"));
    }
    Ok(value as u16)
}

fn connect_tcp(parsed: &ParsedUrl, timeout: Duration) -> DidResult<TcpStream> {
    let addrs = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|err| fetch_error(format!("getaddrinfo failed: {err}")))?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }
    Err(fetch_error(format!(
        "connect failed{}",
        last_error.map(|err| format!(": {err}")).unwrap_or_default()
    )))
}

fn host_header(parsed: &ParsedUrl) -> String {
    let default = (parsed.scheme == "https" && parsed.port == 443)
        || (parsed.scheme == "http" && parsed.port == 80);
    let host = if parsed.host.contains(':') {
        format!("[{}]", parsed.host)
    } else {
        parsed.host.clone()
    };
    if default {
        host
    } else {
        format!("{host}:{}", parsed.port)
    }
}

fn decode_http_response(response: &[u8], max_response_bytes: usize) -> DidResult<String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let body_start = match parsed.parse(response) {
        Ok(httparse::Status::Complete(body_start)) => body_start,
        Ok(httparse::Status::Partial) => return Err(fetch_error("invalid HTTP response")),
        Err(_) => return Err(fetch_error("invalid HTTP response")),
    };
    let status = parsed
        .code
        .ok_or_else(|| fetch_error("missing HTTP status code"))?;
    if status != 200 {
        return Err(fetch_error("DID document endpoint returned non-200 status"));
    }
    let mut content_length = None;
    let mut chunked = false;
    for header in parsed.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| fetch_error("HTTP response headers are not UTF-8"))?;
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| fetch_error("invalid HTTP Content-Length"))?,
            );
        } else if header.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(header.value)
                .map_err(|_| fetch_error("HTTP response headers are not UTF-8"))?
                .to_ascii_lowercase()
                .contains("chunked")
        {
            chunked = true;
        }
    }
    let body = if chunked {
        decode_chunked_body(&response[body_start..], max_response_bytes)?
    } else if let Some(length) = content_length {
        let end = body_start
            .checked_add(length)
            .ok_or_else(|| fetch_error("HTTP Content-Length overflow"))?;
        if end > response.len() {
            return Err(fetch_error("truncated HTTP response body"));
        }
        response[body_start..end].to_vec()
    } else {
        response[body_start..].to_vec()
    };
    if body.len() > max_response_bytes {
        return Err(fetch_error("DID document response exceeded max size"));
    }
    String::from_utf8(body).map_err(|_| fetch_error("DID document response body is not UTF-8"))
}

fn decode_chunked_body(input: &[u8], max_response_bytes: usize) -> DidResult<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let Some(line_end_rel) = find_crlf(&input[pos..]) else {
            return Err(fetch_error("truncated chunked response"));
        };
        let line_end = pos + line_end_rel;
        let line = std::str::from_utf8(&input[pos..line_end])
            .map_err(|_| fetch_error("invalid chunk size line"))?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() {
            return Err(fetch_error("missing chunk size"));
        }
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| fetch_error("invalid chunk size"))?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        let data_end = pos
            .checked_add(size)
            .ok_or_else(|| fetch_error("chunk size overflow"))?;
        let crlf_end = data_end
            .checked_add(2)
            .ok_or_else(|| fetch_error("chunk size overflow"))?;
        if crlf_end > input.len() {
            return Err(fetch_error("truncated chunk data"));
        }
        if &input[data_end..crlf_end] != b"\r\n" {
            return Err(fetch_error("chunk missing CRLF terminator"));
        }
        out.extend_from_slice(&input[pos..data_end]);
        if out.len() > max_response_bytes {
            return Err(fetch_error("DID document response exceeded max size"));
        }
        pos = crlf_end;
    }
}

fn find_crlf(input: &[u8]) -> Option<usize> {
    input.windows(2).position(|window| window == b"\r\n")
}

fn invalid_url_error(message: impl Into<String>) -> DidError {
    DidError::new(DidErrorCode::InvalidDidUri, message)
}

fn fetch_error(message: impl Into<String>) -> DidError {
    DidError::new(DidErrorCode::NetworkError, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_chunked_response_body() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: application/json\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "7\r\n{\"id\":\"\r\n",
            "e;ext=value\r\ndid:web:test\"}\r\n",
            "0\r\n",
            "\r\n"
        );
        assert_eq!(
            decode_http_response(response.as_bytes(), 1024).unwrap(),
            r#"{"id":"did:web:test"}"#
        );
    }

    #[test]
    fn decode_chunked_response_rejects_bad_chunks() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nx\r\nnope\r\n0\r\n\r\n";
        assert!(decode_http_response(response, 1024).is_err());

        let too_large =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n1234\r\n0\r\n\r\n";
        assert!(decode_http_response(too_large, 3).is_err());
    }
}
