use super::{DidResult, error};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Did {
    pub uri: String,
    pub method: String,
    pub method_id: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DidUrl {
    pub did: Did,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

pub fn is_method_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit()
}

pub fn is_method_id_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-' | '%')
}

pub fn is_hex_char(ch: char) -> bool {
    ch.is_ascii_hexdigit()
}

pub fn is_did_uri(candidate: &str) -> bool {
    if !candidate.starts_with("did:") {
        return false;
    }
    let Some(second_colon) = candidate[4..].find(':').map(|idx| idx + 4) else {
        return false;
    };
    if second_colon == candidate.len() - 1 {
        return false;
    }
    let method = &candidate[4..second_colon];
    if method.is_empty() || !method.chars().all(is_method_char) {
        return false;
    }
    let method_id = &candidate[second_colon + 1..];
    if method_id.is_empty() {
        return false;
    }
    let chars: Vec<char> = method_id.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if !is_method_id_char(ch) {
            return false;
        }
        if ch == '%' {
            if i + 2 >= chars.len() || !is_hex_char(chars[i + 1]) || !is_hex_char(chars[i + 2]) {
                return false;
            }
            i += 2;
        }
        i += 1;
    }
    true
}

pub fn parse(uri: &str) -> DidResult<Did> {
    if !is_did_uri(uri) {
        return Err(error::invalid_did_uri(""));
    }
    let Some(second_colon) = uri[4..].find(':').map(|idx| idx + 4) else {
        return Err(error::invalid_did_uri(""));
    };
    Ok(Did {
        uri: uri.to_string(),
        method: uri[4..second_colon].to_string(),
        method_id: uri[second_colon + 1..].to_string(),
    })
}

pub fn parse_url(did_url: &str) -> DidResult<DidUrl> {
    let hash_pos = did_url.find('#');
    let query_pos = did_url.find('?');
    let path_pos = did_url[4.min(did_url.len())..].find('/').map(|idx| idx + 4);
    let mut did_end = did_url.len();
    for pos in [path_pos, query_pos, hash_pos].into_iter().flatten() {
        did_end = did_end.min(pos);
    }
    let did = parse(&did_url[..did_end])?;
    let mut out = DidUrl {
        did,
        ..DidUrl::default()
    };
    if let Some(path_start) = path_pos {
        let path_end = [query_pos, hash_pos]
            .into_iter()
            .flatten()
            .filter(|pos| *pos > path_start)
            .min()
            .unwrap_or(did_url.len());
        out.path = did_url[path_start..path_end].to_string();
    }
    if let Some(query_start) = query_pos {
        let query_end = hash_pos
            .filter(|pos| *pos > query_start)
            .unwrap_or(did_url.len());
        out.query = did_url[query_start + 1..query_end].to_string();
    }
    if let Some(hash_start) = hash_pos {
        out.fragment = did_url[hash_start + 1..].to_string();
    }
    Ok(out)
}

pub fn percent_decode(input: &str) -> DidResult<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 2 >= bytes.len() {
            return Err(error::invalid_percent_encoding());
        }
        let h1 = hex_value(bytes[i + 1]).ok_or_else(error::invalid_percent_encoding)?;
        let h2 = hex_value(bytes[i + 2]).ok_or_else(error::invalid_percent_encoding)?;
        out.push((h1 << 4) | h2);
        i += 3;
    }
    String::from_utf8(out).map_err(|_| error::invalid_percent_encoding())
}

pub(crate) fn hex_value(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(10 + ch - b'a'),
        b'A'..=b'F' => Some(10 + ch - b'A'),
        _ => None,
    }
}

pub fn did_web_document_url(did_uri: &str) -> DidResult<String> {
    let parsed = parse(did_uri)?;
    if parsed.method != "web" {
        return Err(error::invalid_method_id("method must be 'web'"));
    }
    let segments: Vec<&str> = parsed.method_id.split(':').collect();
    if segments.first().is_none_or(|s| s.is_empty()) {
        return Err(error::invalid_method_id("did:web method-id is empty"));
    }
    let mut url = format!("https://{}", percent_decode(segments[0])?);
    if segments.len() == 1 {
        url.push_str("/.well-known/did.json");
        return Ok(url);
    }
    for segment in &segments[1..] {
        url.push('/');
        url.push_str(&percent_decode(segment)?);
    }
    url.push_str("/did.json");
    Ok(url)
}
