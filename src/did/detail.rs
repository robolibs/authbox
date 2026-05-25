//! Compatibility helpers for the shared C++ `authbox::did::detail` namespace.
//!
//! Several C++ DID headers reopen the same `authbox::did::detail` namespace
//! (`key.hpp`, `jwk.hpp`, and `x509.hpp`).  Keep these as a small Rust
//! namespace shim over the hierarchy-matched implementations instead of
//! moving the real method-specific code out of `src/did/key.rs`,
//! `src/did/jwk.rs`, and `src/did/x509.rs`.

use super::{DidResult, JsonWebKey, error, key};
use crate::json::{Json, to_compact_string};

pub const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];
pub const MULTICODEC_X25519_PUB: [u8; 2] = [0xec, 0x01];

pub fn base58_value(ch: char) -> i32 {
    match ch {
        '1'..='9' => ch as i32 - '1' as i32,
        'A'..='H' => 9 + ch as i32 - 'A' as i32,
        'J'..='N' => 17 + ch as i32 - 'J' as i32,
        'P'..='Z' => 22 + ch as i32 - 'P' as i32,
        'a'..='k' => 33 + ch as i32 - 'a' as i32,
        'm'..='z' => 44 + ch as i32 - 'm' as i32,
        _ => -1,
    }
}

pub fn base58btc_decode(input: &str) -> DidResult<Vec<u8>> {
    key::base58btc_decode(input)
}

pub fn base58btc_encode(bytes: &[u8]) -> String {
    key::base58btc_encode(bytes)
}

pub fn base64url_encode_key(bytes: &[u8]) -> String {
    key::base64url_encode(bytes)
}

pub fn base64url_encode(bytes: &[u8]) -> String {
    key::base64url_encode(bytes)
}

pub fn base64url_decode(input: &str) -> DidResult<Vec<u8>> {
    key::base64url_decode(input)
}

pub fn canonicalize_jwk_json(jwk_json: &str) -> DidResult<String> {
    super::jwk::canonicalize_jwk_json(jwk_json)
}

pub fn has_reference(refs: &[String], id: &str) -> bool {
    refs.iter().any(|candidate| candidate == id)
}

pub fn find_object_field<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    let Json::Object(fields) = value else {
        return None;
    };
    fields.get(key)
}

pub fn parse_required_string_field(value: &Json, key: &str) -> DidResult<String> {
    let Some(field) = find_object_field(value, key) else {
        return Err(error::missing_field(key));
    };
    let Json::String(text) = field else {
        return Err(error::field_not_string(key));
    };
    Ok(text.clone())
}

pub fn parse_string_array(value: Option<&Json>) -> Vec<String> {
    let Some(Json::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            Json::String(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

pub fn json_value_to_string(value: Option<&Json>) -> String {
    let Some(value) = value else {
        return "null".to_string();
    };
    to_compact_string(value)
}

pub fn parse_jwk(value: &Json) -> DidResult<JsonWebKey> {
    Ok(JsonWebKey {
        kty: parse_required_string_field(value, "kty")?,
        crv: parse_required_string_field(value, "crv")?,
        x: parse_required_string_field(value, "x")?,
        y: match find_object_field(value, "y") {
            Some(Json::String(text)) => text.clone(),
            _ => String::new(),
        },
    })
}
