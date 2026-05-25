use super::{DidResult, base64url_decode, base64url_encode, error, parse};
use crate::json::{Json, JsonParser, json_string};
use std::collections::BTreeMap;

pub fn canonicalize_jwk_json(jwk_json: &str) -> DidResult<String> {
    let root = JsonParser::new(jwk_json)
        .parse()
        .map_err(|_| error::invalid_key_format("invalid JWK JSON"))?;
    let Json::Object(fields) = root else {
        return Err(error::invalid_key_format("JWK must be a JSON object"));
    };
    let mut canonical = BTreeMap::new();
    for (key, value) in fields {
        if let Json::String(text) = value {
            canonical.insert(key, text);
        }
    }
    Ok(canonicalize_string_fields_no_escape(&canonical))
}

fn canonicalize_string_fields_no_escape(fields: &BTreeMap<String, String>) -> String {
    serde_json::to_string(fields).expect("BTreeMap<String, String> is always JSON serializable")
}

pub fn parse_did_jwk(did_uri: &str) -> DidResult<String> {
    let parsed = parse(did_uri)?;
    if parsed.method != "jwk" {
        return Err(error::invalid_method_id("method must be 'jwk'"));
    }
    let decoded = base64url_decode(&parsed.method_id)?;
    let jwk_json = String::from_utf8(decoded)
        .map_err(|_| error::invalid_key_format("embedded JWK is not valid JSON"))?;
    let root = JsonParser::new(&jwk_json)
        .parse()
        .map_err(|_| error::invalid_key_format("embedded JWK is not valid JSON"))?;
    let Json::Object(fields) = &root else {
        return Err(error::invalid_key_format(
            "embedded JWK must be a JSON object",
        ));
    };
    if !matches!(fields.get("kty"), Some(Json::String(_))) {
        return Err(error::invalid_key_format("JWK missing required field: kty"));
    }
    Ok(jwk_json)
}

pub fn encode_did_jwk(jwk_json: &str) -> DidResult<String> {
    let root = JsonParser::new(jwk_json)
        .parse()
        .map_err(|_| error::invalid_key_format("invalid JWK JSON"))?;
    let Json::Object(fields) = &root else {
        return Err(error::invalid_key_format("JWK must be a JSON object"));
    };
    if !matches!(fields.get("kty"), Some(Json::String(_))) {
        return Err(error::invalid_key_format("JWK missing required field: kty"));
    }
    let canonical = canonicalize_jwk_json(jwk_json)?;
    Ok(format!(
        "did:jwk:{}",
        base64url_encode(canonical.as_bytes())
    ))
}

pub fn resolve_did_jwk_document_json(did_uri: &str) -> DidResult<String> {
    let jwk_json = parse_did_jwk(did_uri)?;
    let root = JsonParser::new(&jwk_json)
        .parse()
        .map_err(|_| error::invalid_key_format("embedded JWK is not valid JSON"))?;
    let kty =
        json_string(&root, "kty").ok_or_else(|| error::invalid_key_format("JWK missing 'kty'"))?;
    let crv = json_string(&root, "crv");
    let relationship_key = match kty.as_str() {
        "OKP" | "EC" => match crv.as_deref() {
            Some("X25519" | "X448") => "keyAgreement",
            _ => "authentication",
        },
        "RSA" => "authentication",
        other => return Err(error::unsupported_key_type(other)),
    };
    let vm_id = format!("{did_uri}#0");
    Ok(format!(
        "{{\n  \"@context\": [\n    \"https://www.w3.org/ns/did/v1\",\n    \"https://w3id.org/security/suites/jws-2020/v1\"\n  ],\n  \"id\": \"{did_uri}\",\n  \"verificationMethod\": [\n    {{\n      \"id\": \"{vm_id}\",\n      \"type\": \"JsonWebKey2020\",\n      \"controller\": \"{did_uri}\",\n      \"publicKeyJwk\": {jwk_json}\n    }}\n  ],\n  \"{relationship_key}\": [\n    \"{vm_id}\"\n  ]\n}}\n"
    ))
}
