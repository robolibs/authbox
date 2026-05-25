use super::{DidResult, error, parse};
use base64ct::{Base64UrlUnpadded, Encoding as _};

pub fn base58btc_decode(input: &str) -> DidResult<Vec<u8>> {
    if input.is_empty() {
        return Err(error::invalid_key_format("empty base58 string"));
    }
    bs58::decode(input)
        .into_vec()
        .map_err(|_| error::invalid_key_format("invalid base58 character"))
}

pub fn base58btc_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        // Preserve the existing C++-surface test expectation for the helper.
        "1".to_string()
    } else {
        bs58::encode(bytes).into_string()
    }
}

pub fn base64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn base64url_decode(input: &str) -> DidResult<Vec<u8>> {
    if input.is_empty() {
        return Err(error::invalid_key_format("empty base64url string"));
    }
    if input.contains('=') {
        return Err(error::invalid_key_format("invalid base64url encoding"));
    }
    Base64UrlUnpadded::decode_vec(input)
        .map_err(|_| error::invalid_key_format("invalid base64url encoding"))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DidKeyType {
    #[default]
    Ed25519,
    X25519,
}

#[allow(non_upper_case_globals)]
impl DidKeyType {
    pub const ED25519: Self = Self::Ed25519;
    pub const X25519: Self = Self::X25519;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DidKeyInfo {
    pub type_: DidKeyType,
    pub public_key: Vec<u8>,
    pub prefixed_key: Vec<u8>,
    pub fingerprint: String,
    pub did_uri: String,
}

pub fn parse_did_key(did_uri: &str) -> DidResult<DidKeyInfo> {
    let parsed = parse(did_uri)?;
    if parsed.method != "key" {
        return Err(error::invalid_method_id("method must be 'key'"));
    }
    if parsed.method_id.len() < 2 || !parsed.method_id.starts_with('z') {
        return Err(error::invalid_key_format(
            "did:key fingerprint must use multibase base58btc (z...)",
        ));
    }
    let decoded = base58btc_decode(&parsed.method_id[1..])?;
    if decoded.len() < 34 {
        return Err(error::invalid_key_format("multicodec payload too short"));
    }
    let type_ = match decoded[..2] {
        [0xed, 0x01] => DidKeyType::Ed25519,
        [0xec, 0x01] => DidKeyType::X25519,
        _ => return Err(error::unsupported_key_type("unsupported multicodec prefix")),
    };
    let public_key = decoded[2..].to_vec();
    if public_key.len() != 32 {
        return Err(error::invalid_key_length(32, public_key.len()));
    }
    Ok(DidKeyInfo {
        type_,
        public_key,
        prefixed_key: decoded,
        fingerprint: parsed.method_id,
        did_uri: did_uri.to_string(),
    })
}

pub fn encode_ed25519_did_key(public_key: [u8; 32]) -> DidResult<String> {
    let mut payload = Vec::with_capacity(34);
    payload.extend([0xed, 0x01]);
    payload.extend(public_key);
    Ok(format!("did:key:z{}", base58btc_encode(&payload)))
}

pub fn resolve_did_key_document_json(did_uri: &str) -> DidResult<String> {
    let info = parse_did_key(did_uri)?;
    let vm_id = format!("{did_uri}#{}", info.fingerprint);
    let x = base64url_encode(&info.public_key);
    let (crv, relationship_key) = match info.type_ {
        DidKeyType::Ed25519 => ("Ed25519", "authentication"),
        DidKeyType::X25519 => ("X25519", "keyAgreement"),
    };
    Ok(format!(
        "{{\n  \"@context\": [\n    \"https://www.w3.org/ns/did/v1\",\n    \"https://w3id.org/security/suites/jws-2020/v1\"\n  ],\n  \"id\": \"{did_uri}\",\n  \"verificationMethod\": [\n    {{\n      \"id\": \"{vm_id}\",\n      \"type\": \"JsonWebKey2020\",\n      \"controller\": \"{did_uri}\",\n      \"publicKeyJwk\": {{\n        \"kty\": \"OKP\",\n        \"crv\": \"{crv}\",\n        \"x\": \"{x}\"\n      }}\n    }}\n  ],\n  \"{relationship_key}\": [\n    \"{vm_id}\"\n  ]\n}}\n"
    ))
}
