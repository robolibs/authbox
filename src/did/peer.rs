use super::{DidResult, base58btc_decode, base64url_decode, base64url_encode, error, parse};
use crate::json::{Json, parse as parse_json, to_compact_string};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PeerElementType {
    #[default]
    Verification,
    Encryption,
    Service,
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerElement {
    pub type_: PeerElementType,
    pub encoded_value: String,
}

pub fn parse_did_peer(did_uri: &str) -> DidResult<Vec<PeerElement>> {
    let parsed = parse(did_uri)?;
    if parsed.method != "peer" {
        return Err(error::invalid_method_id("method must be 'peer'"));
    }
    if !parsed.method_id.starts_with("2.") {
        return Err(error::not_implemented("only did:peer:2 is supported"));
    }
    let mut out = Vec::new();
    for element in parsed.method_id[2..].split('.') {
        if element.is_empty() {
            continue;
        }
        let (type_char, encoded_value) = element.split_at(1);
        let type_ = match type_char {
            "V" => PeerElementType::Verification,
            "E" => PeerElementType::Encryption,
            "S" => PeerElementType::Service,
            _ => PeerElementType::Unknown,
        };
        out.push(PeerElement {
            type_,
            encoded_value: encoded_value.to_string(),
        });
    }
    if out.is_empty() {
        return Err(error::invalid_method_id(
            "did:peer:2 must have at least one element",
        ));
    }
    Ok(out)
}

pub fn decode_peer_key(encoded: &str) -> DidResult<Vec<u8>> {
    if encoded.is_empty() {
        return Err(error::invalid_key_format("empty encoded key"));
    }
    if !encoded.starts_with('z') {
        return Err(error::invalid_key_format(
            "only base58btc (z) encoding is supported",
        ));
    }
    base58btc_decode(&encoded[1..])
}

pub fn resolve_did_peer_document_json(did_uri: &str) -> DidResult<String> {
    let elements = parse_did_peer(did_uri)?;
    let mut vm_entries = Vec::new();
    let mut auth_refs = Vec::new();
    let mut ka_refs = Vec::new();
    let mut service_entries = Vec::new();
    let mut vm_index = 0usize;
    let mut service_index = 0usize;
    for element in &elements {
        match element.type_ {
            PeerElementType::Verification | PeerElementType::Encryption => {
                let key_bytes = match decode_peer_key(&element.encoded_value) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                if key_bytes.len() < 34 {
                    continue;
                }
                let crv = match key_bytes[..2] {
                    [0xed, 0x01] => "Ed25519",
                    [0xec, 0x01] => "X25519",
                    _ => continue,
                };
                let raw_key = &key_bytes[2..];
                if raw_key.len() != 32 {
                    continue;
                }
                let vm_id = format!("{did_uri}#key-{vm_index}");
                vm_entries.push(format!(
                    "    {{\n      \"id\": \"{vm_id}\",\n      \"type\": \"JsonWebKey2020\",\n      \"controller\": \"{did_uri}\",\n      \"publicKeyJwk\": {{\n        \"kty\": \"OKP\",\n        \"crv\": \"{crv}\",\n        \"x\": \"{}\"\n      }}\n    }}",
                    base64url_encode(raw_key)
                ));
                vm_index += 1;
            }
            PeerElementType::Service => {
                if let Some(entry) = service_entry(did_uri, &element.encoded_value, service_index) {
                    service_entries.push(entry);
                    service_index += 1;
                }
            }
            _ => {}
        }
    }
    // C++ compatibility: relationship references are assigned in a second pass
    // from all V/E elements, even if the corresponding verificationMethod entry
    // was skipped because its key could not be decoded.
    let mut relationship_index = 0usize;
    for element in &elements {
        match element.type_ {
            PeerElementType::Verification => {
                auth_refs.push(format!("{did_uri}#key-{relationship_index}"));
                relationship_index += 1;
            }
            PeerElementType::Encryption => {
                ka_refs.push(format!("{did_uri}#key-{relationship_index}"));
                relationship_index += 1;
            }
            _ => {}
        }
    }
    let mut doc = format!(
        "{{\n  \"@context\": [\n    \"https://www.w3.org/ns/did/v1\",\n    \"https://w3id.org/security/suites/jws-2020/v1\"\n  ],\n  \"id\": \"{did_uri}\",\n  \"verificationMethod\": [\n{}\n  ]",
        vm_entries.join(",\n")
    );
    if !auth_refs.is_empty() {
        doc.push_str(",\n  \"authentication\": [\n");
        doc.push_str(
            &auth_refs
                .iter()
                .map(|r| format!("    \"{r}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        doc.push_str("\n  ]");
    }
    if !ka_refs.is_empty() {
        doc.push_str(",\n  \"keyAgreement\": [\n");
        doc.push_str(
            &ka_refs
                .iter()
                .map(|r| format!("    \"{r}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        doc.push_str("\n  ]");
    }
    if !service_entries.is_empty() {
        doc.push_str(",\n  \"service\": [\n");
        doc.push_str(&service_entries.join(",\n"));
        doc.push_str("\n  ]");
    }
    doc.push_str("\n}\n");
    Ok(doc)
}

fn service_entry(did_uri: &str, encoded_value: &str, service_index: usize) -> Option<String> {
    let decoded = base64url_decode(encoded_value).ok()?;
    let service_json = std::str::from_utf8(&decoded).ok()?;
    let Json::Object(object) = parse_json(service_json).ok()? else {
        return None;
    };
    let id = json_string_field(&object, "id")
        .or_else(|| json_string_field(&object, "i"))
        .unwrap_or_else(|| format!("#service-{service_index}"));
    let type_ = json_string_field(&object, "type")
        .or_else(|| json_string_field(&object, "t"))
        .unwrap_or_else(|| "DIDCommMessaging".to_string());
    let endpoint = object
        .get("serviceEndpoint")
        .or_else(|| object.get("s"))
        .map(to_compact_string)?;
    let id = if id.starts_with('#') {
        format!("{did_uri}{id}")
    } else {
        id
    };
    Some(format!(
        "    {{\n      \"id\": {},\n      \"type\": {},\n      \"serviceEndpoint\": {}\n    }}",
        to_compact_string(&Json::String(id)),
        to_compact_string(&Json::String(type_)),
        endpoint
    ))
}

fn json_string_field(
    object: &std::collections::BTreeMap<String, Json>,
    key: &str,
) -> Option<String> {
    match object.get(key) {
        Some(Json::String(text)) => Some(text.clone()),
        _ => None,
    }
}
