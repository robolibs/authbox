use super::{DidResult, error, parse};
use keylock::crypto::{Context, secp256k1};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PkhComponents {
    pub namespace_id: String,
    pub chain_id: String,
    pub address: String,
}

pub fn parse_did_pkh(did_uri: &str) -> DidResult<PkhComponents> {
    let parsed = parse(did_uri)?;
    if parsed.method != "pkh" {
        return Err(error::invalid_method_id("method must be 'pkh'"));
    }
    if parsed.method_id.is_empty() {
        return Err(error::invalid_method_id("did:pkh method-id is empty"));
    }
    let parts: Vec<&str> = parsed.method_id.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(error::invalid_method_id(
            "did:pkh method-id must contain at least two colons",
        ));
    }
    let namespace_id = parts[0];
    let chain_id = parts[1];
    let address = parts[2];
    if namespace_id.len() < 3 || namespace_id.len() > 8 {
        return Err(error::invalid_method_id("namespace must be 3-8 characters"));
    }
    if !namespace_id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(error::invalid_method_id(
            "namespace must be lowercase alphanumeric",
        ));
    }
    if chain_id.is_empty() || chain_id.len() > 32 {
        return Err(error::invalid_method_id("chain_id must be 1-32 characters"));
    }
    if !chain_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(error::invalid_method_id(
            "chain_id must be alphanumeric with . or -",
        ));
    }
    if address.is_empty() || address.len() > 64 {
        return Err(error::invalid_method_id("address must be 1-64 characters"));
    }
    if !address
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(error::invalid_method_id(
            "address contains invalid characters",
        ));
    }
    Ok(PkhComponents {
        namespace_id: namespace_id.to_string(),
        chain_id: chain_id.to_string(),
        address: address.to_string(),
    })
}

pub fn get_blockchain_account_id(components: &PkhComponents) -> String {
    format!(
        "{}:{}:{}",
        components.namespace_id, components.chain_id, components.address
    )
}

pub fn get_chain_name(components: &PkhComponents) -> String {
    match (
        components.namespace_id.as_str(),
        components.chain_id.as_str(),
    ) {
        ("eip155", "1") => "Ethereum Mainnet".to_string(),
        ("eip155", "5") => "Ethereum Goerli".to_string(),
        ("eip155", "137") => "Polygon Mainnet".to_string(),
        ("eip155", "8453") => "Base".to_string(),
        ("eip155", chain) => format!("Ethereum Chain {chain}"),
        ("bip122", _) => "Bitcoin".to_string(),
        ("cosmos", chain) => format!("Cosmos {chain}"),
        _ => format!("{}:{}", components.namespace_id, components.chain_id),
    }
}

pub fn resolve_did_pkh_document_json(did_uri: &str) -> DidResult<String> {
    let components = parse_did_pkh(did_uri)?;
    let account_id = get_blockchain_account_id(&components);
    Ok(format!(
        "{{\n  \"@context\": [\n    \"https://www.w3.org/ns/did/v1\",\n    \"https://w3id.org/security/suites/secp256k1-2019/v1\"\n  ],\n  \"id\": \"{did_uri}\",\n  \"verificationMethod\": [\n    {{\n      \"id\": \"{did_uri}#blockchainAccountId\",\n      \"type\": \"EcdsaSecp256k1RecoveryMethod2020\",\n      \"controller\": \"{did_uri}\",\n      \"blockchainAccountId\": \"{account_id}\"\n    }}\n  ],\n  \"authentication\": [\"{did_uri}#blockchainAccountId\"],\n  \"assertionMethod\": [\"{did_uri}#blockchainAccountId\"]\n}}\n"
    ))
}

pub fn verify_ethereum_signature(address: &str, message: &str, signature: &str) -> DidResult<bool> {
    let expected_address = normalize_ethereum_address(address)?;
    let signature = decode_prefixed_hex(signature)?;
    if signature.len() != secp256k1::RECOVERABLE_SIGNATURE_BYTES {
        return Err(error::invalid_key_length(
            secp256k1::RECOVERABLE_SIGNATURE_BYTES,
            signature.len(),
        ));
    }

    let normalized_v = secp256k1::normalize_recovery_id(signature[64]);
    if !normalized_v.success {
        return Err(error::invalid_key_format(normalized_v.error_message));
    }

    let digest = ethereum_personal_message_digest(message.as_bytes());
    let recovered =
        secp256k1::recover_public_key(&digest, &signature[..64], normalized_v.recovery_id);
    if !recovered.success {
        return Err(error::invalid_key_format(recovered.error_message));
    }

    let recovered_address = Context::to_hex(&secp256k1::ethereum_address_from_uncompressed_pubkey(
        &recovered.public_key_uncompressed,
    ));
    Ok(recovered_address == expected_address)
}

fn normalize_ethereum_address(address: &str) -> DidResult<String> {
    let stripped = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .ok_or_else(|| error::invalid_key_format("Ethereum address must start with 0x"))?;
    if stripped.len() != 40 {
        return Err(error::invalid_key_format(
            "Ethereum address must contain 20 bytes",
        ));
    }
    if !stripped.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error::invalid_key_format(
            "Ethereum address contains non-hex characters",
        ));
    }
    Ok(stripped.to_ascii_lowercase())
}

fn decode_prefixed_hex(value: &str) -> DidResult<Vec<u8>> {
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !stripped.len().is_multiple_of(2) {
        return Err(error::invalid_key_format("hex value has odd length"));
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for pair in stripped.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])
            .ok_or_else(|| error::invalid_key_format("hex value contains non-hex characters"))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| error::invalid_key_format("hex value contains non-hex characters"))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + byte - b'a'),
        b'A'..=b'F' => Some(10 + byte - b'A'),
        _ => None,
    }
}

fn ethereum_personal_message_digest(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut framed = Vec::with_capacity(prefix.len() + message.len());
    framed.extend_from_slice(prefix.as_bytes());
    framed.extend_from_slice(message);
    keylock::keccak256(&framed)
}
