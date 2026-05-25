use super::super::*;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, signature::hazmat::PrehashSigner};
use keylock::crypto::Context;

const ETH_MAINNET: &str = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";
const POLYGON: &str = "did:pkh:eip155:137:0x1234567890123456789012345678901234567890";
const BITCOIN: &str = "did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3";
const COSMOS: &str = "did:pkh:cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0";

#[test]
fn did_pkh_components_default_matches_cpp_aggregate_defaults() {
    let components = PkhComponents::default();

    assert_eq!(components.namespace_id, "");
    assert_eq!(components.chain_id, "");
    assert_eq!(components.address, "");
}

#[test]
fn did_pkh_parses_supported_account_ids() {
    let eth = parse_did_pkh(ETH_MAINNET).unwrap();
    assert_eq!(eth.namespace_id, "eip155");
    assert_eq!(eth.chain_id, "1");
    assert_eq!(eth.address, "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");

    let polygon = parse_did_pkh(POLYGON).unwrap();
    assert_eq!(polygon.namespace_id, "eip155");
    assert_eq!(polygon.chain_id, "137");
    assert_eq!(
        polygon.address,
        "0x1234567890123456789012345678901234567890"
    );

    let bitcoin = parse_did_pkh(BITCOIN).unwrap();
    assert_eq!(bitcoin.namespace_id, "bip122");
    assert_eq!(bitcoin.chain_id, "000000000019d6689c085ae165831e93");
    assert_eq!(bitcoin.address, "128Lkh3S7CkDTBZ8W7BbpsN3");

    let cosmos = parse_did_pkh(COSMOS).unwrap();
    assert_eq!(cosmos.namespace_id, "cosmos");
    assert_eq!(cosmos.chain_id, "cosmoshub-3");
    assert_eq!(
        cosmos.address,
        "cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0"
    );
}

#[test]
fn did_pkh_rejects_invalid_method_id_shapes() {
    assert!(parse_did_pkh("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_err());
    assert!(parse_did_pkh("did:pkh:").is_err());
    assert!(parse_did_pkh("did:pkh:eip155-1-0xabcd").is_err());
    assert!(parse_did_pkh("did:pkh:ab:1:0xabcd").is_err());
    assert!(parse_did_pkh("did:pkh:EIP155:1:0xabcd").is_err());
    assert!(parse_did_pkh("did:pkh:eip155:123456789012345678901234567890123:0xabcd").is_err());
    assert!(parse_did_pkh(&format!("did:pkh:eip155:1:{}", "a".repeat(65))).is_err());
}

#[test]
fn did_pkh_validation_errors_match_cpp_surface() {
    fn assert_method_id_error(did_uri: &str, expected_detail: &str) {
        let error = match parse_did_pkh(did_uri) {
            Ok(_) => panic!("expected did:pkh parse error for {did_uri}"),
            Err(error) => error,
        };
        assert_eq!(error.code, DidErrorCode::InvalidMethodSpecificId);
        assert_eq!(
            error.message,
            format!("Invalid DID method-specific-id: {expected_detail}")
        );
    }

    assert_method_id_error(
        "did:pkh:eip155-1-0xabcd",
        "did:pkh method-id must contain at least two colons",
    );
    assert_method_id_error("did:pkh:ab:1:0xabcd", "namespace must be 3-8 characters");
    assert_method_id_error(
        "did:pkh:EIP155:1:0xabcd",
        "namespace must be lowercase alphanumeric",
    );
    assert_method_id_error(
        "did:pkh:eip155:123456789012345678901234567890123:0xabcd",
        "chain_id must be 1-32 characters",
    );
    assert_method_id_error(
        "did:pkh:eip155:bad_chain:0xabcd",
        "chain_id must be alphanumeric with . or -",
    );
    assert_method_id_error(
        &format!("did:pkh:eip155:1:{}", "a".repeat(65)),
        "address must be 1-64 characters",
    );
    assert_method_id_error(
        "did:pkh:eip155:1:0xabc%20",
        "address contains invalid characters",
    );
}

#[test]
fn did_pkh_formats_account_id_and_chain_names() {
    let eth = PkhComponents {
        namespace_id: "eip155".to_string(),
        chain_id: "1".to_string(),
        address: "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb".to_string(),
    };
    assert_eq!(
        get_blockchain_account_id(&eth),
        "eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"
    );
    assert_eq!(get_chain_name(&eth), "Ethereum Mainnet");

    let polygon = PkhComponents {
        namespace_id: "eip155".to_string(),
        chain_id: "137".to_string(),
        address: "0xabcd".to_string(),
    };
    assert_eq!(get_chain_name(&polygon), "Polygon Mainnet");

    let unknown = PkhComponents {
        namespace_id: "eip155".to_string(),
        chain_id: "999".to_string(),
        address: "0xabcd".to_string(),
    };
    assert_eq!(get_chain_name(&unknown), "Ethereum Chain 999");
}

#[test]
fn did_pkh_resolves_documents_with_blockchain_account_ids() {
    let eth_json = resolve_did_pkh_document_json(ETH_MAINNET).unwrap();
    assert!(eth_json.contains(&format!("\"id\": \"{ETH_MAINNET}\"")));
    assert!(eth_json.contains("verificationMethod"));
    assert!(eth_json.contains("authentication"));
    assert!(eth_json.contains("blockchainAccountId"));
    assert!(eth_json.contains("eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"));
    assert!(eth_json.contains("EcdsaSecp256k1RecoveryMethod2020"));

    let bitcoin_json = resolve_did_pkh_document_json(BITCOIN).unwrap();
    assert!(bitcoin_json.contains(&format!("\"id\": \"{BITCOIN}\"")));
    assert!(bitcoin_json.contains("blockchainAccountId"));

    let cosmos_json = resolve_did_pkh_document_json(COSMOS).unwrap();
    assert!(cosmos_json.contains(&format!("\"id\": \"{COSMOS}\"")));
    assert!(cosmos_json.contains("cosmos"));
}

#[test]
fn did_pkh_integration_with_resolver_parses_document() {
    let mut resolver = Resolver::new();
    resolver
        .registry_mut()
        .register_method("pkh", |did_uri, _| resolve_did_pkh_document_json(did_uri));

    let resolution = resolver.resolve(ETH_MAINNET).unwrap();
    assert_eq!(resolution.document.id, ETH_MAINNET);
    assert_eq!(resolution.document.verification_methods.len(), 1);
    assert_eq!(
        resolution.document.verification_methods[0]
            .blockchain_account_id
            .as_deref(),
        Some("eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb")
    );
    assert_eq!(resolution.source_url, "did:pkh:inline");
}

#[test]
fn did_pkh_ethereum_signature_helper_recovers_personal_sign_address() {
    let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let address = Context::ethereum_address_from_uncompressed_pubkey(&public_key);
    assert!(address.success, "{}", address.error_message);
    let address_hex = format!("0x{}", Context::to_hex(&address.data));

    let message = "hello from did:pkh";
    let digest = ethereum_personal_message_digest_for_test(message.as_bytes());
    let (signature, recovery_id): (Signature, RecoveryId) =
        signing_key.sign_prehash(&digest).unwrap();
    let mut signature_bytes = signature.to_bytes().to_vec();
    signature_bytes.push(recovery_id.to_byte() + 27);
    let signature_hex = format!("0x{}", Context::to_hex(&signature_bytes));

    assert!(verify_ethereum_signature(&address_hex, message, &signature_hex).unwrap());
    assert!(
        !verify_ethereum_signature(
            "0x0000000000000000000000000000000000000000",
            message,
            &signature_hex
        )
        .unwrap()
    );

    let malformed = verify_ethereum_signature(&address_hex, message, "0xdeadbeef");
    assert!(malformed.is_err());
    assert_eq!(malformed.unwrap_err().code, DidErrorCode::InvalidKeyLength);
}

fn ethereum_personal_message_digest_for_test(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut framed = Vec::with_capacity(prefix.len() + message.len());
    framed.extend_from_slice(prefix.as_bytes());
    framed.extend_from_slice(message);
    keylock::keccak256(&framed)
}
