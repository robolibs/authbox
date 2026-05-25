use super::{
    DidDocument, DidError, DidErrorCode, DidResult, JsonWebKey, base64url_encode, error,
    validate_document,
};
use crate::pki::{Certificate, has_did_binding};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DidWebDocumentBundle {
    pub did_uri: String,
    pub verification_method_id: String,
    pub did_document_json: String,
}

pub fn jwk_from_public_key_bytes(public_key: &[u8]) -> DidResult<JsonWebKey> {
    if public_key.len() == 32 {
        return Ok(JsonWebKey {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: base64url_encode(public_key),
            y: String::new(),
        });
    }
    if public_key.len() == 65 && public_key[0] == 0x04 {
        return Ok(JsonWebKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: base64url_encode(&public_key[1..33]),
            y: base64url_encode(&public_key[33..65]),
        });
    }
    Err(DidError::new(
        DidErrorCode::UnsupportedKeyType,
        "Unsupported public key format for DID JWK",
    ))
}

pub fn jwk_from_certificate_public_key(certificate: &Certificate) -> DidResult<JsonWebKey> {
    if certificate
        .tbs
        .subject_public_key_info
        .public_key
        .is_empty()
    {
        return Err(DidError::new(
            DidErrorCode::InvalidKeyFormat,
            "Certificate public key is empty",
        ));
    }
    jwk_from_public_key_bytes(&certificate.tbs.subject_public_key_info.public_key)
}

pub fn generate_did_web_document(
    domain: &str,
    public_key: &[u8],
) -> DidResult<DidWebDocumentBundle> {
    generate_did_web_document_with_fragment(domain, public_key, "#0")
}

pub fn generate_did_web_document_with_fragment(
    domain: &str,
    public_key: &[u8],
    key_fragment: &str,
) -> DidResult<DidWebDocumentBundle> {
    if domain.is_empty() {
        return Err(DidError::new(
            DidErrorCode::InvalidMethodSpecificId,
            "Domain must not be empty",
        ));
    }
    let jwk = jwk_from_public_key_bytes(public_key)?;
    let did_uri = format!("did:web:{domain}");
    let fragment = if key_fragment.is_empty() {
        "#0"
    } else {
        key_fragment
    };
    let fragment = if fragment.starts_with('#') {
        fragment.to_string()
    } else {
        format!("#{fragment}")
    };
    let vm_id = format!("{did_uri}{fragment}");
    let y_line = if jwk.y.is_empty() {
        "".to_string()
    } else {
        format!(",\n        \"y\": \"{}\"", jwk.y)
    };
    let did_document_json = format!(
        "{{\n  \"@context\": [\n    \"https://www.w3.org/ns/did/v1\",\n    \"https://w3id.org/security/suites/jws-2020/v1\"\n  ],\n  \"id\": \"{did_uri}\",\n  \"verificationMethod\": [\n    {{\n      \"id\": \"{vm_id}\",\n      \"type\": \"JsonWebKey2020\",\n      \"controller\": \"{did_uri}\",\n      \"publicKeyJwk\": {{\n        \"kty\": \"{}\",\n        \"crv\": \"{}\",\n        \"x\": \"{}\"{}\n      }}\n    }}\n  ],\n  \"authentication\": [\n    \"{vm_id}\"\n  ],\n  \"assertionMethod\": [\n    \"{vm_id}\"\n  ]\n}}\n",
        jwk.kty, jwk.crv, jwk.x, y_line
    );
    Ok(DidWebDocumentBundle {
        did_uri,
        verification_method_id: vm_id,
        did_document_json,
    })
}

pub fn generate_did_web_document_from_certificate(
    domain: &str,
    certificate: &Certificate,
) -> DidResult<DidWebDocumentBundle> {
    generate_did_web_document_from_certificate_with_fragment(domain, certificate, "#0")
}

pub fn generate_did_web_document_from_certificate_with_fragment(
    domain: &str,
    certificate: &Certificate,
    key_fragment: &str,
) -> DidResult<DidWebDocumentBundle> {
    generate_did_web_document_with_fragment(
        domain,
        &certificate.tbs.subject_public_key_info.public_key,
        key_fragment,
    )
}

pub fn verify_document_binding(
    document: &DidDocument,
    expected_did_uri: &str,
    public_key: &[u8],
) -> DidResult<bool> {
    validate_document(document, expected_did_uri)?;
    let cert_jwk = jwk_from_public_key_bytes(public_key)?;
    for method in &document.verification_methods {
        let Some(method_jwk) = &method.public_key_jwk else {
            continue;
        };
        if method_jwk == &cert_jwk
            && (document.authentication.contains(&method.id)
                || document.assertion_method.contains(&method.id))
        {
            return Ok(true);
        }
    }
    Err(error::invalid_verification_method(
        "no DID verificationMethod matches public key",
    ))
}

pub fn verify_certificate_binding(
    certificate: &Certificate,
    document: &DidDocument,
    expected_did_uri: &str,
) -> DidResult<bool> {
    validate_document(document, expected_did_uri)?;
    if !has_did_binding(certificate, expected_did_uri) {
        return Err(DidError::new(
            DidErrorCode::InvalidVerificationMethod,
            "Certificate does not contain matching DID URI in SAN",
        ));
    }
    let cert_jwk = jwk_from_certificate_public_key(certificate)?;
    for method in &document.verification_methods {
        let Some(method_jwk) = &method.public_key_jwk else {
            continue;
        };
        if method_jwk == &cert_jwk
            && (document.authentication.contains(&method.id)
                || document.assertion_method.contains(&method.id))
        {
            return Ok(true);
        }
    }
    Err(DidError::new(
        DidErrorCode::InvalidVerificationMethod,
        "No DID verificationMethod matches certificate public key",
    ))
}

pub fn verify_certificate_binding_json(
    did_document_json: &str,
    certificate: &Certificate,
    expected_did_uri: &str,
) -> DidResult<bool> {
    let document = super::parse_document(did_document_json)?;
    verify_certificate_binding(certificate, &document, expected_did_uri)
}
