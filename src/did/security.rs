use super::{DidDocument, VerificationMethod};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptographicStrength {
    Deprecated,
    Acceptable,
    Recommended,
    Experimental,
}

impl CryptographicStrength {
    pub const DEPRECATED: Self = Self::Deprecated;
    pub const ACCEPTABLE: Self = Self::Acceptable;
    pub const RECOMMENDED: Self = Self::Recommended;
    pub const EXPERIMENTAL: Self = Self::Experimental;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityConcern {
    pub strength: CryptographicStrength,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub location: String,
    pub method_id: String,
}

pub fn evaluate_key_type(type_: &str) -> CryptographicStrength {
    if type_.contains("Ed25519") || type_.contains("EdDSA") {
        return CryptographicStrength::Recommended;
    }
    if type_.contains("secp256k1") || type_.contains("EcdsaSecp256k1") {
        return CryptographicStrength::Deprecated;
    }
    if type_.contains("P-256") || type_.contains("secp256r1") || type_.contains("ES256") {
        return CryptographicStrength::Acceptable;
    }
    if type_.contains("P-384") || type_.contains("secp384r1") || type_.contains("ES384") {
        return CryptographicStrength::Acceptable;
    }
    if type_.contains("P-521") || type_.contains("secp521r1") || type_.contains("ES512") {
        return CryptographicStrength::Acceptable;
    }
    if type_.contains("RSA")
        || type_.contains("RS256")
        || type_.contains("RS384")
        || type_.contains("RS512")
    {
        return CryptographicStrength::Acceptable;
    }
    if type_.contains("X25519") {
        return CryptographicStrength::Recommended;
    }
    if type_.contains("Bls12381") {
        return CryptographicStrength::Recommended;
    }
    if type_.contains("Dilithium") || type_.contains("Kyber") || type_.contains("Falcon") {
        return CryptographicStrength::Experimental;
    }
    CryptographicStrength::Acceptable
}

pub fn evaluate_jwk_curve(crv: &str) -> CryptographicStrength {
    match crv {
        "Ed25519" | "Ed448" => CryptographicStrength::Recommended,
        "P-256" | "secp256r1" => CryptographicStrength::Acceptable,
        "P-384" | "secp384r1" => CryptographicStrength::Acceptable,
        "P-521" | "secp521r1" => CryptographicStrength::Acceptable,
        "secp256k1" => CryptographicStrength::Deprecated,
        "X25519" | "X448" => CryptographicStrength::Recommended,
        _ => CryptographicStrength::Acceptable,
    }
}

pub fn evaluate_verification_method(method: &VerificationMethod, index: usize) -> SecurityConcern {
    let mut strength = evaluate_key_type(&method.type_);
    if let Some(jwk) = &method.public_key_jwk
        && !jwk.crv.is_empty()
    {
        strength = evaluate_jwk_curve(&jwk.crv);
    }
    let (category, description, recommendation) = match strength {
        CryptographicStrength::Deprecated => (
            "Deprecated Cryptography",
            format!("Uses deprecated cryptographic algorithm: {}", method.type_),
            "Migrate to Ed25519 or other recommended algorithms. W3C DID Implementation Guide advises against secp256k1 and RSA < 2048.",
        ),
        CryptographicStrength::Acceptable => (
            "Acceptable Cryptography",
            format!(
                "Uses acceptable but not recommended algorithm: {}",
                method.type_
            ),
            "Consider Ed25519 for signatures or X25519 for key agreement in new implementations.",
        ),
        CryptographicStrength::Recommended => (
            "Recommended Cryptography",
            format!("Uses recommended cryptographic algorithm: {}", method.type_),
            "No action needed. This is a recommended algorithm.",
        ),
        CryptographicStrength::Experimental => (
            "Experimental Cryptography",
            format!(
                "Uses experimental cryptographic algorithm: {}",
                method.type_
            ),
            "Ensure thorough testing and monitor for standardization progress.",
        ),
    };
    SecurityConcern {
        strength,
        category: category.to_string(),
        description,
        recommendation: recommendation.to_string(),
        location: format!("verificationMethod[{index}]"),
        method_id: method.id.clone(),
    }
}

pub fn scan_document(doc: &DidDocument) -> Vec<SecurityConcern> {
    doc.verification_methods
        .iter()
        .enumerate()
        .map(|(idx, method)| evaluate_verification_method(method, idx))
        .filter(|concern| concern.strength != CryptographicStrength::Recommended)
        .collect()
}

pub fn uses_recommended_cryptography(doc: &DidDocument) -> bool {
    doc.verification_methods
        .iter()
        .all(|method| evaluate_key_type(&method.type_) != CryptographicStrength::Deprecated)
}

pub fn get_cryptography_summary(doc: &DidDocument) -> String {
    let mut deprecated = 0;
    let mut acceptable = 0;
    let mut recommended = 0;
    let mut experimental = 0;
    for method in &doc.verification_methods {
        match evaluate_key_type(&method.type_) {
            CryptographicStrength::Deprecated => deprecated += 1,
            CryptographicStrength::Acceptable => acceptable += 1,
            CryptographicStrength::Recommended => recommended += 1,
            CryptographicStrength::Experimental => experimental += 1,
        }
    }
    format!(
        "Cryptography Summary:\n  Recommended: {recommended}\n  Acceptable: {acceptable}\n  Deprecated: {deprecated}\n  Experimental: {experimental}\n"
    )
}

pub fn format_concerns(concerns: &[SecurityConcern]) -> String {
    if concerns.is_empty() {
        return "No security concerns detected. All cryptography uses recommended algorithms."
            .to_string();
    }

    let mut result = String::from("Security Concerns:\n");
    for concern in concerns {
        result.push_str("\n[");
        result.push_str(match concern.strength {
            CryptographicStrength::Deprecated => "DEPRECATED",
            CryptographicStrength::Acceptable => "ACCEPTABLE",
            CryptographicStrength::Recommended => "RECOMMENDED",
            CryptographicStrength::Experimental => "EXPERIMENTAL",
        });
        result.push_str("] ");
        result.push_str(&concern.category);
        result.push('\n');
        result.push_str("  Location: ");
        result.push_str(&concern.location);
        result.push('\n');
        result.push_str("  Details: ");
        result.push_str(&concern.description);
        result.push('\n');
        result.push_str("  Recommendation: ");
        result.push_str(&concern.recommendation);
        result.push('\n');
    }

    result
}
