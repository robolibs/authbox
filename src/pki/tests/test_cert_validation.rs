use super::*;

#[test]
fn cert_validation_verifies_signature_against_issuer() {
    let root_key = generate_ed25519_keypair().unwrap();
    let leaf_key = generate_ed25519_keypair().unwrap();
    let root_dn = helpers::dn_from_string("CN=Root");
    let leaf_dn = helpers::dn_from_string("CN=Leaf");
    let root_cert = helpers::make_certificate(
        &root_dn,
        &root_dn,
        &root_key,
        &root_key,
        true,
        key_usage::KEY_CERT_SIGN,
        0x7601,
    );
    let leaf_cert = helpers::make_certificate(
        &root_dn,
        &leaf_dn,
        &root_key,
        &leaf_key,
        false,
        key_usage::DIGITAL_SIGNATURE,
        0x7602,
    );

    assert!(leaf_cert.verify_signature(&root_cert).unwrap());
}

#[test]
fn cert_validation_sign_helper_matches_stored_ed25519_signature() {
    let (cert, key) = helpers::make_self_signed_certificate("SignHelper", 0x7701);

    let signature = cert.sign(&key).unwrap();

    assert_eq!(signature, cert.signature_value);
}

#[test]
fn cert_validation_result_wrappers_match_cpp_surface() {
    let (cert, key) = helpers::make_self_signed_certificate("ResultWrappers", 0x7704);

    let signature: CertificateSignatureResult = cert.sign_result(&key);
    assert!(signature.success);
    assert_eq!(signature.value, cert.signature_value);
    assert!(signature.error.is_empty());

    let valid: CertificateBoolResult = cert.verify_signature_result(&cert);
    assert!(valid.success);
    assert!(valid.value);
    assert!(valid.error.is_empty());
}

#[test]
fn cert_validation_validity_contains_matches_cpp_surface() {
    let validity = Validity {
        not_before: der_time(2026, 1, 1),
        not_after: der_time(2026, 12, 31),
    };

    assert!(validity.contains(&der_time(2026, 1, 1)));
    assert!(validity.contains(&der_time(2026, 6, 1)));
    assert!(validity.contains(&der_time(2026, 12, 31)));
    assert!(!validity.contains(&der_time(2025, 12, 31)));
    assert!(!validity.contains(&der_time(2027, 1, 1)));

    let cert = Certificate {
        tbs: TbsCertificate {
            validity: validity.clone(),
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };
    assert!(cert.check_validity());
    assert!(cert.check_validity_now());
    assert!(cert.check_validity_at(&der_time(2026, 6, 1)));
    assert!(!cert.check_validity_at(&der_time(2027, 1, 1)));
}
