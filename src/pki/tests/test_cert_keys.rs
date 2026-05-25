use super::*;

#[test]
fn cert_keys_public_key_der_and_fingerprint() {
    let (cert, _key) = helpers::make_self_signed_certificate("Key Test", 0x6b);

    assert!(!cert.public_key_der().is_empty());
    assert!(!cert.fingerprint(HashAlgorithm::Sha256).unwrap().is_empty());
    assert_eq!(
        cert.public_key_der(),
        spki_from_ed25519_public(&cert.tbs.subject_public_key_info.public_key).unwrap()
    );
}

#[test]
fn cert_keys_public_key_fingerprint_and_json_helpers() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x5a)
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_subject_from_string("CN=Print Test")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x5a; 32])
        .build_with_signature(vec![0x5a; 64], false)
        .unwrap();

    assert_eq!(
        cert.public_key_der(),
        spki_from_ed25519_public(&[0x5a; 32]).unwrap()
    );
    assert_eq!(
        cert.fingerprint(HashAlgorithm::Sha256).unwrap(),
        sha256(cert.der()).to_vec()
    );
    assert_eq!(
        cert.fingerprint(HashAlgorithm::Sha512).unwrap(),
        sha512(cert.der()).to_vec()
    );
    assert!(cert.print_info().contains("Print Test"));
    assert!(cert.to_json().contains("Print Test"));
}

#[test]
fn cert_keys_spki_helper_keeps_cpp_lenient_public_key_length() {
    let spki = spki_from_ed25519_public(&[0x42; 31]).unwrap();

    let parsed = parse_subject_public_key_info(&spki).unwrap();
    assert_eq!(
        parsed.value.algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(parsed.value.public_key, vec![0x42; 31]);
}

#[test]
fn cert_keys_sec1_round_trips_for_each_p_curve() {
    let p256 = generate_ecdsa_p256_keypair().unwrap();
    let sec1_p256 = sec1_from_ecdsa_p256_private(&p256.private_key).unwrap();
    assert_eq!(
        raw_ecdsa_p256_private_key_from_sec1(&sec1_p256).unwrap(),
        p256.private_key
    );

    let p384 = generate_ecdsa_p384_keypair().unwrap();
    let sec1_p384 = sec1_from_ecdsa_p384_private(&p384.private_key).unwrap();
    assert_eq!(
        raw_ecdsa_p384_private_key_from_sec1(&sec1_p384).unwrap(),
        p384.private_key
    );

    let p521 = generate_ecdsa_p521_keypair().unwrap();
    let sec1_p521 = sec1_from_ecdsa_p521_private(&p521.private_key).unwrap();
    assert_eq!(
        raw_ecdsa_p521_private_key_from_sec1(&sec1_p521).unwrap(),
        p521.private_key
    );
}

#[test]
fn cert_keys_sec1_rejects_curve_mismatch() {
    let p256 = generate_ecdsa_p256_keypair().unwrap();
    let sec1_p256 = sec1_from_ecdsa_p256_private(&p256.private_key).unwrap();
    assert!(raw_ecdsa_p384_private_key_from_sec1(&sec1_p256).is_err());
    assert!(raw_ecdsa_p521_private_key_from_sec1(&sec1_p256).is_err());

    let p384 = generate_ecdsa_p384_keypair().unwrap();
    let sec1_p384 = sec1_from_ecdsa_p384_private(&p384.private_key).unwrap();
    assert!(raw_ecdsa_p256_private_key_from_sec1(&sec1_p384).is_err());
}

#[test]
fn cert_keys_pkcs8_pem_encrypt_decrypt_round_trip() {
    let rsa = generate_rsa_keypair(2048).unwrap();
    let pkcs8_der = rsa_private_key_pkcs8_der(&rsa.private_key).unwrap();

    let encrypted_pem =
        encrypt_pkcs8_private_key_pem(&pkcs8_der, b"correct horse battery").unwrap();
    assert!(encrypted_pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    assert!(encrypted_pem.contains("-----END ENCRYPTED PRIVATE KEY-----"));

    let decrypted =
        decrypt_pkcs8_private_key_pem(&encrypted_pem, b"correct horse battery").unwrap();
    assert_eq!(decrypted, pkcs8_der);

    assert!(decrypt_pkcs8_private_key_pem(&encrypted_pem, b"wrong password").is_err());
}

#[test]
fn cert_keys_pkcs8_pem_decrypt_rejects_unrelated_label() {
    let rsa = generate_rsa_keypair(2048).unwrap();
    let pkcs8_der = rsa_private_key_pkcs8_der(&rsa.private_key).unwrap();
    let plain_pem = crate::pki::pem::pem_encode_private_key(&pkcs8_der);
    assert!(decrypt_pkcs8_private_key_pem(&plain_pem, b"any").is_err());
}
