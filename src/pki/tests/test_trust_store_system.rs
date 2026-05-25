use super::*;

#[test]
fn cert_trust_store_system_rejects_missing_explicit_cert_file() {
    let err = TrustStore::load_from_system_paths(Some("/nonexistent/doesnotexist.pem"), None)
        .unwrap_err();

    assert!(
        err.message.contains("SSL_CERT_FILE set but failed to load")
            || err.message.contains("unable to locate system trust store")
    );
}

#[test]
fn cert_trust_store_system_load_from_system_respects_explicit_file() {
    let missing = TrustStore::load_from_system_paths(Some("/nonexistent/doesnotexist.pem"), None);
    assert!(missing.is_err());
    assert!(
        missing
            .unwrap_err()
            .message
            .contains("SSL_CERT_FILE set but failed to load")
    );

    let root = CertificateBuilder::new()
        .set_serial_u64(0x42)
        .set_issuer_from_string("CN=SystemIssuer")
        .unwrap()
        .set_subject_from_string("CN=SystemRoot")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x42; 32])
        .build_with_signature(vec![0x42; 64], false)
        .unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "authbox-system-trust-{}-{}.pem",
        std::process::id(),
        root.tbs.serial_number[0]
    ));
    write_binary_result(root.to_pem().as_bytes(), &path).unwrap();

    let loaded = TrustStore::load_from_system_paths(Some(path.to_str().unwrap()), None).unwrap();
    assert_eq!(loaded.anchors().len(), 1);
    assert!(loaded.contains_subject(&root.tbs.subject));

    std::fs::remove_file(path).unwrap();
}
