use super::*;

#[test]
fn cert_integration_parses_certificate_with_extensions_after_pem_roundtrip() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=Test Certificate, O=Test Org, C=US");

    let cert = CertificateBuilder::new()
        .set_serial_u64(12345)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_basic_constraints(true, Some(0))
        .unwrap()
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    let pem = pem_encode_certificate(cert.der());
    let decoded = pem_decode_block_with_expected_label(&pem, Some("CERTIFICATE")).unwrap();
    let parsed = parse_x509_cert(&decoded.data).unwrap();

    let subject = parsed.subject.to_string();
    assert!(subject.contains("Test Certificate"));
    assert!(subject.contains("Test Org"));
}

#[test]
fn cert_integration_loads_openssl_generated_ed25519_certificate_when_available() {
    if std::process::Command::new("openssl")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| !status.success())
        .unwrap_or(true)
    {
        return;
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("authbox-openssl-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("key.pem");
    let cert_path = dir.join("cert.pem");

    let status = std::process::Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("ed25519")
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg("1")
        .arg("-nodes")
        .arg("-subj")
        .arg("/CN=InteropTest")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let certs = Certificate::load(&cert_path).unwrap();
    assert!(!certs.is_empty());
    assert!(certs[0].tbs.subject.to_string().contains("InteropTest"));

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cert_integration_loads_chain_from_pem_files_and_validates() {
    let (root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let mut dir = std::env::temp_dir();
    dir.push(format!("authbox-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let root_path = dir.join("root.pem");
    let intermediate_path = dir.join("intermediate.pem");
    std::fs::write(&root_path, root_cert.to_pem()).unwrap();
    std::fs::write(&intermediate_path, intermediate_cert.to_pem()).unwrap();

    let store = TrustStore::load_from_file(&root_path).unwrap();
    let parsed_intermediate = Certificate::load(&intermediate_path).unwrap();

    assert!(
        leaf_cert
            .validate_chain(&parsed_intermediate, &store)
            .unwrap()
    );

    std::fs::remove_file(root_path).unwrap();
    std::fs::remove_file(intermediate_path).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn cert_integration_reports_expired_and_revoked_certificates() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=Expired");
    let cert = CertificateBuilder::new()
        .set_serial_u64(999)
        .set_subject(dn.clone())
        .set_issuer(dn.clone())
        .set_validity(der_time(2020, 1, 1), der_time(2021, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_basic_constraints_with_critical(false, None, false)
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(!cert.check_validity_at(&der_time(2026, 5, 24)));

    let crl = CrlBuilder::new()
        .set_issuer(dn)
        .set_this_update(der_time(2026, 5, 24))
        .add_revoked_serial_with_reason(
            cert.tbs.serial_number.clone(),
            der_time(2026, 5, 24),
            CrlReason::Superseded,
        )
        .build_ed25519(&key)
        .unwrap();

    assert!(cert.is_revoked(&crl));
}
