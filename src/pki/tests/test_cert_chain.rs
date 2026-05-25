use super::*;

#[test]
fn cert_chain_validation_with_trust_store() {
    let (root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let leaf_subject = leaf_cert.tbs.subject.clone();
    let mut store = TrustStore::new();
    store.add(root_cert);

    assert!(
        leaf_cert
            .validate_chain(std::slice::from_ref(&intermediate_cert), &store)
            .unwrap()
    );
    assert!(leaf_cert.match_subject(&leaf_subject));
}

#[test]
fn cert_chain_validation_accepts_unordered_intermediates() {
    let (root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let mut store = TrustStore::new();
    store.add(root_cert.clone());

    assert!(
        leaf_cert
            .validate_chain(&[intermediate_cert, root_cert], &store)
            .unwrap()
    );
}

#[test]
fn cert_chain_validation_succeeds_when_issuer_is_directly_trusted() {
    let (_root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let mut store = TrustStore::new();
    store.add(intermediate_cert);

    assert!(leaf_cert.validate_chain(&[], &store).unwrap());
}

#[test]
fn cert_chain_detailed_validation_reports_unknown_critical_extension() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=StrictRoot");
    let cert = CertificateBuilder::new()
        .set_serial_u64(700)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(
            DerTime {
                year: 2024,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
            DerTime {
                year: 2025,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_basic_constraints(true, Some(0))
        .unwrap()
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
        .unwrap()
        .add_extension(RawExtension {
            id: ExtensionId::Unknown,
            oid: Oid::new([1, 2, 3, 4, 5, 6]),
            critical: true,
            value: vec![0x05, 0x00],
        })
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();
    let mut store = TrustStore::new();
    store.add(cert.clone());

    let report = validate_chain_detailed_with_options(
        &cert,
        &[],
        &store,
        &ChainValidationOptions {
            reject_unknown_critical_extensions: true,
            ..ChainValidationOptions::default()
        },
    )
    .unwrap();

    assert!(!report.valid);
    assert_eq!(report.code, ChainValidationCode::UnknownCriticalExtension);
}

#[test]
fn cert_chain_detailed_validation_supports_revocation_policy_modes() {
    let (root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let mut store = TrustStore::new();
    store.add(root_cert);

    let unknown_checker = |_cert: &Certificate| None;
    let strict_unknown = ChainValidationOptions {
        revocation_policy: RevocationPolicy::Strict,
        revocation_checker: Some(&unknown_checker),
        ..ChainValidationOptions::default()
    };
    let unknown_report = validate_chain_detailed_with_options(
        &leaf_cert,
        std::slice::from_ref(&intermediate_cert),
        &store,
        &strict_unknown,
    )
    .unwrap();
    assert!(!unknown_report.valid);
    assert_eq!(
        unknown_report.code,
        ChainValidationCode::RevocationStatusUnknown
    );

    let best_effort_unknown = ChainValidationOptions {
        revocation_policy: RevocationPolicy::BestEffort,
        revocation_checker: Some(&unknown_checker),
        ..ChainValidationOptions::default()
    };
    let best_effort_report = validate_chain_detailed_with_options(
        &leaf_cert,
        std::slice::from_ref(&intermediate_cert),
        &store,
        &best_effort_unknown,
    )
    .unwrap();
    assert!(best_effort_report.valid);

    let revoked_checker =
        |cert: &Certificate| Some(cert.tbs.serial_number == leaf_cert.tbs.serial_number);
    let revoked_options = ChainValidationOptions {
        revocation_policy: RevocationPolicy::BestEffort,
        revocation_checker: Some(&revoked_checker),
        ..ChainValidationOptions::default()
    };
    let revoked_report = validate_chain_detailed_with_options(
        &leaf_cert,
        std::slice::from_ref(&intermediate_cert),
        &store,
        &revoked_options,
    )
    .unwrap();
    assert!(!revoked_report.valid);
    assert_eq!(revoked_report.code, ChainValidationCode::Revoked);
}

#[test]
fn cert_chain_validates_structural_chain_to_anchor() {
    let root = test_chain_ca_cert("CN=Root", "CN=Root", 1, Some(1));
    let intermediate = test_chain_ca_cert("CN=Intermediate", "CN=Root", 2, Some(0));
    let leaf = test_chain_leaf_cert("CN=Leaf", "CN=Intermediate", 3);
    let mut trust = TrustStore::new();
    assert!(trust.add(root.clone()));
    assert!(trust.contains_subject(&root.tbs.subject));
    assert!(trust.find_issuer(&intermediate).is_some());

    let report = validate_chain_detailed_with_options(
        &leaf,
        &[intermediate],
        &trust,
        &ChainValidationOptions {
            require_signature_verification: false,
            ..ChainValidationOptions::default()
        },
    )
    .unwrap();
    assert!(report.valid);
    assert_eq!(report.code, ChainValidationCode::Ok);
    assert!(!leaf.validate_chain(&[], &trust).unwrap());
}

#[test]
fn cert_chain_rejects_non_ca_revoked_and_unknown_critical() {
    let root = test_chain_ca_cert("CN=Root", "CN=Root", 1, Some(1));
    let bad_issuer = test_chain_leaf_cert("CN=BadIssuer", "CN=Root", 4);
    let leaf = test_chain_leaf_cert("CN=Leaf", "CN=BadIssuer", 5);
    let mut trust = TrustStore::new();
    trust.add(root.clone());

    let report = validate_chain_detailed_with_options(
        &leaf,
        &[bad_issuer],
        &trust,
        &ChainValidationOptions {
            require_signature_verification: false,
            ..ChainValidationOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.code, ChainValidationCode::IssuerNotCa);

    let checker = |cert: &Certificate| Some(cert.tbs.serial_number == vec![5]);
    let report = validate_chain_detailed_with_options(
        &leaf,
        &[],
        &trust,
        &ChainValidationOptions {
            revocation_policy: RevocationPolicy::Strict,
            revocation_checker: Some(&checker),
            ..ChainValidationOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.code, ChainValidationCode::Revoked);

    let mut weird = leaf.clone();
    weird.tbs.extensions.push(RawExtension {
        oid: Oid::new([1, 2, 3, 4, 5]),
        id: ExtensionId::Unknown,
        critical: true,
        value: Vec::new(),
    });
    let report = validate_chain_detailed_with_options(
        &weird,
        &[],
        &trust,
        &ChainValidationOptions {
            reject_unknown_critical_extensions: true,
            ..ChainValidationOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.code, ChainValidationCode::UnknownCriticalExtension);
}

#[test]
fn cert_chain_default_verifies_rsa_signatures_and_validity() {
    let rsa_key = helpers::test_rsa_keypair(80);
    let root = test_chain_rsa_signed_cert(
        "CN=RsaRoot",
        "CN=RsaRoot",
        0x11,
        true,
        Some(1),
        der_time(2020, 1, 1),
        der_time(2035, 1, 1),
        &rsa_key,
    );
    let leaf = test_chain_rsa_signed_cert(
        "CN=RsaLeaf",
        "CN=RsaRoot",
        0x12,
        false,
        None,
        der_time(2020, 1, 1),
        der_time(2035, 1, 1),
        &rsa_key,
    );
    let mut trust = TrustStore::new();
    trust.add(root.clone());

    let report = validate_chain_detailed(&leaf, &[], &trust).unwrap();
    assert!(report.valid);
    assert_eq!(report.code, ChainValidationCode::Ok);
    assert!(root.validate_chain(&[], &trust).unwrap());

    let expired = test_chain_rsa_signed_cert(
        "CN=ExpiredLeaf",
        "CN=RsaRoot",
        0x13,
        false,
        None,
        der_time(2020, 1, 1),
        der_time(2020, 1, 2),
        &rsa_key,
    );
    let report = validate_chain_detailed(&expired, &[], &trust).unwrap();
    assert_eq!(
        report.code,
        ChainValidationCode::CertificateNotYetValidOrExpired
    );
}

fn test_chain_ca_cert(
    subject: &str,
    issuer: &str,
    serial: u64,
    path_len: Option<u32>,
) -> Certificate {
    CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_issuer_from_string(issuer)
        .unwrap()
        .set_subject_from_string(subject)
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![serial as u8; 32])
        .set_basic_constraints(true, path_len)
        .unwrap()
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
        .unwrap()
        .build_with_signature(vec![serial as u8; 64], subject == issuer)
        .unwrap()
}

fn test_chain_leaf_cert(subject: &str, issuer: &str, serial: u64) -> Certificate {
    CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_issuer_from_string(issuer)
        .unwrap()
        .set_subject_from_string(subject)
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![serial as u8; 32])
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .build_with_signature(vec![serial as u8; 64], false)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn test_chain_rsa_signed_cert(
    subject: &str,
    issuer: &str,
    serial: u64,
    is_ca: bool,
    path_len: Option<u32>,
    not_before: DerTime,
    not_after: DerTime,
    signing_key: &KeyPair,
) -> Certificate {
    let self_signed = subject == issuer;
    let mut builder = CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .set_issuer_from_string(issuer)
        .unwrap()
        .set_subject_from_string(subject)
        .unwrap()
        .set_validity(not_before, not_after)
        .set_subject_public_key_rsa(signing_key.public_key.clone());
    builder = if is_ca {
        builder
            .set_basic_constraints(true, path_len)
            .unwrap()
            .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
            .unwrap()
    } else {
        builder.set_key_usage(key_usage::DIGITAL_SIGNATURE).unwrap()
    };
    let tbs = builder.build_unsigned_tbs(self_signed).unwrap();
    let signature =
        sign_rsa_pkcs1v15_keypair(SignatureAlgorithmId::RsaPkcs1Sha256, &tbs, signing_key).unwrap();
    builder
        .build_with_signature(signature, self_signed)
        .unwrap()
}
