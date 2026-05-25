use super::*;

#[test]
fn cert_trust_store_adds_and_removes_trust_anchor() {
    let (cert, _key) = helpers::make_self_signed_certificate("Anchor", 0x7901);
    let mut store = TrustStore::new();

    assert!(store.add(cert.clone()));
    assert_eq!(store.anchors().len(), 1);
    assert!(store.contains_subject(&cert.tbs.subject));

    assert!(store.remove_by_subject(&cert.tbs.subject));
    assert!(store.anchors().is_empty());
    assert!(!store.contains_subject(&cert.tbs.subject));
}

#[test]
fn cert_trust_store_result_wrappers_match_cpp_surface() {
    let (root_cert, intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    let mut store = TrustStore::new();
    store.add(root_cert.clone());

    let chain = parse_pem_certificate_chain_result(&root_cert.to_pem());
    assert!(chain.success);
    assert_eq!(chain.value.len(), 1);
    assert!(chain.error.is_empty());

    let detailed = validate_chain_detailed_result(
        &leaf_cert,
        std::slice::from_ref(&intermediate_cert),
        &store,
    );
    assert!(detailed.success);
    assert!(detailed.value.valid);
    assert_eq!(detailed.value.code, ChainValidationCode::Ok);

    let valid = leaf_cert.validate_chain_result(std::slice::from_ref(&intermediate_cert), &store);
    assert!(valid.success);
    assert!(valid.value);
    assert!(valid.error.is_empty());

    let empty_chain = parse_pem_certificate_chain_result("");
    assert!(!empty_chain.success);
    assert_eq!(empty_chain.error, "no certificates found in PEM data");

    let missing = TrustStore::load_from_file_result("/nonexistent/authbox-trust-store.pem");
    assert!(!missing.success);
    assert!(missing.error.starts_with("Failed to open file:"));
}

#[test]
fn cert_trust_store_load_from_pem_and_der_follow_cpp_auto_detect_load_path() {
    let (cert, _key) = helpers::make_self_signed_certificate("AutoDetectAnchor", 0x7902);
    let mut pem_path = std::env::temp_dir();
    pem_path.push(format!(
        "authbox-trust-auto-{}-{}.pem",
        std::process::id(),
        0x7902_u16
    ));
    let mut der_path = std::env::temp_dir();
    der_path.push(format!(
        "authbox-trust-auto-{}-{}.der",
        std::process::id(),
        0x7902_u16
    ));

    write_binary_result(cert.to_pem().as_bytes(), &pem_path).unwrap();
    write_binary_result(cert.der(), &der_path).unwrap();

    let pem_via_pem = TrustStore::load_from_pem(&pem_path).unwrap();
    let pem_via_der = TrustStore::load_from_der(&pem_path).unwrap();
    let der_via_pem = TrustStore::load_from_pem(&der_path).unwrap();
    let der_via_der = TrustStore::load_from_der(&der_path).unwrap();

    assert!(pem_via_pem.contains_subject(&cert.tbs.subject));
    assert!(pem_via_der.contains_subject(&cert.tbs.subject));
    assert!(der_via_pem.contains_subject(&cert.tbs.subject));
    assert!(der_via_der.contains_subject(&cert.tbs.subject));

    std::fs::remove_file(pem_path).unwrap();
    std::fs::remove_file(der_path).unwrap();
}

#[test]
fn cert_trust_store_detail_namespace_matches_cpp_helper_surface() {
    let (_root_cert, _intermediate_cert, leaf_cert, ..) = helpers::make_chain();
    assert!(!trust_store::detail::has_unknown_critical_extension(
        &leaf_cert
    ));

    let mut with_unknown = leaf_cert.clone();
    with_unknown.tbs.extensions.push(RawExtension {
        id: ExtensionId::Unknown,
        oid: Oid::new([1, 2, 840, 113_549, 1, 9, 99]),
        critical: true,
        value: vec![0x05, 0x00],
    });
    assert!(trust_store::detail::has_unknown_critical_extension(
        &with_unknown
    ));

    let off = trust_store::detail::run_revocation_check(
        &leaf_cert,
        7,
        &ChainValidationOptions::default(),
    );
    assert!(off.success);
    assert!(off.value.valid);
    assert_eq!(off.value.code, ChainValidationCode::Ok);
    assert_eq!(off.value.cert_index, 7);

    let strict_without_checker = trust_store::detail::run_revocation_check(
        &leaf_cert,
        3,
        &ChainValidationOptions {
            revocation_policy: RevocationPolicy::Strict,
            ..ChainValidationOptions::default()
        },
    );
    assert!(strict_without_checker.success);
    assert!(!strict_without_checker.value.valid);
    assert_eq!(
        strict_without_checker.value.code,
        ChainValidationCode::RevocationStatusUnknown
    );
    assert_eq!(
        strict_without_checker.value.message,
        "No revocation checker configured"
    );

    let checker = |_cert: &Certificate| Some(true);
    let revoked = trust_store::detail::run_revocation_check(
        &leaf_cert,
        2,
        &ChainValidationOptions {
            revocation_policy: RevocationPolicy::BestEffort,
            revocation_checker: Some(&checker),
            ..ChainValidationOptions::default()
        },
    );
    assert!(revoked.success);
    assert!(!revoked.value.valid);
    assert_eq!(revoked.value.code, ChainValidationCode::Revoked);
    assert_eq!(revoked.value.message, "Certificate is revoked");
    assert_eq!(revoked.value.cert_index, 2);
}
