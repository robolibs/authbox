use super::*;

#[test]
fn cert_vectors_have_deterministic_der_and_fingerprint_for_same_key() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=VectorRoot");

    let cert1 =
        helpers::make_certificate(&dn, &dn, &key, &key, true, key_usage::KEY_CERT_SIGN, 123);
    let cert2 =
        helpers::make_certificate(&dn, &dn, &key, &key, true, key_usage::KEY_CERT_SIGN, 123);

    assert_eq!(cert1.der(), cert2.der());
    assert_eq!(
        cert1.fingerprint(HashAlgorithm::Sha256).unwrap(),
        cert2.fingerprint(HashAlgorithm::Sha256).unwrap()
    );
}

#[test]
fn cert_vectors_generate_chain_csr_and_crl_artifacts() {
    let (root, intermediate, leaf, root_key, _intermediate_key, leaf_key) = helpers::make_chain();

    let validation = leaf.validate_chain(std::slice::from_ref(&intermediate), &TrustStore::new());
    assert!(!validation.unwrap());

    let csr = CsrBuilder::new()
        .set_subject(leaf.tbs.subject.clone())
        .set_subject_public_key_ed25519(leaf.tbs.subject_public_key_info.public_key.clone())
        .build_ed25519(&leaf_key)
        .unwrap();
    assert!(csr.verify_signature().unwrap());

    let crl = CrlBuilder::new()
        .set_issuer(root.tbs.subject.clone())
        .set_this_update(helpers::fixed_time())
        .add_revoked_serial_with_reason(
            leaf.tbs.serial_number.clone(),
            helpers::fixed_time(),
            CrlReason::Superseded,
        )
        .build_ed25519(&root_key)
        .unwrap();
    assert!(leaf.is_revoked(&crl));
    assert!(crl.verify_signature(&root).unwrap());
}
