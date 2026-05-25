use super::*;

#[test]
fn cert_oid_signature_oid_lookup() {
    let oid = Oid::new([1, 3, 101, 112]);
    assert_eq!(find_sig_alg_by_oid(&oid), SignatureAlgorithmId::Ed25519);
}

#[test]
fn cert_oid_detail_namespace_matches_cpp_registry_tables() {
    assert_eq!(detail::kOidEd25519, &[1, 3, 101, 112]);
    assert_eq!(detail::kOidRsaPss, &[1, 2, 840, 113549, 1, 1, 10]);
    assert_eq!(detail::kSignatureAlgorithms.len(), 9);
    assert_eq!(detail::kHashAlgorithms.len(), 3);
    assert_eq!(detail::kCurveOids.len(), 8);
    assert_eq!(detail::kExtensionOids.len(), 14);

    let ed25519 = Oid::new(detail::kOidEd25519);
    assert_eq!(
        detail::lookup_enum(
            &ed25519,
            detail::kSignatureAlgorithms,
            SignatureAlgorithmId::Unknown,
        ),
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(
        detail::lookup_enum(&Oid::new([1, 2, 3]), detail::kCurveOids, CurveId::Unknown,),
        CurveId::Unknown
    );

    assert_eq!(
        oid_for_signature(SignatureAlgorithmId::RsaPssSha512),
        Some(Oid::new(detail::kOidRsaPss))
    );
    assert_eq!(
        oid_for_curve(CurveId::X25519),
        Some(Oid::new(detail::kOidX25519))
    );
    assert_eq!(
        oid_for_extension(ExtensionId::InhibitAnyPolicy),
        Some(Oid::new(detail::kOidInhibitAnyPolicy))
    );
}

#[test]
fn cert_oid_hash_oid_lookup() {
    let oid = Oid::new([2, 16, 840, 1, 101, 3, 4, 2, 1]);
    assert_eq!(find_hash_by_oid(&oid), Some(HashAlgorithm::Sha256));
    assert_eq!(
        oid_for_hash(HashAlgorithm::Sha256),
        Some(Oid::new([2, 16, 840, 1, 101, 3, 4, 2, 1]))
    );
    assert_eq!(
        find_hash_by_oid(&Oid::new([2, 16, 840, 1, 101, 3, 4, 2, 2])),
        None
    );
    assert_eq!(oid_for_hash(HashAlgorithm::Sha384), None);
}
