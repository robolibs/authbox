use super::{CurveId, ExtensionId, HashAlgorithm, Oid, SignatureAlgorithmId, detail};

pub fn find_sig_alg_by_oid(oid: &Oid) -> SignatureAlgorithmId {
    detail::lookup_enum(
        oid,
        detail::K_SIGNATURE_ALGORITHMS,
        SignatureAlgorithmId::Unknown,
    )
}

pub fn find_hash_by_oid(oid: &Oid) -> Option<HashAlgorithm> {
    detail::K_HASH_ALGORITHMS
        .iter()
        .find(|(_, pattern)| oid.nodes == *pattern)
        .map(|(value, _)| *value)
}

pub fn find_curve_by_oid(oid: &Oid) -> CurveId {
    detail::lookup_enum(oid, detail::K_CURVE_OIDS, CurveId::Unknown)
}

pub fn find_extension_by_oid(oid: &Oid) -> ExtensionId {
    detail::lookup_enum(oid, detail::K_EXTENSION_OIDS, ExtensionId::Unknown)
}

pub fn oid_for_signature(id: SignatureAlgorithmId) -> Option<Oid> {
    if matches!(
        id,
        SignatureAlgorithmId::RsaPssSha384 | SignatureAlgorithmId::RsaPssSha512
    ) {
        return Some(Oid::new(detail::K_OID_RSA_PSS));
    }
    detail::K_SIGNATURE_ALGORITHMS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
}

pub fn oid_for_curve(id: CurveId) -> Option<Oid> {
    detail::K_CURVE_OIDS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
}

pub fn oid_for_extension(id: ExtensionId) -> Option<Oid> {
    detail::K_EXTENSION_OIDS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
}

pub fn oid_for_hash(id: HashAlgorithm) -> Option<Oid> {
    detail::K_HASH_ALGORITHMS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
}
