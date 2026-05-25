use super::{
    Certificate, CertificateBoolResult, CertificateChainResult, CertificateResult,
    DistinguishedName, ExtensionId, PkiError, PkiResult, key_usage, read_binary_bytes,
};

pub type RevocationChecker<'a> = dyn Fn(&Certificate) -> Option<bool> + 'a;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ChainValidationCode {
    #[default]
    Ok,
    ChainConstructionFailed,
    SignatureVerificationError,
    SignatureMismatch,
    CertificateNotYetValidOrExpired,
    IssuerNotCa,
    IssuerMissingKeyCertSign,
    PathLenConstraintViolated,
    TrustAnchorNotFound,
    UnknownCriticalExtension,
    Revoked,
    RevocationStatusUnknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChainValidationReport {
    pub valid: bool,
    pub code: ChainValidationCode,
    pub message: String,
    pub cert_index: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RevocationPolicy {
    #[default]
    Off,
    BestEffort,
    Strict,
}

pub struct ChainValidationOptions<'a> {
    pub reject_unknown_critical_extensions: bool,
    pub revocation_policy: RevocationPolicy,
    pub revocation_checker: Option<&'a RevocationChecker<'a>>,
    pub require_signature_verification: bool,
}

impl Default for ChainValidationOptions<'_> {
    fn default() -> Self {
        Self {
            reject_unknown_critical_extensions: false,
            revocation_policy: RevocationPolicy::Off,
            revocation_checker: None,
            require_signature_verification: true,
        }
    }
}

/// Compatibility namespace mirroring the helper namespace in
/// `xtra/authbox/include/pki/trust_store.hpp`.
pub mod detail {
    use super::{
        Certificate, CertificateResult, ChainValidationOptions, ChainValidationReport,
        has_unknown_critical_extension_impl, run_revocation_check_impl,
    };

    pub fn has_unknown_critical_extension(cert: &Certificate) -> bool {
        has_unknown_critical_extension_impl(cert)
    }

    pub fn run_revocation_check(
        cert: &Certificate,
        cert_index: usize,
        options: &ChainValidationOptions<'_>,
    ) -> CertificateResult<ChainValidationReport> {
        CertificateResult::ok(run_revocation_check_impl(cert, cert_index, options))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cert: Certificate) -> bool {
        self.anchors.push(cert);
        true
    }

    pub fn remove_by_subject(&mut self, subject: &DistinguishedName) -> bool {
        let original = self.anchors.len();
        self.anchors
            .retain(|cert| cert.tbs.subject.der() != subject.der());
        self.anchors.len() != original
    }

    pub fn find_issuer(&self, cert: &Certificate) -> Option<&Certificate> {
        self.anchors
            .iter()
            .find(|anchor| anchor.tbs.subject.der() == cert.tbs.issuer.der())
    }

    pub fn contains_subject(&self, subject: &DistinguishedName) -> bool {
        self.anchors
            .iter()
            .any(|anchor| anchor.tbs.subject.der() == subject.der())
    }

    pub fn anchors(&self) -> &[Certificate] {
        &self.anchors
    }

    pub fn load_from_pem(path: impl AsRef<std::path::Path>) -> PkiResult<Self> {
        let certs = Certificate::load_with_relaxed(path, true)?;
        let mut store = TrustStore::new();
        for cert in certs {
            store.add(cert);
        }
        Ok(store)
    }

    pub fn load_from_pem_result(path: impl AsRef<std::path::Path>) -> CertificateResult<Self> {
        match Self::load_from_pem(path) {
            Ok(store) => CertificateResult::ok(store),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn load_from_der(path: impl AsRef<std::path::Path>) -> PkiResult<Self> {
        let mut store = TrustStore::new();
        for cert in Certificate::load_with_relaxed(path, true)? {
            store.add(cert);
        }
        Ok(store)
    }

    pub fn load_from_der_result(path: impl AsRef<std::path::Path>) -> CertificateResult<Self> {
        match Self::load_from_der(path) {
            Ok(store) => CertificateResult::ok(store),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> PkiResult<Self> {
        let bytes = read_binary_bytes(path.as_ref())?;
        if bytes
            .windows(b"-----BEGIN".len())
            .any(|window| window == b"-----BEGIN")
        {
            Self::load_from_pem(path)
        } else {
            Self::load_from_der(path)
        }
    }

    pub fn load_from_file_result(path: impl AsRef<std::path::Path>) -> CertificateResult<Self> {
        match Self::load_from_file(path) {
            Ok(store) => CertificateResult::ok(store),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn load_from_system() -> PkiResult<Self> {
        Self::load_from_system_paths(
            std::env::var("SSL_CERT_FILE").ok().as_deref(),
            std::env::var("SSL_CERT_DIR").ok().as_deref(),
        )
    }

    pub fn load_from_system_result() -> CertificateResult<Self> {
        match Self::load_from_system() {
            Ok(store) => CertificateResult::ok(store),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub(crate) fn load_from_system_paths(
        ssl_cert_file: Option<&str>,
        ssl_cert_dir: Option<&str>,
    ) -> PkiResult<Self> {
        if let Some(path) = ssl_cert_file.filter(|path| !path.is_empty()) {
            return Self::load_from_file(path).map_err(|err| {
                PkiError::new(format!(
                    "SSL_CERT_FILE set but failed to load: {}",
                    err.message
                ))
            });
        }

        if let Some(dir) = ssl_cert_dir.filter(|dir| !dir.is_empty()) {
            for name in ["ca-certificates.crt", "ca-bundle.crt", "cert.pem"] {
                let candidate = std::path::Path::new(dir).join(name);
                if let Ok(store) = Self::load_from_file(&candidate) {
                    return Ok(store);
                }
            }
        }

        for path in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/usr/local/share/certs/ca-root-nss.crt",
        ] {
            if let Ok(store) = Self::load_from_file(path) {
                return Ok(store);
            }
        }

        Err(PkiError::new("unable to locate system trust store"))
    }
}

pub fn parse_pem_certificate_chain(pem: &str) -> PkiResult<Vec<Certificate>> {
    Certificate::parse_pem_chain_with_relaxed(pem, true)
}

pub fn parse_pem_certificate_chain_result(pem: &str) -> CertificateChainResult {
    match parse_pem_certificate_chain(pem) {
        Ok(chain) => CertificateResult::ok(chain),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn validate_chain_detailed(
    leaf: &Certificate,
    chain: &[Certificate],
    trust: &TrustStore,
) -> PkiResult<ChainValidationReport> {
    validate_chain_detailed_with_options(leaf, chain, trust, &ChainValidationOptions::default())
}

pub fn validate_chain_detailed_with_options(
    leaf: &Certificate,
    chain: &[Certificate],
    trust: &TrustStore,
    options: &ChainValidationOptions<'_>,
) -> PkiResult<ChainValidationReport> {
    let mut order: Vec<&Certificate> = vec![leaf];
    let mut remaining = chain.iter().collect::<Vec<_>>();
    let mut current = leaf;
    while !remaining.is_empty() {
        let Some(pos) = remaining
            .iter()
            .position(|candidate| candidate.tbs.subject.der() == current.tbs.issuer.der())
        else {
            break;
        };
        current = remaining.remove(pos);
        order.push(current);
    }
    if !remaining.is_empty() {
        return Ok(report(
            false,
            ChainValidationCode::ChainConstructionFailed,
            "Provided chain cannot be linked by issuer",
            0,
        ));
    }

    let is_ca = order
        .iter()
        .map(|cert| cert.basic_constraints_ca().unwrap_or(false))
        .collect::<Vec<_>>();

    for (idx, cert) in order.iter().enumerate() {
        if options.reject_unknown_critical_extensions && has_unknown_critical_extension_impl(cert) {
            return Ok(report(
                false,
                ChainValidationCode::UnknownCriticalExtension,
                "Unknown critical extension present",
                idx,
            ));
        }
        let revocation = run_revocation_check_impl(cert, idx, options);
        if !revocation.valid {
            return Ok(revocation);
        }
    }

    for i in 0..order.len().saturating_sub(1) {
        let result = validate_link(i, i + 1, &order, &is_ca, options);
        if !result.valid {
            return Ok(result);
        }
    }

    let last = *order.last().expect("order contains leaf");
    if trust.contains_subject(&last.tbs.subject) {
        return validate_trust_anchor(last, order.len() - 1, options);
    }

    let Some(anchor) = trust.find_issuer(last) else {
        return Ok(report(
            false,
            ChainValidationCode::TrustAnchorNotFound,
            "Trust anchor not found",
            order.len(),
        ));
    };
    if options.reject_unknown_critical_extensions && has_unknown_critical_extension_impl(anchor) {
        return Ok(report(
            false,
            ChainValidationCode::UnknownCriticalExtension,
            "Unknown critical extension present on trust anchor",
            order.len(),
        ));
    }
    let mut with_anchor = order.clone();
    with_anchor.push(anchor);
    let mut with_anchor_ca = is_ca;
    with_anchor_ca.push(anchor.basic_constraints_ca().unwrap_or(false));
    let anchor_result = validate_link(
        with_anchor.len() - 2,
        with_anchor.len() - 1,
        &with_anchor,
        &with_anchor_ca,
        options,
    );
    if !anchor_result.valid {
        return Ok(anchor_result);
    }
    let revocation = run_revocation_check_impl(anchor, with_anchor.len() - 1, options);
    if !revocation.valid {
        return Ok(revocation);
    }
    Ok(report(
        true,
        ChainValidationCode::Ok,
        "",
        with_anchor.len() - 1,
    ))
}

pub fn validate_chain_detailed_result(
    leaf: &Certificate,
    chain: &[Certificate],
    trust: &TrustStore,
) -> CertificateResult<ChainValidationReport> {
    validate_chain_detailed_result_with_options(
        leaf,
        chain,
        trust,
        &ChainValidationOptions::default(),
    )
}

pub fn validate_chain_detailed_result_with_options(
    leaf: &Certificate,
    chain: &[Certificate],
    trust: &TrustStore,
    options: &ChainValidationOptions<'_>,
) -> CertificateResult<ChainValidationReport> {
    match validate_chain_detailed_with_options(leaf, chain, trust, options) {
        Ok(report) => CertificateResult::ok(report),
        Err(error) => CertificateResult::failure(error.message),
    }
}

impl Certificate {
    pub fn validate_chain(&self, chain: &[Certificate], trust: &TrustStore) -> PkiResult<bool> {
        validate_chain_detailed(self, chain, trust).map(|report| report.valid)
    }

    pub fn validate_chain_result(
        &self,
        chain: &[Certificate],
        trust: &TrustStore,
    ) -> CertificateBoolResult {
        match self.validate_chain(chain, trust) {
            Ok(valid) => CertificateResult::ok(valid),
            Err(error) => CertificateResult::failure(error.message),
        }
    }
}

fn validate_link(
    child_idx: usize,
    issuer_idx: usize,
    order: &[&Certificate],
    is_ca: &[bool],
    options: &ChainValidationOptions<'_>,
) -> ChainValidationReport {
    let child = order[child_idx];
    let issuer = order[issuer_idx];
    if child.tbs.issuer.der() != issuer.tbs.subject.der() {
        return report(
            false,
            ChainValidationCode::ChainConstructionFailed,
            "Certificate issuer does not match issuer subject",
            child_idx,
        );
    }
    if options.require_signature_verification {
        match child.verify_signature(issuer) {
            Ok(true) => {}
            Ok(false) => {
                return report(
                    false,
                    ChainValidationCode::SignatureMismatch,
                    "Certificate signature mismatch",
                    child_idx,
                );
            }
            Err(err) => {
                return report(
                    false,
                    ChainValidationCode::SignatureVerificationError,
                    err.message,
                    child_idx,
                );
            }
        }
    }
    if !child.check_validity_now() {
        return report(
            false,
            ChainValidationCode::CertificateNotYetValidOrExpired,
            "Certificate validity period check failed",
            child_idx,
        );
    }
    if !issuer.check_validity_now() {
        return report(
            false,
            ChainValidationCode::CertificateNotYetValidOrExpired,
            "Issuer validity period check failed",
            issuer_idx,
        );
    }
    if !issuer.basic_constraints_ca().unwrap_or(false) {
        return report(
            false,
            ChainValidationCode::IssuerNotCa,
            "Issuer is not a CA",
            issuer_idx,
        );
    }
    if let Some(usage) = issuer.key_usage_bits()
        && usage & key_usage::KEY_CERT_SIGN == 0
    {
        return report(
            false,
            ChainValidationCode::IssuerMissingKeyCertSign,
            "Issuer keyUsage does not allow certificate signing",
            issuer_idx,
        );
    }
    if let Some(path_len) = issuer.basic_constraints_path_length() {
        let intermediates = intermediate_ca_count(child_idx, issuer_idx, is_ca);
        if intermediates > path_len as usize {
            return report(
                false,
                ChainValidationCode::PathLenConstraintViolated,
                "pathLenConstraint violated by certification path",
                issuer_idx,
            );
        }
    }
    report(true, ChainValidationCode::Ok, "", child_idx)
}

fn validate_trust_anchor(
    anchor: &Certificate,
    index: usize,
    options: &ChainValidationOptions<'_>,
) -> PkiResult<ChainValidationReport> {
    if options.reject_unknown_critical_extensions && has_unknown_critical_extension_impl(anchor) {
        return Ok(report(
            false,
            ChainValidationCode::UnknownCriticalExtension,
            "Unknown critical extension present on trust anchor",
            index,
        ));
    }
    if !anchor.check_validity_now() {
        return Ok(report(
            false,
            ChainValidationCode::CertificateNotYetValidOrExpired,
            "Trust anchor validity check failed",
            index,
        ));
    }
    if !anchor.basic_constraints_ca().unwrap_or(false) {
        return Ok(report(
            false,
            ChainValidationCode::IssuerNotCa,
            "Trust anchor is not a CA",
            index,
        ));
    }
    if let Some(usage) = anchor.key_usage_bits()
        && usage & key_usage::KEY_CERT_SIGN == 0
    {
        return Ok(report(
            false,
            ChainValidationCode::IssuerMissingKeyCertSign,
            "Trust anchor keyUsage does not allow certificate signing",
            index,
        ));
    }
    if options.require_signature_verification && anchor.tbs.subject.der() == anchor.tbs.issuer.der()
    {
        match anchor.verify_signature(anchor) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(report(
                    false,
                    ChainValidationCode::SignatureMismatch,
                    "Trust anchor self-signature mismatch",
                    index,
                ));
            }
            Err(err) => {
                return Ok(report(
                    false,
                    ChainValidationCode::SignatureVerificationError,
                    err.message,
                    index,
                ));
            }
        }
    }
    let revocation = run_revocation_check_impl(anchor, index, options);
    if !revocation.valid {
        return Ok(revocation);
    }
    Ok(report(true, ChainValidationCode::Ok, "", index))
}

fn has_unknown_critical_extension_impl(cert: &Certificate) -> bool {
    cert.tbs
        .extensions
        .iter()
        .any(|ext| ext.id == ExtensionId::Unknown && ext.critical)
}

fn run_revocation_check_impl(
    cert: &Certificate,
    cert_index: usize,
    options: &ChainValidationOptions<'_>,
) -> ChainValidationReport {
    if options.revocation_policy == RevocationPolicy::Off {
        return report(true, ChainValidationCode::Ok, "", cert_index);
    }
    let Some(checker) = options.revocation_checker else {
        return if options.revocation_policy == RevocationPolicy::Strict {
            report(
                false,
                ChainValidationCode::RevocationStatusUnknown,
                "No revocation checker configured",
                cert_index,
            )
        } else {
            report(true, ChainValidationCode::Ok, "", cert_index)
        };
    };
    match checker(cert) {
        Some(true) => report(
            false,
            ChainValidationCode::Revoked,
            "Certificate is revoked",
            cert_index,
        ),
        Some(false) => report(true, ChainValidationCode::Ok, "", cert_index),
        None if options.revocation_policy == RevocationPolicy::Strict => report(
            false,
            ChainValidationCode::RevocationStatusUnknown,
            "Revocation status unknown",
            cert_index,
        ),
        None => report(true, ChainValidationCode::Ok, "", cert_index),
    }
}

fn intermediate_ca_count(subject_idx: usize, issuer_idx: usize, is_ca: &[bool]) -> usize {
    (subject_idx + 1..issuer_idx)
        .filter(|idx| is_ca.get(*idx).copied().unwrap_or(false))
        .count()
}

fn report(
    valid: bool,
    code: ChainValidationCode,
    message: impl Into<String>,
    cert_index: usize,
) -> ChainValidationReport {
    ChainValidationReport {
        valid,
        code,
        message: message.into(),
        cert_index,
    }
}
