use super::{Certificate, PkiError, PkiResult, TrustStore};
use crate::did;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateRecord {
    pub certificate: Certificate,
    pub did_uris: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkiFacadeResult<T> {
    pub success: bool,
    pub value: T,
    pub error: String,
}

impl<T> PkiFacadeResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            success: true,
            value,
            error: String::new(),
        }
    }

    pub fn into_result(self) -> PkiResult<T> {
        if self.success {
            Ok(self.value)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

impl<T: Default> PkiFacadeResult<T> {
    pub fn err(error: impl Into<String>) -> Self {
        Self {
            success: false,
            value: T::default(),
            error: error.into(),
        }
    }
}

impl<T: Default> Default for PkiFacadeResult<T> {
    fn default() -> Self {
        Self {
            success: false,
            value: T::default(),
            error: String::new(),
        }
    }
}

pub fn to_dp_string(value: impl AsRef<str>) -> String {
    value.as_ref().to_string()
}

pub fn collect_did_uris(certificate: &Certificate) -> Vec<String> {
    certificate
        .subject_alt_names()
        .into_iter()
        .filter(|name| name.type_ == super::GeneralNameType::Uri)
        .filter_map(|name| String::from_utf8(name.value).ok())
        .filter(|uri| did::is_did_uri(uri))
        .collect()
}

pub fn parse_pem_certificate_with_relaxed(
    pem: &str,
    relaxed: bool,
) -> PkiResult<CertificateRecord> {
    let chain = Certificate::parse_pem_chain_with_relaxed(pem, relaxed)?;
    let Some(certificate) = chain.into_iter().next() else {
        return Err(PkiError::new("Certificate chain is empty"));
    };
    let did_uris = collect_did_uris(&certificate);
    Ok(CertificateRecord {
        certificate,
        did_uris,
    })
}

pub fn parse_pem_certificate(pem: &str) -> PkiResult<CertificateRecord> {
    parse_pem_certificate_with_relaxed(pem, false)
}

pub fn parse_pem_certificate_result(pem: &str) -> PkiFacadeResult<CertificateRecord> {
    parse_pem_certificate_result_with_relaxed(pem, false)
}

pub fn parse_pem_certificate_result_with_relaxed(
    pem: &str,
    relaxed: bool,
) -> PkiFacadeResult<CertificateRecord> {
    match parse_pem_certificate_with_relaxed(pem, relaxed) {
        Ok(record) => PkiFacadeResult::ok(record),
        Err(error) => PkiFacadeResult::err(error.message),
    }
}

pub fn has_did_binding(certificate: &Certificate, did_uri: &str) -> bool {
    collect_did_uris(certificate)
        .iter()
        .any(|candidate| candidate == did_uri)
}

pub fn validate_with_trust(leaf: &Certificate, trust: &TrustStore) -> PkiResult<bool> {
    leaf.validate_chain(&[], trust)
}

pub fn validate_with_trust_result(leaf: &Certificate, trust: &TrustStore) -> PkiFacadeResult<bool> {
    match validate_with_trust(leaf, trust) {
        Ok(valid) => PkiFacadeResult::ok(valid),
        Err(error) => PkiFacadeResult::err(error.message),
    }
}

pub fn validate_with_system_trust(leaf: &Certificate) -> PkiResult<bool> {
    let trust = TrustStore::load_from_system()?;
    leaf.validate_chain(&[], &trust)
}

pub fn validate_with_system_trust_result(leaf: &Certificate) -> PkiFacadeResult<bool> {
    match validate_with_system_trust(leaf) {
        Ok(valid) => PkiFacadeResult::ok(valid),
        Err(error) => PkiFacadeResult::err(error.message),
    }
}
