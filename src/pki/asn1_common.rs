/// C++ `ASN1_MAX_TAG_NUMBER` guardrail for corrupted long-form tag numbers.
pub const ASN1_MAX_TAG_NUMBER: u32 = 1 << 28;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum Asn1Class {
    #[default]
    Universal = 0x00,
    Application = 0x40,
    ContextSpecific = 0x80,
    Private = 0xc0,
}

#[allow(clippy::upper_case_acronyms)]
pub type ASN1Class = Asn1Class;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Asn1Tag {
    EndOfContent = 0x00,
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    ObjectDescriptor = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0x0a,
    EmbeddedPdv = 0x0b,
    Utf8String = 0x0c,
    RelativeOid = 0x0d,
    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13,
    T61String = 0x14,
    VideotexString = 0x15,
    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1a,
    GeneralString = 0x1b,
    UniversalString = 0x1c,
    CharacterString = 0x1d,
    BmpString = 0x1e,
}

#[allow(clippy::upper_case_acronyms)]
pub type ASN1Tag = Asn1Tag;

#[allow(non_upper_case_globals)]
impl Asn1Tag {
    pub const UTF8String: Self = Self::Utf8String;
    pub const RelativeOID: Self = Self::RelativeOid;
    pub const IA5String: Self = Self::Ia5String;
    pub const UTCTime: Self = Self::UtcTime;
    pub const BMPString: Self = Self::BmpString;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Asn1Identifier {
    pub tag_class: Asn1Class,
    pub constructed: bool,
    pub tag_number: u32,
}

#[allow(clippy::upper_case_acronyms)]
pub type ASN1Identifier = Asn1Identifier;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedHeader {
    pub identifier: Asn1Identifier,
    pub length: usize,
    pub header_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Read<T> {
    pub value: T,
    pub bytes_consumed: usize,
}

impl<T> Asn1Read<T> {
    pub fn new(value: T, bytes_consumed: usize) -> Self {
        Self {
            value,
            bytes_consumed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Result<T> {
    pub success: bool,
    pub value: T,
    pub bytes_consumed: usize,
    pub error: String,
}

impl<T> Asn1Result<T> {
    pub fn ok(value: T, bytes_consumed: usize) -> Self {
        Self {
            success: true,
            value,
            bytes_consumed,
            error: String::new(),
        }
    }

    pub fn into_result(self) -> crate::pki::PkiResult<Asn1Read<T>> {
        if self.success {
            Ok(Asn1Read::new(self.value, self.bytes_consumed))
        } else {
            Err(crate::pki::PkiError::new(self.error))
        }
    }
}

impl<T: Default> Asn1Result<T> {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            value: T::default(),
            bytes_consumed: 0,
            error: error.into(),
        }
    }
}

impl<T: Default> Default for Asn1Result<T> {
    fn default() -> Self {
        Self {
            success: false,
            value: T::default(),
            bytes_consumed: 0,
            error: String::new(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
pub type ASN1Result<T> = Asn1Result<T>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BitString {
    pub unused_bits: u8,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Oid {
    pub nodes: Vec<u32>,
}

impl Oid {
    pub fn new(nodes: impl Into<Vec<u32>>) -> Self {
        Self {
            nodes: nodes.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SignatureAlgorithmId {
    #[default]
    Unknown,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Ed25519,
    Ed448,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
    Blake2b,
    Keccak256,
}

#[allow(non_upper_case_globals)]
impl HashAlgorithm {
    pub const SHA256: Self = Self::Sha256;
    pub const SHA384: Self = Self::Sha384;
    pub const SHA512: Self = Self::Sha512;
    pub const BLAKE2b: Self = Self::Blake2b;
    pub const KECCAK256: Self = Self::Keccak256;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CurveId {
    #[default]
    Unknown,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Secp256k1,
    Ed25519,
    Ed448,
    X25519,
    X448,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExtensionId {
    #[default]
    Unknown,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    SubjectAltName,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
    CertificatePolicies,
    CrlDistributionPoints,
    AuthorityInfoAccess,
    NameConstraints,
    IssuerAltName,
    PolicyMappings,
    PolicyConstraints,
    InhibitAnyPolicy,
}

#[allow(non_upper_case_globals)]
impl ExtensionId {
    pub const CRLDistributionPoints: Self = Self::CrlDistributionPoints;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CrlEntryExtensionId {
    #[default]
    Unknown,
    ReasonCode,
    InvalidityDate,
    CertificateIssuer,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CrlExtensionId {
    #[default]
    Unknown,
    AuthorityKeyIdentifier,
    IssuerAltName,
    CrlNumber,
    DeltaCrlIndicator,
    IssuingDistributionPoint,
    FreshestCrl,
    AuthorityInfoAccess,
    ExpiredCertsOnCrl,
}

#[allow(non_upper_case_globals)]
impl CrlExtensionId {
    pub const CRLNumber: Self = Self::CrlNumber;
    pub const DeltaCRLIndicator: Self = Self::DeltaCrlIndicator;
    pub const FreshestCRL: Self = Self::FreshestCrl;
    pub const ExpiredCertsOnCRL: Self = Self::ExpiredCertsOnCrl;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AlgorithmIdentifier {
    pub signature: SignatureAlgorithmId,
    pub hash: HashAlgorithm,
    pub curve: CurveId,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: Vec<u8>,
    pub unused_bits: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawExtension {
    pub oid: Oid,
    pub id: ExtensionId,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Extension {
    id: ExtensionId,
    critical: bool,
}

impl Extension {
    pub fn new(id: ExtensionId, critical: bool) -> Self {
        Self { id, critical }
    }

    pub fn id(&self) -> ExtensionId {
        self.id
    }

    pub fn critical(&self) -> bool {
        self.critical
    }
}

impl From<&RawExtension> for Extension {
    fn from(raw: &RawExtension) -> Self {
        Self::new(raw.id, raw.critical)
    }
}

pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;
    pub const NON_REPUDIATION: u16 = 0x4000;
    pub const KEY_ENCIPHERMENT: u16 = 0x2000;
    pub const DATA_ENCIPHERMENT: u16 = 0x1000;
    pub const KEY_AGREEMENT: u16 = 0x0800;
    pub const KEY_CERT_SIGN: u16 = 0x0400;
    pub const CRL_SIGN: u16 = 0x0200;
    pub const ENCIPHER_ONLY: u16 = 0x0100;
    pub const DECIPHER_ONLY: u16 = 0x0080;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicConstraintsExtension {
    critical: bool,
    ca: bool,
    path_length: Option<u32>,
}

impl BasicConstraintsExtension {
    pub fn new(critical: bool, ca_flag: bool, path_length: Option<u32>) -> Self {
        Self {
            critical,
            ca: ca_flag,
            path_length,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::BasicConstraints
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn is_ca(&self) -> bool {
        self.ca
    }

    pub fn path_length(&self) -> Option<u32> {
        self.path_length
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyUsageExtension {
    critical: bool,
    bits: u16,
}

#[allow(non_upper_case_globals)]
impl KeyUsageExtension {
    pub const DigitalSignature: u16 = key_usage::DIGITAL_SIGNATURE;
    pub const NonRepudiation: u16 = key_usage::NON_REPUDIATION;
    pub const KeyEncipherment: u16 = key_usage::KEY_ENCIPHERMENT;
    pub const DataEncipherment: u16 = key_usage::DATA_ENCIPHERMENT;
    pub const KeyAgreement: u16 = key_usage::KEY_AGREEMENT;
    pub const KeyCertSign: u16 = key_usage::KEY_CERT_SIGN;
    pub const CRLSign: u16 = key_usage::CRL_SIGN;
    pub const EncipherOnly: u16 = key_usage::ENCIPHER_ONLY;
    pub const DecipherOnly: u16 = key_usage::DECIPHER_ONLY;

    pub fn new(critical: bool, bits: u16) -> Self {
        Self { critical, bits }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::KeyUsage
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn has(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }

    pub fn bits(&self) -> u16 {
        self.bits
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyIdentifierExtension {
    critical: bool,
    identifier: Vec<u8>,
}

impl SubjectKeyIdentifierExtension {
    pub fn new(critical: bool, identifier: Vec<u8>) -> Self {
        Self {
            critical,
            identifier,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::SubjectKeyIdentifier
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityKeyIdentifierExtension {
    critical: bool,
    key_identifier: Vec<u8>,
}

impl AuthorityKeyIdentifierExtension {
    pub fn new(critical: bool, key_id: Vec<u8>) -> Self {
        Self {
            critical,
            key_identifier: key_id,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::AuthorityKeyIdentifier
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn key_identifier(&self) -> &[u8] {
        &self.key_identifier
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GeneralNameType {
    DnsName,
    Uri,
    IpAddress,
    Email,
    #[default]
    Other,
}

#[allow(non_upper_case_globals)]
impl GeneralNameType {
    pub const DNSName: Self = Self::DnsName;
    pub const URI: Self = Self::Uri;
    pub const IPAddress: Self = Self::IpAddress;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneralName {
    pub type_: GeneralNameType,
    /// GeneralName value bytes. DNS, URI, and Email values are ASCII/UTF-8;
    /// IPAddress values may be RFC 5280 raw octets or the C++ builder's
    /// textual IPv4/IPv6 input, which the builder encodes to octets.
    pub value: Vec<u8>,
}

impl GeneralName {
    pub fn new(type_: GeneralNameType, value: impl AsRef<str>) -> Self {
        Self {
            type_,
            value: value.as_ref().as_bytes().to_vec(),
        }
    }

    pub fn value_string(&self) -> String {
        String::from_utf8_lossy(&self.value).into_owned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAltNameExtension {
    critical: bool,
    names: Vec<GeneralName>,
}

impl SubjectAltNameExtension {
    pub fn new(critical: bool, names: Vec<GeneralName>) -> Self {
        Self { critical, names }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::SubjectAltName
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn names(&self) -> &[GeneralName] {
        &self.names
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum KeyPurposeId {
    #[default]
    Unknown,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    AnyExtendedKeyUsage,
}

#[allow(non_upper_case_globals)]
impl KeyPurposeId {
    pub const OCSPSigning: Self = Self::OcspSigning;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtendedKeyUsage {
    pub critical: bool,
    pub purpose_oids: Vec<Oid>,
}

impl ExtendedKeyUsage {
    pub fn purpose_to_oid(purpose: KeyPurposeId) -> Oid {
        match purpose {
            KeyPurposeId::ServerAuth => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 1]),
            KeyPurposeId::ClientAuth => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 2]),
            KeyPurposeId::CodeSigning => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 3]),
            KeyPurposeId::EmailProtection => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 4]),
            KeyPurposeId::TimeStamping => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 8]),
            KeyPurposeId::OcspSigning => Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 9]),
            KeyPurposeId::AnyExtendedKeyUsage => Oid::new([2, 5, 29, 37, 0]),
            KeyPurposeId::Unknown => Oid::default(),
        }
    }

    pub fn oid_to_purpose(oid: &Oid) -> KeyPurposeId {
        match oid.nodes.as_slice() {
            [1, 3, 6, 1, 5, 5, 7, 3, 1] => KeyPurposeId::ServerAuth,
            [1, 3, 6, 1, 5, 5, 7, 3, 2] => KeyPurposeId::ClientAuth,
            [1, 3, 6, 1, 5, 5, 7, 3, 3] => KeyPurposeId::CodeSigning,
            [1, 3, 6, 1, 5, 5, 7, 3, 4] => KeyPurposeId::EmailProtection,
            [1, 3, 6, 1, 5, 5, 7, 3, 8] => KeyPurposeId::TimeStamping,
            [1, 3, 6, 1, 5, 5, 7, 3, 9] => KeyPurposeId::OcspSigning,
            [2, 5, 29, 37, 0] => KeyPurposeId::AnyExtendedKeyUsage,
            _ => KeyPurposeId::Unknown,
        }
    }

    pub fn has_purpose(&self, purpose: KeyPurposeId) -> bool {
        if purpose == KeyPurposeId::Unknown {
            return false;
        }
        self.has_purpose_oid(&Self::purpose_to_oid(purpose))
    }

    pub fn has_purpose_oid(&self, purpose_oid: &Oid) -> bool {
        self.purpose_oids
            .iter()
            .any(|oid| oid.nodes.as_slice() == [2, 5, 29, 37, 0])
            || self.purpose_oids.iter().any(|oid| oid == purpose_oid)
    }

    pub fn allows_any(&self) -> bool {
        self.purpose_oids
            .iter()
            .any(|oid| oid.nodes.as_slice() == [2, 5, 29, 37, 0])
    }

    pub fn allows_server_auth(&self) -> bool {
        self.has_purpose(KeyPurposeId::ServerAuth)
    }

    pub fn allows_client_auth(&self) -> bool {
        self.has_purpose(KeyPurposeId::ClientAuth)
    }

    pub fn allows_code_signing(&self) -> bool {
        self.has_purpose(KeyPurposeId::CodeSigning)
    }

    pub fn allows_email_protection(&self) -> bool {
        self.has_purpose(KeyPurposeId::EmailProtection)
    }

    pub fn allows_time_stamping(&self) -> bool {
        self.has_purpose(KeyPurposeId::TimeStamping)
    }

    pub fn allows_ocsp_signing(&self) -> bool {
        self.has_purpose(KeyPurposeId::OcspSigning)
    }

    pub fn recognized_purposes(&self) -> Vec<KeyPurposeId> {
        self.purpose_oids
            .iter()
            .map(Self::oid_to_purpose)
            .filter(|purpose| *purpose != KeyPurposeId::Unknown)
            .collect()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtendedKeyUsageExtension {
    critical: bool,
    purpose_oids: Vec<Oid>,
}

impl ExtendedKeyUsageExtension {
    pub fn new(critical: bool, purpose_oids: Vec<Oid>) -> Self {
        Self {
            critical,
            purpose_oids,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::ExtendedKeyUsage
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn purpose_oids(&self) -> &[Oid] {
        &self.purpose_oids
    }

    pub fn purpose_to_oid(purpose: KeyPurposeId) -> Oid {
        ExtendedKeyUsage::purpose_to_oid(purpose)
    }

    pub fn oid_to_purpose(oid: &Oid) -> KeyPurposeId {
        ExtendedKeyUsage::oid_to_purpose(oid)
    }

    pub fn has_purpose(&self, purpose: KeyPurposeId) -> bool {
        ExtendedKeyUsage {
            critical: self.critical,
            purpose_oids: self.purpose_oids.clone(),
        }
        .has_purpose(purpose)
    }

    pub fn has_purpose_oid(&self, purpose_oid: &Oid) -> bool {
        ExtendedKeyUsage {
            critical: self.critical,
            purpose_oids: self.purpose_oids.clone(),
        }
        .has_purpose_oid(purpose_oid)
    }

    pub fn recognized_purposes(&self) -> Vec<KeyPurposeId> {
        ExtendedKeyUsage {
            critical: self.critical,
            purpose_oids: self.purpose_oids.clone(),
        }
        .recognized_purposes()
    }

    pub fn allows_server_auth(&self) -> bool {
        self.has_purpose(KeyPurposeId::ServerAuth)
    }

    pub fn allows_client_auth(&self) -> bool {
        self.has_purpose(KeyPurposeId::ClientAuth)
    }

    pub fn allows_code_signing(&self) -> bool {
        self.has_purpose(KeyPurposeId::CodeSigning)
    }

    pub fn allows_email_protection(&self) -> bool {
        self.has_purpose(KeyPurposeId::EmailProtection)
    }

    pub fn allows_time_stamping(&self) -> bool {
        self.has_purpose(KeyPurposeId::TimeStamping)
    }

    pub fn allows_ocsp_signing(&self) -> bool {
        self.has_purpose(KeyPurposeId::OcspSigning)
    }

    pub fn allows_any(&self) -> bool {
        ExtendedKeyUsage {
            critical: self.critical,
            purpose_oids: self.purpose_oids.clone(),
        }
        .allows_any()
    }
}

impl From<ExtendedKeyUsage> for ExtendedKeyUsageExtension {
    fn from(value: ExtendedKeyUsage) -> Self {
        Self {
            critical: value.critical,
            purpose_oids: value.purpose_oids,
        }
    }
}

impl From<ExtendedKeyUsageExtension> for ExtendedKeyUsage {
    fn from(value: ExtendedKeyUsageExtension) -> Self {
        Self {
            critical: value.critical,
            purpose_oids: value.purpose_oids,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAltNameExtension {
    critical: bool,
    names: Vec<GeneralName>,
}

impl IssuerAltNameExtension {
    pub fn new(critical: bool, names: Vec<GeneralName>) -> Self {
        Self { critical, names }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::IssuerAltName
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn names(&self) -> &[GeneralName] {
        &self.names
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyMapping {
    pub issuer_domain_policy: Vec<u32>,
    pub subject_domain_policy: Vec<u32>,
}

impl PolicyMapping {
    pub fn new(issuer_domain_policy: Vec<u32>, subject_domain_policy: Vec<u32>) -> Self {
        Self {
            issuer_domain_policy,
            subject_domain_policy,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyMappingsExtension {
    critical: bool,
    mappings: Vec<PolicyMapping>,
}

impl PolicyMappingsExtension {
    pub fn new(critical: bool, mappings: Vec<PolicyMapping>) -> Self {
        Self { critical, mappings }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::PolicyMappings
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn mappings(&self) -> &[PolicyMapping] {
        &self.mappings
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyConstraints {
    pub critical: bool,
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyConstraintsExtension {
    critical: bool,
    require_explicit_policy: Option<u32>,
    inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraintsExtension {
    pub fn new(
        critical: bool,
        require_explicit_policy: Option<u32>,
        inhibit_policy_mapping: Option<u32>,
    ) -> Self {
        Self {
            critical,
            require_explicit_policy,
            inhibit_policy_mapping,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::PolicyConstraints
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn require_explicit_policy(&self) -> Option<u32> {
        self.require_explicit_policy
    }

    pub fn inhibit_policy_mapping(&self) -> Option<u32> {
        self.inhibit_policy_mapping
    }
}

impl From<PolicyConstraints> for PolicyConstraintsExtension {
    fn from(value: PolicyConstraints) -> Self {
        Self {
            critical: value.critical,
            require_explicit_policy: value.require_explicit_policy,
            inhibit_policy_mapping: value.inhibit_policy_mapping,
        }
    }
}

impl From<PolicyConstraintsExtension> for PolicyConstraints {
    fn from(value: PolicyConstraintsExtension) -> Self {
        Self {
            critical: value.critical,
            require_explicit_policy: value.require_explicit_policy,
            inhibit_policy_mapping: value.inhibit_policy_mapping,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InhibitAnyPolicyExtension {
    critical: bool,
    skip_certs: u32,
}

impl InhibitAnyPolicyExtension {
    pub fn new(critical: bool, skip_certs: u32) -> Self {
        Self {
            critical,
            skip_certs,
        }
    }

    pub fn id(&self) -> ExtensionId {
        ExtensionId::InhibitAnyPolicy
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn skip_certs(&self) -> u32 {
        self.skip_certs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificatePurpose {
    TlsServer,
    TlsClient,
    CodeSigning,
}

#[allow(non_upper_case_globals)]
impl CertificatePurpose {
    pub const TLSServer: Self = Self::TlsServer;
    pub const TLSClient: Self = Self::TlsClient;
}
