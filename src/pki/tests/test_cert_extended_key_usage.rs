use super::*;

fn eku_cert(purposes: &[Oid], critical: bool, serial: u64) -> Certificate {
    let key = generate_ed25519_keypair().unwrap();
    CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_subject_from_string("CN=EKU Test")
        .unwrap()
        .set_issuer_from_string("CN=EKU Test")
        .unwrap()
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
        .set_extended_key_usage_with_critical(purposes, critical)
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap()
}

fn eku_cert_with_usage(
    purposes: &[Oid],
    key_usage_bits: u16,
    dns_name: Option<&str>,
    serial: u64,
) -> Certificate {
    let key = generate_ed25519_keypair().unwrap();
    let mut builder = CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_subject_from_string("CN=example.com")
        .unwrap()
        .set_issuer_from_string("CN=EKU Test CA")
        .unwrap()
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
        .set_key_usage(key_usage_bits)
        .unwrap()
        .set_extended_key_usage(purposes)
        .unwrap();
    if let Some(dns_name) = dns_name {
        builder = builder
            .set_subject_alt_name(&[GeneralName {
                type_: GeneralNameType::DnsName,
                value: dns_name.as_bytes().to_vec(),
            }])
            .unwrap();
    }
    builder.build_ed25519_with_self_signed(&key, true).unwrap()
}

#[test]
fn cert_extended_key_usage_oid_to_purpose_conversion() {
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 1])),
        KeyPurposeId::ServerAuth
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 2])),
        KeyPurposeId::ClientAuth
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 3])),
        KeyPurposeId::CodeSigning
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 4])),
        KeyPurposeId::EmailProtection
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 8])),
        KeyPurposeId::TimeStamping
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 9])),
        KeyPurposeId::OcspSigning
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([2, 5, 29, 37, 0])),
        KeyPurposeId::AnyExtendedKeyUsage
    );
    assert_eq!(
        ExtendedKeyUsage::oid_to_purpose(&Oid::new([1, 2, 3, 4, 5])),
        KeyPurposeId::Unknown
    );
}

#[test]
fn cert_extended_key_usage_cpp_named_wrapper_surface_works() {
    let purposes = vec![
        ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId::ServerAuth),
        ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId::OCSPSigning),
    ];
    let eku = ExtendedKeyUsageExtension::new(true, purposes.clone());

    assert_eq!(eku.id(), ExtensionId::ExtendedKeyUsage);
    assert!(eku.critical());
    assert_eq!(eku.purpose_oids(), purposes.as_slice());
    assert_eq!(
        ExtendedKeyUsageExtension::oid_to_purpose(&purposes[0]),
        KeyPurposeId::ServerAuth
    );
    assert!(eku.has_purpose(KeyPurposeId::ServerAuth));
    assert!(eku.has_purpose(KeyPurposeId::OCSPSigning));
    assert!(eku.has_purpose_oid(&purposes[1]));
    assert!(eku.allows_server_auth());
    assert!(eku.allows_ocsp_signing());
    assert!(!eku.allows_client_auth());

    let flat: ExtendedKeyUsage = eku.clone().into();
    let roundtrip = ExtendedKeyUsageExtension::from(flat);
    assert_eq!(roundtrip, eku);
}

#[test]
fn cert_extended_key_usage_purpose_to_oid_conversion() {
    assert_eq!(
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth).nodes,
        vec![1, 3, 6, 1, 5, 5, 7, 3, 1]
    );
    assert_eq!(
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth).nodes,
        vec![1, 3, 6, 1, 5, 5, 7, 3, 2]
    );
    assert_eq!(
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::CodeSigning).nodes,
        vec![1, 3, 6, 1, 5, 5, 7, 3, 3]
    );
}

#[test]
fn cert_extended_key_usage_has_purpose_and_allows_any() {
    let eku = ExtendedKeyUsage {
        critical: false,
        purpose_oids: vec![
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth),
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth),
        ],
    };
    assert!(eku.has_purpose(KeyPurposeId::ServerAuth));
    assert!(eku.has_purpose(KeyPurposeId::ClientAuth));
    assert!(!eku.has_purpose(KeyPurposeId::CodeSigning));
    assert!(!eku.has_purpose(KeyPurposeId::EmailProtection));
    assert!(eku.has_purpose_oid(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 1])));
    assert!(!eku.has_purpose_oid(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 3])));

    let any = ExtendedKeyUsage {
        critical: false,
        purpose_oids: vec![ExtendedKeyUsage::purpose_to_oid(
            KeyPurposeId::AnyExtendedKeyUsage,
        )],
    };
    assert!(any.allows_any());
    assert!(any.has_purpose(KeyPurposeId::ServerAuth));
    assert!(any.has_purpose(KeyPurposeId::CodeSigning));
    assert!(any.has_purpose_oid(&Oid::new([1, 2, 3, 4, 5])));
}

#[test]
fn cert_extended_key_usage_helper_methods_and_recognized_purposes() {
    let eku = ExtendedKeyUsage {
        critical: false,
        purpose_oids: vec![
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth),
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::CodeSigning),
            Oid::new([9, 9, 9, 9, 9]),
        ],
    };

    assert!(eku.allows_server_auth());
    assert!(!eku.allows_client_auth());
    assert!(eku.allows_code_signing());
    assert!(!eku.allows_email_protection());
    assert!(!eku.allows_any());
    assert_eq!(
        eku.recognized_purposes(),
        vec![KeyPurposeId::ServerAuth, KeyPurposeId::CodeSigning]
    );
}

#[test]
fn cert_extended_key_usage_builder_and_accessor() {
    let purposes = [
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth),
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth),
    ];
    let cert = eku_cert(&purposes, false, 0x450);
    let eku = cert.extended_key_usage().unwrap();

    assert_eq!(eku.purpose_oids.len(), 2);
    assert!(eku.allows_server_auth());
    assert!(eku.allows_client_auth());

    let no_eku = eku_cert(&[], false, 0x451);
    assert!(no_eku.extended_key_usage().is_none());
}

#[test]
fn cert_extended_key_usage_purpose_specific_certificates() {
    let server_cert = eku_cert(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth)],
        false,
        0x452,
    );
    let server_eku = server_cert.extended_key_usage().unwrap();
    assert!(server_eku.allows_server_auth());
    assert!(!server_eku.allows_client_auth());

    let client_cert = eku_cert(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth)],
        false,
        0x453,
    );
    let client_eku = client_cert.extended_key_usage().unwrap();
    assert!(client_eku.allows_client_auth());
    assert!(!client_eku.allows_server_auth());

    let ocsp_cert = eku_cert(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::OcspSigning)],
        false,
        0x454,
    );
    assert!(
        ocsp_cert
            .extended_key_usage()
            .unwrap()
            .allows_ocsp_signing()
    );

    let time_stamping_cert = eku_cert(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::TimeStamping)],
        false,
        0x456,
    );
    assert!(
        time_stamping_cert
            .extended_key_usage()
            .unwrap()
            .allows_time_stamping()
    );
}

#[test]
fn cert_extended_key_usage_critical_and_roundtrip() {
    let purposes = [
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth),
        ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::CodeSigning),
    ];
    let cert = eku_cert(&purposes, true, 0x455);
    assert!(cert.extended_key_usage().unwrap().critical);

    let parsed = Certificate::parse_der(cert.der()).unwrap();
    let eku = parsed.extended_key_usage().unwrap();
    assert_eq!(eku.purpose_oids.len(), 2);
    assert!(eku.allows_server_auth());
    assert!(eku.allows_code_signing());
    assert!(eku.critical);
}

#[test]
fn cert_extended_key_usage_verify_extensions_matches_cpp_purpose_rules() {
    let server = eku_cert_with_usage(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth)],
        key_usage::DIGITAL_SIGNATURE,
        Some("example.com"),
        0x457,
    );
    assert!(server.verify_extensions(CertificatePurpose::TlsServer));
    assert!(server.match_hostname("example.com"));

    let client = eku_cert_with_usage(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth)],
        key_usage::DIGITAL_SIGNATURE,
        None,
        0x458,
    );
    assert!(client.verify_extensions(CertificatePurpose::TlsClient));
    assert!(!client.verify_extensions(CertificatePurpose::TlsServer));

    let multipurpose = eku_cert_with_usage(
        &[
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth),
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth),
            ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::EmailProtection),
        ],
        key_usage::DIGITAL_SIGNATURE,
        Some("example.com"),
        0x459,
    );
    let eku = multipurpose.extended_key_usage().unwrap();
    assert!(eku.allows_server_auth());
    assert!(eku.allows_client_auth());
    assert!(eku.allows_email_protection());
    assert_eq!(eku.recognized_purposes().len(), 3);
    assert!(multipurpose.verify_extensions(CertificatePurpose::TlsServer));
    assert!(multipurpose.verify_extensions(CertificatePurpose::TlsClient));

    let code_signing_without_non_repudiation = eku_cert_with_usage(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::CodeSigning)],
        key_usage::DIGITAL_SIGNATURE,
        None,
        0x45a,
    );
    assert!(
        !code_signing_without_non_repudiation.verify_extensions(CertificatePurpose::CodeSigning)
    );

    let code_signing = eku_cert_with_usage(
        &[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::CodeSigning)],
        key_usage::DIGITAL_SIGNATURE | key_usage::NON_REPUDIATION,
        None,
        0x45b,
    );
    assert!(code_signing.verify_extensions(CertificatePurpose::CodeSigning));
}
