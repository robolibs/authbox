use super::*;

fn test_cert_with_extensions(extensions: Vec<RawExtension>, subject_cn: &str) -> Certificate {
    Certificate {
        tbs: TbsCertificate {
            version: 3,
            subject: DistinguishedName::from_string(&format!("CN={subject_cn}")).unwrap(),
            extensions,
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    }
}

#[test]
fn cert_extensions_decode_core_extension_helpers() {
    let basic_constraints = RawExtension {
        oid: Oid::new([2, 5, 29, 19]),
        id: ExtensionId::BasicConstraints,
        critical: true,
        value: der::encode_sequence(&der::concat(&[
            der::encode_boolean(true),
            der::encode_integer(3),
        ])),
    };
    let key_usage = RawExtension {
        oid: Oid::new([2, 5, 29, 15]),
        id: ExtensionId::KeyUsage,
        critical: true,
        value: der::encode_bit_string(&[0xa0, 0x00]),
    };
    let subject_alt_name = RawExtension {
        oid: Oid::new([2, 5, 29, 17]),
        id: ExtensionId::SubjectAltName,
        critical: false,
        value: der::encode_sequence(&der::concat(&[
            der::encode_context_primitive(2, b"example.com"),
            der::encode_context_primitive(2, b"*.example.org"),
            der::encode_context_primitive(7, &[127, 0, 0, 1]),
        ])),
    };
    let extended_key_usage = RawExtension {
        oid: Oid::new([2, 5, 29, 37]),
        id: ExtensionId::ExtendedKeyUsage,
        critical: false,
        value: der::encode_sequence(&der::concat(&[
            der::encode_oid(&ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth)),
            der::encode_oid(&ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ClientAuth)),
        ])),
    };
    let cert = test_cert_with_extensions(
        vec![
            basic_constraints,
            key_usage,
            subject_alt_name,
            extended_key_usage,
        ],
        "fallback.example",
    );

    assert_eq!(cert.basic_constraints_ca(), Some(true));
    assert_eq!(cert.basic_constraints_path_length(), Some(3));
    assert_eq!(
        cert.key_usage_bits(),
        Some(key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT)
    );
    assert!(cert.verify_key_usage(key_usage::DIGITAL_SIGNATURE));

    let names = cert.subject_alt_names();
    assert_eq!(names.len(), 3);
    assert_eq!(names[0].type_, GeneralNameType::DnsName);
    assert_eq!(names[0].value_string(), "example.com");
    assert!(cert.match_hostname("example.com"));
    assert!(cert.match_hostname("api.example.org"));
    assert!(!cert.match_hostname("deep.api.example.org"));
    assert!(cert.match_hostname("127.0.0.1"));
    assert!(!cert.match_hostname("fallback.example"));

    let eku = cert.extended_key_usage().unwrap();
    assert!(eku.has_purpose(KeyPurposeId::ServerAuth));
    assert!(eku.has_purpose(KeyPurposeId::ClientAuth));
    assert!(!eku.has_purpose(KeyPurposeId::CodeSigning));
    assert!(cert.verify_extensions(CertificatePurpose::TlsServer));
    assert!(cert.verify_extensions(CertificatePurpose::TlsClient));
    assert!(!cert.verify_extensions(CertificatePurpose::CodeSigning));
}

#[test]
fn cert_extensions_cpp_named_certificate_purpose_constants_match_rust_variants() {
    assert_eq!(CertificatePurpose::TLSServer, CertificatePurpose::TlsServer);
    assert_eq!(CertificatePurpose::TLSClient, CertificatePurpose::TlsClient);
}

#[test]
fn cert_extensions_cpp_named_extension_id_constants_match_rust_variants() {
    assert_eq!(
        ExtensionId::CRLDistributionPoints,
        ExtensionId::CrlDistributionPoints
    );
}

#[test]
fn cert_extensions_cpp_base_extension_surface_works() {
    let extension = Extension::new(ExtensionId::KeyUsage, true);
    assert_eq!(extension.id(), ExtensionId::KeyUsage);
    assert!(extension.critical());

    let raw = RawExtension {
        oid: Oid::new([2, 5, 29, 19]),
        id: ExtensionId::BasicConstraints,
        critical: false,
        value: der::encode_sequence(&[]),
    };
    let copied = Extension::from(&raw);
    assert_eq!(copied.id(), ExtensionId::BasicConstraints);
    assert!(!copied.critical());
}

#[test]
fn cert_extensions_cpp_named_wrapper_surfaces_work() {
    let basic_constraints = BasicConstraintsExtension::new(true, true, Some(2));
    assert_eq!(basic_constraints.id(), ExtensionId::BasicConstraints);
    assert!(basic_constraints.critical());
    assert!(basic_constraints.is_ca());
    assert_eq!(basic_constraints.path_length(), Some(2));

    let key_usage = KeyUsageExtension::new(
        true,
        KeyUsageExtension::DigitalSignature | KeyUsageExtension::KeyCertSign,
    );
    assert_eq!(key_usage.id(), ExtensionId::KeyUsage);
    assert!(key_usage.critical());
    assert!(key_usage.has(KeyUsageExtension::DigitalSignature));
    assert!(key_usage.has(KeyUsageExtension::KeyCertSign));
    assert!(!key_usage.has(KeyUsageExtension::CRLSign));
    assert_eq!(
        key_usage.bits(),
        key_usage::DIGITAL_SIGNATURE | key_usage::KEY_CERT_SIGN
    );

    let san = SubjectAltNameExtension::new(
        false,
        vec![
            GeneralName::new(GeneralNameType::DNSName, "example.com"),
            GeneralName::new(GeneralNameType::URI, "did:web:example.com"),
            GeneralName::new(GeneralNameType::IPAddress, "192.0.2.1"),
        ],
    );
    assert_eq!(san.id(), ExtensionId::SubjectAltName);
    assert!(!san.critical());
    assert_eq!(san.names().len(), 3);
    assert_eq!(san.names()[0].value_string(), "example.com");
    assert_eq!(san.names()[1].type_, GeneralNameType::Uri);
    assert_eq!(san.names()[2].type_, GeneralNameType::IpAddress);

    let subject_key_identifier = SubjectKeyIdentifierExtension::new(false, vec![1, 2, 3, 4]);
    assert_eq!(
        subject_key_identifier.id(),
        ExtensionId::SubjectKeyIdentifier
    );
    assert!(!subject_key_identifier.critical());
    assert_eq!(subject_key_identifier.identifier(), &[1, 2, 3, 4]);

    let authority_key_identifier = AuthorityKeyIdentifierExtension::new(true, vec![5, 6, 7, 8]);
    assert_eq!(
        authority_key_identifier.id(),
        ExtensionId::AuthorityKeyIdentifier
    );
    assert!(authority_key_identifier.critical());
    assert_eq!(authority_key_identifier.key_identifier(), &[5, 6, 7, 8]);
}

#[test]
fn cert_extensions_san_and_key_usage_verification() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=example.com");

    let cert = CertificateBuilder::new()
        .set_serial_u64(100)
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
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .set_subject_alt_name(&[GeneralName {
            type_: GeneralNameType::DnsName,
            value: b"example.com".to_vec(),
        }])
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(cert.verify_key_usage(key_usage::DIGITAL_SIGNATURE));
    assert!(cert.verify_extensions(CertificatePurpose::TlsServer));
    assert!(cert.match_hostname("example.com"));
}
