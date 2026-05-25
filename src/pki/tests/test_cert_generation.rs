use super::*;

#[test]
fn cert_generation_builder_generates_self_signed_certificate() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=BuilderTest");

    let cert = CertificateBuilder::new()
        .set_serial_u64(42)
        .set_subject(dn.clone())
        .set_issuer(dn.clone())
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
        .set_key_usage(key_usage::KEY_CERT_SIGN)
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(cert.match_subject(&dn));
    assert!(cert.verify_signature(&cert).unwrap());
    assert_eq!(cert.basic_constraints_ca(), Some(true));
}

#[test]
fn cert_generation_builder_default_critical_flags_match_cpp_defaults() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x4401)
        .set_subject_from_string("CN=BuilderDefaults")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x44; 32])
        .set_basic_constraints(false, None)
        .unwrap()
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .set_extended_key_usage(&[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth)])
        .unwrap()
        .set_subject_alt_name(&[GeneralName {
            type_: GeneralNameType::DnsName,
            value: b"default.example".to_vec(),
        }])
        .unwrap()
        .set_subject_key_identifier(&[0x01, 0x02, 0x03])
        .unwrap()
        .set_authority_key_identifier(&[0x04, 0x05, 0x06])
        .unwrap()
        .build_with_signature(vec![0x44; 64], true)
        .unwrap();

    let extension = |id| cert.tbs.extensions.iter().find(|ext| ext.id == id).unwrap();
    assert!(extension(ExtensionId::BasicConstraints).critical);
    assert!(extension(ExtensionId::KeyUsage).critical);
    assert!(!extension(ExtensionId::ExtendedKeyUsage).critical);
    assert!(!extension(ExtensionId::SubjectAltName).critical);
    assert!(!extension(ExtensionId::SubjectKeyIdentifier).critical);
    assert!(!extension(ExtensionId::AuthorityKeyIdentifier).critical);
}

#[test]
fn cert_generation_builder_uses_random_positive_serial_when_absent() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=RandomSerial");

    let build = || {
        CertificateBuilder::new()
            .set_subject(dn.clone())
            .set_issuer(dn.clone())
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
            .set_key_usage(key_usage::KEY_CERT_SIGN)
            .unwrap()
            .build_ed25519_with_self_signed(&key, true)
            .unwrap()
    };

    let cert1 = build();
    let cert2 = build();

    assert_eq!(cert1.tbs.serial_number.len(), 16);
    assert_eq!(cert2.tbs.serial_number.len(), 16);
    assert_eq!(cert1.tbs.serial_number[0] & 0x80, 0);
    assert_eq!(cert2.tbs.serial_number[0] & 0x80, 0);
    assert_ne!(cert1.tbs.serial_number, cert2.tbs.serial_number);
    assert!(cert1.verify_signature(&cert1).unwrap());
    assert!(cert2.verify_signature(&cert2).unwrap());
}

#[test]
fn cert_generation_detail_namespace_matches_cpp_builder_helpers() {
    let serial = detail::make_random_serial().unwrap();
    assert_eq!(serial.len(), 16);
    assert_eq!(serial[0] & 0x80, 0);

    assert_eq!(
        detail::get_extension_oid(ExtensionId::BasicConstraints),
        Oid::new([2, 5, 29, 19])
    );
    assert_eq!(
        detail::get_extension_oid(ExtensionId::Unknown),
        Oid::default()
    );

    assert_eq!(
        detail::get_signature_oid(SignatureAlgorithmId::Ed25519).unwrap(),
        Oid::new([1, 3, 101, 112])
    );
    assert_eq!(
        detail::get_signature_oid(SignatureAlgorithmId::RsaPssSha512).unwrap(),
        Oid::new([1, 2, 840, 113549, 1, 1, 10])
    );
    assert_eq!(
        detail::get_signature_oid(SignatureAlgorithmId::Unknown)
            .unwrap_err()
            .message,
        "Failed to get OID for signature algorithm ID"
    );

    assert!(detail::is_utctime(&DerTime {
        year: 2049,
        month: 12,
        day: 31,
        hour: 23,
        minute: 59,
        second: 59,
    }));
    assert!(!detail::is_utctime(&DerTime {
        year: 2050,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }));

    assert_eq!(
        detail::to_gmtime(std::time::UNIX_EPOCH),
        DerTime {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        }
    );
}

#[test]
fn cert_generation_builder_result_wrappers_match_cpp_surface() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=BuilderResult");
    let builder = || {
        CertificateBuilder::new()
            .set_serial_u64(0x7902)
            .set_subject(dn.clone())
            .set_issuer(dn.clone())
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
    };

    let unsigned = builder().build_unsigned_tbs_result(true);
    assert!(unsigned.success);
    assert!(!unsigned.value.is_empty());
    assert!(unsigned.error.is_empty());

    let built = builder().build_ed25519_result_with_self_signed(&key, true);
    assert!(built.success);
    assert!(built.value.verify_signature(&built.value).unwrap());

    let built_via_dispatch = builder().build_result_with_self_signed(&key, true);
    assert!(built_via_dispatch.success);
    assert!(built_via_dispatch.value.match_subject(&dn));

    let missing_subject = CertificateBuilder::new()
        .set_issuer(dn.clone())
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
        .build_result_with_self_signed(&key, true);
    assert!(!missing_subject.success);
    assert_eq!(missing_subject.error, "Subject not set");

    let unsupported_signature = builder()
        .set_signature_algorithm(SignatureAlgorithmId::Unknown)
        .build_result_with_self_signed(&key, true);
    assert!(!unsupported_signature.success);
    assert_eq!(
        unsupported_signature.error,
        "Unsupported signature algorithm for builder"
    );
}

#[test]
fn cert_generation_builder_build_defaults_to_non_self_signed_like_cpp() {
    let key = generate_ed25519_keypair().unwrap();
    let issuer = helpers::dn_from_string("CN=IssuerDefault");
    let subject = helpers::dn_from_string("CN=SubjectDefault");

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7903)
        .set_issuer(issuer.clone())
        .set_subject(subject.clone())
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519(&key)
        .unwrap();

    assert_eq!(cert.tbs.issuer, issuer);
    assert_eq!(cert.tbs.subject, subject);

    let missing_issuer = CertificateBuilder::new()
        .set_serial_u64(0x7904)
        .set_subject_from_string("CN=NeedsIssuerByDefault")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_result(&key);
    assert!(!missing_issuer.success);
    assert_eq!(missing_issuer.error, "Issuer not set");

    let explicit_self_signed = CertificateBuilder::new()
        .set_serial_u64(0x7905)
        .set_subject_from_string("CN=ExplicitSelfSigned")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();
    assert_eq!(
        explicit_self_signed.tbs.issuer,
        explicit_self_signed.tbs.subject
    );
}

#[test]
fn cert_generation_builder_roundtrips_der_and_extensions() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x19)
        .set_issuer_from_string("CN=Issuer, O=Robolibs, C=NL")
        .unwrap()
        .set_subject_from_string("CN=device.example, O=Robolibs, C=NL")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x55; 32])
        .set_basic_constraints(false, None)
        .unwrap()
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .set_extended_key_usage(&[ExtendedKeyUsage::purpose_to_oid(KeyPurposeId::ServerAuth)])
        .unwrap()
        .set_subject_alt_name(&[GeneralName {
            type_: GeneralNameType::DnsName,
            value: b"device.example".to_vec(),
        }])
        .unwrap()
        .build_with_signature(vec![0xcc; 64], false)
        .unwrap();

    let parsed = Certificate::parse_der(&cert.der).unwrap();
    assert_eq!(parsed.tbs.version, 3);
    assert_eq!(parsed.tbs.serial_number, vec![0x19]);
    assert_eq!(
        parsed
            .tbs
            .issuer
            .first(DistinguishedNameAttribute::CommonName),
        Some("Issuer")
    );
    assert_eq!(
        parsed
            .tbs
            .subject
            .first(DistinguishedNameAttribute::CommonName),
        Some("device.example")
    );
    assert_eq!(
        parsed.tbs.subject_public_key_info.public_key,
        vec![0x55; 32]
    );
    assert_eq!(parsed.signature_value, vec![0xcc; 64]);
    assert_eq!(parsed.basic_constraints_ca(), Some(false));
    assert!(parsed.verify_key_usage(key_usage::DIGITAL_SIGNATURE));
    assert!(parsed.match_hostname("device.example"));
    assert!(parsed.verify_extensions(CertificatePurpose::TlsServer));
}

#[test]
fn cert_generation_builder_supports_self_signed_unsigned_tbs() {
    let builder = CertificateBuilder::new()
        .set_subject_from_string("CN=self-signed")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x66; 32]);

    let tbs = builder.build_unsigned_tbs(true).unwrap();
    assert!(!tbs.is_empty());
    let cert = builder
        .set_basic_constraints(true, Some(1))
        .unwrap()
        .build_with_signature(vec![0xdd; 64], true)
        .unwrap();
    assert_eq!(cert.tbs.issuer, cert.tbs.subject);
    assert_eq!(cert.basic_constraints_ca(), Some(true));
    assert_eq!(cert.basic_constraints_path_length(), Some(1));
}
