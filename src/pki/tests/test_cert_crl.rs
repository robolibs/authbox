use super::*;

#[test]
fn cert_crl_cpp_named_crl_extension_id_constants_match_rust_variants() {
    assert_eq!(CrlExtensionId::CRLNumber, CrlExtensionId::CrlNumber);
    assert_eq!(
        CrlExtensionId::DeltaCRLIndicator,
        CrlExtensionId::DeltaCrlIndicator
    );
    assert_eq!(CrlExtensionId::FreshestCRL, CrlExtensionId::FreshestCrl);
    assert_eq!(
        CrlExtensionId::ExpiredCertsOnCRL,
        CrlExtensionId::ExpiredCertsOnCrl
    );
}

#[test]
fn cert_crl_detail_namespace_matches_cpp_helpers() {
    let mut cursor = detail::CrlDerCursor::new(&[1, 2, 3, 4]);
    assert_eq!(cursor.remaining(), &[1, 2, 3, 4]);
    assert_eq!(cursor.offset(), 0);
    assert!(cursor.advance(2));
    assert_eq!(cursor.remaining(), &[3, 4]);
    assert_eq!(cursor.offset(), 2);
    assert!(!cursor.advance(3));
    assert_eq!(cursor.offset(), 2);
    assert!(cursor.advance(2));
    assert!(cursor.empty());
    assert_eq!(detail::crl_copy_span(&[0xaa, 0xbb]), vec![0xaa, 0xbb]);

    let name_der = DistinguishedName::from_string("CN=crl-detail")
        .unwrap()
        .der()
        .to_vec();
    let parsed_name = detail::crl_parse_name(&name_der).unwrap();
    assert_eq!(parsed_name.value.to_string(), "CN=crl-detail");
    assert_eq!(parsed_name.bytes_consumed, name_der.len());

    let alg_der = der::encode_sequence(&der::encode_oid(&Oid::new(detail::kOidEd25519)));
    let parsed_alg = detail::crl_parse_algorithm_identifier(&alg_der).unwrap();
    assert_eq!(parsed_alg.value.signature, SignatureAlgorithmId::Ed25519);

    let time_der = der::encode_utctime("260524000000Z");
    let parsed_time = detail::crl_parse_time(&time_der).unwrap();
    assert_eq!(
        parsed_time.value,
        DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        }
    );
    assert_eq!(
        detail::crl_parse_time(&[]).unwrap_err().message,
        "empty time"
    );
    assert_eq!(
        detail::crl_parse_time(&der::encode_boolean(true))
            .unwrap_err()
            .message,
        "unsupported time type"
    );

    assert_eq!(
        detail::parse_reason_code(&der::encode_tlv(
            Asn1Class::Universal,
            false,
            Asn1Tag::Enumerated as u32,
            &[CrlReason::KeyCompromise as u8],
        )),
        Some(CrlReason::KeyCompromise)
    );
    assert_eq!(detail::parse_reason_code(&[0x0a, 0x01, 0x07]), None);
    assert_eq!(
        detail::identify_crl_entry_extension(&Oid::new([2, 5, 29, 21])),
        CrlEntryExtensionId::ReasonCode
    );
    assert_eq!(
        detail::identify_crl_extension(&Oid::new([2, 5, 29, 20])),
        CrlExtensionId::CrlNumber
    );

    let reason_value = der::encode_tlv(
        Asn1Class::Universal,
        false,
        Asn1Tag::Enumerated as u32,
        &[CrlReason::Superseded as u8],
    );
    let entry_extension = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([2, 5, 29, 21])),
        der::encode_octet_string(&reason_value),
    ]));
    let entry_extensions = der::encode_sequence(&entry_extension);
    let mut revoked = RevokedCertificate::default();
    let parsed_entry_extensions =
        detail::parse_crl_entry_extensions(&entry_extensions, &mut revoked).unwrap();
    assert_eq!(parsed_entry_extensions.value.len(), 1);
    assert_eq!(
        parsed_entry_extensions.value[0].id,
        CrlEntryExtensionId::ReasonCode
    );
    assert_eq!(revoked.reason, Some(CrlReason::Superseded));

    let aki_value = der::encode_sequence(&der::encode_tlv(
        Asn1Class::ContextSpecific,
        false,
        0,
        &[0xde, 0xad],
    ));
    let aki_extension = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([2, 5, 29, 35])),
        der::encode_octet_string(&aki_value),
    ]));
    let crl_number_value = der::encode_integer(7);
    let crl_number_extension = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([2, 5, 29, 20])),
        der::encode_octet_string(&crl_number_value),
    ]));
    let crl_extensions = der::encode_context_constructed(
        0,
        &der::encode_sequence(&der::concat(&[aki_extension, crl_number_extension])),
    );
    let mut crl = Crl::default();
    let parsed_crl_extensions = detail::parse_crl_extensions(&crl_extensions, &mut crl).unwrap();
    assert_eq!(parsed_crl_extensions.value.len(), 2);
    assert_eq!(crl.authority_key_identifier, Some(vec![0xde, 0xad]));
    assert_eq!(crl.crl_number, Some(vec![7]));
}

#[test]
fn cert_crl_unsupported_verify_error_matches_cpp_surface() {
    let issuer = Certificate::default();
    let crl = Crl {
        outer_signature: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Unknown,
            ..AlgorithmIdentifier::default()
        },
        tbs_der: b"unsupported-crl".to_vec(),
        signature_value: vec![0xaa; 64],
        ..Crl::default()
    };

    let result = crl.verify_signature_result(&issuer);
    assert!(!result.success);
    assert_eq!(
        result.error,
        "Unsupported signature algorithm for CRL verification"
    );
}

#[test]
fn cert_crl_parser_keeps_cpp_lenient_extension_behavior_and_error_prefixes() {
    let algorithm = AlgorithmIdentifier {
        signature: SignatureAlgorithmId::Ed25519,
        ..AlgorithmIdentifier::default()
    };
    let signature_algorithm = encode_algorithm_identifier(&algorithm).unwrap();
    let issuer = DistinguishedName::from_string("CN=lenient-crl")
        .unwrap()
        .der()
        .to_vec();
    let bad_crl_extensions =
        der::encode_context_constructed(0, &der::encode_tlv(Asn1Class::Universal, false, 5, &[]));
    let tbs = der::encode_sequence(&der::concat(&[
        der::encode_integer(1),
        signature_algorithm.clone(),
        issuer.clone(),
        der::encode_utctime("260524000000Z"),
        bad_crl_extensions,
    ]));
    let crl_der = der::encode_sequence(&der::concat(&[
        tbs,
        signature_algorithm.clone(),
        der::encode_bit_string(&[0x55; 64]),
    ]));
    let parsed = parse_crl(&crl_der).unwrap();
    assert_eq!(parsed.version, 2);
    assert!(parsed.extensions.is_empty());

    let malformed_revoked = der::encode_sequence(&der::encode_sequence(&der::concat(&[
        der::encode_tlv(Asn1Class::Universal, false, Asn1Tag::Null as u32, &[]),
        der::encode_utctime("260524000000Z"),
    ])));
    let bad_serial_tbs = der::encode_sequence(&der::concat(&[
        signature_algorithm.clone(),
        issuer.clone(),
        der::encode_utctime("260524000000Z"),
        malformed_revoked,
    ]));
    let bad_serial_crl = der::encode_sequence(&der::concat(&[
        bad_serial_tbs,
        signature_algorithm.clone(),
        der::encode_bit_string(&[0x56; 64]),
    ]));
    assert_eq!(
        parse_crl(&bad_serial_crl).unwrap_err().message,
        "failed to parse revoked cert serial: expected INTEGER"
    );

    let malformed_revocation_time = der::encode_sequence(&der::encode_sequence(&der::concat(&[
        der::encode_integer(9),
        der::encode_boolean(true),
    ])));
    let bad_time_tbs = der::encode_sequence(&der::concat(&[
        signature_algorithm.clone(),
        issuer,
        der::encode_utctime("260524000000Z"),
        malformed_revocation_time,
    ]));
    let bad_time_crl = der::encode_sequence(&der::concat(&[
        bad_time_tbs,
        signature_algorithm,
        der::encode_bit_string(&[0x57; 64]),
    ]));
    assert_eq!(
        parse_crl(&bad_time_crl).unwrap_err().message,
        "failed to parse revocation time: unsupported time type"
    );
}

#[test]
fn cert_crl_check_validity_now_matches_cpp_default_time_surface() {
    let valid_now = Crl {
        this_update: der_time(2020, 1, 1),
        next_update: Some(der_time(2100, 1, 1)),
        ..Crl::default()
    };
    assert!(valid_now.check_validity());
    assert!(valid_now.check_validity_now());

    let expired = Crl {
        this_update: der_time(2020, 1, 1),
        next_update: Some(der_time(2021, 1, 1)),
        ..Crl::default()
    };
    assert!(!expired.check_validity());
    assert!(!expired.check_validity_now());
}

#[test]
fn cert_crl_builder_and_revocation() {
    let (root_cert, root_key) = helpers::make_self_signed_certificate("Root CA", 0x7801);
    let leaf_key = generate_ed25519_keypair().unwrap();
    let leaf_dn = helpers::dn_from_string("CN=revoked");
    let leaf_cert = helpers::make_certificate(
        &root_cert.tbs.subject,
        &leaf_dn,
        &root_key,
        &leaf_key,
        false,
        key_usage::DIGITAL_SIGNATURE,
        0x7802,
    );

    let crl = CrlBuilder::new()
        .set_issuer(root_cert.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .add_revoked_serial_with_reason(
            leaf_cert.tbs.serial_number.clone(),
            DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            CrlReason::KeyCompromise,
        )
        .build_ed25519(&root_key)
        .unwrap();

    let parsed = parse_crl(&crl.der).unwrap();
    assert!(leaf_cert.is_revoked(&parsed));
    assert!(parsed.verify_signature(&root_cert).unwrap());
}

#[test]
fn cert_crl_sign_helper_matches_stored_ed25519_signature() {
    let (root_cert, root_key) = helpers::make_self_signed_certificate("Root CA", 0x7811);
    let crl = CrlBuilder::new()
        .set_issuer(root_cert.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .build_ed25519(&root_key)
        .unwrap();

    assert_eq!(crl.sign(&root_key).unwrap(), crl.signature_value);
}

#[test]
fn cert_crl_result_wrappers_match_cpp_surface() {
    let (root_cert, root_key) = helpers::make_self_signed_certificate("Root CA", 0x7812);
    let crl = CrlBuilder::new()
        .set_issuer(root_cert.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .build_ed25519_result(&root_key);
    assert!(crl.success);
    assert!(crl.error.is_empty());

    let parsed = parse_crl_result(&crl.value.der);
    assert!(parsed.success);
    assert!(parsed.value.verify_signature_result(&root_cert).value);
    assert_eq!(
        parsed.value.sign_result(&root_key).value,
        parsed.value.signature_value
    );

    let top = parse_sequence(&crl.value.der).unwrap();
    let trailing = der::encode_sequence(&der::concat(&[
        top.value,
        der::encode_tlv(Asn1Class::Universal, false, Asn1Tag::Null as u32, &[]),
    ]));
    let strict = parse_crl_result_with_relaxed(&trailing, false);
    assert!(!strict.success);
    assert_eq!(strict.error, "unexpected trailing data in CRL");
    let relaxed = parse_crl_result_with_relaxed(&trailing, true);
    assert!(relaxed.success);
    assert_eq!(relaxed.value.der, trailing);
    assert_eq!(relaxed.value.tbs_der, crl.value.tbs_der);
    assert_eq!(
        parse_crl_with_relaxed(&trailing, true).unwrap().der,
        trailing
    );

    let from_der = Crl::from_der_result(&parsed.value.der);
    assert!(from_der.success);
    assert_eq!(from_der.value.der, parsed.value.der);

    let from_pem = Crl::from_pem_result(&parsed.value.to_pem());
    assert!(from_pem.success);
    assert_eq!(from_pem.value.der, parsed.value.der);

    let pem_chain = parse_pem_crl_chain_result(&parsed.value.to_pem());
    assert!(pem_chain.success);
    assert_eq!(pem_chain.value.len(), 1);

    let missing_issuer = CrlBuilder::new().build_unsigned_tbs_result();
    assert!(!missing_issuer.success);
    assert_eq!(missing_issuer.error, "issuer not set");

    let unsupported_builder = CrlBuilder::new()
        .set_issuer(root_cert.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::Unknown)
        .build_result(&root_key);
    assert!(!unsupported_builder.success);
    assert_eq!(
        unsupported_builder.error,
        "Unsupported CRL signature algorithm"
    );

    let unsupported_sign = Crl {
        outer_signature: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Unknown,
            ..AlgorithmIdentifier::default()
        },
        tbs_der: b"unsupported-crl-sign".to_vec(),
        ..Crl::default()
    }
    .sign_result(&root_key);
    assert!(!unsupported_sign.success);
    assert_eq!(
        unsupported_sign.error,
        "Unsupported CRL signature algorithm"
    );
}

#[test]
fn cert_crl_builder_der_encodes_ecdsa_signatures_for_emit() {
    let raw_ecdsa_signature = {
        let mut sig = vec![0x11; 32];
        sig.extend(vec![0x22; 32]);
        sig
    };
    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=issuer")
        .unwrap()
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .add_revoked_serial_with_reason(
            vec![0x02],
            DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            CrlReason::Superseded,
        )
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256)
        .build_with_signature(raw_ecdsa_signature)
        .unwrap();

    let parsed = parse_crl(&crl.der).unwrap();
    assert_eq!(
        parsed.outer_signature.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(!parsed.signature_value.is_empty());
    assert_eq!(parsed.signature_value[0], 0x30);
    assert_eq!(parsed.revoked[0].reason, Some(CrlReason::Superseded));
}

#[test]
fn cert_crl_build_signs_rsa_pkcs1v15() {
    let key = helpers::test_rsa_keypair(80);
    let issuer = Certificate {
        tbs: TbsCertificate {
            subject: helpers::dn_from_string("CN=rsa-crl-issuer"),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: SignatureAlgorithmId::RsaPkcs1Sha256,
                    hash: HashAlgorithm::Sha256,
                    curve: CurveId::Unknown,
                },
                public_key: key.public_key.clone(),
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };

    let crl = CrlBuilder::new()
        .set_issuer(issuer.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build(&key)
        .unwrap();

    assert!(crl.verify_signature(&issuer).unwrap());
    assert_eq!(crl.sign(&key).unwrap(), crl.signature_value);
}

#[test]
fn cert_crl_build_signs_rsa_pss() {
    let key = helpers::test_rsa_keypair(80);
    let issuer = Certificate {
        tbs: TbsCertificate {
            subject: helpers::dn_from_string("CN=rsa-pss-crl-issuer"),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: SignatureAlgorithmId::RsaPssSha256,
                    hash: HashAlgorithm::Sha256,
                    curve: CurveId::Unknown,
                },
                public_key: key.public_key.clone(),
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };

    let crl = CrlBuilder::new()
        .set_issuer(issuer.tbs.subject.clone())
        .set_this_update(DerTime {
            year: 2026,
            month: 5,
            day: 24,
            hour: 0,
            minute: 0,
            second: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::RsaPssSha256)
        .build(&key)
        .unwrap();

    assert!(crl.verify_signature(&issuer).unwrap());
    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPssSha256,
            &crl.tbs_der,
            &crl.sign(&key).unwrap(),
            &key.public_key
        )
        .unwrap()
    );
}

#[test]
fn cert_crl_verify_signature_supports_ecdsa_p384_sha384_issuer_key() {
    use p384::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 48];
    scalar[47] = 17;
    let signing_key = p384::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let issuer = Certificate {
        tbs: TbsCertificate {
            subject: helpers::dn_from_string("CN=p384-crl-issuer"),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: SignatureAlgorithmId::EcdsaSha384,
                    hash: HashAlgorithm::Sha384,
                    curve: CurveId::Secp384r1,
                },
                public_key: public_key.as_bytes().to_vec(),
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };
    let builder = CrlBuilder::new()
        .set_issuer(issuer.tbs.subject.clone())
        .set_this_update(der_time(2026, 5, 24))
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha384);
    let tbs = builder.build_unsigned_tbs().unwrap();
    let signature: p384::ecdsa::Signature = signing_key.sign(&tbs);
    let crl = builder
        .build_with_signature(signature.to_der().as_bytes().to_vec())
        .unwrap();

    assert_eq!(crl.tbs_der, tbs);
    assert!(crl.verify_signature(&issuer).unwrap());
    let parsed = Crl::from_der(&crl.der).unwrap();
    assert!(parsed.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_crl_verify_signature_supports_ecdsa_p521_sha512_issuer_key() {
    use p521::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 66];
    scalar[65] = 19;
    let signing_key = p521::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);
    let issuer = Certificate {
        tbs: TbsCertificate {
            subject: helpers::dn_from_string("CN=p521-crl-issuer"),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: SignatureAlgorithmId::EcdsaSha512,
                    hash: HashAlgorithm::Sha512,
                    curve: CurveId::Secp521r1,
                },
                public_key: public_key.as_bytes().to_vec(),
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };
    let builder = CrlBuilder::new()
        .set_issuer(issuer.tbs.subject.clone())
        .set_this_update(der_time(2026, 5, 24))
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha512);
    let tbs = builder.build_unsigned_tbs().unwrap();
    let signature: p521::ecdsa::Signature = signing_key.sign(&tbs);
    let crl = builder
        .build_with_signature(signature.to_der().as_bytes().to_vec())
        .unwrap();

    assert_eq!(crl.tbs_der, tbs);
    assert!(crl.verify_signature(&issuer).unwrap());
    let parsed = Crl::from_der(&crl.der).unwrap();
    assert!(parsed.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_crl_builder_parser_and_certificate_revocation_roundtrip() {
    let leaf = Certificate::parse_der(&super::test_cert_parser::minimal_certificate_der(3, false))
        .unwrap();
    let invalidity = DerTime {
        year: 2026,
        month: 5,
        day: 24,
        hour: 11,
        minute: 30,
        second: 0,
    };
    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=Issuer, O=Robolibs, C=NL")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .set_next_update(der_time(2026, 6, 24))
        .add_revoked_serial_with_options(
            leaf.tbs.serial_number.clone(),
            der_time(2026, 5, 24),
            Some(CrlReason::KeyCompromise),
            Some(invalidity.clone()),
        )
        .build_with_signature(vec![0xbb; 64])
        .unwrap();

    let parsed = parse_crl(&crl.der).unwrap();
    assert_eq!(parsed.version, 2);
    assert_eq!(
        parsed.issuer.first(DistinguishedNameAttribute::CommonName),
        Some("Issuer")
    );
    assert_eq!(
        parsed.outer_signature.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(parsed.signature_value, vec![0xbb; 64]);
    assert!(parsed.is_certificate_revoked(&leaf.tbs.serial_number));
    assert!(leaf.is_revoked(&parsed));
    assert!(parsed.check_validity_at(&der_time(2026, 5, 25)));
    assert!(!parsed.check_validity_at(&der_time(2026, 7, 1)));

    let entry = parsed.find_revoked_cert(&leaf.tbs.serial_number).unwrap();
    assert_eq!(entry.reason, Some(CrlReason::KeyCompromise));
    assert_eq!(entry.invalidity_date, Some(invalidity));
    assert_eq!(entry.extensions.len(), 2);

    let pem = parsed.to_pem();
    let pem_chain = parse_pem_crl_chain(&pem).unwrap();
    assert_eq!(pem_chain.len(), 1);
    assert_eq!(pem_chain[0].der, parsed.der);
}

#[test]
fn cert_crl_builder_exposes_unsigned_tbs_for_external_signing() {
    let tbs = CrlBuilder::new()
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .add_revoked_serial_with_reason(vec![0x01], der_time(2026, 5, 24), CrlReason::Superseded)
        .build_unsigned_tbs()
        .unwrap();
    assert!(!tbs.is_empty());
    assert_eq!(parse_sequence(&tbs).unwrap().bytes_consumed, tbs.len());
}

#[test]
fn cert_crl_builder_add_revoked_serial_defaults_match_cpp_surface() {
    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .add_revoked_serial(vec![0x01], der_time(2026, 5, 24))
        .build_with_signature(vec![0x11; 64])
        .unwrap();

    let parsed = parse_crl(&crl.der).unwrap();
    let entry = parsed.find_revoked_cert(&[0x01]).unwrap();
    assert_eq!(entry.reason, None);
    assert_eq!(entry.invalidity_date, None);
    assert!(entry.extensions.is_empty());
}

#[test]
fn cert_crl_verify_signature_supports_rsa_pkcs1_sha256_issuer_key() {
    let rsa_key = helpers::test_rsa_keypair(80);
    let issuer = Certificate {
        tbs: TbsCertificate {
            subject: DistinguishedName::from_string("CN=Issuer").unwrap(),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: SignatureAlgorithmId::RsaPkcs1Sha256,
                    hash: HashAlgorithm::Sha256,
                    curve: CurveId::Unknown,
                },
                public_key: rsa_key.public_key.clone(),
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    };
    let unsigned_tbs = CrlBuilder::new()
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build_unsigned_tbs()
        .unwrap();
    let signature = sign_rsa_pkcs1v15_keypair(
        SignatureAlgorithmId::RsaPkcs1Sha256,
        &unsigned_tbs,
        &rsa_key,
    )
    .unwrap();
    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build_with_signature(signature)
        .unwrap();

    assert_eq!(crl.tbs_der, unsigned_tbs);
    assert!(crl.verify_signature(&issuer).unwrap());
    let parsed = Crl::from_der(&crl.der).unwrap();
    assert!(parsed.verify_signature(&issuer).unwrap());

    let mut tampered = parsed;
    tampered.signature_value[5] ^= 0x40;
    assert!(!tampered.verify_signature(&issuer).unwrap());
}
