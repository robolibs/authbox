use super::*;

fn ed25519_algorithm_identifier() -> Vec<u8> {
    der::encode_sequence(&der::encode_oid(&Oid::new([1, 3, 101, 112])))
}

pub(super) fn minimal_certificate_der(version: i32, with_extension: bool) -> Vec<u8> {
    let alg = ed25519_algorithm_identifier();
    let issuer = DistinguishedName::from_string("CN=Issuer, O=Robolibs, C=NL")
        .unwrap()
        .der()
        .to_vec();
    let subject = DistinguishedName::from_string("CN=Subject, O=Robolibs, C=NL")
        .unwrap()
        .der()
        .to_vec();
    let validity = der::encode_sequence(&der::concat(&[
        der::encode_utctime("240101000000Z"),
        der::encode_utctime("250101000000Z"),
    ]));
    let public_key = [0x42u8; 32];
    let spki = der::encode_sequence(&der::concat(&[
        alg.clone(),
        der::encode_bit_string(&public_key),
    ]));

    let mut tbs_parts = Vec::new();
    if version > 1 {
        tbs_parts.push(der::encode_tlv(
            Asn1Class::ContextSpecific,
            true,
            0,
            &der::encode_integer((version - 1) as u64),
        ));
    }
    tbs_parts.extend([
        der::encode_integer(0x1234),
        alg.clone(),
        issuer,
        validity,
        subject,
        spki,
    ]);
    if with_extension {
        let ext = der::encode_sequence(&der::concat(&[
            der::encode_oid(&Oid::new([2, 5, 29, 19])),
            der::encode_boolean(true),
            der::encode_octet_string(&der::encode_sequence(&[])),
        ]));
        let ext_seq = der::encode_sequence(&ext);
        tbs_parts.push(der::encode_tlv(
            Asn1Class::ContextSpecific,
            true,
            3,
            &ext_seq,
        ));
    }

    let tbs = der::encode_sequence(&der::concat(&tbs_parts));
    der::encode_sequence(&der::concat(&[
        tbs,
        alg,
        der::encode_bit_string(&[0xaa; 64]),
    ]))
}

#[test]
fn cert_parser_minimal_x509_certificate_context() {
    let der = minimal_certificate_der(3, true);
    let ctx = parse_x509_cert(&der).unwrap();
    assert_eq!(ctx.version, 3);
    assert_eq!(ctx.serial_number, vec![0x12, 0x34]);
    assert_eq!(ctx.outer_signature.signature, SignatureAlgorithmId::Ed25519);
    assert_eq!(
        ctx.subject.first(DistinguishedNameAttribute::CommonName),
        Some("Subject")
    );
    assert_eq!(
        ctx.issuer.first(DistinguishedNameAttribute::CommonName),
        Some("Issuer")
    );
    assert_eq!(ctx.subject_public_key_info.public_key, vec![0x42; 32]);
    assert_eq!(ctx.extensions.len(), 1);
    assert_eq!(ctx.extensions[0].id, ExtensionId::BasicConstraints);
    assert!(ctx.extensions[0].critical);
    assert_eq!(ctx.signature_value, vec![0xaa; 64]);
    assert!(!ctx.tbs_certificate.is_empty());
}

#[test]
fn cert_parser_der_and_pem_populates_tbs() {
    let der = minimal_certificate_der(3, false);
    let cert = Certificate::parse_der(&der).unwrap();
    assert_eq!(cert.der(), der);
    assert_eq!(cert.tbs.version, 3);
    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(cert.tbs.subject_public_key_info.public_key, vec![0x42; 32]);

    let pem = pem_encode_certificate(&der);
    let parsed_pem = Certificate::parse_pem(&pem).unwrap();
    assert_eq!(
        parsed_pem.tbs.subject.to_string(),
        "CN=Subject, O=Robolibs, C=NL"
    );
}

#[test]
fn cert_parser_cpp_style_certificate_accessors_match_fields() {
    let der = minimal_certificate_der(3, false);
    let cert = Certificate::parse_der(&der).unwrap();

    assert_eq!(cert.tbs().version, cert.tbs.version);
    assert_eq!(
        cert.signature_algorithm().signature,
        cert.signature_algorithm.signature
    );
    assert_eq!(cert.signature_value(), cert.signature_value.as_slice());
    assert_eq!(cert.tbs_der(), cert.tbs_der.as_slice());
}

#[test]
fn cert_parser_cpp_named_tbs_certificate_alias_matches_rust_model() {
    let tbs: TBSCertificate = TbsCertificate {
        version: 3,
        serial_number: vec![0x01, 0x02, 0x03],
        subject: DistinguishedName::from_string("CN=Alias Subject").unwrap(),
        issuer: DistinguishedName::from_string("CN=Alias Issuer").unwrap(),
        ..TBSCertificate::default()
    };

    assert_eq!(tbs.version, 3);
    assert_eq!(tbs.serial_number, vec![0x01, 0x02, 0x03]);
    assert_eq!(tbs.subject.to_string(), "CN=Alias Subject");
    assert_eq!(tbs.issuer.to_string(), "CN=Alias Issuer");
}

#[test]
fn cert_parser_detail_namespace_matches_cpp_parse_helpers() {
    assert_eq!(detail::copy_bytes(&[1, 2, 3]), vec![1, 2, 3]);

    let version =
        detail::parse_version(&der::encode_context_constructed(0, &der::encode_integer(2)))
            .unwrap();
    assert_eq!(version.value, 3);

    let alg_der = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([1, 2, 840, 10045, 4, 3, 2])),
        der::encode_oid(&Oid::new([1, 2, 840, 10045, 3, 1, 7])),
    ]));
    let alg = detail::parse_algorithm_identifier_full(&alg_der).unwrap();
    assert_eq!(alg.value.signature, SignatureAlgorithmId::EcdsaSha256);
    assert_eq!(alg.value.curve, CurveId::Secp256r1);

    let name_der = DistinguishedName::from_string("CN=Detail Parser")
        .unwrap()
        .der()
        .to_vec();
    let name = detail::parse_name_full(&name_der).unwrap();
    assert_eq!(name.value.to_string(), "CN=Detail Parser");

    let utc = detail::parse_time_choice_full(&der::encode_utctime("240101000000Z")).unwrap();
    assert_eq!(utc.value.year, 2024);

    let validity_der = der::encode_sequence(&der::concat(&[
        der::encode_utctime("240101000000Z"),
        der::encode_utctime("250101000000Z"),
    ]));
    let validity: Asn1Read<detail::ValidityRange> = detail::parse_validity(&validity_der).unwrap();
    assert_eq!(validity.value.not_before.year, 2024);
    assert_eq!(validity.value.not_after.year, 2025);

    let spki_der = der::encode_sequence(&der::concat(&[
        der::encode_sequence(&der::encode_oid(&Oid::new([1, 3, 101, 112]))),
        der::encode_bit_string(&[0x42; 32]),
    ]));
    let spki = detail::parse_subject_public_key_info_full(&spki_der).unwrap();
    assert_eq!(
        spki.value.algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(spki.value.public_key, vec![0x42; 32]);

    let extension_der = der::encode_sequence(&der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([2, 5, 29, 19])),
        der::encode_boolean(true),
        der::encode_octet_string(&der::encode_sequence(&[])),
    ])));
    let extensions = detail::parse_extension_sequence(&extension_der).unwrap();
    assert_eq!(extensions.value.len(), 1);
    assert_eq!(extensions.value[0].id, ExtensionId::BasicConstraints);
    assert!(extensions.value[0].critical);

    let explicit_extensions =
        detail::parse_extensions_full(&der::encode_context_constructed(3, &extension_der)).unwrap();
    assert_eq!(explicit_extensions.value, extensions.value);

    let parse_error: detail::ParseResult = detail::make_error("nope");
    assert!(!parse_error.success);
    assert_eq!(parse_error.error, "nope");
    assert!(parse_error.into_result().is_err());

    let parsed = detail::parse_certificate(&minimal_certificate_der(3, true), false);
    assert!(parsed.success);
    assert_eq!(parsed.certificate.version, 3);
    assert_eq!(
        parsed
            .certificate
            .subject
            .first(DistinguishedNameAttribute::CommonName),
        Some("Subject")
    );

    let spki_with_extra = der::encode_sequence(&der::concat(&[
        der::encode_sequence(&der::encode_oid(&Oid::new([1, 3, 101, 112]))),
        der::encode_bit_string(&[0x42; 32]),
        der::encode_boolean(true),
    ]));
    assert_eq!(
        detail::parse_subject_public_key_info_full(&spki_with_extra)
            .unwrap_err()
            .message,
        "extra data in SubjectPublicKeyInfo"
    );
}

#[test]
fn cert_parser_strict_rejects_extensions_on_v1_certificate() {
    let der = minimal_certificate_der(1, true);
    let err = parse_x509_cert(&der).unwrap_err();
    assert!(err.message.contains("extensions present but version < 3"));
    assert!(parse_x509_cert_relaxed(&der).is_ok());
}

#[test]
fn cert_parser_parse_self_signed_certificate() {
    let (cert, _key) = helpers::make_self_signed_certificate("Root CA", 0x7701);

    let parsed = parse_x509_cert(cert.der()).unwrap();

    assert!(parsed.subject.to_string().contains("Root CA"));
}

#[test]
fn cert_parser_certificate_parse_alias_matches_cpp_surface() {
    let (cert, _key) = helpers::make_self_signed_certificate("Root CA", 0x7703);

    let parsed = Certificate::parse(cert.der()).unwrap();

    assert_eq!(parsed.der(), cert.der());
    assert!(parsed.tbs.subject.to_string().contains("Root CA"));
}

#[test]
fn cert_parser_certificate_result_surface_matches_cpp_shape() {
    let (cert, _key) = helpers::make_self_signed_certificate("Root CA", 0x7704);

    let parsed: CertificateParseResult = Certificate::parse_result(cert.der());
    assert!(parsed.success);
    assert_eq!(parsed.value.der(), cert.der());
    assert!(parsed.error.is_empty());

    let pem_chain: CertificateChainResult = Certificate::parse_pem_chain_result(&cert.to_pem());
    assert!(pem_chain.success);
    assert_eq!(pem_chain.value.len(), 1);
    assert_eq!(pem_chain.value[0].der(), cert.der());

    let mut concatenated_der = cert.der().to_vec();
    concatenated_der.extend(cert.der());
    let der_chain = Certificate::parse_der_chain_result(&concatenated_der);
    assert!(der_chain.success);
    assert_eq!(der_chain.value.len(), 2);

    let empty = Certificate::parse_result(&[]);
    assert!(!empty.success);
    assert_eq!(empty.error, "empty DER buffer");
    assert!(empty.value.der().is_empty());
    assert_eq!(empty.into_result().unwrap_err().message, "empty DER buffer");
}

#[test]
fn cert_parser_pem_encode_decode_roundtrip() {
    let (cert, _key) = helpers::make_self_signed_certificate("Root CA", 0x7702);
    let pem = cert.to_pem();
    let decoded = pem_decode_block_with_expected_label(&pem, Some("CERTIFICATE")).unwrap();

    assert_eq!(decoded.data, cert.der());
}
