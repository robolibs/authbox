use super::*;

#[test]
fn cert_utils_print_info_and_to_json() {
    let (cert, _key) = helpers::make_self_signed_certificate("Print Test", 0x71);

    assert!(cert.print_info().contains("Print Test"));
    assert!(cert.to_json().contains("Print Test"));
}

#[test]
fn cert_utils_identity_equality() {
    let (cert_a, _key_a) = helpers::make_self_signed_certificate("Identity", 0x72);
    let (cert_b, _key_b) = helpers::make_self_signed_certificate("Identity", 0x73);

    assert_ne!(cert_a.der(), cert_b.der());
    assert!(!cert_a.equals_identity(&cert_b));
    assert!(cert_a.equals_identity(&cert_a));
}

#[test]
fn cert_utils_certificate_equality_uses_der_bytes_like_cpp_operator() {
    let (cert, _key) = helpers::make_self_signed_certificate("DerEquality", 0x74);
    let mut same_der_different_fields = Certificate::from_der(cert.der().to_vec());
    same_der_different_fields.tbs.serial_number = vec![0xff];
    same_der_different_fields.signature_value = vec![0xee];

    assert_eq!(cert, same_der_different_fields);
}

#[test]
fn cert_utils_distinguished_name_result_matches_cpp_surface() {
    let result = DistinguishedName::from_string_result("CN=Example, O=Authbox, C=nl");
    assert!(result.success);
    assert_eq!(result.error, "");
    assert_eq!(
        result.value.first(DistinguishedNameAttribute::CountryName),
        Some("nl")
    );
    let reparsed = DistinguishedName::from_der(result.value.der().to_vec()).unwrap();
    assert_eq!(reparsed.to_string(), "CN=Example, O=Authbox, C=NL");

    let invalid = DistinguishedName::from_string_result("EMAIL=ops@example.com");
    assert!(!invalid.success);
    assert_eq!(invalid.error, "unsupported DN attribute");
    assert!(invalid.into_result().is_err());
}

#[test]
fn cert_utils_distinguished_name_detail_namespace_matches_cpp_helpers() {
    let mut cursor = detail::DnSpanCursor::new(&[1, 2, 3, 4]);
    assert_eq!(cursor.remaining(), &[1, 2, 3, 4]);
    assert!(!cursor.empty());
    assert!(cursor.advance(2));
    assert_eq!(cursor.remaining(), &[3, 4]);
    assert!(!cursor.advance(3));
    assert_eq!(cursor.offset, 2);
    assert!(cursor.advance(2));
    assert!(cursor.empty());

    assert_eq!(
        detail::attribute_from_oid(&Oid::new([2, 5, 4, 3])),
        DistinguishedNameAttribute::CommonName
    );
    assert_eq!(
        detail::oid_from_attribute(DistinguishedNameAttribute::LocalityName).unwrap(),
        Oid::new([2, 5, 4, 7])
    );
    assert_eq!(
        detail::oid_from_attribute(DistinguishedNameAttribute::Unknown)
            .unwrap_err()
            .message,
        "Cannot convert Unknown or invalid DistinguishedNameAttribute to OID"
    );
    assert!(detail::is_printable_string("Authbox + Rust?"));
    assert!(!detail::is_printable_string("Authbox 🚜"));
    assert_eq!(detail::dn_trim(" \t CN "), "CN");
    assert_eq!(
        detail::attribute_from_string("S"),
        Some(DistinguishedNameAttribute::StateOrProvinceName)
    );

    let country = AttributeTypeAndValue {
        oid: Oid::new([2, 5, 4, 6]),
        attribute: DistinguishedNameAttribute::CountryName,
        value: "nl".to_string(),
    };
    assert_eq!(
        detail::encode_directory_string(&country),
        der::encode_printable_string("NL")
    );

    let parsed = detail::parse_dn_string(" CN=Example + OU=Robots, C=nl ");
    assert!(parsed.success);
    assert_eq!(parsed.rdns.len(), 2);
    assert_eq!(parsed.rdns[0].len(), 2);
    assert_eq!(
        parsed.rdns[0][1].attribute,
        DistinguishedNameAttribute::OrganizationalUnitName
    );
    assert_eq!(
        detail::encode_name(&parsed.rdns),
        DistinguishedName::from_string("CN=Example+OU=Robots,C=nl")
            .unwrap()
            .der()
    );

    let invalid = detail::parse_dn_string("CN=Example+");
    assert!(!invalid.success);
    assert_eq!(invalid.error, "invalid DN component");
}

#[test]
fn cert_utils_distinguished_name_string_der_roundtrip() {
    let dn = DistinguishedName::from_string("CN=Example, O=Robolibs, C=nl").unwrap();
    assert_eq!(
        dn.first(DistinguishedNameAttribute::CommonName),
        Some("Example")
    );
    assert_eq!(dn.to_string(), "CN=Example, O=Robolibs, C=nl");

    let reparsed = DistinguishedName::from_der(dn.der().to_vec()).unwrap();
    assert_eq!(reparsed.to_string(), "CN=Example, O=Robolibs, C=NL");
}

#[test]
fn cert_utils_certificate_detail_namespace_matches_cpp_helpers() {
    assert!(detail::contains_pem_marker(
        "noise\n-----BEGIN CERTIFICATE-----\n"
    ));
    assert!(detail::contains_pem_marker(
        b"\x00-----BEGIN CERTIFICATE-----".as_slice()
    ));
    assert!(!detail::contains_pem_marker("plain der bytes"));
    assert!(detail::equals_case_insensitive(
        "ExAmPlE.COM",
        "example.com"
    ));
    assert!(!detail::equals_case_insensitive("example", "examples"));

    let eku = RawExtension {
        oid: Oid::new(detail::kOidExtendedKeyUsage),
        id: ExtensionId::ExtendedKeyUsage,
        critical: false,
        value: der::encode_sequence(&der::concat(&[
            der::encode_oid(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 1])),
            der::encode_oid(&Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 2])),
        ])),
    };
    assert_eq!(
        detail::parse_extended_key_usage(&eku),
        vec![
            Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 1]),
            Oid::new([1, 3, 6, 1, 5, 5, 7, 3, 2])
        ]
    );
    assert!(
        detail::parse_extended_key_usage(&RawExtension {
            value: vec![0xff],
            ..RawExtension::default()
        })
        .is_empty()
    );

    assert_eq!(detail::label_count("www.example.com"), 3);
    assert_eq!(detail::label_count(""), 0);
    assert_eq!(detail::parse_ipv4("127.0.0.1"), Some([127, 0, 0, 1]));
    assert!(detail::is_ipv4_literal("192.168.1.1"));
    assert!(!detail::is_ipv4_literal("192.168.1"));
    assert!(!detail::is_ipv4_literal("256.1.1.1"));
    assert!(detail::ipv4_equal_bytes(b"\x7f\0\0\x01", &[127, 0, 0, 1]));
    assert!(!detail::ipv4_equal_bytes(b"\x7f\0\0", &[127, 0, 0, 1]));

    assert!(detail::wildcard_match("*.Example.com", "api.example.com"));
    assert!(!detail::wildcard_match(
        "*.example.com",
        "deep.api.example.com"
    ));
    assert!(!detail::wildcard_match("api.*.com", "api.example.com"));
    assert_eq!(detail::strip_integer_padding(vec![0, 0, 0x7f]), vec![0x7f]);
    assert_eq!(detail::strip_integer_padding(vec![0]), vec![0]);
}

#[test]
fn cert_utils_certificate_detail_crypto_normalizers_match_cpp_helpers() {
    let rsa_der = vec![0x30, 0x08, 0x02, 0x03, 0x00, 0xaa, 0xbb, 0x02, 0x01, 0x03];
    assert_eq!(
        detail::parse_rsa_public_key_der(&rsa_der),
        Some((vec![0xaa, 0xbb], vec![0x03]))
    );
    assert_eq!(detail::parse_rsa_public_key_der(&[0xff]), None);

    let rsa_spki = SubjectPublicKeyInfo {
        public_key: rsa_der,
        ..SubjectPublicKeyInfo::default()
    };
    assert_eq!(
        detail::normalize_public_key_for_verify(&rsa_spki, SignatureAlgorithmId::RsaPkcs1Sha256)
            .value,
        vec![0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 1, 0x03]
    );

    let ed_spki = SubjectPublicKeyInfo {
        public_key: vec![7; 32],
        ..SubjectPublicKeyInfo::default()
    };
    assert_eq!(
        detail::normalize_public_key_for_verify(&ed_spki, SignatureAlgorithmId::Ed25519).value,
        vec![7; 32]
    );
    assert!(
        !detail::normalize_public_key_for_verify(
            &SubjectPublicKeyInfo {
                public_key: vec![7; 31],
                ..SubjectPublicKeyInfo::default()
            },
            SignatureAlgorithmId::Ed25519
        )
        .success
    );

    let mut uncompressed = vec![0x04];
    uncompressed.extend([9u8; 64]);
    let ecdsa_spki = SubjectPublicKeyInfo {
        public_key: uncompressed,
        ..SubjectPublicKeyInfo::default()
    };
    assert_eq!(
        detail::normalize_public_key_for_verify(&ecdsa_spki, SignatureAlgorithmId::EcdsaSha256)
            .value,
        vec![9; 64]
    );
    assert!(detail::keylock_signature_algorithm(SignatureAlgorithmId::EcdsaSha256).is_some());
    assert_eq!(
        detail::keylock_signature_algorithm(SignatureAlgorithmId::Ed448),
        None
    );

    let mut raw_signature = vec![0u8; 64];
    raw_signature[31] = 1;
    raw_signature[63] = 2;
    let der_signature =
        detail::normalize_signature_for_emit(&raw_signature, SignatureAlgorithmId::EcdsaSha256);
    assert!(der_signature.success);
    assert_ne!(der_signature.value, raw_signature);
    assert_eq!(
        detail::normalize_signature_for_verify(
            &der_signature.value,
            SignatureAlgorithmId::EcdsaSha256,
        )
        .value,
        raw_signature
    );
    assert_eq!(
        detail::normalize_signature_for_verify(&[1, 2, 3], SignatureAlgorithmId::Ed25519).value,
        vec![1, 2, 3]
    );
    assert!(
        !detail::normalize_signature_for_emit(&[1, 2], SignatureAlgorithmId::EcdsaSha256).success
    );
}
