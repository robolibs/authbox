use super::*;

#[test]
fn cert_asn1_parse_integer_matches_cpp_vector() {
    let result = parse_integer(&[0x02, 0x01, 0x05]).unwrap();
    assert_eq!(result.value, vec![0x05]);
    assert_eq!(result.bytes_consumed, 3);
}

#[test]
fn cert_asn1_result_wrappers_match_cpp_surface() {
    assert_eq!(ASN1_MAX_TAG_NUMBER, 1 << 28);

    let length = get_length_result(&[0x81, 0x80]);
    assert!(length.success);
    assert_eq!(length.value, 128);
    assert_eq!(length.bytes_consumed, 2);
    assert!(length.error.is_empty());
    assert_eq!(length.into_result().unwrap().value, 128);

    let integer = parse_integer_result(&[0x02, 0x01, 0x05]);
    assert!(integer.success);
    assert_eq!(integer.value, vec![0x05]);
    assert_eq!(integer.bytes_consumed, 3);

    let bad = parse_integer_result(&[0x04, 0x01, 0x05]);
    assert!(!bad.success);
    assert_eq!(bad.value, Vec::<u8>::new());
    assert_eq!(bad.bytes_consumed, 0);
    assert_eq!(bad.error, "expected INTEGER");

    let header = parse_id_len_result(&[0x30, 0x00]);
    assert!(header.success);
    assert_eq!(header.value.identifier.tag_class, Asn1Class::Universal);
    assert!(header.value.identifier.constructed);
    assert_eq!(header.value.identifier.tag_number, Asn1Tag::Sequence as u32);
    assert_eq!(header.bytes_consumed, 2);

    let tag_guard = parse_id_len_result(&[0x1f, 0x81, 0x80, 0x80, 0x80, 0x00, 0x00]);
    assert!(!tag_guard.success);
    assert_eq!(tag_guard.error, "tag number exceeds supported range");
}

#[test]
fn cert_asn1_cpp_named_identifier_and_tag_surfaces_work() {
    let identifier = ASN1Identifier {
        tag_class: ASN1Class::ContextSpecific,
        constructed: true,
        tag_number: ASN1Tag::UTF8String as u32,
    };

    assert_eq!(identifier.tag_class, Asn1Class::ContextSpecific);
    assert!(identifier.constructed);
    assert_eq!(identifier.tag_number, Asn1Tag::Utf8String as u32);
    assert_eq!(ASN1Tag::RelativeOID, Asn1Tag::RelativeOid);
    assert_eq!(ASN1Tag::IA5String, Asn1Tag::Ia5String);
    assert_eq!(ASN1Tag::UTCTime, Asn1Tag::UtcTime);
    assert_eq!(ASN1Tag::BMPString, Asn1Tag::BmpString);
}

#[test]
fn cert_asn1_parse_object_identifier_matches_cpp_vector() {
    let result = parse_oid(&[0x06, 0x03, 0x2a, 0x03, 0x04]).unwrap();
    assert_eq!(result.value.nodes[0], 1);
    assert_eq!(result.value.nodes[1], 2);
    assert_eq!(result.value.nodes[2], 3);
    assert_eq!(result.value.nodes[3], 4);
}

#[test]
fn cert_asn1_parse_utc_time_matches_cpp_vector() {
    let result = parse_utc_time(&[
        0x17, 0x0d, b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
    ])
    .unwrap();
    assert_eq!(result.value.year, 2023);
    assert_eq!(result.value.month, 1);
    assert_eq!(result.value.day, 1);
}

#[test]
fn cert_asn1_time_rejects_invalid_calendar_dates_like_cpp() {
    let invalid_feb_31 = parse_utc_time_result(&[
        0x17, 0x0d, b'2', b'3', b'0', b'2', b'3', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
    ]);
    assert!(!invalid_feb_31.success);
    assert_eq!(invalid_feb_31.error, "invalid calendar date");

    let invalid_non_leap_day = parse_generalized_time_result(&[
        0x18, 0x0f, b'2', b'0', b'2', b'3', b'0', b'2', b'2', b'9', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ]);
    assert!(!invalid_non_leap_day.success);
    assert_eq!(invalid_non_leap_day.error, "invalid calendar date");

    let valid_leap_day = parse_generalized_time(&[
        0x18, 0x0f, b'2', b'0', b'2', b'4', b'0', b'2', b'2', b'9', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ])
    .unwrap();
    assert_eq!(valid_leap_day.value.year, 2024);
    assert_eq!(valid_leap_day.value.month, 2);
    assert_eq!(valid_leap_day.value.day, 29);
}

#[test]
fn cert_asn1_detail_namespace_matches_cpp_time_helpers() {
    assert_eq!(detail::kMaxLengthOctets, std::mem::size_of::<usize>());
    assert_eq!(detail::K_MAX_LENGTH_OCTETS, detail::kMaxLengthOctets);

    assert!(detail::is_digit('0'));
    assert!(detail::is_digit('9'));
    assert!(!detail::is_digit('a'));

    let mut value = -1;
    assert!(detail::parse_decimal("2026", &mut value));
    assert_eq!(value, 2026);
    assert!(!detail::parse_decimal("", &mut value));
    assert_eq!(value, 0);
    assert!(!detail::parse_decimal("20x6", &mut value));
    assert_eq!(value, 20);

    let leap_day = detail::make_time_point(2024, 2, 29, 0, 0, 0);
    assert!(leap_day.success);
    assert_eq!(leap_day.bytes_consumed, 0);
    assert_eq!(der::format_time(leap_day.value, false), "20240229000000Z");

    let leap_second = detail::make_time_point(1970, 1, 1, 0, 0, 60);
    assert!(leap_second.success);
    assert_eq!(der::format_time(leap_second.value, true), "700101000100Z");

    let invalid_non_leap_day = detail::make_time_point(2023, 2, 29, 0, 0, 0);
    assert!(!invalid_non_leap_day.success);
    assert_eq!(invalid_non_leap_day.error, "invalid calendar date");

    let invalid_component = detail::make_time_point(2024, 13, 1, 0, 0, 0);
    assert!(!invalid_component.success);
    assert_eq!(invalid_component.error, "invalid time component");
}

#[test]
fn cert_asn1_der_detail_namespace_matches_cpp_writer_helpers() {
    let mut identifier = Vec::new();
    der::detail::append_identifier(&mut identifier, Asn1Class::Universal, false, 4);
    assert_eq!(identifier, vec![0x04]);

    let mut long_identifier = Vec::new();
    der::detail::append_identifier(
        &mut long_identifier,
        Asn1Class::ContextSpecific,
        true,
        0x201,
    );
    assert_eq!(long_identifier, vec![0xbf, 0x84, 0x01]);

    let mut short_length = Vec::new();
    der::detail::append_length(&mut short_length, 0x7f);
    assert_eq!(short_length, vec![0x7f]);

    let mut long_length = Vec::new();
    der::detail::append_length(&mut long_length, 0x0123);
    assert_eq!(long_length, vec![0x82, 0x01, 0x23]);

    assert_eq!(
        der::detail::encode_string("hi", Asn1Tag::Utf8String),
        vec![0x0c, 0x02, b'h', b'i']
    );
    assert_eq!(
        der::detail::encode_time_string("700101000000Z", Asn1Tag::UtcTime),
        der::encode_utctime("700101000000Z")
    );
}

#[test]
fn cert_asn1_der_writer_roundtrips_oid_and_sequence() {
    let oid = Oid::new([1, 3, 101, 112]);
    let encoded = der::encode_oid(&oid);
    assert_eq!(parse_oid(&encoded).unwrap().value, oid);

    let seq = der::encode_sequence(&der::concat(&[
        der::encode_integer(5),
        der::encode_boolean(true),
    ]));
    let body = parse_sequence(&seq).unwrap();
    let mut cursor = Cursor::new(&body.value);
    assert_eq!(parse_integer(cursor.remaining()).unwrap().value, vec![5]);
    cursor
        .advance(parse_integer(cursor.remaining()).unwrap().bytes_consumed)
        .unwrap();
    assert!(parse_boolean(cursor.remaining()).unwrap().value);
}

#[test]
fn cert_asn1_der_writer_bit_string_default_matches_cpp_surface() {
    let default = der::encode_bit_string(&[0xa0]);
    assert_eq!(default, der::encode_bit_string_with_unused_bits(&[0xa0], 0));
    let parsed_default = parse_bit_string(&default).unwrap();
    assert_eq!(parsed_default.value.unused_bits, 0);
    assert_eq!(parsed_default.value.bytes, vec![0xa0]);

    let explicit = der::encode_bit_string_with_unused_bits(&[0xa0], 3);
    let parsed_explicit = parse_bit_string(&explicit).unwrap();
    assert_eq!(parsed_explicit.value.unused_bits, 3);
    assert_eq!(parsed_explicit.value.bytes, vec![0xa0]);
}

#[test]
fn cert_asn1_der_writer_formats_and_serializes_time_like_cpp() {
    let unix_epoch = std::time::UNIX_EPOCH;
    assert_eq!(der::format_time(unix_epoch, true), "700101000000Z");
    assert_eq!(der::format_time(unix_epoch, false), "19700101000000Z");
    assert_eq!(
        der::serialize_time(unix_epoch),
        der::encode_utctime("700101000000Z")
    );

    let year_2050 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_524_608_000);
    assert_eq!(der::format_time(year_2050, false), "20500101000000Z");
    assert_eq!(
        der::serialize_time(year_2050),
        der::encode_generalized_time("20500101000000Z")
    );
}

#[test]
fn cert_asn1_parser_utils_expose_cpp_named_helpers() {
    let name_der = DistinguishedName::from_string("CN=parser-utils")
        .unwrap()
        .der()
        .to_vec();
    let parsed_name = parser_utils::parse_name(&name_der).unwrap();
    assert_eq!(parsed_name.value.to_string(), "CN=parser-utils".to_string());
    assert_eq!(parsed_name.bytes_consumed, name_der.len());

    let alg_der = der::encode_sequence(&der::encode_oid(&Oid::new([1, 3, 101, 112])));
    let parsed_alg = parser_utils::parse_algorithm_identifier(&alg_der).unwrap();
    assert_eq!(parsed_alg.value.signature, SignatureAlgorithmId::Ed25519);

    let alg_with_curve_parameter = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([1, 2, 840, 10045, 4, 3, 2])),
        der::encode_oid(&Oid::new([1, 2, 840, 10045, 3, 1, 7])),
    ]));
    let parsed_alg = parser_utils::parse_algorithm_identifier(&alg_with_curve_parameter).unwrap();
    assert_eq!(
        parsed_alg.value.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert_eq!(parsed_alg.value.curve, CurveId::Unknown);

    let parsed_alg_full = parse_algorithm_identifier_full(&alg_with_curve_parameter).unwrap();
    assert_eq!(
        parsed_alg_full.value.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert_eq!(parsed_alg_full.value.curve, CurveId::Secp256r1);

    let ed25519_alg_der = der::encode_sequence(&der::encode_oid(&Oid::new([1, 3, 101, 112])));
    let parsed_ed25519_full = parse_algorithm_identifier_full(&ed25519_alg_der).unwrap();
    assert_eq!(
        parsed_ed25519_full.value.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(parsed_ed25519_full.value.curve, CurveId::Unknown);

    let spki_der = spki_from_ed25519_public(&[0x42; 32]).unwrap();
    let spki = parser_utils::parse_subject_public_key_info(&spki_der).unwrap();
    assert_eq!(spki.value.public_key, vec![0x42; 32]);
    assert_eq!(
        parser_utils::parse_spki(&spki_der).unwrap().value,
        spki.value
    );

    let time_der = der::encode_utctime("230101000000Z");
    let time = parser_utils::parse_time_choice(&time_der).unwrap();
    assert_eq!(time.value.year, 2023);
    assert_eq!(
        parser_utils::parse_certificate_time_choice(&time_der)
            .unwrap()
            .value,
        time.value
    );
    assert_eq!(
        parser_utils::parse_time_choice(&[]).unwrap_err().message,
        "empty time"
    );
    assert_eq!(
        parser_utils::parse_time_choice(&der::encode_boolean(true))
            .unwrap_err()
            .message,
        "invalid time tag"
    );

    let extension = RawExtension {
        oid: Oid::new([2, 5, 29, 19]),
        id: ExtensionId::BasicConstraints,
        critical: true,
        value: der::encode_sequence(&der::encode_boolean(true)),
    };
    let extension_der = der::encode_context_constructed(
        3,
        &der::encode_sequence(&der::encode_sequence(&der::concat(&[
            der::encode_oid(&extension.oid),
            der::encode_boolean(extension.critical),
            der::encode_octet_string(&extension.value),
        ]))),
    );
    let extensions = parser_utils::parse_extensions(&extension_der).unwrap();
    assert_eq!(extensions.value, vec![extension.clone()]);
    assert_eq!(
        parser_utils::parse_explicit_extensions(&extension_der)
            .unwrap()
            .value,
        extensions.value
    );

    let valid_extension = der::encode_sequence(&der::concat(&[
        der::encode_oid(&extension.oid),
        der::encode_boolean(extension.critical),
        der::encode_octet_string(&extension.value),
    ]));
    let malformed_extension = der::encode_sequence(&der::encode_tlv(
        Asn1Class::Universal,
        false,
        Asn1Tag::Null as u32,
        &[],
    ));
    let lenient_extensions = der::encode_context_constructed(
        3,
        &der::encode_sequence(&der::concat(&[valid_extension, malformed_extension])),
    );
    let parsed_lenient = parser_utils::parse_extensions(&lenient_extensions).unwrap();
    assert_eq!(parsed_lenient.value, vec![extension]);
}

#[test]
fn cert_asn1_parse_id_len_rejects_oversize_length_without_panic() {
    let mut crafted = vec![0x30, 0x88];
    crafted.extend_from_slice(&[0xff; 8]);
    let err = asn1_utils::parse_id_len(&crafted).unwrap_err();
    assert!(
        err.message.contains("overflow") || err.message.contains("exceeds buffer"),
        "{}",
        err.message
    );
}

#[test]
fn cert_asn1_get_length_rejects_indefinite_and_excessive_octet_count() {
    let indefinite = [0x80];
    assert!(
        asn1_utils::get_length(&indefinite)
            .unwrap_err()
            .message
            .contains("indefinite")
    );

    let too_many_octets = [0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(
        asn1_utils::get_length(&too_many_octets)
            .unwrap_err()
            .message
            .contains("more bytes than supported")
    );
}
