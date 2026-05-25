use super::*;

#[test]
fn cert_pem_certificate_encode_decode() {
    let (cert, _key) = helpers::make_self_signed_certificate("PEMTest", 0x70);
    let pem = cert.to_pem();
    let decoded = pem_decode_block_with_expected_label(&pem, Some("CERTIFICATE")).unwrap();

    assert_eq!(decoded.label, "CERTIFICATE");
    assert_eq!(decoded.data, cert.der());
}

#[test]
fn cert_pem_raw_certificate_helper_roundtrips_der() {
    let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
    let pem = pem_encode_certificate(&der);
    let decoded = pem_decode_block_with_expected_label(&pem, Some("CERTIFICATE")).unwrap();

    assert_eq!(decoded.label, "CERTIFICATE");
    assert_eq!(decoded.data, der);
}

#[test]
fn cert_pem_certificate_helpers_roundtrip_der() {
    let cert = Certificate::from_der([0x30, 0x00]);
    let pem = cert.to_pem();
    let parsed = Certificate::from_pem(&pem).unwrap();

    assert_eq!(parsed.der(), cert.der());
}

#[test]
fn cert_pem_certificate_line_length_surface_matches_cpp_to_pem() {
    let cert = Certificate::from_der((0u8..18).collect::<Vec<_>>());

    let compact = cert.to_pem_with_line_length(0);
    assert_eq!(
        compact,
        "-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQoLDA0ODxAR\n-----END CERTIFICATE-----\n"
    );

    let wrapped = cert.to_pem_with_line_length(8);
    assert_eq!(
        wrapped,
        "-----BEGIN CERTIFICATE-----\nAAECAwQF\nBgcICQoL\nDA0ODxAR\n-----END CERTIFICATE-----\n"
    );
    assert_eq!(Certificate::from_pem(&wrapped).unwrap().der(), cert.der());
}

#[test]
fn cert_pem_result_surface_matches_cpp_pem_result_shape() {
    let der = vec![0xde, 0xad, 0xbe, 0xef];
    let pem = pem_encode_private_key(&der);
    assert_eq!(pem, pem_encode(&der, "PRIVATE KEY"));
    assert_eq!(
        pem_encode_with_line_length(&der, "PRIVATE KEY", 4),
        "-----BEGIN PRIVATE KEY-----\n3q2+\n7w==\n-----END PRIVATE KEY-----\n"
    );
    let result = pem_decode_private_key(&pem);

    assert!(result.success);
    assert_eq!(result.error, "");
    assert_eq!(result.block.label, "PRIVATE KEY");
    assert_eq!(result.block.data, der);
    assert_eq!(
        result.clone().into_result().unwrap(),
        PemBlock {
            label: "PRIVATE KEY".to_string(),
            data: vec![0xde, 0xad, 0xbe, 0xef],
        }
    );

    let error = pem_decode_certificate(&pem);
    assert!(!error.success);
    assert_eq!(error.error, "unexpected PEM label");
    assert!(error.block.data.is_empty());

    let generic = pem_decode_with_expected_label(&pem, Some("PRIVATE KEY"));
    assert!(generic.success);
    assert_eq!(generic.block.label, "PRIVATE KEY");
    assert_eq!(generic.block.data, der);
    assert_eq!(
        pem_decode_result_with_expected_label(&pem, Some("PRIVATE KEY")),
        generic
    );
    assert_eq!(pem_decode_private_key_result(&pem), generic);

    let default_label = pem_decode(&pem);
    assert!(default_label.success);
    assert_eq!(default_label.block.label, "PRIVATE KEY");
    assert_eq!(pem_decode_result(&pem), default_label);
    assert_eq!(pem_decode_block(&pem).unwrap().data, der);
}

#[test]
fn cert_pem_detail_namespace_matches_cpp_base64_and_block_helpers() {
    assert_eq!(detail::kBeginMarker, "-----BEGIN ");
    assert_eq!(detail::kEndMarker, "-----END ");
    assert_eq!(detail::kTrailer, "-----");
    assert_eq!(detail::decode_base64_char('A'), 0);
    assert_eq!(detail::decode_base64_char('/'), 63);
    assert_eq!(detail::decode_base64_char('='), -2);
    assert_eq!(detail::decode_base64_char('?'), -1);

    let encoded = detail::encode_base64(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(encoded, "3q2+7w==");
    let mut decoded = vec![0xff];
    assert!(detail::decode_base64(&encoded, &mut decoded));
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(!detail::decode_base64("bad!", &mut decoded));
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);

    assert_eq!(detail::strip_whitespace("xx A A\r\nB\tB yy", 3, 11), "AABB");

    let error = detail::error_result("boom");
    assert!(!error.success);
    assert_eq!(error.error, "boom");
    assert_eq!(
        detail::build_block("TEST", "QUJDRA==", 4),
        "-----BEGIN TEST-----\nQUJD\nRA==\n-----END TEST-----\n"
    );
    assert_eq!(
        detail::build_block("TEST", "QUJDRA==", 0),
        "-----BEGIN TEST-----\nQUJDRA==\n-----END TEST-----\n"
    );
}
