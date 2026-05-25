use super::*;

#[test]
fn hostname_verification_matches_dns_san_exact_and_wildcard() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=www.example.com");

    let cert = CertificateBuilder::new()
        .set_serial_u64(200)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .set_subject_alt_name(&[GeneralName {
            type_: GeneralNameType::DnsName,
            value: b"*.example.com".to_vec(),
        }])
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(cert.match_hostname("www.example.com"));
    assert!(!cert.match_hostname("a.b.example.com"));
    assert!(!cert.match_hostname("example.com"));
}

#[test]
fn hostname_verification_gives_san_precedence_over_cn_and_matches_ipv4_san() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=should-not-be-used.example.com");

    let cert = CertificateBuilder::new()
        .set_serial_u64(201)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)
        .unwrap()
        .set_subject_alt_name(&[
            GeneralName {
                type_: GeneralNameType::DnsName,
                value: b"app.example.com".to_vec(),
            },
            GeneralName {
                type_: GeneralNameType::IpAddress,
                value: vec![192, 168, 1, 10],
            },
        ])
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(cert.match_hostname("192.168.1.10"));
    assert!(!cert.match_hostname("192.168.1.11"));
    assert!(cert.match_hostname("app.example.com"));
    assert!(!cert.match_hostname("should-not-be-used.example.com"));
}

#[test]
fn hostname_verification_builder_encodes_cpp_style_textual_ip_san() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=text-ip.example.com");

    let cert = CertificateBuilder::new()
        .set_serial_u64(203)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_subject_alt_name(&[GeneralName {
            type_: GeneralNameType::IpAddress,
            value: b"192.168.1.10".to_vec(),
        }])
        .unwrap()
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    let parsed = Certificate::parse_der(&cert.der).unwrap();
    let names = parsed.subject_alt_names();
    assert_eq!(names[0].value, vec![192, 168, 1, 10]);
    assert!(parsed.match_hostname("192.168.1.10"));
    assert!(!parsed.match_hostname("192.168.1.11"));
}

#[test]
fn hostname_verification_falls_back_to_common_name_without_san() {
    let key = generate_ed25519_keypair().unwrap();
    let dn = helpers::dn_from_string("CN=*.fallback.example");

    let cert = CertificateBuilder::new()
        .set_serial_u64(202)
        .set_subject(dn.clone())
        .set_issuer(dn)
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519_with_self_signed(&key, true)
        .unwrap();

    assert!(cert.match_hostname("api.fallback.example"));
    assert!(!cert.match_hostname("deep.api.fallback.example"));
}
