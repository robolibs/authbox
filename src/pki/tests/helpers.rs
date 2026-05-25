#![allow(dead_code)]

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn fixed_time() -> DerTime {
    DerTime {
        year: 2024,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }
}

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn dn_from_string(text: &str) -> DistinguishedName {
    DistinguishedName::from_string(text).unwrap()
}

pub fn make_certificate(
    issuer_dn: &DistinguishedName,
    subject_dn: &DistinguishedName,
    issuer_key: &KeyPair,
    subject_key: &KeyPair,
    is_ca: bool,
    key_usage_bits: u16,
    serial: u64,
) -> Certificate {
    let self_signed = issuer_dn.der() == subject_dn.der();
    CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_subject(subject_dn.clone())
        .set_issuer(issuer_dn.clone())
        .set_validity(
            DerTime {
                year: 2020,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
            DerTime {
                year: 2035,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ed25519(subject_key.public_key.clone())
        .set_key_usage(key_usage_bits)
        .unwrap()
        .set_basic_constraints(is_ca, None)
        .unwrap()
        .build_ed25519_with_self_signed(issuer_key, self_signed)
        .unwrap()
}

pub fn make_self_signed_certificate(subject_cn: &str, serial: u64) -> (Certificate, KeyPair) {
    let key = generate_ed25519_keypair().unwrap();
    let dn = dn_from_string(&format!("CN={subject_cn}"));
    let cert = make_certificate(&dn, &dn, &key, &key, true, key_usage::KEY_CERT_SIGN, serial);
    (cert, key)
}

pub fn make_chain() -> (
    Certificate,
    Certificate,
    Certificate,
    KeyPair,
    KeyPair,
    KeyPair,
) {
    let (root_cert, root_key) = make_self_signed_certificate("Test Root", 10);
    let intermediate_key = generate_ed25519_keypair().unwrap();
    let intermediate_dn = dn_from_string("CN=Test Intermediate");
    let intermediate_cert = make_certificate(
        &root_cert.tbs.subject,
        &intermediate_dn,
        &root_key,
        &intermediate_key,
        true,
        key_usage::KEY_CERT_SIGN,
        11,
    );
    let leaf_key = generate_ed25519_keypair().unwrap();
    let leaf_dn = dn_from_string("CN=Test Leaf");
    let leaf_cert = make_certificate(
        &intermediate_dn,
        &leaf_dn,
        &intermediate_key,
        &leaf_key,
        false,
        key_usage::DIGITAL_SIGNATURE,
        12,
    );

    (
        root_cert,
        intermediate_cert,
        leaf_cert,
        root_key,
        intermediate_key,
        leaf_key,
    )
}

pub fn test_rsa_keypair(encoded_len: usize) -> KeyPair {
    let _ = encoded_len;
    generate_rsa_keypair(1024).unwrap()
}

pub fn test_rsa_public_key_der_from_key(key: &KeyPair) -> Vec<u8> {
    let parsed = parse_rsa_public_key_blob(&key.public_key).unwrap();
    der::encode_sequence(&der::concat(&[
        der::encode_integer_bytes(&parsed.modulus),
        der::encode_integer_bytes(&parsed.exponent),
    ]))
}

pub fn hex_bytes(input: &str) -> Vec<u8> {
    let compact = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    compact
        .chunks_exact(2)
        .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
        .collect()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}

pub fn test_rsa_public_key_der(encoded_len: usize) -> Vec<u8> {
    let mut modulus = vec![0x02];
    modulus.extend(std::iter::repeat_n(0xff, encoded_len - 1));
    der::encode_sequence(&der::concat(&[
        der::encode_integer_bytes(&modulus),
        der::encode_integer(1),
    ]))
}

pub fn der_time(year: i32, month: u8, day: u8) -> DerTime {
    DerTime {
        year,
        month,
        day,
        hour: 12,
        minute: 0,
        second: 0,
    }
}
