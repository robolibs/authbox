use super::*;

#[test]
fn cert_signature_algorithms_unsupported_verify_errors_match_cpp_surface() {
    let algorithm = SignatureAlgorithmId::Unknown;
    let target = signature_target(algorithm, vec![0xaa; 64], b"unsupported".to_vec());
    let issuer = issuer_with_public_key(vec![0x04; 65], algorithm, CurveId::Unknown);

    let error = target.verify_signature(&issuer).unwrap_err();
    assert_eq!(
        error.message,
        "Unsupported signature algorithm for verification"
    );
}

#[test]
fn cert_signature_algorithms_verify_ed448_with_ecosystem_crate() {
    let seed = [0x44u8; 57];
    let public_key = ed448_public_key_from_seed(&seed).unwrap();
    let mut private_key = seed.to_vec();
    private_key.extend(&public_key);
    let tbs_der = b"ed448-certificate-signature".to_vec();
    let signature = sign_ed448_detached(&tbs_der, &private_key).unwrap();

    let target = signature_target(
        SignatureAlgorithmId::Ed448,
        signature.clone(),
        tbs_der.clone(),
    );
    let issuer = issuer_with_public_key(public_key, SignatureAlgorithmId::Ed448, CurveId::Ed448);
    assert!(target.verify_signature(&issuer).unwrap());

    let mut tampered = signature;
    tampered[0] ^= 1;
    let tampered_target = signature_target(SignatureAlgorithmId::Ed448, tampered, tbs_der);
    assert!(!tampered_target.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_ecdsa_p384_sha384_with_ecosystem_crate() {
    use p384::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 48];
    scalar[47] = 7;
    let signing_key = p384::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let tbs_der = b"ecdsa-p384-sha384".to_vec();
    let signature: p384::ecdsa::Signature = signing_key.sign(&tbs_der);

    let target = signature_target(
        SignatureAlgorithmId::EcdsaSha384,
        signature.to_der().as_bytes().to_vec(),
        tbs_der.clone(),
    );
    let issuer = issuer_with_public_key(
        public_key.as_bytes().to_vec(),
        SignatureAlgorithmId::EcdsaSha384,
        CurveId::Secp384r1,
    );
    assert!(target.verify_signature(&issuer).unwrap());

    let raw_target = signature_target(
        SignatureAlgorithmId::EcdsaSha384,
        signature.to_bytes().to_vec(),
        tbs_der,
    );
    assert!(raw_target.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_ecdsa_p521_sha512_with_ecosystem_crate() {
    use p521::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 66];
    scalar[65] = 9;
    let signing_key = p521::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);
    let tbs_der = b"ecdsa-p521-sha512".to_vec();
    let signature: p521::ecdsa::Signature = signing_key.sign(&tbs_der);

    let target = signature_target(
        SignatureAlgorithmId::EcdsaSha512,
        signature.to_der().as_bytes().to_vec(),
        tbs_der.clone(),
    );
    let issuer = issuer_with_public_key(
        public_key.as_bytes().to_vec(),
        SignatureAlgorithmId::EcdsaSha512,
        CurveId::Secp521r1,
    );
    assert!(target.verify_signature(&issuer).unwrap());

    let raw_target = signature_target(
        SignatureAlgorithmId::EcdsaSha512,
        signature.to_bytes().to_vec(),
        tbs_der,
    );
    assert!(raw_target.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_unsupported_sign_error_matches_cpp_surface() {
    let target = signature_target(
        SignatureAlgorithmId::Unknown,
        vec![0xaa; 64],
        b"unsupported-sign".to_vec(),
    );
    let error = target.sign(&KeyPair::default()).unwrap_err();

    assert_eq!(error.message, "Unsupported signature algorithm for signing");
    let result = target.sign_result(&KeyPair::default());
    assert!(!result.success);
    assert_eq!(result.error, "Unsupported signature algorithm for signing");

    let result = target.sign_result_with_hash(&KeyPair::default(), HashAlgorithm::Sha512);
    assert!(!result.success);
    assert_eq!(result.error, "Unsupported signature algorithm for signing");
}

#[test]
fn cert_signature_algorithms_verify_rsa_pkcs1v15_sha256_with_der_public_key() {
    let tbs_der = b"rsa-pkcs1".to_vec();
    let key = helpers::test_rsa_keypair(80);
    let signature =
        sign_rsa_pkcs1v15_keypair(SignatureAlgorithmId::RsaPkcs1Sha256, &tbs_der, &key).unwrap();
    let rsa_public_key_der = test_rsa_public_key_der_from_key(&key);

    let target = signature_target(SignatureAlgorithmId::RsaPkcs1Sha256, signature, tbs_der);
    let issuer = issuer_with_public_key(
        rsa_public_key_der,
        SignatureAlgorithmId::RsaPkcs1Sha256,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_pkcs1v15_sha256_with_explicit_der_key() {
    let tbs_der = b"rsa-pkcs1-test".to_vec();
    let key = helpers::test_rsa_keypair(80);
    let signature =
        sign_rsa_pkcs1v15_keypair(SignatureAlgorithmId::RsaPkcs1Sha256, &tbs_der, &key).unwrap();
    let rsa_public_key_der = test_rsa_public_key_der_from_key(&key);
    let public_numbers = parse_rsa_public_key_blob(&key.public_key).unwrap();

    let target = signature_target(
        SignatureAlgorithmId::RsaPkcs1Sha256,
        signature.clone(),
        tbs_der,
    );
    let issuer = issuer_with_public_key(
        rsa_public_key_der.clone(),
        SignatureAlgorithmId::RsaPkcs1Sha256,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let parsed = parse_rsa_public_key_der(&rsa_public_key_der).unwrap();
    assert_eq!(parsed.modulus, public_numbers.modulus);
    assert_eq!(parsed.exponent, public_numbers.exponent);

    let mut tampered = target.clone();
    tampered.tbs_der.push(b'!');
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_pkcs1v15_sha384_with_der_public_key() {
    let tbs_der = b"rsa-pkcs1-sha384-test".to_vec();
    let key = helpers::test_rsa_keypair(96);
    let signature =
        sign_rsa_pkcs1v15_keypair(SignatureAlgorithmId::RsaPkcs1Sha384, &tbs_der, &key).unwrap();
    let rsa_public_key_der = test_rsa_public_key_der_from_key(&key);

    let target = signature_target(SignatureAlgorithmId::RsaPkcs1Sha384, signature, tbs_der);
    let issuer = issuer_with_public_key(
        rsa_public_key_der,
        SignatureAlgorithmId::RsaPkcs1Sha384,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.signature_value[10] ^= 0x01;
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_pss_sha256_with_der_public_key() {
    let tbs_der = b"rsa-pss-test".to_vec();
    let rsa_public_key_der = vec![
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc1, 0x9d, 0x7e, 0x13, 0xf7, 0x24, 0x67, 0xbc,
        0xbb, 0x1c, 0x39, 0x74, 0x32, 0x1a, 0x30, 0x6a, 0x17, 0xef, 0xbd, 0xda, 0x5d, 0x6a, 0xd4,
        0x99, 0x28, 0xc7, 0x52, 0x93, 0x7e, 0xcb, 0x40, 0x5e, 0x2b, 0xc0, 0x0c, 0x11, 0x35, 0xfb,
        0x41, 0xce, 0x81, 0x33, 0x81, 0xcd, 0x1e, 0x4c, 0x7a, 0x1f, 0x60, 0xe4, 0xc8, 0x3d, 0x75,
        0xa0, 0x3c, 0xfe, 0xe3, 0x1b, 0x82, 0xc3, 0x79, 0xbb, 0x87, 0xbe, 0xfb, 0xe1, 0xdd, 0x15,
        0xfe, 0xb8, 0xe8, 0x97, 0x52, 0x05, 0x90, 0x8d, 0x06, 0x53, 0xb3, 0x1a, 0x4f, 0x5d, 0xa3,
        0x7f, 0xcd, 0xe8, 0x0a, 0x24, 0xe2, 0xbb, 0xf3, 0xd5, 0xb4, 0x87, 0x7f, 0x6b, 0x0e, 0x5b,
        0x9d, 0x02, 0xc9, 0xfd, 0x6f, 0x2e, 0xbe, 0x43, 0x60, 0xb2, 0x7e, 0xc6, 0x01, 0x45, 0x6f,
        0x31, 0xce, 0xbb, 0xc9, 0x22, 0xe5, 0xf5, 0x0d, 0x42, 0xbc, 0x3d, 0x17, 0x85, 0xb8, 0xd1,
        0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let signature = vec![
        0x08, 0x9c, 0x31, 0xa8, 0x3f, 0xde, 0x9d, 0xa8, 0x44, 0xd8, 0x17, 0x1e, 0x99, 0x19, 0x41,
        0x5f, 0xd1, 0x57, 0x77, 0xf5, 0x67, 0x74, 0x00, 0xe4, 0xe9, 0xb6, 0x30, 0xf2, 0xa1, 0x1c,
        0x4e, 0x56, 0xfb, 0x31, 0x0d, 0x3c, 0x6b, 0xe7, 0xfd, 0xae, 0x1e, 0x78, 0x4f, 0xcc, 0x10,
        0x62, 0xba, 0xc6, 0xba, 0xef, 0xb7, 0xc7, 0x9b, 0xfa, 0x98, 0x02, 0x14, 0xf3, 0x44, 0x2d,
        0xc0, 0xbd, 0xc3, 0xab, 0x20, 0xe6, 0xed, 0x6e, 0xc7, 0x15, 0xc6, 0xb1, 0x89, 0x8b, 0xd4,
        0xaa, 0xbf, 0x53, 0xa9, 0xc4, 0x52, 0xc4, 0xb4, 0x4e, 0x13, 0xe4, 0xe6, 0xb4, 0x60, 0x38,
        0x3f, 0xea, 0x5f, 0xa9, 0xe5, 0xb1, 0xfd, 0x0d, 0x46, 0x81, 0xd4, 0x4e, 0x98, 0xce, 0xf4,
        0x52, 0x12, 0x26, 0x54, 0x78, 0x9c, 0xb1, 0x91, 0xc1, 0xac, 0x64, 0xd6, 0xdc, 0x0b, 0x46,
        0xd7, 0xc3, 0xe6, 0x34, 0xe2, 0x71, 0x19, 0x48,
    ];

    let target = signature_target(SignatureAlgorithmId::RsaPssSha256, signature, tbs_der);
    let issuer = issuer_with_public_key(
        rsa_public_key_der,
        SignatureAlgorithmId::RsaPssSha256,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.tbs_der.push(b'!');
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_pss_sha256_variable_salt() {
    let tbs_der = b"rsa-pss-variable-salt-test".to_vec();
    let rsa_public_key_der = vec![
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xdd, 0x7f, 0x78, 0x0f, 0x71, 0xf6, 0x43, 0xbd,
        0x83, 0x5d, 0x9a, 0x0d, 0x38, 0x3a, 0x09, 0xbb, 0x92, 0x09, 0x77, 0xad, 0x2d, 0xd5, 0xd2,
        0x8d, 0xda, 0x3e, 0xda, 0x3c, 0xc5, 0x1d, 0xd0, 0x93, 0xcf, 0xd7, 0xf3, 0x05, 0x9a, 0x90,
        0x4f, 0x77, 0x88, 0xb7, 0xff, 0x4b, 0x4a, 0x3b, 0x2b, 0x8e, 0xf3, 0x33, 0x2a, 0x0f, 0x35,
        0x75, 0x8f, 0x08, 0x5d, 0x3e, 0xf2, 0x9f, 0xee, 0x3f, 0xa8, 0x9b, 0xdd, 0x4c, 0x30, 0xc7,
        0xcc, 0xe7, 0x67, 0x25, 0xa3, 0x8d, 0xbe, 0xe9, 0xa5, 0x04, 0xba, 0xaf, 0xbc, 0x1a, 0xd1,
        0x0a, 0xa7, 0xbc, 0xfc, 0x8e, 0xb0, 0x2e, 0x74, 0x18, 0x9c, 0xa6, 0xfe, 0x30, 0x72, 0xe3,
        0x28, 0x42, 0x05, 0x87, 0x4e, 0x38, 0x35, 0xf5, 0x93, 0x66, 0x4f, 0x8b, 0x0c, 0x08, 0x8b,
        0x98, 0x8c, 0x08, 0x1a, 0x68, 0x85, 0x0b, 0xac, 0x55, 0x39, 0xa5, 0x22, 0xec, 0xba, 0x2f,
        0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let signature = vec![
        0x2a, 0xf5, 0xce, 0x2c, 0xd0, 0x9b, 0xa4, 0x26, 0x11, 0xf0, 0x61, 0x26, 0xe0, 0x9d, 0xbf,
        0xcb, 0x1a, 0xa7, 0xd4, 0xcf, 0x04, 0x4a, 0x28, 0xc7, 0xda, 0xaa, 0xfd, 0x79, 0xca, 0xd3,
        0x0a, 0x4a, 0xbb, 0x6f, 0x15, 0xf9, 0xa5, 0xda, 0x79, 0x33, 0x69, 0xdc, 0x6a, 0xa5, 0xc1,
        0xa5, 0xca, 0xb2, 0x9a, 0xf1, 0xe1, 0x44, 0xbc, 0xd8, 0xc1, 0xb0, 0x02, 0x01, 0x4c, 0xbc,
        0xbc, 0x50, 0x84, 0xdf, 0x39, 0x86, 0x40, 0x87, 0xf6, 0xe5, 0xea, 0xa7, 0x28, 0xab, 0x8f,
        0x96, 0x29, 0x4e, 0xf1, 0xce, 0xee, 0xbd, 0xc5, 0xb3, 0xec, 0x32, 0x33, 0x8b, 0x2e, 0xf6,
        0x56, 0x77, 0x12, 0x56, 0x0b, 0xd3, 0xa3, 0x1a, 0xd6, 0x03, 0xc9, 0x83, 0x83, 0x4b, 0x30,
        0xbe, 0x54, 0x14, 0xde, 0x76, 0xf0, 0x34, 0xdb, 0xd8, 0xac, 0xc6, 0x1d, 0x3f, 0xd8, 0xbd,
        0xf2, 0xf3, 0xb9, 0xb0, 0x29, 0x93, 0xc8, 0x61,
    ];

    let target = signature_target(SignatureAlgorithmId::RsaPssSha256, signature, tbs_der);
    let issuer = issuer_with_public_key(
        rsa_public_key_der,
        SignatureAlgorithmId::RsaPssSha256,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.signature_value[42] ^= 0x20;
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_pss_sha384_with_der_public_key() {
    let tbs_der = b"rsa-pss-sha384-test".to_vec();
    let rsa_public_key_der = vec![
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xaf, 0x83, 0xd9, 0x82, 0x27, 0x67, 0x83, 0x03,
        0xdf, 0x38, 0x72, 0xc5, 0x0f, 0x58, 0xa6, 0x3b, 0x54, 0xb5, 0xe7, 0x4e, 0x1f, 0x13, 0xf5,
        0xe7, 0xb1, 0x2e, 0x6c, 0x55, 0x77, 0x9b, 0x5f, 0xa3, 0xe1, 0xe6, 0xf2, 0xf5, 0xcb, 0x78,
        0x01, 0x9d, 0x7a, 0xb6, 0x4f, 0xc7, 0x14, 0x07, 0x63, 0xc4, 0x70, 0xcc, 0xd8, 0xba, 0xc3,
        0xdf, 0xdd, 0xf6, 0x0f, 0xf9, 0x83, 0x49, 0xb7, 0xbb, 0xf8, 0x7c, 0x71, 0x24, 0x2d, 0x63,
        0xd7, 0x8d, 0xf3, 0x47, 0x41, 0xc4, 0xa6, 0x38, 0xbb, 0x47, 0x0d, 0x1c, 0xca, 0xc1, 0x90,
        0x5c, 0xc6, 0x10, 0xa0, 0x10, 0xce, 0x34, 0x07, 0x66, 0x45, 0xb7, 0xfe, 0x31, 0x37, 0x25,
        0x95, 0x24, 0x4c, 0x2b, 0x1e, 0x9a, 0x1a, 0xa2, 0x8b, 0xfe, 0x64, 0xb2, 0x8d, 0x37, 0x62,
        0xda, 0xb1, 0x3b, 0x5a, 0xaa, 0xda, 0x83, 0xdd, 0x67, 0x47, 0x08, 0x8f, 0xae, 0xef, 0x17,
        0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let signature = vec![
        0x8d, 0xf0, 0x7f, 0xd2, 0x44, 0xe6, 0x0c, 0xa9, 0xe3, 0xb5, 0x41, 0x61, 0xe7, 0xac, 0xc4,
        0xf6, 0x58, 0x49, 0xb6, 0xd0, 0x7e, 0x20, 0x76, 0x74, 0x4c, 0x2a, 0xb8, 0x75, 0x89, 0x0a,
        0x76, 0x65, 0x67, 0xe7, 0x13, 0xdc, 0x76, 0xbc, 0xc5, 0x92, 0xfc, 0x6c, 0xc9, 0x2d, 0xff,
        0x33, 0x7f, 0xf4, 0xaa, 0x4a, 0x52, 0x3c, 0xb0, 0xeb, 0x85, 0xd3, 0xfb, 0x99, 0xd6, 0x52,
        0xdf, 0xcf, 0x4d, 0x99, 0x50, 0x9a, 0xfb, 0x00, 0x7e, 0x90, 0xb1, 0x4a, 0x51, 0xe1, 0x79,
        0xfa, 0xfe, 0x5d, 0x27, 0xc3, 0xc2, 0x83, 0xd4, 0x5c, 0x16, 0x4e, 0x36, 0x61, 0xb9, 0x82,
        0x78, 0x40, 0xbd, 0x95, 0x44, 0x30, 0x44, 0xb7, 0xf1, 0x14, 0xdc, 0x32, 0x69, 0x5d, 0x38,
        0x8c, 0x8a, 0x20, 0x9e, 0x67, 0xed, 0x0b, 0x52, 0xc8, 0xb4, 0x5c, 0xf3, 0x63, 0x59, 0x7c,
        0x2f, 0x45, 0x91, 0x4f, 0x93, 0x18, 0x85, 0xdf,
    ];

    let target = signature_target_with_hash(
        SignatureAlgorithmId::RsaPssSha384,
        HashAlgorithm::Sha384,
        signature,
        tbs_der,
    );
    let issuer = issuer_with_public_key_and_hash(
        rsa_public_key_der,
        SignatureAlgorithmId::RsaPssSha384,
        HashAlgorithm::Sha384,
        CurveId::Unknown,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.tbs_der.push(b'!');
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_rsa_public_key_der_decoding() {
    let rsa_public_key_der = test_rsa_public_key_der(80);
    let parsed = parse_rsa_public_key_der(&rsa_public_key_der).unwrap();

    assert_eq!(parsed.modulus[0], 0x02);
    assert_eq!(parsed.modulus.len(), 80);
    assert_eq!(parsed.exponent, vec![1]);
}

#[test]
fn cert_signature_algorithms_verify_ecdsa_p256_der_signature_with_uncompressed_key() {
    let tbs_der = b"ecdsa".to_vec();
    let public_key = hex_bytes(
        "04ab7e085fcc8b702bf70ac4b9d7c03e7b0f4b415955b6c0b93494a2628fe67f8\
         c7aeb87c58c5731c34a62841fceef3b7c220db942115c27f985bf77c8e3b9a4a1",
    );
    let signature = hex_bytes(
        "3044022100f83db0d7c73ca010d9e81659798dc39f839dd44a673e0cfd0e987426\
         613d8f4d021f2244efce0304ef8fc5792f4c9ac0b1f3a02342346f13596300aec\
         46466399d",
    );

    let target = signature_target(SignatureAlgorithmId::EcdsaSha256, signature, tbs_der);
    let issuer = issuer_with_public_key(
        public_key,
        SignatureAlgorithmId::EcdsaSha256,
        CurveId::Secp256r1,
    );

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.tbs_der.push(b'!');
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_verify_ed25519_rfc8032_certificate_vector() {
    let public_key = hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
         fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let target = signature_target(SignatureAlgorithmId::Ed25519, signature, Vec::new());
    let issuer =
        issuer_with_public_key(public_key, SignatureAlgorithmId::Ed25519, CurveId::Ed25519);

    assert!(target.verify_signature(&issuer).unwrap());
    let mut tampered = target.clone();
    tampered.tbs_der.push(b'!');
    assert!(!tampered.verify_signature(&issuer).unwrap());
}

#[test]
fn cert_signature_algorithms_builders_der_encode_raw_ecdsa_p256_signatures_for_emit() {
    let public_key = hex_bytes(
        "ab7e085fcc8b702bf70ac4b9d7c03e7b0f4b415955b6c0b93494a2628fe67f8\
         c7aeb87c58c5731c34a62841fceef3b7c220db942115c27f985bf77c8e3b9a4a1",
    );
    let raw_signature = hex_bytes(
        "f83db0d7c73ca010d9e81659798dc39f839dd44a673e0cfd0e987426613d8f4d\
         002244efce0304ef8fc5792f4c9ac0b1f3a02342346f13596300aec46466399d",
    );

    let cert = CertificateBuilder::new()
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256)
        .set_subject_from_string("CN=ecdsa-cert")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ecdsa_p256(public_key.clone())
        .build_with_signature(raw_signature.clone(), true)
        .unwrap();
    assert_eq!(cert.signature_value.first(), Some(&0x30));

    let csr = CsrBuilder::new()
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256)
        .set_subject_from_string("CN=ecdsa-csr")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::EcdsaSha256,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Secp256r1,
            },
            public_key: public_key.clone(),
            unused_bits: 0,
        })
        .build_with_signature(raw_signature.clone())
        .unwrap();
    assert_eq!(csr.signature.first(), Some(&0x30));

    let crl = CrlBuilder::new()
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256)
        .set_issuer_from_string("CN=ecdsa-issuer")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .build_with_signature(raw_signature)
        .unwrap();
    assert_eq!(crl.signature_value.first(), Some(&0x30));
}

#[test]
fn cert_signature_algorithms_builder_sets_rsa_hash_and_pss_metadata() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x5151)
        .set_subject_from_string("CN=rsa-pss-sha512-subject")
        .unwrap()
        .set_issuer_from_string("CN=rsa-pss-sha512-issuer")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_signature_algorithm_with_hash(
            SignatureAlgorithmId::RsaPssSha512,
            HashAlgorithm::Sha512,
        )
        .set_subject_public_key_rsa_with_options(
            test_rsa_public_key_der(80),
            HashAlgorithm::Sha512,
            true,
        )
        .build_with_signature(vec![0x51; 80], false)
        .unwrap();

    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::RsaPssSha512
    );
    assert_eq!(cert.signature_algorithm.hash, HashAlgorithm::Sha512);
    assert_eq!(
        cert.tbs.subject_public_key_info.algorithm.signature,
        SignatureAlgorithmId::RsaPssSha512
    );
    assert_eq!(
        cert.tbs.subject_public_key_info.algorithm.hash,
        HashAlgorithm::Sha512
    );
}

#[test]
fn cert_signature_algorithms_rsa_helper_maps_hashes_and_padding_modes() {
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha256, false),
        SignatureAlgorithmId::RsaPkcs1Sha256
    );
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha384, false),
        SignatureAlgorithmId::RsaPkcs1Sha384
    );
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha512, false),
        SignatureAlgorithmId::RsaPkcs1Sha512
    );
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha256, true),
        SignatureAlgorithmId::RsaPssSha256
    );
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha384, true),
        SignatureAlgorithmId::RsaPssSha384
    );
    assert_eq!(
        rsa_signature_algorithm_for_hash(HashAlgorithm::Sha512, true),
        SignatureAlgorithmId::RsaPssSha512
    );
}

#[test]
fn cert_signature_algorithms_signs_rsa_pkcs1v15_from_private_key_der() {
    let message = b"rsa-private-key-der";
    let key = helpers::test_rsa_keypair(80);
    let signature =
        sign_rsa_pkcs1v15_keypair(SignatureAlgorithmId::RsaPkcs1Sha256, message, &key).unwrap();

    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPkcs1Sha256,
            message,
            &signature,
            &key.public_key
        )
        .unwrap()
    );
}

#[test]
fn cert_signature_algorithms_signs_rsa_pss_with_ecosystem_crate() {
    let message = b"rsa-pss-private-key-der";
    let key = helpers::test_rsa_keypair(80);
    let signature =
        sign_rsa_pss_keypair(SignatureAlgorithmId::RsaPssSha256, message, &key).unwrap();

    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPssSha256,
            message,
            &signature,
            &key.public_key
        )
        .unwrap()
    );
}

#[test]
fn cert_signature_algorithms_builds_rsa_pkcs1v15_certificate() {
    let key = helpers::test_rsa_keypair(80);
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x5252)
        .set_subject_from_string("CN=rsa-subject")
        .unwrap()
        .set_issuer_from_string("CN=rsa-subject")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_signature_algorithm_with_hash(
            SignatureAlgorithmId::RsaPkcs1Sha256,
            HashAlgorithm::Sha256,
        )
        .set_subject_public_key_rsa(key.public_key.clone())
        .build_with_self_signed(&key, true)
        .unwrap();

    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::RsaPkcs1Sha256
    );
    assert!(cert.verify_signature(&cert).unwrap());
    assert_eq!(cert.sign(&key).unwrap(), cert.signature_value);
    assert_eq!(
        cert.sign_with_hash(&key, HashAlgorithm::Sha512).unwrap(),
        cert.signature_value
    );
    let result = cert.sign_result_with_hash(&key, HashAlgorithm::Sha512);
    assert!(result.success);
    assert_eq!(result.value, cert.signature_value);
}

#[test]
fn cert_signature_algorithms_builds_rsa_pss_certificate() {
    let key = helpers::test_rsa_keypair(80);
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x5253)
        .set_subject_from_string("CN=rsa-pss-subject")
        .unwrap()
        .set_issuer_from_string("CN=rsa-pss-subject")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_signature_algorithm_with_hash(
            SignatureAlgorithmId::RsaPssSha256,
            HashAlgorithm::Sha256,
        )
        .set_subject_public_key_rsa_with_options(
            key.public_key.clone(),
            HashAlgorithm::Sha256,
            true,
        )
        .build_with_self_signed(&key, true)
        .unwrap();

    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::RsaPssSha256
    );
    assert!(cert.verify_signature(&cert).unwrap());
    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPssSha256,
            &cert.tbs_der,
            &cert.sign(&key).unwrap(),
            &key.public_key
        )
        .unwrap()
    );
}

#[test]
fn cert_signature_algorithms_builders_can_sign_ed25519_certificate_csr_and_crl() {
    let keypair = generate_ed25519_keypair().unwrap();
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x26)
        .set_subject_from_string("CN=ed25519-signed-root")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_basic_constraints(true, Some(1))
        .unwrap()
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
        .unwrap()
        .build_ed25519_with_self_signed(&keypair, true)
        .unwrap();
    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(cert.signature_value.len(), 64);
    assert!(cert.verify_signature(&cert).unwrap());

    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=ed25519-csr")
        .unwrap()
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .build_ed25519(&keypair)
        .unwrap();
    assert_eq!(
        csr.signature_algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert!(csr.verify_signature().unwrap());

    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=ed25519-signed-root")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .set_next_update(der_time(2026, 6, 24))
        .add_revoked_serial(vec![0x99], der_time(2026, 5, 24))
        .build_ed25519(&keypair)
        .unwrap();
    assert_eq!(crl.outer_signature.signature, SignatureAlgorithmId::Ed25519);
    assert!(crl.verify_signature(&cert).unwrap());
}

#[test]
fn cert_signature_algorithms_builders_can_sign_ecdsa_p256_certificate_csr_and_crl() {
    let private_key = hex_bytes("0000000000000000000000000000000000000000000000000000000000000001");
    let public_key = p256_public_key_from_private(&private_key).unwrap();
    let keypair = KeyPair {
        public_key: public_key.clone(),
        private_key,
    };
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x126)
        .set_subject_from_string("CN=ecdsa-signed-root")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ecdsa_p256(public_key.clone())
        .set_basic_constraints(true, Some(1))
        .unwrap()
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
        .unwrap()
        .build_ecdsa_p256_sha256_with_self_signed(&keypair, true)
        .unwrap();
    assert_eq!(
        cert.signature_algorithm.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(cert.verify_signature(&cert).unwrap());

    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=ecdsa-csr")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::EcdsaSha256,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Secp256r1,
            },
            public_key: public_key.clone(),
            unused_bits: 0,
        })
        .build_ecdsa_p256_sha256(&keypair)
        .unwrap();
    assert_eq!(
        csr.signature_algorithm.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(csr.verify_signature().unwrap());

    let crl = CrlBuilder::new()
        .set_issuer_from_string("CN=ecdsa-signed-root")
        .unwrap()
        .set_this_update(der_time(2026, 5, 24))
        .set_next_update(der_time(2026, 6, 24))
        .add_revoked_serial(vec![0x99], der_time(2026, 5, 24))
        .build_ecdsa_p256_sha256(&keypair)
        .unwrap();
    assert_eq!(
        crl.outer_signature.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(crl.verify_signature(&cert).unwrap());
}

fn signature_target(
    algorithm: SignatureAlgorithmId,
    signature: Vec<u8>,
    tbs_der: Vec<u8>,
) -> Certificate {
    signature_target_with_hash(algorithm, HashAlgorithm::Sha256, signature, tbs_der)
}

fn signature_target_with_hash(
    algorithm: SignatureAlgorithmId,
    hash: HashAlgorithm,
    signature: Vec<u8>,
    tbs_der: Vec<u8>,
) -> Certificate {
    Certificate {
        tbs: TbsCertificate {
            subject: DistinguishedName::from_string("CN=Leaf").unwrap(),
            issuer: DistinguishedName::from_string("CN=Issuer").unwrap(),
            ..TbsCertificate::default()
        },
        signature_algorithm: AlgorithmIdentifier {
            signature: algorithm,
            hash,
            curve: CurveId::Unknown,
        },
        signature_value: signature,
        tbs_der: tbs_der.clone(),
        der: tbs_der,
    }
}

fn issuer_with_public_key(
    public_key: Vec<u8>,
    algorithm: SignatureAlgorithmId,
    curve: CurveId,
) -> Certificate {
    issuer_with_public_key_and_hash(public_key, algorithm, HashAlgorithm::Sha256, curve)
}

fn issuer_with_public_key_and_hash(
    public_key: Vec<u8>,
    algorithm: SignatureAlgorithmId,
    hash: HashAlgorithm,
    curve: CurveId,
) -> Certificate {
    Certificate {
        tbs: TbsCertificate {
            subject: DistinguishedName::from_string("CN=Issuer").unwrap(),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    signature: algorithm,
                    hash,
                    curve,
                },
                public_key,
                unused_bits: 0,
            },
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    }
}
