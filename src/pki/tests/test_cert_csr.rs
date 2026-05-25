use super::*;

#[test]
fn cert_csr_build_and_parse() {
    let key = generate_ed25519_keypair().unwrap();
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=csr.example")
        .unwrap()
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519(&key)
        .unwrap();

    let parsed = parse_csr(&csr.der).unwrap();

    assert!(parsed.info.subject.to_string().contains("csr.example"));
    assert_eq!(
        parsed.signature_algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert!(parsed.verify_signature().unwrap());
}

#[test]
fn cert_csr_sign_helper_matches_stored_ed25519_signature() {
    let key = generate_ed25519_keypair().unwrap();
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=csr-sign.example")
        .unwrap()
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519(&key)
        .unwrap();

    assert_eq!(csr.sign(&key).unwrap(), csr.signature);
}

#[test]
fn cert_csr_result_wrappers_match_cpp_surface() {
    let key = generate_ed25519_keypair().unwrap();
    let built = CsrBuilder::new()
        .set_subject_from_string("CN=csr-result.example")
        .unwrap()
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_ed25519_result(&key);
    assert!(built.success);
    assert!(built.error.is_empty());

    let parsed = parse_csr_result(&built.value.der);
    assert!(parsed.success);
    assert!(parsed.value.verify_signature_result().value);
    assert_eq!(parsed.value.sign_result(&key).value, parsed.value.signature);

    let from_der = CertificateRequest::from_der_result(&parsed.value.der);
    assert!(from_der.success);
    assert_eq!(from_der.value.der, parsed.value.der);

    let from_pem = CertificateRequest::from_pem_result(&parsed.value.to_pem());
    assert!(from_pem.success);
    assert_eq!(from_pem.value.der, parsed.value.der);

    let missing_subject = CsrBuilder::new()
        .set_subject_public_key_ed25519(key.public_key.clone())
        .build_result(&key);
    assert!(!missing_subject.success);
    assert_eq!(missing_subject.error, "subject not set");

    let unsupported_builder = CsrBuilder::new()
        .set_subject_from_string("CN=unsupported-csr.example")
        .unwrap()
        .set_subject_public_key_ed25519(key.public_key.clone())
        .set_signature_algorithm(SignatureAlgorithmId::Unknown)
        .build_result(&key);
    assert!(!unsupported_builder.success);
    assert_eq!(
        unsupported_builder.error,
        "Unsupported CSR signature algorithm"
    );

    let unsupported_sign = CertificateRequest {
        signature_algorithm: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Unknown,
            ..AlgorithmIdentifier::default()
        },
        cri_der: b"unsupported-csr-sign".to_vec(),
        ..CertificateRequest::default()
    }
    .sign_result(&key);
    assert!(!unsupported_sign.success);
    assert_eq!(
        unsupported_sign.error,
        "Unsupported CSR signature algorithm"
    );
}

#[test]
fn cert_csr_builder_preserves_signature_algorithm_and_der_encodes_ecdsa_signature() {
    let raw_ecdsa_signature = {
        let mut sig = vec![0x11; 32];
        sig.extend(vec![0x22; 32]);
        sig
    };
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=csr-ecdsa.example")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::EcdsaSha256,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Secp256r1,
            },
            public_key: {
                let mut key = vec![0x04];
                key.extend(vec![0x33; 64]);
                key
            },
            unused_bits: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256)
        .build_with_signature(raw_ecdsa_signature)
        .unwrap();

    let parsed = parse_csr(&csr.der).unwrap();
    assert_eq!(
        parsed.signature_algorithm.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(!parsed.signature.is_empty());
    assert_eq!(parsed.signature[0], 0x30);
}

#[test]
fn cert_csr_build_signs_rsa_pkcs1v15() {
    let key = helpers::test_rsa_keypair(80);
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=csr-rsa.example")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::RsaPkcs1Sha256,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Unknown,
            },
            public_key: key.public_key.clone(),
            unused_bits: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build(&key)
        .unwrap();

    assert!(csr.verify_signature().unwrap());
    assert_eq!(csr.sign(&key).unwrap(), csr.signature);
}

#[test]
fn cert_csr_build_signs_rsa_pss() {
    let key = helpers::test_rsa_keypair(80);
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=csr-rsa-pss.example")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::RsaPssSha256,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Unknown,
            },
            public_key: key.public_key.clone(),
            unused_bits: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::RsaPssSha256)
        .build(&key)
        .unwrap();

    assert!(csr.verify_signature().unwrap());
    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPssSha256,
            &csr.cri_der,
            &csr.sign(&key).unwrap(),
            &key.public_key
        )
        .unwrap()
    );
}

#[test]
fn cert_csr_verify_signature_supports_ecdsa_p384_sha384_subject_key() {
    use p384::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 48];
    scalar[47] = 11;
    let signing_key = p384::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let builder = CsrBuilder::new()
        .set_subject_from_string("CN=csr-p384.example")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::EcdsaSha384,
                hash: HashAlgorithm::Sha384,
                curve: CurveId::Secp384r1,
            },
            public_key: public_key.as_bytes().to_vec(),
            unused_bits: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha384);
    let cri = builder.clone().build_unsigned_for_signing().unwrap();
    let signature: p384::ecdsa::Signature = signing_key.sign(&cri.der);
    let csr = builder
        .build_with_signature(signature.to_der().as_bytes().to_vec())
        .unwrap();

    assert_eq!(csr.cri_der, cri.der);
    assert!(csr.verify_signature().unwrap());
    let parsed = parse_csr(&csr.der).unwrap();
    assert!(parsed.verify_signature().unwrap());
}

#[test]
fn cert_csr_verify_signature_supports_ecdsa_p521_sha512_subject_key() {
    use p521::ecdsa::signature::Signer as _;

    let mut scalar = [0u8; 66];
    scalar[65] = 13;
    let signing_key = p521::ecdsa::SigningKey::from_slice(&scalar).unwrap();
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);
    let builder = CsrBuilder::new()
        .set_subject_from_string("CN=csr-p521.example")
        .unwrap()
        .set_subject_public_key(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::EcdsaSha512,
                hash: HashAlgorithm::Sha512,
                curve: CurveId::Secp521r1,
            },
            public_key: public_key.as_bytes().to_vec(),
            unused_bits: 0,
        })
        .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha512);
    let cri = builder.clone().build_unsigned_for_signing().unwrap();
    let signature: p521::ecdsa::Signature = signing_key.sign(&cri.der);
    let csr = builder
        .build_with_signature(signature.to_der().as_bytes().to_vec())
        .unwrap();

    assert_eq!(csr.cri_der, cri.der);
    assert!(csr.verify_signature().unwrap());
    let parsed = parse_csr(&csr.der).unwrap();
    assert!(parsed.verify_signature().unwrap());
}

#[test]
fn cert_csr_builder_and_parser_roundtrip_subject_spki_and_extensions() {
    let basic_constraints = RawExtension {
        oid: oid_for_extension(ExtensionId::BasicConstraints).unwrap(),
        id: ExtensionId::BasicConstraints,
        critical: true,
        value: der::encode_sequence(&der::encode_boolean(false)),
    };
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=device-1, O=Robolibs, C=NL")
        .unwrap()
        .set_subject_public_key_ed25519(vec![0x33; 32])
        .add_extension(basic_constraints.clone())
        .build_with_signature(vec![0xaa; 64])
        .unwrap();

    let parsed = parse_csr(&csr.der).unwrap();
    assert_eq!(parsed.info.version, 0);
    assert_eq!(
        parsed
            .info
            .subject
            .first(DistinguishedNameAttribute::CommonName),
        Some("device-1")
    );
    assert_eq!(
        parsed.info.subject_public_key_info.algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(
        parsed.info.subject_public_key_info.public_key,
        vec![0x33; 32]
    );
    assert_eq!(
        parsed.signature_algorithm.signature,
        SignatureAlgorithmId::Ed25519
    );
    assert_eq!(parsed.signature, vec![0xaa; 64]);
    assert_eq!(parsed.info.extensions, vec![basic_constraints]);
    assert_eq!(parsed.cri_der, csr.cri_der);

    let pem = parsed.to_pem();
    let from_pem = CertificateRequest::from_pem(&pem).unwrap();
    assert_eq!(from_pem.der, csr.der);
}

#[test]
fn cert_csr_builder_exposes_unsigned_cri_for_external_signing() {
    let cri = CsrBuilder::new()
        .set_subject_from_string("CN=sign-me")
        .unwrap()
        .set_subject_public_key_ed25519([0x44; 32])
        .build_unsigned_for_signing()
        .unwrap();
    assert!(!cri.der.is_empty());
    assert_eq!(
        cri.subject.first(DistinguishedNameAttribute::CommonName),
        Some("sign-me")
    );
    assert_eq!(cri.subject_public_key_info.public_key, vec![0x44; 32]);
}

#[test]
fn cert_csr_verify_signature_supports_rsa_pkcs1_sha256_subject_key() {
    let rsa_key = helpers::test_rsa_keypair(80);
    let spki = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::RsaPkcs1Sha256,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Unknown,
        },
        public_key: rsa_key.public_key.clone(),
        unused_bits: 0,
    };
    let unsigned = CsrBuilder::new()
        .set_subject_from_string("CN=rsa-csr")
        .unwrap()
        .set_subject_public_key(spki.clone())
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build_unsigned_for_signing()
        .unwrap();
    let signature = sign_rsa_pkcs1v15_keypair(
        SignatureAlgorithmId::RsaPkcs1Sha256,
        &unsigned.der,
        &rsa_key,
    )
    .unwrap();
    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=rsa-csr")
        .unwrap()
        .set_subject_public_key(spki)
        .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256)
        .build_with_signature(signature)
        .unwrap();

    assert_eq!(csr.cri_der, unsigned.der);
    assert!(csr.verify_signature().unwrap());
    let parsed = CertificateRequest::from_der(&csr.der).unwrap();
    assert!(parsed.verify_signature().unwrap());

    let mut tampered = parsed;
    tampered.cri_der.push(0);
    assert!(!tampered.verify_signature().unwrap());
}
