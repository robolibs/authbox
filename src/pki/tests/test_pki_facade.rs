use super::*;

#[test]
fn pki_facade_extracts_did_bindings_and_result_wrappers_match_cpp_surface() {
    let did_uri = "did:web:device.example";
    assert_eq!(to_dp_string(did_uri), did_uri);

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x33)
        .set_subject_from_string("CN=device.example")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x88; 32])
        .set_subject_alt_name(&[
            GeneralName {
                type_: GeneralNameType::Uri,
                value: did_uri.as_bytes().to_vec(),
            },
            GeneralName {
                type_: GeneralNameType::DnsName,
                value: b"device.example".to_vec(),
            },
        ])
        .unwrap()
        .build_with_signature(vec![0x33; 64], true)
        .unwrap();

    assert_eq!(collect_did_uris(&cert), vec![did_uri.to_string()]);
    assert!(has_did_binding(&cert, did_uri));

    let record = parse_pem_certificate_with_relaxed(&cert.to_pem(), true).unwrap();
    assert_eq!(record.did_uris, vec![did_uri.to_string()]);
    let strict_record = parse_pem_certificate(&cert.to_pem()).unwrap();
    assert_eq!(strict_record.did_uris, vec![did_uri.to_string()]);

    let result: PkiFacadeResult<CertificateRecord> = parse_pem_certificate_result(&cert.to_pem());
    assert!(result.success);
    assert_eq!(result.value.did_uris, vec![did_uri.to_string()]);
    assert!(result.error.is_empty());

    let relaxed_result = parse_pem_certificate_result_with_relaxed(&cert.to_pem(), true);
    assert!(relaxed_result.success);
    assert_eq!(relaxed_result.value.did_uris, vec![did_uri.to_string()]);

    let invalid = parse_pem_certificate_result("");
    assert!(!invalid.success);
    assert_eq!(invalid.error, "no certificates found in PEM data");
    assert_eq!(
        invalid.into_result().unwrap_err().message,
        "no certificates found in PEM data"
    );
}

#[test]
fn key_utils_helpers_preserve_raw_ed25519_surface() {
    let keypair = generate_ed25519_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 32);
    assert_eq!(keypair.private_key.len(), 64);
    assert_eq!(&keypair.private_key[32..], keypair.public_key.as_slice());
    let signature = sign_ed25519_detached(b"key-utils-generated", &keypair.private_key).unwrap();
    assert!(
        verify_ed25519_signature(b"key-utils-generated", &signature, &keypair.public_key).unwrap()
    );

    let spki = spki_from_ed25519_public(&[0x88; 32]).unwrap();
    let raw = raw_ed25519_public_key_from_spki(&spki).unwrap();
    assert_eq!(raw, vec![0x88; 32]);
    let short_spki = spki_from_ed25519_public(&[1, 2, 3]).unwrap();
    assert!(raw_ed25519_public_key_from_spki(&short_spki).is_err());

    let mut cursor = parser_utils::DerCursor::new(&spki);
    assert!(!cursor.empty());
    assert_eq!(cursor.remaining(), spki.as_slice());
    assert!(cursor.advance(spki.len()));
    assert!(cursor.empty());
}

#[test]
fn key_utils_helpers_cover_ed448_surface() {
    let keypair = generate_ed448_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 57);
    assert_eq!(keypair.private_key.len(), 114);
    assert_eq!(&keypair.private_key[57..], keypair.public_key.as_slice());
    let signature = sign_ed448_detached(b"key-utils-ed448", &keypair.private_key).unwrap();
    assert!(verify_ed448_signature(b"key-utils-ed448", &signature, &keypair.public_key).unwrap());

    let spki = spki_from_ed448_public(&keypair.public_key).unwrap();
    let raw = raw_ed448_public_key_from_spki(&spki).unwrap();
    assert_eq!(raw, keypair.public_key);
    let short_spki = spki_from_ed448_public(&[1, 2, 3]).unwrap();
    assert!(raw_ed448_public_key_from_spki(&short_spki).is_err());

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x448)
        .set_issuer_from_string("CN=Ed448 Issuer")
        .unwrap()
        .set_subject_from_string("CN=Ed448 Subject")
        .unwrap()
        .set_validity(
            DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            DerTime {
                year: 2027,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ed448(keypair.public_key.clone())
        .build_with_signature(vec![0x44; 114], true)
        .unwrap();
    assert_eq!(
        cert.tbs.subject_public_key_info.algorithm.signature,
        SignatureAlgorithmId::Ed448
    );

    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=Ed448 CSR")
        .unwrap()
        .set_subject_public_key_ed448(keypair.public_key.clone())
        .build_ed448(&keypair)
        .unwrap();
    assert_eq!(
        csr.signature_algorithm.signature,
        SignatureAlgorithmId::Ed448
    );
    assert!(csr.verify_signature().unwrap());
}

#[test]
fn key_utils_helpers_cover_ecdsa_p256_surface() {
    let keypair = generate_ecdsa_p256_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 64);
    assert_eq!(keypair.private_key.len(), 32);
    assert_eq!(
        p256_public_key_from_private(&keypair.private_key).unwrap(),
        keypair.public_key
    );
    let signature = sign_ecdsa_p256_sha256(b"key-utils-p256", &keypair.private_key).unwrap();
    assert!(verify_ecdsa_p256_sha256(b"key-utils-p256", &signature, &keypair.public_key).unwrap());

    let spki = spki_from_ecdsa_p256_public(&keypair.public_key).unwrap();
    let raw = raw_ecdsa_p256_public_key_from_spki(&spki).unwrap();
    assert_eq!(raw, keypair.public_key);

    let sec1_private = sec1_from_ecdsa_p256_private(&keypair.private_key).unwrap();
    assert_eq!(
        raw_ecdsa_p256_private_key_from_sec1(&sec1_private).unwrap(),
        keypair.private_key
    );

    let mut uncompressed = vec![0x04];
    uncompressed.extend(&keypair.public_key);
    let uncompressed_spki = spki_from_ecdsa_p256_public(&uncompressed).unwrap();
    assert_eq!(
        raw_ecdsa_p256_public_key_from_spki(&uncompressed_spki).unwrap(),
        keypair.public_key
    );

    let short_spki =
        encode_certificate_subject_public_key_info(&ecdsa_p256_subject_public_key_info(vec![
            1, 2, 3,
        ]))
        .unwrap();
    assert!(raw_ecdsa_p256_public_key_from_spki(&short_spki).is_err());

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x256)
        .set_issuer_from_string("CN=P256 Issuer")
        .unwrap()
        .set_subject_from_string("CN=P256 Subject")
        .unwrap()
        .set_validity(
            DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            DerTime {
                year: 2027,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ecdsa_p256(keypair.public_key.clone())
        .build_ecdsa_p256_sha256_with_self_signed(&keypair, true)
        .unwrap();
    assert!(cert.verify_signature(&cert).unwrap());

    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=P256 CSR")
        .unwrap()
        .set_subject_public_key_ecdsa_p256(keypair.public_key.clone())
        .build_ecdsa_p256_sha256(&keypair)
        .unwrap();
    assert_eq!(
        csr.signature_algorithm.signature,
        SignatureAlgorithmId::EcdsaSha256
    );
    assert!(csr.verify_signature().unwrap());
}

#[test]
fn key_utils_helpers_cover_ecdsa_p384_surface() {
    assert_ecdsa_key_utils_surface(EcdsaKeySurface {
        label: "P384",
        coordinate_len: 48,
        signature_algorithm: SignatureAlgorithmId::EcdsaSha384,
        hash_algorithm: HashAlgorithm::Sha384,
        curve: CurveId::Secp384r1,
        generate: generate_ecdsa_p384_keypair,
        public_from_private: p384_public_key_from_private,
        sign: sign_ecdsa_p384_sha384,
        verify: verify_ecdsa_p384_sha384,
        spki: spki_from_ecdsa_p384_public,
        raw_from_spki: raw_ecdsa_p384_public_key_from_spki,
        set_cert_public_key: CertificateBuilder::set_subject_public_key_ecdsa_p384,
        build_cert: CertificateBuilder::build_ecdsa_p384_sha384_with_self_signed,
        set_csr_public_key: CsrBuilder::set_subject_public_key_ecdsa_p384,
        build_csr: CsrBuilder::build_ecdsa_p384_sha384,
        build_crl: CrlBuilder::build_ecdsa_p384_sha384,
    });
}

#[test]
fn key_utils_helpers_cover_ecdsa_p521_surface() {
    assert_ecdsa_key_utils_surface(EcdsaKeySurface {
        label: "P521",
        coordinate_len: 66,
        signature_algorithm: SignatureAlgorithmId::EcdsaSha512,
        hash_algorithm: HashAlgorithm::Sha512,
        curve: CurveId::Secp521r1,
        generate: generate_ecdsa_p521_keypair,
        public_from_private: p521_public_key_from_private,
        sign: sign_ecdsa_p521_sha512,
        verify: verify_ecdsa_p521_sha512,
        spki: spki_from_ecdsa_p521_public,
        raw_from_spki: raw_ecdsa_p521_public_key_from_spki,
        set_cert_public_key: CertificateBuilder::set_subject_public_key_ecdsa_p521,
        build_cert: CertificateBuilder::build_ecdsa_p521_sha512_with_self_signed,
        set_csr_public_key: CsrBuilder::set_subject_public_key_ecdsa_p521,
        build_csr: CsrBuilder::build_ecdsa_p521_sha512,
        build_crl: CrlBuilder::build_ecdsa_p521_sha512,
    });
}

#[test]
fn key_utils_helpers_cover_rsa_spki_surface() {
    let generated = generate_rsa_keypair(1024).unwrap();
    let generated_public = parse_rsa_public_key(&generated.public_key).unwrap();
    let generated_private = parse_rsa_private_key(&generated.private_key).unwrap();
    assert_eq!(generated_private.modulus, generated_public.modulus);
    assert_eq!(generated_private.public_exponent, generated_public.exponent);
    assert_eq!(generated_private.primes.len(), 2);

    let generated_spki = rsa_public_key_spki_der(&generated.public_key).unwrap();
    assert_eq!(
        rsa_public_key_from_spki_der(&generated_spki).unwrap(),
        generated.public_key
    );

    let generated_pkcs8 = rsa_private_key_pkcs8_der(&generated.private_key).unwrap();
    let generated_private_blob = rsa_private_key_from_pkcs8_der(&generated_pkcs8).unwrap();
    let generated_private_roundtrip = parse_rsa_private_key(&generated_private_blob).unwrap();
    assert_eq!(
        generated_private_roundtrip.modulus,
        generated_public.modulus
    );
    assert_eq!(
        generated_private_roundtrip.public_exponent,
        generated_public.exponent
    );
    assert_eq!(
        generated_private_roundtrip.private_exponent,
        generated_private.private_exponent
    );
    assert_eq!(generated_private_roundtrip.primes.len(), 2);

    let generated_pkcs1 = rsa_private_key_pkcs1_der(&generated.private_key).unwrap();
    let generated_pkcs1_blob = rsa_private_key_from_pkcs1_der(&generated_pkcs1).unwrap();
    let generated_pkcs1_roundtrip = parse_rsa_private_key_der(&generated_pkcs1).unwrap();
    assert_eq!(generated_pkcs1_roundtrip.modulus, generated_public.modulus);
    assert_eq!(
        generated_pkcs1_roundtrip.private_exponent,
        generated_private.private_exponent
    );
    assert_eq!(
        parse_rsa_private_key(&generated_pkcs1_blob)
            .unwrap()
            .private_exponent,
        generated_private.private_exponent
    );

    let generated_signature = sign_rsa_pkcs1v15_keypair(
        SignatureAlgorithmId::RsaPkcs1Sha256,
        b"generated-rsa-key-utils",
        &KeyPair {
            public_key: generated.public_key.clone(),
            private_key: generated_private_blob,
            algorithm: keylock::Algorithm::RsaPkcs1v15Sha256,
        },
    )
    .unwrap();
    assert!(
        verify_signature_bytes(
            SignatureAlgorithmId::RsaPkcs1Sha256,
            b"generated-rsa-key-utils",
            &generated_signature,
            &generated.public_key,
        )
        .unwrap()
    );

    let rsa_public_der = test_rsa_public_key_der(80);
    let parsed = parse_rsa_public_key_der(&rsa_public_der).unwrap();
    let rsa_public_blob = rsa_public_key_blob(&parsed.modulus, &parsed.exponent);

    let default_spki = spki_from_rsa_public(&rsa_public_der).unwrap();
    let default_spki_info = parse_subject_public_key_info(&default_spki).unwrap().value;
    assert_eq!(
        default_spki_info.algorithm.signature,
        SignatureAlgorithmId::RsaPkcs1Sha256
    );
    assert_eq!(default_spki_info.algorithm.hash, HashAlgorithm::Sha256);
    assert_eq!(default_spki_info.public_key, rsa_public_blob);
    assert_eq!(
        raw_rsa_public_key_from_spki(&default_spki).unwrap(),
        rsa_public_blob
    );

    let sha384_spki =
        spki_from_rsa_public_with_options(&rsa_public_blob, HashAlgorithm::Sha384, false).unwrap();
    let sha384_info = parse_subject_public_key_info(&sha384_spki).unwrap().value;
    assert_eq!(
        sha384_info.algorithm.signature,
        SignatureAlgorithmId::RsaPkcs1Sha384
    );
    assert_eq!(
        raw_rsa_public_key_from_spki(&sha384_spki).unwrap(),
        rsa_public_blob
    );

    let sha512_info = rsa_subject_public_key_info_with_options(
        rsa_public_blob.clone(),
        HashAlgorithm::Sha512,
        false,
    );
    assert_eq!(
        sha512_info.algorithm.signature,
        SignatureAlgorithmId::RsaPkcs1Sha512
    );
    assert_eq!(sha512_info.algorithm.hash, HashAlgorithm::Sha512);
    assert_eq!(
        rsa_subject_public_key_info_with_options(
            rsa_public_blob.clone(),
            HashAlgorithm::Sha384,
            true
        )
        .algorithm
        .signature,
        SignatureAlgorithmId::RsaPssSha384
    );
    assert_eq!(
        rsa_subject_public_key_info(rsa_public_blob.clone())
            .algorithm
            .signature,
        SignatureAlgorithmId::RsaPkcs1Sha256
    );

    assert!(spki_from_rsa_public(&[1, 2, 3]).is_err());
    let ed_spki = spki_from_ed25519_public(&[0x11; 32]).unwrap();
    assert!(raw_rsa_public_key_from_spki(&ed_spki).is_err());
}

struct EcdsaKeySurface {
    label: &'static str,
    coordinate_len: usize,
    signature_algorithm: SignatureAlgorithmId,
    hash_algorithm: HashAlgorithm,
    curve: CurveId,
    generate: fn() -> PkiResult<KeyPair>,
    public_from_private: fn(&[u8]) -> PkiResult<Vec<u8>>,
    sign: fn(&[u8], &[u8]) -> PkiResult<Vec<u8>>,
    verify: EcdsaVerifyFn,
    spki: fn(&[u8]) -> PkiResult<Vec<u8>>,
    raw_from_spki: fn(&[u8]) -> PkiResult<Vec<u8>>,
    set_cert_public_key: fn(CertificateBuilder, Vec<u8>) -> CertificateBuilder,
    build_cert: fn(CertificateBuilder, &KeyPair, bool) -> PkiResult<Certificate>,
    set_csr_public_key: fn(CsrBuilder, Vec<u8>) -> CsrBuilder,
    build_csr: fn(CsrBuilder, &KeyPair) -> PkiResult<CertificateRequest>,
    build_crl: fn(CrlBuilder, &KeyPair) -> PkiResult<Crl>,
}

type EcdsaVerifyFn = fn(&[u8], &[u8], &[u8]) -> PkiResult<bool>;

fn assert_ecdsa_key_utils_surface(surface: EcdsaKeySurface) {
    let keypair = (surface.generate)().unwrap();
    assert_eq!(keypair.public_key.len(), surface.coordinate_len * 2);
    assert_eq!(keypair.private_key.len(), surface.coordinate_len);
    assert_eq!(
        (surface.public_from_private)(&keypair.private_key).unwrap(),
        keypair.public_key
    );
    let message = format!("key-utils-{}", surface.label);
    let signature = (surface.sign)(message.as_bytes(), &keypair.private_key).unwrap();
    assert!((surface.verify)(message.as_bytes(), &signature, &keypair.public_key).unwrap());

    let spki = (surface.spki)(&keypair.public_key).unwrap();
    assert_eq!((surface.raw_from_spki)(&spki).unwrap(), keypair.public_key);
    let mut uncompressed = vec![0x04];
    uncompressed.extend(&keypair.public_key);
    assert_eq!(
        (surface.raw_from_spki)(&(surface.spki)(&uncompressed).unwrap()).unwrap(),
        keypair.public_key
    );

    let malformed_spki = encode_certificate_subject_public_key_info(&SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature: surface.signature_algorithm,
            hash: surface.hash_algorithm,
            curve: surface.curve,
        },
        public_key: vec![1, 2, 3],
        unused_bits: 0,
    })
    .unwrap();
    assert!((surface.raw_from_spki)(&malformed_spki).is_err());

    let not_before = DerTime {
        year: 2026,
        month: 5,
        day: 24,
        hour: 0,
        minute: 0,
        second: 0,
    };
    let not_after = DerTime {
        year: 2027,
        month: 5,
        day: 24,
        hour: 0,
        minute: 0,
        second: 0,
    };
    let cert_builder = CertificateBuilder::new()
        .set_serial_u64(surface.coordinate_len as u64)
        .set_issuer_from_string(&format!("CN={} Issuer", surface.label))
        .unwrap()
        .set_subject_from_string(&format!("CN={} Subject", surface.label))
        .unwrap()
        .set_validity(not_before.clone(), not_after.clone());
    let cert = (surface.build_cert)(
        (surface.set_cert_public_key)(cert_builder, keypair.public_key.clone()),
        &keypair,
        true,
    )
    .unwrap();
    assert_eq!(
        cert.tbs.subject_public_key_info.algorithm.signature,
        surface.signature_algorithm
    );
    assert!(cert.verify_signature(&cert).unwrap());

    let csr_builder = CsrBuilder::new()
        .set_subject_from_string(&format!("CN={} CSR", surface.label))
        .unwrap();
    let csr = (surface.build_csr)(
        (surface.set_csr_public_key)(csr_builder, keypair.public_key.clone()),
        &keypair,
    )
    .unwrap();
    assert_eq!(
        csr.signature_algorithm.signature,
        surface.signature_algorithm
    );
    assert!(csr.verify_signature().unwrap());

    let crl = (surface.build_crl)(
        CrlBuilder::new()
            .set_issuer_from_string(&format!("CN={} Issuer", surface.label))
            .unwrap()
            .set_this_update(not_before)
            .set_next_update(not_after),
        &keypair,
    )
    .unwrap();
    assert_eq!(crl.outer_signature.signature, surface.signature_algorithm);
    assert!(crl.verify_signature(&cert).unwrap());
}
