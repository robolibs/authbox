//! Top-level compatibility checks for `xtra/authbox/include/authbox.hpp`.

use super::*;

#[test]
fn authbox_root_exports_version_and_pik_namespace_alias() {
    assert_eq!(VERSION, "0.0.1");
    assert_eq!(ab::VERSION, VERSION);

    let cert = pik::CertificateBuilder::new()
        .set_serial_u64(0xab01)
        .set_subject_from_string("CN=pik-alias")
        .unwrap()
        .set_validity(
            pik::DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            pik::DerTime {
                year: 2027,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ed25519(vec![0xab; 32])
        .build_with_signature(vec![0xab; 64], true)
        .unwrap();

    assert_eq!(cert.tbs.subject.to_string(), "CN=pik-alias");
    assert_eq!(
        pik::spki_from_ed25519_public(&[0xab; 32]).unwrap().len(),
        cert.public_key_der().len()
    );
}

#[test]
fn authbox_root_mirrors_cpp_doctest_did_parser_smoke_cases() {
    let parsed = did::parse("did:web:example.com").unwrap();
    assert_eq!(parsed.method, "web");

    assert!(did::parse("https://example.com").is_err());
}

#[test]
fn authbox_root_exports_cpp_io_namespace_from_files_header() {
    let path = std::env::temp_dir().join(format!(
        "authbox-root-io-{}-{}.bin",
        std::process::id(),
        0xab01_u16
    ));
    let bytes = vec![0xab, 0xcd, 0xef];

    assert!(io::write_binary(&bytes, &path));
    let result = io::read_binary(&path);
    assert!(result.success);
    assert_eq!(result.error_message, "");
    assert_eq!(result.data, bytes);
    assert_eq!(
        io::read_binary_bytes(&path).unwrap(),
        vec![0xab, 0xcd, 0xef]
    );

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn authbox_root_reexports_completed_keylock_context() {
    let ed = keylock::crypto::Context::new(keylock::Algorithm::Ed25519);
    let pair = ed.generate_keypair().unwrap();
    let signature = ed.sign(b"authbox uses sibling keylock", &pair.private_key);
    assert!(signature.success, "{}", signature.error_message);
    assert!(
        ed.verify(
            b"authbox uses sibling keylock",
            &signature.data,
            &pair.public_key
        )
        .success
    );

    let rsa = keylock::crypto::Context::new(keylock::Algorithm::RSA_OAEP_SHA256);
    let pair = rsa.generate_keypair().unwrap();
    let ciphertext = rsa.encrypt_asymmetric(b"rsa from keylock", &pair.public_key);
    assert!(ciphertext.success, "{}", ciphertext.error_message);
    let plaintext = rsa.decrypt_asymmetric(&ciphertext.data, &pair.private_key);
    assert_eq!(plaintext.data, b"rsa from keylock");
}
