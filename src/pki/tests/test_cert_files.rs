use super::*;

#[test]
fn cert_files_binary_result_surface_matches_cpp_shape() {
    let path = std::env::temp_dir().join(format!(
        "authbox-files-{}-{}.bin",
        std::process::id(),
        0x51_u8
    ));
    let data = vec![0x10, 0x20, 0x30, 0x40];

    assert!(write_binary(&data, &path));
    assert!(write_binary_bool(&data, &path));
    write_binary_result(&data, &path).unwrap();
    let result = read_binary(&path);
    assert!(result.success);
    assert_eq!(result.error_message, "");
    assert_eq!(result.data, data);
    assert_eq!(result.clone().into_result().unwrap(), data);
    assert_eq!(
        read_binary_bytes(&path).unwrap(),
        vec![0x10, 0x20, 0x30, 0x40]
    );
    assert_eq!(read_binary_result(&path), result);

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn cert_files_binary_result_reports_missing_file_without_panicking() {
    let path = std::env::temp_dir().join(format!(
        "authbox-missing-{}-{}.bin",
        std::process::id(),
        0x52_u8
    ));

    let result = read_binary(&path);
    assert!(!result.success);
    assert!(result.data.is_empty());
    assert!(result.error_message.starts_with("Failed to open file:"));
    let result_error = result.clone().into_result().unwrap_err();
    assert_eq!(result_error.message, result.error_message);
    assert_eq!(
        read_binary_result(&path).error_message,
        result.error_message
    );
    let direct_error = read_binary_bytes(&path).unwrap_err();
    assert_eq!(direct_error.message, result.error_message);
}

#[test]
fn cert_files_certificate_chain_load_save_roundtrips_pem_and_der() {
    let first = CertificateBuilder::new()
        .set_serial_u64(0x51)
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_subject_from_string("CN=first.example")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x51; 32])
        .build_with_signature(vec![0x51; 64], false)
        .unwrap();
    let second = CertificateBuilder::new()
        .set_serial_u64(0x52)
        .set_issuer_from_string("CN=Issuer")
        .unwrap()
        .set_subject_from_string("CN=second.example")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x52; 32])
        .build_with_signature(vec![0x52; 64], false)
        .unwrap();

    let pem_chain = format!("{}{}", first.to_pem(), second.to_pem());
    let parsed_pem = Certificate::parse_pem_chain(&pem_chain).unwrap();
    assert_eq!(parsed_pem.len(), 2);
    assert_eq!(parsed_pem[0].der(), first.der());
    assert_eq!(parsed_pem[1].der(), second.der());

    let der_chain = [first.der(), second.der()].concat();
    let parsed_der = Certificate::parse_der_chain(&der_chain).unwrap();
    assert_eq!(parsed_der.len(), 2);
    assert_eq!(parsed_der[0].der(), first.der());
    assert_eq!(parsed_der[1].der(), second.der());

    let mut path = std::env::temp_dir();
    path.push(format!(
        "authbox-cert-save-{}-{}.pem",
        std::process::id(),
        0x51
    ));
    first.save(&path).unwrap();
    let loaded = Certificate::load(&path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].to_der(), first.to_der());
    std::fs::remove_file(path).unwrap();

    let der_path = std::env::temp_dir().join(format!(
        "authbox-cert-save-{}-{}.der",
        std::process::id(),
        0x52
    ));
    first.save_as(&der_path, CertificateFormat::Der).unwrap();
    let loaded_der = Certificate::load(&der_path).unwrap();
    assert_eq!(loaded_der.len(), 1);
    assert_eq!(loaded_der[0].to_der(), first.to_der());
    std::fs::remove_file(der_path).unwrap();
}

#[test]
fn cert_files_cpp_named_certificate_format_constants_match_rust_variants() {
    assert_eq!(CertificateFormat::DER, CertificateFormat::Der);
    assert_eq!(CertificateFormat::PEM, CertificateFormat::Pem);
}
