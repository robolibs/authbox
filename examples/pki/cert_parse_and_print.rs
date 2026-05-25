use authbox::pki::{
    Certificate, CertificateBuilder, DerTime, HashAlgorithm, digest, generate_ed25519_keypair,
    key_usage,
};

fn example_time(year: i32) -> DerTime {
    DerTime {
        year,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fallback_certificate() -> Result<Certificate, Box<dyn std::error::Error>> {
    let keypair = generate_ed25519_keypair()?;
    Ok(CertificateBuilder::new()
        .set_subject_from_string("CN=On-The-Fly Cert,O=keylock")?
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_validity(example_time(2024), example_time(2025))
        .set_basic_constraints(false, None)?
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)?
        .build_ed25519_with_self_signed(&keypair, true)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certificate = if let Some(path) = std::env::args().nth(1) {
        Certificate::load_with_relaxed(path, true)?
            .into_iter()
            .next()
            .ok_or("certificate file did not contain a certificate")?
    } else {
        fallback_certificate()?
    };

    print!("{}", certificate.print_info());
    let sans = certificate.subject_alt_names();
    println!("SubjectAltName count: {}", sans.len());
    let fingerprint = digest(HashAlgorithm::Sha256, certificate.der())?;
    println!("Fingerprint (SHA-256): {}", to_hex(&fingerprint));

    Ok(())
}
