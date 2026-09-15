use authbox::pki::{CertificateBuilder, DerTime, key_usage};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_key = keylock::generate_ed25519_keypair()?;

    let certificate = CertificateBuilder::new()
        .set_subject_from_string("CN=keylock Dev CA,O=keylock Labs,C=US")?
        .set_subject_public_key_ed25519(ca_key.public_key.clone())
        .set_validity(example_time(2024), example_time(2026))
        .set_basic_constraints(true, Some(1))?
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)?
        .set_subject_key_identifier(&ca_key.public_key)?
        .build_ed25519_with_self_signed(&ca_key, true)?;

    let path = std::env::temp_dir().join("authbox_dev_ca.pem");
    certificate.save(&path)?;

    println!("CA certificate saved to {}", path.display());

    Ok(())
}
