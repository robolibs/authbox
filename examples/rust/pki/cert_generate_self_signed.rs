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
    let subject_key = keylock::generate_ed25519_keypair()?;

    let certificate = CertificateBuilder::new()
        .set_subject_from_string("CN=keylock Self-Signed,O=keylock,C=US")?
        .set_subject_public_key_ed25519(subject_key.public_key.clone())
        .set_validity(example_time(2024), example_time(2025))
        .set_basic_constraints(false, None)?
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)?
        .build_ed25519_with_self_signed(&subject_key, true)?;

    let path = std::env::temp_dir().join("authbox_self_signed.pem");
    certificate.save(&path)?;

    println!("Wrote PEM certificate to {}", path.display());
    print!("{}", certificate.to_pem());

    Ok(())
}
