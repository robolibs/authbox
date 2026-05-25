use authbox::pki::{Certificate, CertificateBuilder, DerTime, Verifier, VerifyStatus};

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

fn generated_certificate() -> Result<Certificate, Box<dyn std::error::Error>> {
    let keys = authbox::keylock::generate_ed25519_keypair()?;
    Ok(CertificateBuilder::new()
        .set_subject_from_string("CN=Local Verification Demo")?
        .set_issuer_from_string("CN=Local Verification Demo")?
        .set_validity(example_time(2020), example_time(2035))
        .set_subject_public_key_ed25519(keys.public_key.clone())
        .set_basic_constraints(false, None)?
        .build_ed25519_with_self_signed(&keys, true)?)
}

fn load_or_generate_certificate() -> Result<Certificate, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::args().nth(1) {
        println!("Loading certificate from: {path}");
        return Ok(Certificate::load_with_relaxed(path, true)?
            .into_iter()
            .next()
            .ok_or("certificate file did not contain a certificate")?);
    }
    println!("No certificate path supplied; generating a local demo certificate");
    generated_certificate()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("authbox Direct Certificate Revocation Check Example");
    println!("==================================================\n");

    let cert = load_or_generate_certificate()?;
    println!("Certificate loaded successfully");
    println!("Subject: {}\n", cert.tbs.subject);

    let mut verifier = Verifier::new();
    verifier.handler_mut().add_revoked_certificate_at(
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
        "Key compromise",
        1_700_000,
    );
    println!("Added example revoked certificate to the list\n");

    let health = verifier.health_check_result();
    if !health.success || !health.value {
        return Err(format!("Health check failed: {}", health.error).into());
    }
    println!("Verifier is healthy\n");

    let response = verifier
        .verify_chain_result_at(std::slice::from_ref(&cert), 0)
        .into_result()?;

    println!("Verification Result:");
    println!("-------------------");
    match response.status {
        VerifyStatus::Good => {
            println!("Status: GOOD");
            println!("The certificate is valid and not revoked");
        }
        VerifyStatus::Revoked => {
            println!("Status: REVOKED");
            println!("Reason: {}", response.reason);
            println!("Revoked at unix timestamp: {}", response.revocation_time);
        }
        VerifyStatus::Unknown => {
            println!("Status: UNKNOWN");
            if !response.reason.is_empty() {
                println!("Reason: {}", response.reason);
            }
        }
    }

    println!("\nResponse Details:");
    println!("This update: {}", response.this_update);
    println!("Next update: {}", response.next_update);
    println!(
        "Nonce: {}",
        if response.nonce.len() == 32 {
            "Valid"
        } else {
            "Invalid"
        }
    );

    Ok(())
}
