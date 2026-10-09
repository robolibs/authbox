use authbox::pki::{
    Certificate, CertificateBuilder, DerTime, DistinguishedName, Verifier, VerifyStatus,
};
use keylock::generate_ed25519_keypair;

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

fn make_test_certificate(
    subject: &DistinguishedName,
    serial: impl Into<Vec<u8>>,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let keys = generate_ed25519_keypair()?;
    Ok(CertificateBuilder::new()
        .set_version(3)
        .set_serial(serial)
        .set_subject(subject.clone())
        .set_issuer(subject.clone())
        .set_validity(example_time(2020), example_time(2035))
        .set_subject_public_key_ed25519(keys.public_key.clone())
        .set_basic_constraints(false, None)?
        .build_ed25519_with_self_signed(&keys, true)?)
}

fn print_status(response: &authbox::pki::ClientResponse) {
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
    println!(
        "Nonce: {}",
        if response.nonce.len() == 32 {
            "Valid"
        } else {
            "Invalid"
        }
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("keylock Simple Verification Example");
    println!("===================================\n");

    let mut verifier = Verifier::new();
    verifier.handler_mut().add_revoked_certificate_at(
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
        "Key compromise",
        1_700_000,
    );
    verifier.handler_mut().add_revoked_certificate_at(
        vec![0xde, 0xad, 0xbe, 0xef],
        "Certificate hold",
        1_800_000,
    );
    println!("Added 2 revoked certificates to the list\n");

    let subject = DistinguishedName::from_string("CN=Test User,O=Example Organization,C=US")?;
    let test_cert = make_test_certificate(&subject, 12_345_u64.to_be_bytes().to_vec())?;
    println!("Certificate created successfully");
    println!("Subject: {}", test_cert.tbs.subject);
    println!("Serial: 12345\n");

    let health = verifier.health_check_result();
    if !health.success || !health.value {
        return Err(format!("Health check failed: {}", health.error).into());
    }
    println!("Verifier is healthy\n");

    let response = verifier
        .verify_chain_result_at(std::slice::from_ref(&test_cert), 0)
        .into_result()?;
    println!("=== Verification Result ===");
    print_status(&response);

    println!("\n=== Testing with Revoked Certificate ===");
    let revoked_cert = make_test_certificate(&subject, vec![0x01, 0x02, 0x03, 0x04, 0x05])?;
    let revoked_response = verifier
        .verify_chain_result_at(std::slice::from_ref(&revoked_cert), 0)
        .into_result()?;
    print_status(&revoked_response);

    println!("\nDemo completed successfully!");
    Ok(())
}
