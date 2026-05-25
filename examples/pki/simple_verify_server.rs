use authbox::pki::{
    Certificate, CertificateBuilder, CertificateData, DerTime, DistinguishedName,
    HealthCheckRequest, HealthCheckResponse, RequestFlags, RequestProcessor,
    SimpleRevocationHandler, VerifyRequest, VerifyResponse, VerifyStatus, deserialize, methods,
    serialize,
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

fn make_test_certificate(
    subject: &DistinguishedName,
    serial: impl Into<Vec<u8>>,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let keys = keylock::generate_ed25519_keypair()?;
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

fn status_name(status: VerifyStatus) -> &'static str {
    match status {
        VerifyStatus::Good => "GOOD",
        VerifyStatus::Revoked => "REVOKED",
        VerifyStatus::Unknown => "UNKNOWN",
    }
}

fn process_certificate(
    processor: &mut RequestProcessor<SimpleRevocationHandler>,
    cert: &Certificate,
    nonce_seed: u8,
) -> Result<VerifyResponse, Box<dyn std::error::Error>> {
    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: cert.to_der(),
        }],
        validation_timestamp: 0,
        flags: RequestFlags::None,
        nonce: vec![nonce_seed; 32],
    };
    let response_data = processor.process(methods::CHECK_CERTIFICATE, &serialize(&request))?;
    Ok(deserialize(&response_data)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("keylock Request Processor Example");
    println!("=================================\n");

    let mut handler = SimpleRevocationHandler::new();
    handler.add_revoked_certificate_at(
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
        "Key compromise",
        1_700_000,
    );
    handler.add_revoked_certificate_at(vec![0xde, 0xad, 0xbe, 0xef], "Certificate hold", 1_800_000);
    println!("Added 2 revoked certificates to the list\n");

    let mut processor = RequestProcessor::new(handler);
    let signing_key = keylock::generate_ed25519_keypair()?;
    processor.set_signing_key(signing_key.private_key)?;

    let subject = DistinguishedName::from_string("CN=Test Certificate,O=Example Organization")?;
    let test_cert = make_test_certificate(&subject, 99_999_u64.to_be_bytes().to_vec())?;
    println!("Certificate created with serial: 99999\n");

    println!("=== Testing Request Processor ===\n");

    println!("1. Testing health check...");
    let health_data = processor.process(methods::HEALTH_CHECK, &serialize(&HealthCheckRequest))?;
    let health: HealthCheckResponse = deserialize(&health_data)?;
    println!("   Health status: {:?}\n", health.status);

    println!("2. Testing valid certificate verification...");
    let verify_resp = process_certificate(&mut processor, &test_cert, 0x11)?;
    println!("   Status: {}", status_name(verify_resp.status));
    println!("   Reason: {}", verify_resp.reason);
    println!(
        "   Signature present: {}\n",
        if verify_resp.signature.len() == 64 {
            "Yes"
        } else {
            "No"
        }
    );

    println!("3. Testing revoked certificate verification...");
    let revoked_cert = make_test_certificate(&subject, vec![0x01, 0x02, 0x03, 0x04, 0x05])?;
    let revoked_resp = process_certificate(&mut processor, &revoked_cert, 0x22)?;
    println!("   Status: {}", status_name(revoked_resp.status));
    println!("   Reason: {}\n", revoked_resp.reason);

    let stats = processor.stats();
    println!("=== Processor Statistics ===");
    println!("Total requests: {}", stats.total_requests);
    println!("Health checks: {}", stats.total_health_checks);
    println!("GOOD responses: {}", stats.good_responses);
    println!("REVOKED responses: {}", stats.revoked_responses);

    println!("\nDemo completed successfully!");
    println!("Use RequestProcessor::process() to build custom transport layers.");
    Ok(())
}
