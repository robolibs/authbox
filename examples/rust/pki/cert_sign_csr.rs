use authbox::pki::{
    Certificate, CertificateBuilder, CertificateResult, CsrBuilder, DerTime, KeyPair, key_usage,
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

fn make_ca(keypair: &KeyPair) -> CertificateResult<Certificate> {
    let builder = match CertificateBuilder::new()
        .set_subject_from_string("CN=keylock Signing CA,O=keylock")
        .and_then(|builder| {
            builder
                .set_subject_public_key_ed25519(keypair.public_key.clone())
                .set_validity(example_time(2020), example_time(2035))
                .set_basic_constraints(true, Some(2))
        })
        .and_then(|builder| builder.set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN))
        .and_then(|builder| builder.set_subject_key_identifier(&keypair.public_key))
    {
        Ok(builder) => builder,
        Err(error) => return CertificateResult::failure(error.message),
    };

    builder.build_ed25519_result_with_self_signed(keypair, true)
}

fn make_sample_csr(
    leaf_key: &KeyPair,
) -> Result<authbox::pki::CertificateRequest, Box<dyn std::error::Error>> {
    Ok(CsrBuilder::new()
        .set_subject_from_string("CN=keylock Service,O=keylock")?
        .set_subject_public_key_ed25519(leaf_key.public_key.clone())
        .build_ed25519(leaf_key)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_key = keylock::generate_ed25519_keypair()?;
    let ca_cert = make_ca(&ca_key).into_result()?;

    let leaf_key = keylock::generate_ed25519_keypair()?;
    let csr = make_sample_csr(&leaf_key)?;

    let issued = CertificateBuilder::new()
        .set_subject(csr.info.subject.clone())
        .set_subject_public_key_info(csr.info.subject_public_key_info.clone())
        .set_validity(example_time(2026), example_time(2027))
        .set_issuer(ca_cert.tbs.subject.clone())
        .set_basic_constraints(false, None)?
        .set_key_usage(key_usage::DIGITAL_SIGNATURE | key_usage::KEY_AGREEMENT)?
        .build_ed25519(&ca_key)?;

    println!("Issued certificate:\n{}", issued.to_pem());
    let verified = issued.verify_signature(&ca_cert)?;
    println!(
        "Signature verification against CA: {}",
        if verified { "success" } else { "failed" }
    );

    Ok(())
}
