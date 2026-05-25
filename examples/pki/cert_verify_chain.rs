use authbox::pki::{
    Certificate, CertificateBuilder, CertificateResult, DerTime, KeyPair, TrustStore,
    generate_ed25519_keypair, key_usage,
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

fn make_certificate(
    subject_dn: &str,
    subject_key: &KeyPair,
    issuer_cert: Option<&Certificate>,
    issuer_key: &KeyPair,
    is_ca: bool,
    path_length: Option<u32>,
) -> CertificateResult<Certificate> {
    let usage = if is_ca {
        key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN
    } else {
        key_usage::DIGITAL_SIGNATURE
    };

    let mut builder = match CertificateBuilder::new()
        .set_subject_from_string(subject_dn)
        .and_then(|builder| {
            builder
                .set_subject_public_key_ed25519(subject_key.public_key.clone())
                .set_validity(example_time(2020), example_time(2035))
                .set_basic_constraints(is_ca, path_length)
        })
        .and_then(|builder| builder.set_key_usage(usage))
        .and_then(|builder| builder.set_subject_key_identifier(&subject_key.public_key))
    {
        Ok(builder) => builder,
        Err(error) => return CertificateResult::failure(error.message),
    };

    let self_signed = issuer_cert.is_none();
    if let Some(issuer) = issuer_cert {
        builder = match builder
            .set_issuer(issuer.tbs.subject.clone())
            .set_authority_key_identifier(&issuer.tbs.subject_public_key_info.public_key)
        {
            Ok(builder) => builder,
            Err(error) => return CertificateResult::failure(error.message),
        };
    }

    builder.build_ed25519_result_with_self_signed(issuer_key, self_signed)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root_key = generate_ed25519_keypair()?;
    let root_cert = make_certificate(
        "CN=keylock Root CA,O=keylock",
        &root_key,
        None,
        &root_key,
        true,
        Some(2),
    )
    .into_result()?;

    let intermediate_key = generate_ed25519_keypair()?;
    let intermediate_cert = make_certificate(
        "CN=keylock Intermediate CA,O=keylock",
        &intermediate_key,
        Some(&root_cert),
        &root_key,
        true,
        Some(0),
    )
    .into_result()?;

    let leaf_key = generate_ed25519_keypair()?;
    let leaf_cert = make_certificate(
        "CN=Leaf Service,O=keylock",
        &leaf_key,
        Some(&intermediate_cert),
        &intermediate_key,
        false,
        None,
    )
    .into_result()?;

    let mut store = TrustStore::new();
    store.add(root_cert);

    let verdict = leaf_cert.validate_chain(std::slice::from_ref(&intermediate_cert), &store)?;
    println!(
        "Chain validation: {}",
        if verdict { "success" } else { "failed" }
    );

    if verdict {
        Ok(())
    } else {
        Err("chain validation failed".into())
    }
}
