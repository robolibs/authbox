use authbox::pki::{Certificate, CertificateBuilder, DerTime, KeyPair, TrustStore, key_usage};

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

fn build_anchor(keypair: &KeyPair) -> Result<Certificate, Box<dyn std::error::Error>> {
    Ok(CertificateBuilder::new()
        .set_subject_from_string("CN=keylock Anchor,O=keylock")?
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_validity(example_time(2024), example_time(2034))
        .set_basic_constraints(true, Some(1))?
        .set_key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)?
        .build_ed25519_with_self_signed(keypair, true)?)
}

fn build_leaf(
    issuer: &Certificate,
    issuer_key: &KeyPair,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let leaf_key = authbox::keylock::generate_ed25519_keypair()?;
    Ok(CertificateBuilder::new()
        .set_subject_from_string("CN=Trusted Client,O=keylock")?
        .set_issuer(issuer.tbs.subject.clone())
        .set_subject_public_key_ed25519(leaf_key.public_key)
        .set_validity(example_time(2024), example_time(2026))
        .set_basic_constraints(false, None)?
        .set_key_usage(key_usage::DIGITAL_SIGNATURE)?
        .build_ed25519(issuer_key)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = TrustStore::new();

    let anchor_key = authbox::keylock::generate_ed25519_keypair()?;
    let anchor = build_anchor(&anchor_key)?;
    store.add(anchor.clone());
    println!("Anchors loaded: {}", store.anchors().len());

    let leaf = build_leaf(&anchor, &anchor_key)?;
    if let Some(issuer) = store.find_issuer(&leaf) {
        println!("Issuer match: {}", issuer.tbs.subject);
    }

    store.remove_by_subject(&anchor.tbs.subject);
    println!("Anchors after removal: {}", store.anchors().len());

    Ok(())
}
