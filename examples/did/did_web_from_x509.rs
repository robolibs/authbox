use authbox::did::{
    did_web_document_url, generate_did_web_document_from_certificate,
    verify_certificate_binding_json,
};
use authbox::pki::{
    CertificateBuilder, DerTime, GeneralName, GeneralNameType, generate_ed25519_keypair,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let did_uri = "did:web:example.com";
    let keypair = generate_ed25519_keypair()?;

    let did_name = GeneralName {
        type_: GeneralNameType::Uri,
        value: did_uri.as_bytes().to_vec(),
    };
    let cert = CertificateBuilder::new()
        .set_subject_from_string("CN=example.com,O=Example")?
        .set_issuer_from_string("CN=example.com,O=Example")?
        .set_validity(example_time(2024), example_time(2026))
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_basic_constraints(false, None)?
        .set_subject_alt_name(&[did_name])?
        .build_ed25519_with_self_signed(&keypair, true)?;

    let doc = generate_did_web_document_from_certificate("example.com", &cert)?;
    let verified = verify_certificate_binding_json(&doc.did_document_json, &cert, did_uri)?;
    assert!(verified);

    println!("did:web URL: {}", did_web_document_url(did_uri)?);
    println!("Generated did.json:\n{}", doc.did_document_json);
    println!("Binding verification: OK");

    Ok(())
}
