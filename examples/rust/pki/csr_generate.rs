use authbox::pki::{CsrBuilder, pem_encode, write_binary_result};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subject_key = keylock::generate_ed25519_keypair()?;

    let csr = CsrBuilder::new()
        .set_subject_from_string("CN=keylock Client,O=keylock")?
        .set_subject_public_key_ed25519(subject_key.public_key.clone())
        .build_ed25519(&subject_key)?;

    let pem = pem_encode(&csr.der, "CERTIFICATE REQUEST");
    let path = std::env::temp_dir().join("authbox_client_request.csr.pem");
    write_binary_result(pem.as_bytes(), &path)?;

    println!("CSR saved to {}", path.display());

    Ok(())
}
