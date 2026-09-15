use authbox::did::{encode_ed25519_did_key, parse_did_key, resolve_did_key_document_json};
use keylock::generate_ed25519_keypair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = generate_ed25519_keypair()?;
    let public_key: [u8; 32] = keypair.public_key.as_slice().try_into()?;

    let did = encode_ed25519_did_key(public_key)?;
    let parsed = parse_did_key(&did)?;
    let document_json = resolve_did_key_document_json(&did)?;

    println!("did:key: {did}");
    println!("fingerprint: {}", parsed.fingerprint);
    println!("did:key document:\n{document_json}");

    Ok(())
}
