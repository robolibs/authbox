use authbox::did::{
    Resolver, generate_did_web_document_from_certificate,
    rpc::{Client as DidRpcClient, LoopbackRemote, Service},
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
        .set_validity(example_time(2020), example_time(2035))
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_basic_constraints(false, None)?
        .set_subject_alt_name(&[did_name])?
        .build_ed25519_with_self_signed(&keypair, true)?;

    let generated = generate_did_web_document_from_certificate("example.com", &cert)?;
    let expected_doc = generated.did_document_json.clone();
    let resolver = Resolver::with_fetcher(move |url| {
        if url == "https://example.com/.well-known/did.json" {
            Ok(expected_doc.clone())
        } else {
            Err(authbox::did::error::network_error("unexpected URL"))
        }
    });

    let service = Service::new(resolver);
    let remote = LoopbackRemote::new(service);
    let client = DidRpcClient::new(remote);

    let resolved = client.resolve(did_uri)?;
    let verified = client.verify_binding(did_uri, &generated.did_document_json, &cert.to_pem())?;

    if !verified {
        return Err("RPC verify returned invalid binding".into());
    }

    println!("RPC resolve source: {}", resolved.source_url);
    println!("RPC verify: OK");

    Ok(())
}
