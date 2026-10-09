use authbox::did::{
    ResolveOptions, Resolver, encode_did_jwk, parse_did_jwk, parse_document,
    resolve_did_jwk_document_json,
};

fn run_case(label: &str, jwk_json: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("{label}");
    println!("  Original JWK: {jwk_json}");

    let did = encode_did_jwk(jwk_json)?;
    println!("  Generated DID: {did}");

    let parsed_jwk = parse_did_jwk(&did)?;
    println!("  Parsed JWK back: {parsed_jwk}");

    let doc_json = resolve_did_jwk_document_json(&did)?;
    let document = parse_document(&doc_json)?;

    println!(
        "  Verification methods: {}",
        document.verification_methods.len()
    );
    println!(
        "  Authentication methods: {}",
        document.authentication.len()
    );
    println!("  Key agreement methods: {}", document.key_agreement.len());
    println!();

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== did:jwk Roundtrip Example ===\n");

    run_case(
        "Example 1: Ed25519 Key (Authentication)",
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )?;
    run_case(
        "Example 2: X25519 Key (Key Agreement)",
        r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#,
    )?;
    run_case(
        "Example 3: P-256 EC Key",
        r#"{"kty":"EC","crv":"P-256","x":"fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI","y":"hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"}"#,
    )?;

    println!("Example 4: Canonicalization Test");
    let jwk_v1 =
        r#"{"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kty":"OKP","crv":"Ed25519"}"#;
    let jwk_v2 =
        r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let did1 = encode_did_jwk(jwk_v1)?;
    let did2 = encode_did_jwk(jwk_v2)?;
    assert_eq!(did1, did2);
    println!("  Both versions produce the same DID: {did1}\n");

    println!("Example 5: Resolver Integration");
    let did = encode_did_jwk(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )?;
    let mut resolver = Resolver::default();
    resolver
        .registry_mut()
        .register_method("jwk", |did_uri: &str, _options: &ResolveOptions| {
            resolve_did_jwk_document_json(did_uri)
        });
    let resolution = resolver.resolve(&did)?;
    println!("  Resolved DID: {}", resolution.did.uri);
    println!("  Document ID: {}", resolution.document.id);
    println!("  Source: {}", resolution.source_url);
    println!(
        "  Verification methods: {}",
        resolution.document.verification_methods.len()
    );

    println!("\n=== All examples completed successfully ===");
    Ok(())
}
