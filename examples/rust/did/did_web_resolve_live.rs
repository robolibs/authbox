use authbox::did::{WebFetchOptions, make_web_http11_resolver_with_options, parse};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "did_web_resolve_live".to_string());
    let Some(did_uri) = args.next() else {
        println!("Usage: {program} <did:web:...> [--allow-http] [--skip-tls-verify]");
        println!("No DID was supplied, so this example stops before live network resolution.");
        return Ok(());
    };

    if !did_uri.starts_with("did:web:") {
        return Err(format!("Expected a did:web URI, got: {did_uri}").into());
    }

    let mut options = WebFetchOptions::default();
    for flag in args {
        match flag.as_str() {
            "--allow-http" => options.allow_insecure_http = true,
            "--skip-tls-verify" => options.skip_tls_certificate_verification_for_testing = true,
            _ => return Err(format!("Unknown flag: {flag}").into()),
        }
    }

    let resolver = make_web_http11_resolver_with_options(options);
    let resolved = resolver.resolve(&did_uri)?;

    println!("DID: {}", resolved.did.uri);
    println!("Method: {}", parse(&did_uri)?.method);
    println!("Source: {}", resolved.source_url);
    println!("Methods: {}", resolved.document.verification_methods.len());
    println!(
        "Authentication refs: {}",
        resolved.document.authentication.len()
    );
    println!(
        "Assertion refs: {}",
        resolved.document.assertion_method.len()
    );
    println!("\nRaw DID document:");
    println!("{}", resolved.raw_document_json);

    Ok(())
}
