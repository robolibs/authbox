use super::super::*;

const DID_DNS: &str = "did:dns:example.com";

fn mock_document() -> String {
    r#"{
        "id": "did:dns:example.com",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:dns:example.com#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:dns:example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:dns:example.com#key-1"]
    }"#
    .to_string()
}

#[test]
fn did_dns_parses_valid_domains_and_subdomains() {
    assert_eq!(parse_did_dns(DID_DNS).unwrap(), "example.com");
    assert_eq!(
        parse_did_dns("did:dns:identity.example.com").unwrap(),
        "identity.example.com"
    );
}

#[test]
fn did_dns_rejects_invalid_method_empty_domain_spaces_and_missing_tld() {
    assert!(parse_did_dns("did:web:example.com").is_err());
    assert!(parse_did_dns("did:dns:").is_err());
    assert!(parse_did_dns("did:dns:example .com").is_err());
    assert!(parse_did_dns("did:dns:localhost").is_err());
}

#[test]
fn did_dns_gets_txt_query_domain() {
    assert_eq!(get_dns_query_domain("example.com"), "_did.example.com");
}

#[test]
fn did_dns_txt_record_default_matches_cpp_aggregate_defaults() {
    let record = DnsTxtRecord::default();

    assert_eq!(record.value, "");
    assert!(!record.dnssec_valid);
}

#[test]
fn did_dns_resolves_with_mocked_dns_returning_json_document() {
    let document = mock_document();
    let options = DnsResolveOptions::with_lookup(move |domain| {
        assert_eq!(domain, "_did.example.com");
        Ok(vec![DnsTxtRecord {
            value: document.clone(),
            dnssec_valid: true,
        }])
    });

    let resolved = resolve_did_dns_document_json(DID_DNS, &options).unwrap();
    assert_eq!(resolved, mock_document());
}

#[test]
fn did_dns_skips_non_json_txt_and_resolves_later_dnssec_record() {
    let document = mock_document();
    let options = DnsResolveOptions::with_lookup(move |domain| {
        assert_eq!(domain, "_did.example.com");
        Ok(vec![
            DnsTxtRecord {
                value: "this is not json".to_string(),
                dnssec_valid: true,
            },
            DnsTxtRecord {
                value: document.clone(),
                dnssec_valid: true,
            },
        ])
    })
    .require_dnssec(true);

    let resolved = resolve_did_dns_document_json(DID_DNS, &options).unwrap();
    assert_eq!(parse_document(&resolved).unwrap().id, DID_DNS);
}

#[test]
fn did_dns_accepts_any_valid_json_txt_record_like_cpp_surface() {
    let json_record = r#"{"hello":"world"}"#;
    let options = DnsResolveOptions::with_lookup(move |_| {
        Ok(vec![DnsTxtRecord {
            value: json_record.to_string(),
            dnssec_valid: true,
        }])
    });

    let resolved = resolve_did_dns_document_json(DID_DNS, &options).unwrap();

    assert_eq!(resolved, json_record);
}

#[test]
fn did_dns_returns_original_json_txt_record_without_trimming() {
    let json_record = " \n {\"hello\":\"world\"}\t ";
    let options = DnsResolveOptions::with_lookup(move |_| {
        Ok(vec![DnsTxtRecord {
            value: json_record.to_string(),
            dnssec_valid: true,
        }])
    });

    let resolved = resolve_did_dns_document_json(DID_DNS, &options).unwrap();

    assert_eq!(resolved, json_record);
}

#[test]
fn did_dns_resolve_failures_match_cpp_surface() {
    assert!(resolve_did_dns_document_json(DID_DNS, &DnsResolveOptions::default()).is_err());

    let empty_records = DnsResolveOptions::with_lookup(|_| Ok(vec![]));
    assert!(resolve_did_dns_document_json(DID_DNS, &empty_records).is_err());

    let invalid_json = DnsResolveOptions::with_lookup(|_| {
        Ok(vec![DnsTxtRecord {
            value: "this is not json".to_string(),
            dnssec_valid: true,
        }])
    });
    assert!(resolve_did_dns_document_json(DID_DNS, &invalid_json).is_err());
}

#[test]
fn did_dns_respects_dnssec_requirement() {
    let valid = DnsResolveOptions::with_lookup(|_| {
        Ok(vec![DnsTxtRecord {
            value: mock_document(),
            dnssec_valid: true,
        }])
    })
    .require_dnssec(true);
    assert!(resolve_did_dns_document_json(DID_DNS, &valid).is_ok());

    let invalid = DnsResolveOptions::with_lookup(|_| {
        Ok(vec![DnsTxtRecord {
            value: mock_document(),
            dnssec_valid: false,
        }])
    })
    .require_dnssec(true);
    assert!(resolve_did_dns_document_json(DID_DNS, &invalid).is_err());
}

#[test]
fn did_dns_integrates_with_resolver() {
    let document = mock_document();
    let dns_options = DnsResolveOptions::with_lookup(move |_| {
        Ok(vec![DnsTxtRecord {
            value: document.clone(),
            dnssec_valid: true,
        }])
    });
    let mut resolver = Resolver::new();
    resolver
        .registry_mut()
        .register_method("dns", create_dns_handler(dns_options));

    let resolution = resolver.resolve(DID_DNS).unwrap();

    assert_eq!(resolution.document.id, DID_DNS);
    assert_eq!(resolution.document.verification_methods.len(), 1);
    assert_eq!(resolution.source_url, "dns:_did.example.com");
}

#[test]
fn did_dns_resolver_uses_configured_lookup_and_errors_without_one() {
    let document = mock_document();
    let resolver = Resolver::with_dns_lookup(move |domain| {
        assert_eq!(domain, "_did.example.com");
        Ok(vec![DnsTxtRecord {
            value: document.clone(),
            dnssec_valid: true,
        }])
    });

    let resolution = resolver.resolve(DID_DNS).unwrap();

    assert_eq!(resolution.document.id, DID_DNS);
    assert_eq!(resolution.document.verification_methods.len(), 1);
    assert_eq!(resolution.source_url, "dns:_did.example.com");

    let resolver_without_dns = Resolver::new();
    assert!(resolver_without_dns.resolve(DID_DNS).is_err());
}
