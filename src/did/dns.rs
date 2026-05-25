use super::{DidResult, error, parse};
use crate::json;
use std::sync::Arc;

pub type DnsLookupFn = Arc<dyn Fn(&str) -> DidResult<Vec<DnsTxtRecord>> + Send + Sync>;

#[derive(Clone, Default)]
pub struct DnsResolveOptions {
    pub require_dnssec: bool,
    pub dns_lookup: Option<DnsLookupFn>,
}

impl DnsResolveOptions {
    pub fn with_lookup<F>(dns_lookup: F) -> Self
    where
        F: Fn(&str) -> DidResult<Vec<DnsTxtRecord>> + Send + Sync + 'static,
    {
        Self {
            require_dnssec: false,
            dns_lookup: Some(Arc::new(dns_lookup)),
        }
    }

    pub fn require_dnssec(mut self, require_dnssec: bool) -> Self {
        self.require_dnssec = require_dnssec;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsTxtRecord {
    pub value: String,
    pub dnssec_valid: bool,
}

pub fn parse_did_dns(did_uri: &str) -> DidResult<String> {
    let parsed = parse(did_uri)?;
    if parsed.method != "dns" {
        return Err(error::invalid_method_id("method must be 'dns'"));
    }
    if parsed.method_id.is_empty() {
        return Err(error::invalid_method_id("did:dns method-id is empty"));
    }
    if parsed.method_id.contains(' ') {
        return Err(error::invalid_method_id("domain cannot contain spaces"));
    }
    if !parsed.method_id.contains('.') {
        return Err(error::invalid_method_id(
            "domain must contain at least one dot",
        ));
    }
    Ok(parsed.method_id)
}

pub fn get_dns_query_domain(domain: &str) -> String {
    format!("_did.{domain}")
}

pub fn resolve_did_dns_document_json(
    did_uri: &str,
    options: &DnsResolveOptions,
) -> DidResult<String> {
    let dns_lookup = options
        .dns_lookup
        .as_ref()
        .ok_or_else(error::fetcher_not_configured)?;
    resolve_did_dns_document_json_with_lookup(did_uri, options.require_dnssec, |domain| {
        dns_lookup(domain)
    })
}

pub fn resolve_did_dns_document_json_with_lookup<F>(
    did_uri: &str,
    require_dnssec: bool,
    dns_lookup: F,
) -> DidResult<String>
where
    F: Fn(&str) -> DidResult<Vec<DnsTxtRecord>>,
{
    let domain = parse_did_dns(did_uri)?;
    let query_domain = get_dns_query_domain(&domain);
    let records = dns_lookup(&query_domain)?;
    if records.is_empty() {
        return Err(error::network_error(format!(
            "no TXT records found at {query_domain}"
        )));
    }
    if require_dnssec && !records.iter().any(|record| record.dnssec_valid) {
        return Err(error::network_error("DNSSEC validation failed"));
    }
    for record in records {
        if require_dnssec && !record.dnssec_valid {
            continue;
        }
        let value = record.value.as_str();
        if value.starts_with("did=") {
            return Err(error::not_implemented("DID document URL references"));
        }
        if json::parse(value).is_ok() {
            return Ok(value.to_string());
        }
    }
    Err(error::network_error("no valid DID document in TXT records"))
}

pub fn create_dns_handler(
    dns_options: DnsResolveOptions,
) -> impl Fn(&str, &super::ResolveOptions) -> DidResult<String> + Clone + Send + Sync + 'static {
    move |did_uri, _| resolve_did_dns_document_json(did_uri, &dns_options)
}
