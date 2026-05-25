use super::{
    DidResult, DnsResolveOptions, DnsTxtRecord, DocumentMetadata, MethodRegistry, Resolution,
    ResolutionMetadata, ResolveOptions, create_dns_handler, did_web_document_url, error,
    get_dns_query_domain, parse, parse_did_dns, parse_document_with_options,
    resolve_did_jwk_document_json, resolve_did_key_document_json, resolve_did_peer_document_json,
    resolve_did_pkh_document_json, validate_document,
};
use std::sync::Arc;
pub type FetchDidDocumentFn = Arc<dyn Fn(&str) -> DidResult<String> + Send + Sync>;

#[derive(Clone)]
pub struct Resolver {
    fetcher: Option<FetchDidDocumentFn>,
    dns_options: Option<DnsResolveOptions>,
    registry: MethodRegistry,
}

impl Resolver {
    pub fn new() -> Self {
        Self::with_optional_fetcher(None)
    }

    pub fn with_optional_fetcher(fetcher: Option<FetchDidDocumentFn>) -> Self {
        Self::with_fetcher_and_dns_options(fetcher, None)
    }

    pub fn with_fetcher_and_dns_options(
        fetcher: Option<FetchDidDocumentFn>,
        dns_options: Option<DnsResolveOptions>,
    ) -> Self {
        Self::with_fetcher_dns_and_registry(fetcher, dns_options, MethodRegistry::new())
    }

    pub fn with_registry(fetcher: Option<FetchDidDocumentFn>, registry: MethodRegistry) -> Self {
        Self::with_fetcher_dns_and_registry(fetcher, None, registry)
    }

    pub fn with_fetcher_dns_and_registry(
        fetcher: Option<FetchDidDocumentFn>,
        dns_options: Option<DnsResolveOptions>,
        registry: MethodRegistry,
    ) -> Self {
        let mut resolver = Self {
            fetcher,
            dns_options,
            registry,
        };
        resolver.register_builtin_methods();
        resolver
    }

    pub fn with_fetcher<F>(fetcher: F) -> Self
    where
        F: Fn(&str) -> DidResult<String> + Send + Sync + 'static,
    {
        Self::with_optional_fetcher(Some(Arc::new(fetcher)))
    }

    pub fn with_dns_lookup<F>(dns_lookup: F) -> Self
    where
        F: Fn(&str) -> DidResult<Vec<DnsTxtRecord>> + Send + Sync + 'static,
    {
        Self::with_fetcher_and_dns_options(None, Some(DnsResolveOptions::with_lookup(dns_lookup)))
    }

    pub fn with_fetcher_and_dns_lookup<F, D>(fetcher: F, dns_lookup: D) -> Self
    where
        F: Fn(&str) -> DidResult<String> + Send + Sync + 'static,
        D: Fn(&str) -> DidResult<Vec<DnsTxtRecord>> + Send + Sync + 'static,
    {
        Self::with_fetcher_and_dns_options(
            Some(Arc::new(fetcher)),
            Some(DnsResolveOptions::with_lookup(dns_lookup)),
        )
    }

    pub fn with_dns_options(dns_options: DnsResolveOptions) -> Self {
        Self::with_fetcher_and_dns_options(None, Some(dns_options))
    }

    pub fn registry(&self) -> &MethodRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut MethodRegistry {
        &mut self.registry
    }

    fn register_builtin_methods(&mut self) {
        self.registry
            .register_method("key", |did_uri, _| resolve_did_key_document_json(did_uri));
        self.registry
            .register_method("jwk", |did_uri, _| resolve_did_jwk_document_json(did_uri));
        self.registry
            .register_method("peer", |did_uri, _| resolve_did_peer_document_json(did_uri));
        self.registry
            .register_method("pkh", |did_uri, _| resolve_did_pkh_document_json(did_uri));
        let fetcher = self.fetcher.clone();
        self.registry
            .register_method("web", move |did_uri, options| {
                let doc_url = did_web_document_url(did_uri)?;
                if options.require_https && !doc_url.starts_with("https://") {
                    return Err(error::https_required());
                }
                let fetcher = fetcher.as_ref().ok_or_else(error::fetcher_not_configured)?;
                fetcher(&doc_url)
            });
        if let Some(dns_options) = self.dns_options.clone() {
            self.registry
                .register_method("dns", create_dns_handler(dns_options));
        }
    }

    pub fn resolve(&self, did_uri: &str) -> DidResult<Resolution> {
        self.resolve_with_options(did_uri, &ResolveOptions::default())
    }

    pub fn resolve_with_options(
        &self,
        did_uri: &str,
        options: &ResolveOptions,
    ) -> DidResult<Resolution> {
        let doc_json = self
            .registry
            .resolve_to_document_with_options(did_uri, options)?;
        let parsed = parse(did_uri)?;
        let source_url = match parsed.method.as_str() {
            "web" => did_web_document_url(did_uri).unwrap_or_else(|_| "inline".to_string()),
            "key" => "did:key:inline".to_string(),
            "jwk" => "did:jwk:inline".to_string(),
            "peer" => "did:peer:inline".to_string(),
            "pkh" => "did:pkh:inline".to_string(),
            "dns" => parse_did_dns(did_uri)
                .map(|domain| format!("dns:{}", get_dns_query_domain(&domain)))
                .unwrap_or_else(|_| "dns:inline".to_string()),
            _ => "inline".to_string(),
        };
        Self::resolve_from_document_with_options(did_uri, &doc_json, &source_url, options)
    }

    pub fn resolve_from_document(did_uri: &str, document_json: &str) -> DidResult<Resolution> {
        Self::resolve_from_document_with_options(
            did_uri,
            document_json,
            "inline",
            &ResolveOptions::default(),
        )
    }

    pub fn resolve_from_document_with_source_url(
        did_uri: &str,
        document_json: &str,
        source_url: &str,
    ) -> DidResult<Resolution> {
        Self::resolve_from_document_with_options(
            did_uri,
            document_json,
            source_url,
            &ResolveOptions::default(),
        )
    }

    pub fn resolve_from_document_with_options(
        did_uri: &str,
        document_json: &str,
        source_url: &str,
        options: &ResolveOptions,
    ) -> DidResult<Resolution> {
        let did = parse(did_uri)?;
        let document = parse_document_with_options(document_json, options)?;
        if options.require_matching_id {
            validate_document(&document, did_uri)?;
        }
        Ok(Resolution {
            did,
            document,
            source_url: source_url.to_string(),
            raw_document_json: document_json.to_string(),
            resolution_metadata: ResolutionMetadata {
                content_type: "application/did+ld+json".to_string(),
                ..ResolutionMetadata::default()
            },
            document_metadata: DocumentMetadata::default(),
        })
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}
