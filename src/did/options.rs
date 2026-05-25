use super::{DidDocument, DidResult, error, parse_document};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct ResolveOptions {
    pub require_https: bool,
    pub require_matching_id: bool,
    pub max_document_size: usize,
    pub strict_parsing: bool,
    pub allow_experimental: bool,
    pub allowed_methods: BTreeSet<String>,
    pub blocked_methods: BTreeSet<String>,
    pub validate_contexts: bool,
    pub require_verification_method: bool,
    pub max_verification_methods: usize,
    pub max_services: usize,
    pub max_context_entries: usize,
}

impl ResolveOptions {
    pub fn production() -> Self {
        Self {
            require_https: true,
            require_matching_id: true,
            max_document_size: 1_048_576,
            strict_parsing: false,
            allow_experimental: false,
            allowed_methods: BTreeSet::new(),
            blocked_methods: BTreeSet::new(),
            validate_contexts: false,
            require_verification_method: true,
            max_verification_methods: 100,
            max_services: 50,
            max_context_entries: 10,
        }
    }

    pub fn is_method_allowed(&self, method: &str) -> bool {
        if self.blocked_methods.contains(method) {
            return false;
        }
        self.allowed_methods.is_empty() || self.allowed_methods.contains(method)
    }
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self::production()
    }
}

pub fn parse_document_with_options(
    json_text: &str,
    options: &ResolveOptions,
) -> DidResult<DidDocument> {
    let document = parse_document(json_text)?;
    if document.verification_methods.len() > options.max_verification_methods {
        return Err(error::invalid_document_json(format!(
            "too many verification methods: {} (max: {})",
            document.verification_methods.len(),
            options.max_verification_methods
        )));
    }
    if document.services.len() > options.max_services {
        return Err(error::invalid_document_json(format!(
            "too many services: {} (max: {})",
            document.services.len(),
            options.max_services
        )));
    }
    if document.contexts.len() > options.max_context_entries {
        return Err(error::invalid_document_json(format!(
            "too many @context entries: {} (max: {})",
            document.contexts.len(),
            options.max_context_entries
        )));
    }
    if options.require_verification_method && document.verification_methods.is_empty() {
        return Err(error::no_verification_methods());
    }
    Ok(document)
}

pub fn validate_document(document: &DidDocument, expected_did_uri: &str) -> DidResult<bool> {
    if document.id != expected_did_uri {
        return Err(error::document_id_mismatch(expected_did_uri, &document.id));
    }
    if document.verification_methods.is_empty() {
        return Err(error::no_verification_methods());
    }
    if document.authentication.is_empty()
        && document.assertion_method.is_empty()
        && document.key_agreement.is_empty()
    {
        return Err(error::no_verification_relationships());
    }
    Ok(true)
}
