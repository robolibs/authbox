use super::{Did, DidDocument, DidResult, ResolveOptions, error, parse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
pub type MethodHandler = Arc<dyn Fn(&str, &ResolveOptions) -> DidResult<String> + Send + Sync>;

#[derive(Clone, Default)]
pub struct MethodRegistry {
    handlers: HashMap<String, MethodHandler>,
}

impl MethodRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_method<F>(&mut self, method: impl Into<String>, handler: F)
    where
        F: Fn(&str, &ResolveOptions) -> DidResult<String> + Send + Sync + 'static,
    {
        self.handlers.insert(method.into(), Arc::new(handler));
    }

    pub fn is_registered(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }

    pub fn list_methods(&self) -> Vec<String> {
        let mut methods = self.handlers.keys().cloned().collect::<Vec<_>>();
        methods.sort();
        methods
    }

    pub fn clear(&mut self) {
        self.handlers.clear();
    }

    pub fn global() -> &'static Mutex<MethodRegistry> {
        static GLOBAL: OnceLock<Mutex<MethodRegistry>> = OnceLock::new();
        GLOBAL.get_or_init(|| Mutex::new(MethodRegistry::new()))
    }

    pub fn get_global() -> &'static Mutex<MethodRegistry> {
        Self::global()
    }

    pub fn resolve_to_document(&self, did_uri: &str) -> DidResult<String> {
        self.resolve_to_document_with_options(did_uri, &ResolveOptions::default())
    }

    pub fn resolve_to_document_with_options(
        &self,
        did_uri: &str,
        options: &ResolveOptions,
    ) -> DidResult<String> {
        let parsed = parse(did_uri)?;
        if !options.is_method_allowed(&parsed.method) {
            return Err(error::method_not_allowed(&parsed.method));
        }
        let handler = self
            .handlers
            .get(&parsed.method)
            .ok_or_else(|| error::method_not_registered(&parsed.method))?;
        let document = handler(did_uri, options)?;
        if document.len() > options.max_document_size {
            return Err(error::document_too_large(format!(
                "document exceeds max size of {}",
                options.max_document_size
            )));
        }
        Ok(document)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolutionMetadata {
    pub error: String,
    pub content_type: String,
    pub duration: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DocumentMetadata {
    pub created: String,
    pub updated: String,
    pub deactivated: bool,
    pub next_update: String,
    pub version_id: String,
    pub next_version_id: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Resolution {
    pub did: Did,
    pub document: DidDocument,
    pub source_url: String,
    pub raw_document_json: String,
    pub resolution_metadata: ResolutionMetadata,
    pub document_metadata: DocumentMetadata,
}
