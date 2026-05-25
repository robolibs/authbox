use super::{
    Did, DidDocument, DidResult, ResolveOptions, Resolver, Service, VerificationMethod, error,
    parse_url,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DereferencedResource {
    VerificationMethod(VerificationMethod),
    Service(Service),
    Document(DidDocument),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DereferenceResult {
    pub resource: DereferencedResource,
    pub content_type: String,
    pub did: Did,
}

#[derive(Clone, Debug, Default)]
pub struct DereferenceOptions {
    pub resolve_options: ResolveOptions,
}

pub fn dereference(did_url: &str, resolver: &Resolver) -> DidResult<DereferenceResult> {
    dereference_with_options(did_url, resolver, &DereferenceOptions::default())
}

pub fn dereference_with_options(
    did_url: &str,
    resolver: &Resolver,
    options: &DereferenceOptions,
) -> DidResult<DereferenceResult> {
    let url = parse_url(did_url)?;
    let resolution = resolver.resolve_with_options(&url.did.uri, &options.resolve_options)?;
    if url.fragment.is_empty() {
        return Ok(DereferenceResult {
            resource: DereferencedResource::Document(resolution.document),
            content_type: "application/did+ld+json".to_string(),
            did: url.did,
        });
    }
    for vm in &resolution.document.verification_methods {
        if resource_id_matches(&vm.id, &url.did.uri, &url.fragment) {
            return Ok(DereferenceResult {
                resource: DereferencedResource::VerificationMethod(vm.clone()),
                content_type: "application/did+json".to_string(),
                did: url.did,
            });
        }
    }
    for service in &resolution.document.services {
        if resource_id_matches(&service.id, &url.did.uri, &url.fragment) {
            return Ok(DereferenceResult {
                resource: DereferencedResource::Service(service.clone()),
                content_type: "application/did+json".to_string(),
                did: url.did,
            });
        }
    }
    Err(error::fragment_not_found(url.fragment))
}

fn resource_id_matches(id: &str, did_uri: &str, fragment: &str) -> bool {
    id == fragment || id == format!("{did_uri}#{fragment}") || id.ends_with(&format!("#{fragment}"))
}

pub fn is_verification_method(result: &DereferenceResult) -> bool {
    matches!(result.resource, DereferencedResource::VerificationMethod(_))
}

pub fn is_service(result: &DereferenceResult) -> bool {
    matches!(result.resource, DereferencedResource::Service(_))
}

pub fn is_document(result: &DereferenceResult) -> bool {
    matches!(result.resource, DereferencedResource::Document(_))
}

pub fn get_verification_method(result: &DereferenceResult) -> Option<&VerificationMethod> {
    match &result.resource {
        DereferencedResource::VerificationMethod(method) => Some(method),
        _ => None,
    }
}

pub fn get_service(result: &DereferenceResult) -> Option<&Service> {
    match &result.resource {
        DereferencedResource::Service(service) => Some(service),
        _ => None,
    }
}

pub fn get_document(result: &DereferenceResult) -> Option<&DidDocument> {
    match &result.resource {
        DereferencedResource::Document(document) => Some(document),
        _ => None,
    }
}
