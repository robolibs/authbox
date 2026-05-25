use super::{DidResult, detail, error};
use crate::json::{Json, json_array, json_string, parse_string_array_from_obj};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JsonWebKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerificationMethod {
    pub id: String,
    pub type_: String,
    pub controller: String,
    pub public_key_jwk: Option<JsonWebKey>,
    pub blockchain_account_id: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Service {
    pub id: String,
    pub type_: String,
    pub service_endpoint_json: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DidDocument {
    pub id: String,
    pub contexts: Vec<String>,
    pub verification_methods: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
    pub services: Vec<Service>,
}

pub fn parse_document(json_text: &str) -> DidResult<DidDocument> {
    let root =
        crate::json::parse(json_text).map_err(|_| error::invalid_document_json("parse failed"))?;
    let Json::Object(root_obj) = &root else {
        return Err(error::invalid_document_json("root must be an object"));
    };
    let id = json_string(&root, "id").ok_or_else(|| error::missing_field("id"))?;
    let mut out = DidDocument {
        id,
        ..DidDocument::default()
    };
    if let Some(ctx) = root_obj.get("@context") {
        match ctx {
            Json::String(text) => out.contexts.push(text.clone()),
            Json::Array(items) => {
                out.contexts
                    .extend(items.iter().filter_map(|item| match item {
                        Json::String(text) => Some(text.clone()),
                        _ => None,
                    }));
            }
            _ => {}
        }
    }
    let vm_value = root_obj.get("verificationMethod").ok_or_else(|| {
        error::invalid_document_json("verificationMethod must be a non-empty array")
    })?;
    let Json::Array(vm_array) = vm_value else {
        return Err(error::invalid_document_json(
            "verificationMethod must be a non-empty array",
        ));
    };
    if vm_array.is_empty() {
        return Err(error::invalid_document_json(
            "verificationMethod must be a non-empty array",
        ));
    }
    for item in vm_array {
        let Json::Object(vm_obj) = item else {
            return Err(error::invalid_verification_method(
                "entries must be objects",
            ));
        };
        let id = match vm_obj.get("id") {
            Some(Json::String(text)) => text.clone(),
            _ => {
                return Err(error::invalid_verification_method(
                    "missing required fields",
                ));
            }
        };
        let type_ = match vm_obj.get("type") {
            Some(Json::String(text)) => text.clone(),
            _ => {
                return Err(error::invalid_verification_method(
                    "missing required fields",
                ));
            }
        };
        let controller = match vm_obj.get("controller") {
            Some(Json::String(text)) => text.clone(),
            _ => {
                return Err(error::invalid_verification_method(
                    "missing required fields",
                ));
            }
        };
        let public_key_jwk = match vm_obj.get("publicKeyJwk") {
            Some(jwk @ Json::Object(_)) => Some(detail::parse_jwk(jwk)?),
            _ => None,
        };
        let blockchain_account_id = match vm_obj.get("blockchainAccountId") {
            Some(Json::String(text)) => Some(text.clone()),
            _ => None,
        };
        if public_key_jwk.is_none() && blockchain_account_id.is_none() {
            return Err(error::invalid_verification_method(
                "either publicKeyJwk or blockchainAccountId is required",
            ));
        }
        out.verification_methods.push(VerificationMethod {
            id,
            type_,
            controller,
            public_key_jwk,
            blockchain_account_id,
        });
    }
    out.authentication = parse_string_array_from_obj(&root, "authentication");
    out.assertion_method = parse_string_array_from_obj(&root, "assertionMethod");
    out.key_agreement = parse_string_array_from_obj(&root, "keyAgreement");
    out.capability_invocation = parse_string_array_from_obj(&root, "capabilityInvocation");
    out.capability_delegation = parse_string_array_from_obj(&root, "capabilityDelegation");
    for service in json_array(&root, "service") {
        let Json::Object(service_obj) = service else {
            continue;
        };
        let Some(Json::String(id)) = service_obj.get("id") else {
            continue;
        };
        let Some(Json::String(type_)) = service_obj.get("type") else {
            continue;
        };
        let endpoint = service_obj
            .get("serviceEndpoint")
            .map(|value| detail::json_value_to_string(Some(value)))
            .unwrap_or_else(|| "null".to_string());
        out.services.push(Service {
            id: id.clone(),
            type_: type_.clone(),
            service_endpoint_json: endpoint,
        });
    }
    Ok(out)
}
