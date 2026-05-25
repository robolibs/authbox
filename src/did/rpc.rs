use super::{DidResult, Resolution, Resolver, error};
use crate::json::{Json, json_string, parse as parse_json};
use crate::pki::Certificate;

pub const METHOD_RESOLVE_DID: u32 = 0x4452_4401;
pub const METHOD_VERIFY_BINDING: u32 = 0x4456_4201;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolveRequest {
    pub did_uri: String,
    pub did_document_json: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolveResponse {
    pub success: bool,
    pub error: String,
    pub did_uri: String,
    pub source_url: String,
    pub did_document_json: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyBindingRequest {
    pub did_uri: String,
    pub did_document_json: String,
    pub certificate_pem: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyBindingResponse {
    pub success: bool,
    pub valid: bool,
    pub error: String,
}

pub mod detail {
    use super::{
        DidResult, Json, ResolveResponse, VerifyBindingResponse,
        decode_resolve_response as decode_resolve_response_impl, decode_verify_binding_response,
        encode_resolve_response as encode_resolve_response_impl, encode_verify_binding_response,
        error, json_bool,
    };

    pub fn message_from_string(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec()
    }

    pub fn string_from_message(message: &[u8]) -> String {
        String::from_utf8_lossy(message).into_owned()
    }

    pub fn find_field<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
        let Json::Object(fields) = value else {
            return None;
        };
        fields.get(key)
    }

    pub fn get_string_field(value: &Json, key: &str) -> String {
        match find_field(value, key) {
            Some(Json::String(text)) => text.clone(),
            _ => String::new(),
        }
    }

    pub fn get_bool_field(value: &Json, key: &str) -> bool {
        json_bool(value, key)
    }

    pub fn parse_json_object(payload: &[u8]) -> DidResult<Json> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| error::invalid_document_json("invalid json payload"))?;
        let value = crate::json::parse(text)
            .map_err(|_| error::invalid_document_json("invalid json payload"))?;
        if !matches!(value, Json::Object(_)) {
            return Err(error::invalid_document_json("json payload must be object"));
        }
        Ok(value)
    }

    pub fn json_escape(value: &str) -> String {
        crate::json::escape(value)
    }

    pub fn encode_resolve_response(response: &ResolveResponse) -> Vec<u8> {
        encode_resolve_response_impl(response)
    }

    pub fn decode_resolve_response(payload: &[u8]) -> DidResult<ResolveResponse> {
        decode_resolve_response_impl(payload)
    }

    pub fn encode_verify_response(response: &VerifyBindingResponse) -> Vec<u8> {
        encode_verify_binding_response(response)
    }

    pub fn decode_verify_response(payload: &[u8]) -> DidResult<VerifyBindingResponse> {
        decode_verify_binding_response(payload)
    }
}

#[derive(Clone)]
pub struct Service {
    resolver: Resolver,
}

impl Service {
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }

    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    pub fn dispatch(&self, method_id: u32, request: &[u8]) -> DidResult<Vec<u8>> {
        match method_id {
            METHOD_RESOLVE_DID => self.handle_resolve_payload(request),
            METHOD_VERIFY_BINDING => self.handle_verify_binding_payload(request),
            _ => Err(error::invalid_reference("unknown DID RPC method")),
        }
    }

    pub fn handle_resolve_payload(&self, payload: &[u8]) -> DidResult<Vec<u8>> {
        let request = decode_resolve_request(payload)?;
        Ok(encode_resolve_response(&handle_resolve_request(
            &self.resolver,
            &request,
        )?))
    }

    pub fn handle_verify_binding_payload(&self, payload: &[u8]) -> DidResult<Vec<u8>> {
        let request = decode_verify_binding_request(payload)?;
        Ok(encode_verify_binding_response(
            &handle_verify_binding_request(&request),
        ))
    }
}

pub fn handle_resolve_request(
    resolver: &Resolver,
    request: &ResolveRequest,
) -> DidResult<ResolveResponse> {
    let options = super::ResolveOptions::default();
    let resolution = if request.did_document_json.is_empty() {
        resolver.resolve_with_options(&request.did_uri, &options)
    } else {
        Resolver::resolve_from_document_with_options(
            &request.did_uri,
            &request.did_document_json,
            "inline",
            &options,
        )
    };
    let resolution = match resolution {
        Ok(resolution) => resolution,
        Err(err) => {
            return Ok(ResolveResponse {
                success: false,
                error: err.message,
                did_uri: String::new(),
                source_url: String::new(),
                did_document_json: String::new(),
            });
        }
    };
    Ok(ResolveResponse {
        success: true,
        error: String::new(),
        did_uri: resolution.did.uri,
        source_url: resolution.source_url,
        did_document_json: resolution.raw_document_json,
    })
}

pub fn handle_verify_binding_request(request: &VerifyBindingRequest) -> VerifyBindingResponse {
    let parsed_chain =
        match Certificate::parse_pem_chain_with_relaxed(&request.certificate_pem, true) {
            Ok(chain) if !chain.is_empty() => chain,
            Ok(_) => {
                return VerifyBindingResponse {
                    success: false,
                    valid: false,
                    error: "Failed to parse certificate PEM".to_string(),
                };
            }
            Err(err) => {
                return VerifyBindingResponse {
                    success: false,
                    valid: false,
                    error: err.message,
                };
            }
        };
    match super::x509::verify_certificate_binding_json(
        &request.did_document_json,
        &parsed_chain[0],
        &request.did_uri,
    ) {
        Ok(valid) => VerifyBindingResponse {
            success: true,
            valid,
            error: String::new(),
        },
        Err(err) => VerifyBindingResponse {
            success: false,
            valid: false,
            error: err.message,
        },
    }
}

pub trait Remote {
    fn call(&self, method_id: u32, request: &[u8], timeout_ms: u32) -> DidResult<Vec<u8>>;
}

pub struct Client<R> {
    remote: R,
}

impl<R> Client<R>
where
    R: Remote,
{
    pub fn new(remote: R) -> Self {
        Self { remote }
    }

    pub fn remote(&self) -> &R {
        &self.remote
    }

    pub fn resolve(&self, did_uri: &str) -> DidResult<Resolution> {
        self.resolve_with_document(did_uri, "")
    }

    pub fn resolve_with_document(
        &self,
        did_uri: &str,
        did_document_json: &str,
    ) -> DidResult<Resolution> {
        self.resolve_with_timeout(did_uri, did_document_json, 5000)
    }

    pub fn resolve_with_timeout(
        &self,
        did_uri: &str,
        did_document_json: &str,
        timeout_ms: u32,
    ) -> DidResult<Resolution> {
        let request = ResolveRequest {
            did_uri: did_uri.to_string(),
            did_document_json: did_document_json.to_string(),
        };
        let payload = encode_resolve_request(&request);
        let response_payload = self.remote.call(METHOD_RESOLVE_DID, &payload, timeout_ms)?;
        let response = decode_resolve_response(&response_payload)?;
        if !response.success {
            return Err(error::network_error(response.error));
        }
        Resolver::resolve_from_document_with_source_url(
            &response.did_uri,
            &response.did_document_json,
            &response.source_url,
        )
    }

    pub fn verify_binding(
        &self,
        did_uri: &str,
        did_document_json: &str,
        certificate_pem: &str,
    ) -> DidResult<bool> {
        self.verify_binding_with_timeout(did_uri, did_document_json, certificate_pem, 5000)
    }

    pub fn verify_binding_with_timeout(
        &self,
        did_uri: &str,
        did_document_json: &str,
        certificate_pem: &str,
        timeout_ms: u32,
    ) -> DidResult<bool> {
        let request = VerifyBindingRequest {
            did_uri: did_uri.to_string(),
            did_document_json: did_document_json.to_string(),
            certificate_pem: certificate_pem.to_string(),
        };
        let payload = encode_verify_binding_request(&request);
        let response_payload = self
            .remote
            .call(METHOD_VERIFY_BINDING, &payload, timeout_ms)?;
        let response = decode_verify_binding_response(&response_payload)?;
        if !response.success {
            return Err(error::network_error(response.error));
        }
        Ok(response.valid)
    }
}

pub struct LoopbackRemote {
    service: Service,
}

impl LoopbackRemote {
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &Service {
        &self.service
    }
}

impl Remote for LoopbackRemote {
    fn call(&self, method_id: u32, request: &[u8], _timeout_ms: u32) -> DidResult<Vec<u8>> {
        self.service.dispatch(method_id, request)
    }
}

pub fn encode_resolve_request(request: &ResolveRequest) -> Vec<u8> {
    format!(
        "{{\"did_uri\":\"{}\",\"did_document_json\":\"{}\"}}",
        crate::json::escape(&request.did_uri),
        crate::json::escape(&request.did_document_json)
    )
    .into_bytes()
}

pub fn decode_resolve_request(payload: &[u8]) -> DidResult<ResolveRequest> {
    let object = parse_payload_object(payload)?;
    Ok(ResolveRequest {
        did_uri: json_string(&object, "did_uri").unwrap_or_default(),
        did_document_json: json_string(&object, "did_document_json").unwrap_or_default(),
    })
}

pub fn encode_resolve_response(response: &ResolveResponse) -> Vec<u8> {
    format!(
        "{{\"success\":{},\"error\":\"{}\",\"did_uri\":\"{}\",\"source_url\":\"{}\",\"did_document_json\":\"{}\"}}",
        response.success,
        crate::json::escape(&response.error),
        crate::json::escape(&response.did_uri),
        crate::json::escape(&response.source_url),
        crate::json::escape(&response.did_document_json)
    )
    .into_bytes()
}

pub fn decode_resolve_response(payload: &[u8]) -> DidResult<ResolveResponse> {
    let object = parse_payload_object(payload)?;
    Ok(ResolveResponse {
        success: json_bool(&object, "success"),
        error: json_string(&object, "error").unwrap_or_default(),
        did_uri: json_string(&object, "did_uri").unwrap_or_default(),
        source_url: json_string(&object, "source_url").unwrap_or_default(),
        did_document_json: json_string(&object, "did_document_json").unwrap_or_default(),
    })
}

pub fn encode_verify_binding_request(request: &VerifyBindingRequest) -> Vec<u8> {
    format!(
        "{{\"did_uri\":\"{}\",\"did_document_json\":\"{}\",\"certificate_pem\":\"{}\"}}",
        crate::json::escape(&request.did_uri),
        crate::json::escape(&request.did_document_json),
        crate::json::escape(&request.certificate_pem)
    )
    .into_bytes()
}

pub fn decode_verify_binding_request(payload: &[u8]) -> DidResult<VerifyBindingRequest> {
    let object = parse_payload_object(payload)?;
    Ok(VerifyBindingRequest {
        did_uri: json_string(&object, "did_uri").unwrap_or_default(),
        did_document_json: json_string(&object, "did_document_json").unwrap_or_default(),
        certificate_pem: json_string(&object, "certificate_pem").unwrap_or_default(),
    })
}

pub fn encode_verify_binding_response(response: &VerifyBindingResponse) -> Vec<u8> {
    format!(
        "{{\"success\":{},\"valid\":{},\"error\":\"{}\"}}",
        response.success,
        response.valid,
        crate::json::escape(&response.error)
    )
    .into_bytes()
}

pub fn decode_verify_binding_response(payload: &[u8]) -> DidResult<VerifyBindingResponse> {
    let object = parse_payload_object(payload)?;
    Ok(VerifyBindingResponse {
        success: json_bool(&object, "success"),
        valid: json_bool(&object, "valid"),
        error: json_string(&object, "error").unwrap_or_default(),
    })
}

fn parse_payload_object(payload: &[u8]) -> DidResult<Json> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| error::invalid_document_json("RPC payload is not UTF-8"))?;
    let value = parse_json(text).map_err(|err| error::invalid_document_json(err.message))?;
    if !matches!(value, Json::Object(_)) {
        return Err(error::invalid_document_json("RPC payload must be object"));
    }
    Ok(value)
}

fn json_bool(value: &Json, key: &str) -> bool {
    match value {
        Json::Object(obj) => matches!(obj.get(key), Some(Json::Bool(true))),
        _ => false,
    }
}
