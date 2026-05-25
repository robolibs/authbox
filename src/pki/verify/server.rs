use super::{
    BatchVerifyRequest, BatchVerifyResponse, HealthCheckResponse, ServingStatus, VerifyRequest,
    VerifyResponse, VerifyStatus, deserialize, response_signature_message, serialize,
};
use crate::pki::{Certificate, PkiError, PkiResult, sign_ed25519_detached};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod methods {
    pub const CHECK_CERTIFICATE: u32 = 1;
    pub const CHECK_BATCH: u32 = 2;
    pub const HEALTH_CHECK: u32 = 3;
}

pub trait VerificationHandler {
    fn verify_chain(&self, chain: &[Certificate], validation_timestamp: u64) -> VerifyResponse;

    fn verify_batch(&self, chains: &[Vec<Certificate>]) -> Vec<VerifyResponse> {
        chains
            .iter()
            .map(|chain| self.verify_chain(chain, unix_timestamp_now()))
            .collect()
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationInfo {
    pub reason: String,
    pub revocation_time: u64,
    pub this_update: u64,
    pub next_update: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SimpleRevocationHandler {
    revoked: BTreeMap<Vec<u8>, RevocationInfo>,
}

impl SimpleRevocationHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_revoked_certificate(&mut self, serial_number: impl Into<Vec<u8>>) {
        self.add_revoked_certificate_at(serial_number, "unspecified", unix_timestamp_now());
    }

    pub fn add_revoked_certificate_default(&mut self, serial_number: impl Into<Vec<u8>>) {
        self.add_revoked_certificate(serial_number);
    }

    pub fn add_revoked_certificate_with_reason(
        &mut self,
        serial_number: impl Into<Vec<u8>>,
        reason: impl Into<String>,
    ) {
        self.add_revoked_certificate_at(serial_number, reason, unix_timestamp_now());
    }

    pub fn add_revoked_certificate_now(
        &mut self,
        serial_number: impl Into<Vec<u8>>,
        reason: impl Into<String>,
    ) {
        self.add_revoked_certificate_with_reason(serial_number, reason);
    }

    pub fn add_revoked_certificate_at(
        &mut self,
        serial_number: impl Into<Vec<u8>>,
        reason: impl Into<String>,
        revocation_time: u64,
    ) {
        let this_update = unix_timestamp_now();
        self.revoked.insert(
            serial_number.into(),
            RevocationInfo {
                reason: reason.into(),
                revocation_time,
                this_update,
                next_update: this_update + 86_400,
            },
        );
    }

    pub fn remove_revoked_certificate(&mut self, serial_number: &[u8]) {
        self.revoked.remove(serial_number);
    }

    pub fn is_revoked(&self, serial_number: &[u8]) -> bool {
        self.revoked.contains_key(serial_number)
    }

    pub fn clear(&mut self) {
        self.revoked.clear();
    }
}

impl VerificationHandler for SimpleRevocationHandler {
    fn verify_chain(&self, chain: &[Certificate], _validation_timestamp: u64) -> VerifyResponse {
        if chain.is_empty() {
            return VerifyResponse {
                status: VerifyStatus::Unknown,
                reason: "Empty certificate chain".to_string(),
                ..VerifyResponse::default()
            };
        }
        let serial = &chain[0].tbs.serial_number;
        if let Some(info) = self.revoked.get(serial) {
            VerifyResponse {
                status: VerifyStatus::Revoked,
                reason: info.reason.clone(),
                revocation_time: info.revocation_time,
                this_update: info.this_update,
                next_update: info.next_update,
                ..VerifyResponse::default()
            }
        } else {
            let this_update = unix_timestamp_now();
            VerifyResponse {
                status: VerifyStatus::Good,
                reason: "Certificate is valid".to_string(),
                this_update,
                next_update: this_update + 86_400,
                ..VerifyResponse::default()
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessorStats {
    pub total_requests: u64,
    pub total_batch_requests: u64,
    pub total_health_checks: u64,
    pub good_responses: u64,
    pub revoked_responses: u64,
    pub unknown_responses: u64,
    pub start_time: u64,
}

pub struct RequestProcessor<H: VerificationHandler> {
    handler: H,
    signing_key: Vec<u8>,
    responder_cert_der: Vec<u8>,
    stats: ProcessorStats,
}

impl<H: VerificationHandler> RequestProcessor<H> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            signing_key: Vec::new(),
            responder_cert_der: Vec::new(),
            stats: ProcessorStats {
                start_time: unix_timestamp_now(),
                ..ProcessorStats::default()
            },
        }
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn set_responder_certificate(&mut self, cert: &Certificate) {
        self.responder_cert_der = cert.der().to_vec();
    }

    pub fn set_signing_key(&mut self, ed25519_private_key: impl Into<Vec<u8>>) -> PkiResult<()> {
        let key = ed25519_private_key.into();
        if key.len() != 64 {
            return Err(PkiError::new("Invalid Ed25519 private key size"));
        }
        self.signing_key = key;
        Ok(())
    }

    pub fn stats(&self) -> &ProcessorStats {
        &self.stats
    }

    pub fn get_stats(&self) -> ProcessorStats {
        self.stats.clone()
    }

    pub fn process(&mut self, method_id: u32, request_data: &[u8]) -> PkiResult<Vec<u8>> {
        match method_id {
            methods::CHECK_CERTIFICATE => self.handle_verify_request(request_data),
            methods::CHECK_BATCH => self.handle_batch_request(request_data),
            methods::HEALTH_CHECK => self.handle_health_check(request_data),
            _ => Ok(Vec::new()),
        }
    }

    fn handle_verify_request(&mut self, request_data: &[u8]) -> PkiResult<Vec<u8>> {
        let request: VerifyRequest = match deserialize(request_data) {
            Ok(request) => request,
            Err(_) => {
                return Ok(serialize(&VerifyResponse {
                    status: VerifyStatus::Unknown,
                    reason: "Failed to deserialize request".to_string(),
                    ..VerifyResponse::default()
                }));
            }
        };
        let chain = match parse_chain(&request) {
            Ok(chain) => chain,
            Err(error) => {
                return Ok(serialize(&VerifyResponse {
                    status: VerifyStatus::Unknown,
                    reason: format!("Failed to parse certificate: {}", error.message),
                    nonce: request.nonce,
                    ..VerifyResponse::default()
                }));
            }
        };
        let mut response = self
            .handler
            .verify_chain(&chain, request.validation_timestamp);
        response.nonce = request.nonce;
        if request
            .flags
            .contains(super::RequestFlags::IncludeResponderCert)
        {
            response.responder_cert_der = self.responder_cert_der.clone();
        }
        self.sign_response(&mut response)?;
        self.stats.total_requests += 1;
        self.record_status(response.status);
        Ok(serialize(&response))
    }

    fn handle_batch_request(&mut self, request_data: &[u8]) -> PkiResult<Vec<u8>> {
        let request: BatchVerifyRequest = match deserialize(request_data) {
            Ok(request) => request,
            Err(_) => {
                return Ok(serialize(&BatchVerifyResponse::default()));
            }
        };
        let chains: Vec<Vec<Certificate>> =
            request.requests.iter().map(parse_chain_lossy).collect();
        let mut responses = self.handler.verify_batch(&chains);
        for (response, req) in responses.iter_mut().zip(request.requests.iter()) {
            response.nonce = req.nonce.clone();
            self.sign_response(response)?;
            self.record_status(response.status);
        }
        self.stats.total_batch_requests += 1;
        Ok(serialize(&BatchVerifyResponse { responses }))
    }

    fn handle_health_check(&mut self, request_data: &[u8]) -> PkiResult<Vec<u8>> {
        let _ = request_data;
        self.stats.total_health_checks += 1;
        let status = if self.handler.is_healthy() {
            ServingStatus::Serving
        } else {
            ServingStatus::NotServing
        };
        Ok(serialize(&HealthCheckResponse { status }))
    }

    fn record_status(&mut self, status: VerifyStatus) {
        match status {
            VerifyStatus::Good => self.stats.good_responses += 1,
            VerifyStatus::Revoked => self.stats.revoked_responses += 1,
            VerifyStatus::Unknown => self.stats.unknown_responses += 1,
        }
    }

    fn sign_response(&self, response: &mut VerifyResponse) -> PkiResult<()> {
        if self.signing_key.is_empty() {
            return Ok(());
        }
        response.signature =
            sign_ed25519_detached(&response_signature_message(response), &self.signing_key)?;
        Ok(())
    }
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn parse_chain(request: &VerifyRequest) -> PkiResult<Vec<Certificate>> {
    request
        .certificate_chain
        .iter()
        .map(|cert| Certificate::parse_der_with_relaxed(&cert.der_bytes, true))
        .collect()
}

fn parse_chain_lossy(request: &VerifyRequest) -> Vec<Certificate> {
    request
        .certificate_chain
        .iter()
        .filter_map(|cert| Certificate::parse_der_with_relaxed(&cert.der_bytes, true).ok())
        .collect()
}
