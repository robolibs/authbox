use super::{
    BatchVerifyRequest, BatchVerifyResponse, CertificateData, HealthCheckRequest,
    HealthCheckResponse, ServingStatus, Transport, VerifyRequest, VerifyResponse, VerifyStatus,
    deserialize, methods, response_signature_message, serialize, wire_format::generated_nonce,
};
use crate::pki::{Certificate, PkiError, PkiResult, verify_ed25519_signature};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConfig {
    pub timeout_seconds: u64,
    pub max_retry_attempts: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 5,
            max_retry_attempts: 3,
        }
    }
}

impl ClientConfig {
    pub fn new(timeout_seconds: u64, max_retry_attempts: u32) -> Self {
        Self {
            timeout_seconds,
            max_retry_attempts,
        }
    }

    pub fn timeout(&self) -> u64 {
        self.timeout_seconds
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientResponse {
    pub valid: bool,
    pub reason: String,
    pub status: VerifyStatus,
    pub revocation_time: u64,
    pub this_update: u64,
    pub next_update: u64,
    pub signature: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub struct Client<T: Transport> {
    transport: T,
    config: ClientConfig,
    responder_cert: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientResult<T> {
    pub success: bool,
    pub value: T,
    pub error: String,
}

pub type Response = ClientResponse;
pub type OperationResult<T> = ClientResult<T>;

impl<T> ClientResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            success: true,
            value,
            error: String::new(),
        }
    }

    pub fn into_result(self) -> PkiResult<T> {
        if self.success {
            Ok(self.value)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

impl<T: Default> ClientResult<T> {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            value: T::default(),
            error: error.into(),
        }
    }
}

impl<T: Default> Default for ClientResult<T> {
    fn default() -> Self {
        Self {
            success: false,
            value: T::default(),
            error: String::new(),
        }
    }
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self::with_config(transport, ClientConfig::default())
    }

    pub fn with_config(transport: T, config: ClientConfig) -> Self {
        Self {
            transport,
            config,
            responder_cert: None,
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn is_ready(&self) -> bool {
        self.transport.is_ready()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn set_responder_cert(&mut self, cert: Certificate) {
        self.responder_cert = Some(cert);
    }

    pub fn clear_responder_cert(&mut self) {
        self.responder_cert = None;
    }

    pub fn verify_chain(&mut self, chain: &[Certificate]) -> PkiResult<ClientResponse> {
        self.verify_chain_at(chain, current_unix_timestamp())
    }

    pub fn verify_chain_at(
        &mut self,
        chain: &[Certificate],
        validation_timestamp: u64,
    ) -> PkiResult<ClientResponse> {
        if chain.is_empty() {
            return Err(PkiError::new("Certificate chain is empty"));
        }
        if !self.is_ready() {
            return Err(PkiError::new("Transport is not ready"));
        }
        let request = VerifyRequest {
            certificate_chain: chain
                .iter()
                .map(|cert| CertificateData {
                    der_bytes: cert.der().to_vec(),
                })
                .collect(),
            validation_timestamp,
            nonce: self.next_nonce(),
            ..VerifyRequest::default()
        };
        let request_data = serialize(&request);
        let response_data = match self
            .transport
            .call(methods::CHECK_CERTIFICATE, &request_data)
        {
            Ok(response_data) => response_data,
            Err(error) => {
                let detail = transport_error_detail(self.transport.last_error(), &error.message);
                return Err(PkiError::new(format!("Transport call failed: {detail}")));
            }
        };
        if response_data.is_empty() {
            return Err(PkiError::new(format!(
                "Transport call failed: {}",
                self.transport.last_error()
            )));
        }
        let response: VerifyResponse = deserialize(&response_data)
            .map_err(|_| PkiError::new("Failed to deserialize response"))?;
        if response.nonce != request.nonce {
            return Err(PkiError::new("Nonce mismatch - possible replay attack"));
        }
        if self.responder_cert.is_some() && !self.verify_response_signature(&response)? {
            return Err(PkiError::new("Response signature verification failed"));
        }
        Ok(ClientResponse::from(response))
    }

    pub fn verify_chain_result(&mut self, chain: &[Certificate]) -> ClientResult<ClientResponse> {
        match self.verify_chain(chain) {
            Ok(response) => ClientResult::ok(response),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    pub fn verify_chain_result_at(
        &mut self,
        chain: &[Certificate],
        validation_timestamp: u64,
    ) -> ClientResult<ClientResponse> {
        match self.verify_chain_at(chain, validation_timestamp) {
            Ok(response) => ClientResult::ok(response),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    pub fn verify_chain_now(&mut self, chain: &[Certificate]) -> PkiResult<ClientResponse> {
        self.verify_chain(chain)
    }

    pub fn verify_chain_now_result(
        &mut self,
        chain: &[Certificate],
    ) -> ClientResult<ClientResponse> {
        match self.verify_chain_now(chain) {
            Ok(response) => ClientResult::ok(response),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    pub fn verify_batch(&mut self, chains: &[Vec<Certificate>]) -> PkiResult<Vec<ClientResponse>> {
        if chains.is_empty() {
            return Err(PkiError::new("No chains provided"));
        }
        if !self.is_ready() {
            return Err(PkiError::new("Transport is not ready"));
        }
        let mut requests = Vec::new();
        for chain in chains.iter().filter(|chain| !chain.is_empty()) {
            requests.push(VerifyRequest {
                certificate_chain: chain
                    .iter()
                    .map(|cert| CertificateData {
                        der_bytes: cert.der().to_vec(),
                    })
                    .collect(),
                validation_timestamp: current_unix_timestamp(),
                nonce: self.next_nonce(),
                ..VerifyRequest::default()
            });
        }
        let request = BatchVerifyRequest { requests };
        let response_data = match self
            .transport
            .call(methods::CHECK_BATCH, &serialize(&request))
        {
            Ok(response_data) => response_data,
            Err(error) => {
                let detail = transport_error_detail(self.transport.last_error(), &error.message);
                return Err(PkiError::new(format!("Transport call failed: {detail}")));
            }
        };
        if response_data.is_empty() {
            return Err(PkiError::new(format!(
                "Transport call failed: {}",
                self.transport.last_error()
            )));
        }
        let response: BatchVerifyResponse = deserialize(&response_data)
            .map_err(|_| PkiError::new("Failed to deserialize batch response"))?;
        Ok(response
            .responses
            .into_iter()
            .map(ClientResponse::from)
            .collect())
    }

    pub fn verify_batch_result(
        &mut self,
        chains: &[Vec<Certificate>],
    ) -> ClientResult<Vec<ClientResponse>> {
        match self.verify_batch(chains) {
            Ok(responses) => ClientResult::ok(responses),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    pub fn health_check(&mut self) -> PkiResult<bool> {
        if !self.is_ready() {
            return Err(PkiError::new("Transport is not ready"));
        }
        let response_data = match self
            .transport
            .call(methods::HEALTH_CHECK, &serialize(&HealthCheckRequest))
        {
            Ok(response_data) => response_data,
            Err(error) => {
                let detail = transport_error_detail(self.transport.last_error(), &error.message);
                return Err(PkiError::new(format!("Health check failed: {detail}")));
            }
        };
        if response_data.is_empty() {
            return Err(PkiError::new(format!(
                "Health check failed: {}",
                self.transport.last_error()
            )));
        }
        let response: HealthCheckResponse = deserialize(&response_data)
            .map_err(|_| PkiError::new("Failed to deserialize health check response"))?;
        Ok(response.status == ServingStatus::Serving)
    }

    pub fn health_check_result(&mut self) -> ClientResult<bool> {
        match self.health_check() {
            Ok(healthy) => ClientResult::ok(healthy),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    fn next_nonce(&mut self) -> Vec<u8> {
        generated_nonce()
    }

    fn verify_response_signature(&self, response: &VerifyResponse) -> PkiResult<bool> {
        let Some(responder_cert) = &self.responder_cert else {
            return Ok(false);
        };
        if response.signature.len() != 64 {
            return Ok(false);
        }
        verify_ed25519_signature(
            &response_signature_message(response),
            &response.signature,
            &responder_cert.tbs.subject_public_key_info.public_key,
        )
    }
}

fn transport_error_detail(last_error: &str, fallback: &str) -> String {
    if last_error.is_empty() {
        fallback.to_string()
    } else {
        last_error.to_string()
    }
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl From<VerifyResponse> for ClientResponse {
    fn from(response: VerifyResponse) -> Self {
        Self {
            valid: response.status == VerifyStatus::Good,
            reason: response.reason,
            status: response.status,
            revocation_time: response.revocation_time,
            this_update: response.this_update,
            next_update: response.next_update,
            signature: response.signature,
            nonce: response.nonce,
        }
    }
}
