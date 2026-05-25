use super::{
    Client, ClientResponse, ClientResult, RequestProcessor, SimpleRevocationHandler, Transport,
    VerificationHandler,
};
use crate::pki::{Certificate, PkiError, PkiResult};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub struct DirectTransport<H: VerificationHandler> {
    processor: Option<RequestProcessor<H>>,
    last_error: String,
}

impl<H: VerificationHandler> DirectTransport<H> {
    pub fn new(processor: RequestProcessor<H>) -> Self {
        Self {
            processor: Some(processor),
            last_error: String::new(),
        }
    }

    pub fn unconfigured() -> Self {
        Self {
            processor: None,
            last_error: String::new(),
        }
    }

    pub fn processor(&self) -> &RequestProcessor<H> {
        self.processor
            .as_ref()
            .expect("DirectTransport processor is not configured")
    }

    pub fn processor_mut(&mut self) -> &mut RequestProcessor<H> {
        self.processor
            .as_mut()
            .expect("DirectTransport processor is not configured")
    }

    pub fn set_processor(&mut self, processor: RequestProcessor<H>) {
        self.processor = Some(processor);
        self.last_error.clear();
    }

    pub fn clear_processor(&mut self) {
        self.processor = None;
    }
}

impl<H: VerificationHandler> Transport for DirectTransport<H> {
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>> {
        let Some(processor) = self.processor.as_mut() else {
            self.last_error = "No processor configured".to_string();
            return Ok(Vec::new());
        };
        match catch_unwind(AssertUnwindSafe(|| processor.process(method_id, request))) {
            Ok(Ok(response)) => {
                self.last_error.clear();
                Ok(response)
            }
            Ok(Err(err)) => {
                self.last_error = err.message;
                Ok(Vec::new())
            }
            Err(payload) => {
                self.last_error = panic_message(payload);
                Ok(Vec::new())
            }
        }
    }

    fn is_ready(&self) -> bool {
        self.processor.is_some()
    }

    fn last_error(&self) -> &str {
        &self.last_error
    }
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "Request processor panicked".to_string()
    }
}

pub struct Verifier<H: VerificationHandler = SimpleRevocationHandler> {
    transport: DirectTransport<H>,
    responder_cert: Option<Certificate>,
}

impl Default for Verifier<SimpleRevocationHandler> {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier<SimpleRevocationHandler> {
    pub fn new() -> Self {
        Self::with_handler(SimpleRevocationHandler::new())
    }
}

impl<H: VerificationHandler + Any> Verifier<H> {
    pub fn with_handler(handler: H) -> Self {
        Self {
            transport: DirectTransport::new(RequestProcessor::new(handler)),
            responder_cert: None,
        }
    }

    pub fn handler(&self) -> &H {
        self.transport.processor().handler()
    }

    pub fn handler_mut(&mut self) -> &mut H {
        self.transport.processor_mut().handler_mut()
    }

    pub fn as_revocation_handler(&mut self) -> Option<&mut SimpleRevocationHandler> {
        (self.handler_mut() as &mut dyn Any).downcast_mut::<SimpleRevocationHandler>()
    }

    pub fn client(&mut self) -> Client<&mut DirectTransport<H>> {
        let responder_cert = self.responder_cert.clone();
        let mut client = Client::new(&mut self.transport);
        if let Some(cert) = responder_cert {
            client.set_responder_cert(cert);
        }
        client
    }

    pub fn transport(&mut self) -> &mut DirectTransport<H> {
        &mut self.transport
    }

    pub fn set_signing_key(&mut self, ed25519_private_key: impl Into<Vec<u8>>) -> PkiResult<()> {
        self.transport
            .processor_mut()
            .set_signing_key(ed25519_private_key)
    }

    pub fn set_responder_certificate(&mut self, cert: Certificate) {
        self.transport
            .processor_mut()
            .set_responder_certificate(&cert);
        self.responder_cert = Some(cert);
    }

    pub fn verify_chain(&mut self, chain: &[Certificate]) -> PkiResult<ClientResponse> {
        self.client().verify_chain(chain)
    }

    pub fn verify_chain_at(
        &mut self,
        chain: &[Certificate],
        validation_timestamp: u64,
    ) -> PkiResult<ClientResponse> {
        self.client().verify_chain_at(chain, validation_timestamp)
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
        self.client().verify_chain_now(chain)
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
        self.client().verify_batch(chains)
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
        self.client().health_check()
    }

    pub fn health_check_result(&mut self) -> ClientResult<bool> {
        match self.health_check() {
            Ok(healthy) => ClientResult::ok(healthy),
            Err(error) => ClientResult::failure(error.message),
        }
    }

    pub fn into_transport(self) -> DirectTransport<H> {
        self.transport
    }
}

impl From<PkiError> for String {
    fn from(value: PkiError) -> Self {
        value.message
    }
}
