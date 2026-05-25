use crate::pki::{PkiError, PkiResult};
use std::sync::{Arc, Mutex, MutexGuard};

pub type RequestHandler = dyn FnMut(u32, &[u8]) -> Vec<u8>;

pub trait Transport {
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>>;
    fn is_ready(&self) -> bool;
    fn last_error(&self) -> &str;
}

impl<T: Transport + ?Sized> Transport for &mut T {
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>> {
        (**self).call(method_id, request)
    }

    fn is_ready(&self) -> bool {
        (**self).is_ready()
    }

    fn last_error(&self) -> &str {
        (**self).last_error()
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>> {
        (**self).call(method_id, request)
    }

    fn is_ready(&self) -> bool {
        (**self).is_ready()
    }

    fn last_error(&self) -> &str {
        (**self).last_error()
    }
}

pub struct SharedTransport<T: Transport> {
    inner: Arc<Mutex<T>>,
    last_error: String,
}

impl<T: Transport> SharedTransport<T> {
    pub fn new(transport: T) -> Self {
        Self::from_arc(Arc::new(Mutex::new(transport)))
    }

    pub fn from_arc(inner: Arc<Mutex<T>>) -> Self {
        Self {
            inner,
            last_error: String::new(),
        }
    }

    pub fn inner(&self) -> Arc<Mutex<T>> {
        Arc::clone(&self.inner)
    }

    pub fn lock(&self) -> PkiResult<MutexGuard<'_, T>> {
        self.inner
            .lock()
            .map_err(|_| PkiError::new("Shared transport lock poisoned"))
    }

    pub fn into_inner(self) -> Arc<Mutex<T>> {
        self.inner
    }
}

impl<T: Transport> Clone for SharedTransport<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            last_error: self.last_error.clone(),
        }
    }
}

impl<T: Transport> Transport for SharedTransport<T> {
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>> {
        match self.inner.lock() {
            Ok(mut transport) => {
                let response = transport.call(method_id, request);
                self.last_error = transport.last_error().to_string();
                response
            }
            Err(_) => {
                self.last_error = "Shared transport lock poisoned".to_string();
                Err(PkiError::new(self.last_error.clone()))
            }
        }
    }

    fn is_ready(&self) -> bool {
        self.inner
            .lock()
            .map(|transport| transport.is_ready())
            .unwrap_or(false)
    }

    fn last_error(&self) -> &str {
        &self.last_error
    }
}

pub struct RequestHandlerTransport<F>
where
    F: FnMut(u32, &[u8]) -> Vec<u8>,
{
    handler: F,
    ready: bool,
    last_error: String,
}

impl<F> RequestHandlerTransport<F>
where
    F: FnMut(u32, &[u8]) -> Vec<u8>,
{
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            ready: true,
            last_error: String::new(),
        }
    }

    pub fn with_ready(handler: F, ready: bool) -> Self {
        Self {
            handler,
            ready,
            last_error: String::new(),
        }
    }

    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    pub fn handler_mut(&mut self) -> &mut F {
        &mut self.handler
    }
}

impl<F> Transport for RequestHandlerTransport<F>
where
    F: FnMut(u32, &[u8]) -> Vec<u8>,
{
    fn call(&mut self, method_id: u32, request: &[u8]) -> PkiResult<Vec<u8>> {
        if !self.ready {
            self.last_error = "Request handler transport is not ready".to_string();
            return Err(PkiError::new(self.last_error.clone()));
        }
        self.last_error.clear();
        Ok((self.handler)(method_id, request))
    }

    fn is_ready(&self) -> bool {
        self.ready
    }

    fn last_error(&self) -> &str {
        &self.last_error
    }
}
