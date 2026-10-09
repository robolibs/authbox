//! PyO3 bindings for authbox.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn err_value(error: impl ToString) -> PyErr {
    PyValueError::new_err(error.to_string())
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
fn did_is_uri(did_uri: &str) -> bool {
    crate::did::is_did_uri(did_uri)
}

#[pyfunction]
fn did_web_document_url(did_uri: &str) -> PyResult<String> {
    crate::did::did_web_document_url(did_uri).map_err(err_value)
}

#[pyfunction]
fn did_key_encode_ed25519(public_key: &[u8]) -> PyResult<String> {
    if public_key.len() != 32 {
        return Err(PyValueError::new_err("Ed25519 public key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(public_key);
    crate::did::encode_ed25519_did_key(key).map_err(err_value)
}

#[pyfunction]
fn did_key_resolve_document_json(did_uri: &str) -> PyResult<String> {
    crate::did::resolve_did_key_document_json(did_uri).map_err(err_value)
}

#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &crate::pki::sha256(data))
}

#[pyfunction]
fn keccak256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &crate::pki::keccak256(data))
}

pub fn register_python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(did_is_uri, m)?)?;
    m.add_function(wrap_pyfunction!(did_web_document_url, m)?)?;
    m.add_function(wrap_pyfunction!(did_key_encode_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(did_key_resolve_document_json, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(keccak256, m)?)?;
    Ok(())
}

#[pymodule]
fn authbox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_python_module(m)
}
