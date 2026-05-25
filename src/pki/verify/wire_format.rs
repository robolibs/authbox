use crate::pki::{PkiError, PkiResult};
use std::ops::{BitAnd, BitOr};

pub const VERSION: u8 = 0x01;
pub const MAGIC: [u8; 4] = *b"LKEY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    VerifyRequest = 0x01,
    VerifyResponse = 0x02,
    BatchRequest = 0x03,
    BatchResponse = 0x04,
    HealthCheck = 0x05,
    HealthResponse = 0x06,
}

impl MessageType {
    pub const VERIFY_REQUEST: Self = Self::VerifyRequest;
    pub const VERIFY_RESPONSE: Self = Self::VerifyResponse;
    pub const BATCH_REQUEST: Self = Self::BatchRequest;
    pub const BATCH_RESPONSE: Self = Self::BatchResponse;
    pub const HEALTH_CHECK: Self = Self::HealthCheck;
    pub const HEALTH_RESPONSE: Self = Self::HealthResponse;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum VerifyStatus {
    Good = 0x00,
    Revoked = 0x01,
    #[default]
    Unknown = 0x02,
}

impl VerifyStatus {
    pub const GOOD: Self = Self::Good;
    pub const REVOKED: Self = Self::Revoked;
    pub const UNKNOWN: Self = Self::Unknown;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestFlags(u8);

impl RequestFlags {
    #[allow(non_upper_case_globals)]
    pub const None: Self = Self(0x00);
    #[allow(non_upper_case_globals)]
    pub const IncludeResponderCert: Self = Self(0x01);
    pub const NONE: Self = Self::None;
    pub const INCLUDE_RESPONDER_CERT: Self = Self::IncludeResponderCert;

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub fn contains(self, flag: RequestFlags) -> bool {
        self.bits() & flag.bits() == flag.bits()
    }
}

impl BitOr for RequestFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.bits() | rhs.bits())
    }
}

impl BitAnd for RequestFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.bits() & rhs.bits())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateData {
    pub der_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyRequest {
    pub certificate_chain: Vec<CertificateData>,
    pub validation_timestamp: u64,
    pub flags: RequestFlags,
    pub nonce: Vec<u8>,
}

impl VerifyRequest {
    pub fn new(
        certificate_chain: Vec<CertificateData>,
        validation_timestamp: u64,
        flags: RequestFlags,
    ) -> Self {
        Self {
            certificate_chain,
            validation_timestamp,
            flags,
            nonce: vec![0; 32],
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyResponse {
    pub status: VerifyStatus,
    pub reason: String,
    pub revocation_time: u64,
    pub this_update: u64,
    pub next_update: u64,
    pub signature: Vec<u8>,
    pub nonce: Vec<u8>,
    pub responder_cert_der: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchVerifyRequest {
    pub requests: Vec<VerifyRequest>,
}

impl BatchVerifyRequest {
    pub fn new(requests: Vec<VerifyRequest>) -> Self {
        Self { requests }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchVerifyResponse {
    pub responses: Vec<VerifyResponse>,
}

impl BatchVerifyResponse {
    pub fn new(responses: Vec<VerifyResponse>) -> Self {
        Self { responses }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthCheckRequest;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum ServingStatus {
    #[default]
    Unknown = 0x00,
    Serving = 0x01,
    NotServing = 0x02,
}

impl ServingStatus {
    pub const UNKNOWN: Self = Self::Unknown;
    pub const SERVING: Self = Self::Serving;
    pub const NOT_SERVING: Self = Self::NotServing;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthCheckResponse {
    pub status: ServingStatus,
}

pub trait WireMessage: Sized {
    const TYPE: MessageType;
    fn encode_payload(&self, out: &mut Vec<u8>);
    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self>;
}

pub struct Serializer;

impl Serializer {
    pub fn serialize<T: WireMessage>(message: &T) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(MAGIC);
        Self::write_uint8(&mut out, VERSION);
        Self::write_uint8(&mut out, T::TYPE as u8);
        message.encode_payload(&mut out);
        out
    }

    pub fn deserialize<T: WireMessage>(input: &[u8]) -> PkiResult<T> {
        let mut pos = Self::validate_header(input, T::TYPE)?;
        T::decode_payload(input, &mut pos)
    }

    pub fn deserialize_into<T: WireMessage>(input: &[u8], out: &mut T) -> bool {
        match Self::deserialize(input) {
            Ok(value) => {
                *out = value;
                true
            }
            Err(_) => false,
        }
    }

    pub fn serialize_verify_request(request: &VerifyRequest) -> Vec<u8> {
        Self::serialize(request)
    }

    pub fn serialize_verify_response(response: &VerifyResponse) -> Vec<u8> {
        Self::serialize(response)
    }

    pub fn serialize_batch_verify_request(request: &BatchVerifyRequest) -> Vec<u8> {
        Self::serialize(request)
    }

    pub fn serialize_batch_verify_response(response: &BatchVerifyResponse) -> Vec<u8> {
        Self::serialize(response)
    }

    pub fn serialize_health_check_request(request: &HealthCheckRequest) -> Vec<u8> {
        Self::serialize(request)
    }

    pub fn serialize_health_check_response(response: &HealthCheckResponse) -> Vec<u8> {
        Self::serialize(response)
    }

    pub fn deserialize_verify_request(input: &[u8], out: &mut VerifyRequest) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn deserialize_verify_response(input: &[u8], out: &mut VerifyResponse) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn deserialize_batch_verify_request(input: &[u8], out: &mut BatchVerifyRequest) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn deserialize_batch_verify_response(input: &[u8], out: &mut BatchVerifyResponse) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn deserialize_health_check_request(input: &[u8], out: &mut HealthCheckRequest) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn deserialize_health_check_response(input: &[u8], out: &mut HealthCheckResponse) -> bool {
        Self::deserialize_into(input, out)
    }

    pub fn write_uint8(out: &mut Vec<u8>, value: u8) {
        out.push(value);
    }

    pub fn write_uint16(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_be_bytes());
    }

    pub fn write_uint32(out: &mut Vec<u8>, value: u32) {
        out.extend(value.to_be_bytes());
    }

    pub fn write_uint64(out: &mut Vec<u8>, value: u64) {
        out.extend(value.to_be_bytes());
    }

    pub fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend(bytes);
    }

    pub fn write_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        Self::write_uint32(out, bytes.len() as u32);
        Self::write_bytes(out, bytes);
    }

    pub fn write_string(out: &mut Vec<u8>, value: &str) {
        Self::write_uint16(out, value.len() as u16);
        out.extend(value.as_bytes());
    }

    pub fn write_timestamp(out: &mut Vec<u8>, timestamp: u64) {
        Self::write_uint64(out, timestamp);
    }

    pub fn read_uint8(input: &[u8], pos: &mut usize) -> PkiResult<u8> {
        let Some(value) = input.get(*pos).copied() else {
            return Err(PkiError::new("short wire u8"));
        };
        *pos += 1;
        Ok(value)
    }

    pub fn read_uint16(input: &[u8], pos: &mut usize) -> PkiResult<u16> {
        let bytes = read_exact::<2>(input, pos, "short wire u16")?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_uint32(input: &[u8], pos: &mut usize) -> PkiResult<u32> {
        let bytes = read_exact::<4>(input, pos, "short wire u32")?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_uint64(input: &[u8], pos: &mut usize) -> PkiResult<u64> {
        let bytes = read_exact::<8>(input, pos, "short wire u64")?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_bytes(input: &[u8], pos: &mut usize, length: usize) -> PkiResult<Vec<u8>> {
        if *pos + length > input.len() {
            return Err(PkiError::new("short wire bytes"));
        }
        let out = input[*pos..*pos + length].to_vec();
        *pos += length;
        Ok(out)
    }

    pub fn read_len_prefixed_bytes(input: &[u8], pos: &mut usize) -> PkiResult<Vec<u8>> {
        let len = Self::read_uint32(input, pos)? as usize;
        Self::read_bytes(input, pos, len)
    }

    pub fn read_string(input: &[u8], pos: &mut usize, length: usize) -> PkiResult<String> {
        let bytes = Self::read_bytes(input, pos, length)?;
        std::str::from_utf8(&bytes)
            .map(str::to_string)
            .map_err(|_| PkiError::new("wire string is not UTF-8"))
    }

    pub fn read_len_prefixed_string(input: &[u8], pos: &mut usize) -> PkiResult<String> {
        let len = Self::read_uint16(input, pos)? as usize;
        Self::read_string(input, pos, len)
    }

    pub fn read_timestamp(input: &[u8], pos: &mut usize) -> PkiResult<u64> {
        Self::read_uint64(input, pos)
    }

    pub fn validate_header(input: &[u8], expected: MessageType) -> PkiResult<usize> {
        if input.len() < 6 || input[0..4] != MAGIC {
            return Err(PkiError::new("invalid wire magic"));
        }
        if input[4] != VERSION {
            return Err(PkiError::new("unsupported wire version"));
        }
        if input[5] != expected as u8 {
            return Err(PkiError::new("unexpected wire message type"));
        }
        Ok(6)
    }
}

pub fn serialize<T: WireMessage>(message: &T) -> Vec<u8> {
    Serializer::serialize(message)
}

pub fn deserialize<T: WireMessage>(input: &[u8]) -> PkiResult<T> {
    Serializer::deserialize(input)
}

pub fn response_signature_message(response: &VerifyResponse) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + response.reason.len() + 24 + response.nonce.len());
    message.push(response.status as u8);
    message.extend(response.reason.as_bytes());
    message.extend(response.revocation_time.to_be_bytes());
    message.extend(response.this_update.to_be_bytes());
    message.extend(response.next_update.to_be_bytes());
    message.extend(&response.nonce);
    message
}

fn write_u8(out: &mut Vec<u8>, value: u8) {
    Serializer::write_uint8(out, value);
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    Serializer::write_uint16(out, value);
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    Serializer::write_uint64(out, value);
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    Serializer::write_len_prefixed_bytes(out, bytes);
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u16(out, value.len() as u16);
    out.extend(value.as_bytes());
}

fn read_u8(input: &[u8], pos: &mut usize) -> PkiResult<u8> {
    Serializer::read_uint8(input, pos)
}

fn read_u16(input: &[u8], pos: &mut usize) -> PkiResult<u16> {
    Serializer::read_uint16(input, pos)
}

fn read_u64(input: &[u8], pos: &mut usize) -> PkiResult<u64> {
    Serializer::read_uint64(input, pos)
}

fn read_exact<const N: usize>(input: &[u8], pos: &mut usize, message: &str) -> PkiResult<[u8; N]> {
    if *pos + N > input.len() {
        return Err(PkiError::new(message));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&input[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

fn read_bytes(input: &[u8], pos: &mut usize) -> PkiResult<Vec<u8>> {
    Serializer::read_len_prefixed_bytes(input, pos)
}

fn read_string(input: &[u8], pos: &mut usize) -> PkiResult<String> {
    Serializer::read_len_prefixed_string(input, pos)
}

pub(crate) fn generated_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    fill_random_nonce(&mut nonce);
    nonce
}

fn fill_random_nonce(out: &mut [u8]) {
    let _ = crate::pki::random::fill_random(out);
}

impl WireMessage for VerifyRequest {
    const TYPE: MessageType = MessageType::VerifyRequest;

    fn encode_payload(&self, out: &mut Vec<u8>) {
        write_u16(out, self.certificate_chain.len() as u16);
        for cert in &self.certificate_chain {
            write_bytes(out, &cert.der_bytes);
        }
        write_u64(out, self.validation_timestamp);
        write_u8(out, self.flags.bits());
        let nonce = if self.nonce.is_empty() {
            generated_nonce()
        } else {
            self.nonce.clone()
        };
        write_bytes(out, &nonce);
    }

    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self> {
        let count = read_u16(input, pos)? as usize;
        let mut certificate_chain = Vec::with_capacity(count);
        for _ in 0..count {
            certificate_chain.push(CertificateData {
                der_bytes: read_bytes(input, pos)?,
            });
        }
        let validation_timestamp = read_u64(input, pos)?;
        let flags = RequestFlags::from_bits(read_u8(input, pos)?);
        let nonce = read_bytes(input, pos)?;
        if nonce.len() != 32 {
            return Err(PkiError::new("wire nonce must be 32 bytes"));
        }
        Ok(Self {
            certificate_chain,
            validation_timestamp,
            flags,
            nonce,
        })
    }
}

impl WireMessage for VerifyResponse {
    const TYPE: MessageType = MessageType::VerifyResponse;

    fn encode_payload(&self, out: &mut Vec<u8>) {
        write_u8(out, self.status as u8);
        write_string(out, &self.reason);
        write_u64(out, self.revocation_time);
        write_u64(out, self.this_update);
        write_u64(out, self.next_update);
        write_bytes(out, &self.signature);
        write_bytes(out, &self.nonce);
        write_bytes(out, &self.responder_cert_der);
    }

    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self> {
        let status = match read_u8(input, pos)? {
            0 => VerifyStatus::Good,
            1 => VerifyStatus::Revoked,
            _ => VerifyStatus::Unknown,
        };
        Ok(Self {
            status,
            reason: read_string(input, pos)?,
            revocation_time: read_u64(input, pos)?,
            this_update: read_u64(input, pos)?,
            next_update: read_u64(input, pos)?,
            signature: read_bytes(input, pos)?,
            nonce: read_bytes(input, pos)?,
            responder_cert_der: read_bytes(input, pos)?,
        })
    }
}

impl WireMessage for BatchVerifyRequest {
    const TYPE: MessageType = MessageType::BatchRequest;

    fn encode_payload(&self, out: &mut Vec<u8>) {
        write_u16(out, self.requests.len() as u16);
        for request in &self.requests {
            let encoded = serialize(request);
            out.extend(&encoded[6..]);
        }
    }

    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self> {
        let count = read_u16(input, pos)? as usize;
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            requests.push(VerifyRequest::decode_payload(input, pos)?);
        }
        Ok(Self { requests })
    }
}

impl WireMessage for BatchVerifyResponse {
    const TYPE: MessageType = MessageType::BatchResponse;

    fn encode_payload(&self, out: &mut Vec<u8>) {
        write_u16(out, self.responses.len() as u16);
        for response in &self.responses {
            let encoded = serialize(response);
            out.extend(&encoded[6..]);
        }
    }

    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self> {
        let count = read_u16(input, pos)? as usize;
        let mut responses = Vec::with_capacity(count);
        for _ in 0..count {
            responses.push(VerifyResponse::decode_payload(input, pos)?);
        }
        Ok(Self { responses })
    }
}

impl WireMessage for HealthCheckRequest {
    const TYPE: MessageType = MessageType::HealthCheck;

    fn encode_payload(&self, _out: &mut Vec<u8>) {}

    fn decode_payload(_input: &[u8], _pos: &mut usize) -> PkiResult<Self> {
        Ok(Self)
    }
}

impl WireMessage for HealthCheckResponse {
    const TYPE: MessageType = MessageType::HealthResponse;

    fn encode_payload(&self, out: &mut Vec<u8>) {
        write_u8(out, self.status as u8);
    }

    fn decode_payload(input: &[u8], pos: &mut usize) -> PkiResult<Self> {
        let status = match read_u8(input, pos)? {
            1 => ServingStatus::Serving,
            2 => ServingStatus::NotServing,
            _ => ServingStatus::Unknown,
        };
        Ok(Self { status })
    }
}
