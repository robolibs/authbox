use crypto_secretbox::{
    Nonce as XSalsa20Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use super::{PkiError, PkiResult, read_binary_bytes};

pub const MAGIC: u32 = 0x4c4b_5847;
pub const VERSION: u8 = 1;
pub const DIGEST_SIZE: usize = 32;
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const X25519_SECRET_KEY_BYTES: usize = 32;
pub const SEALED_BOX_OVERHEAD_BYTES: usize = 48;

/// Compatibility namespace mirroring the C++ `authbox::pki::key_exchange::detail`.
pub mod detail {
    pub use super::{DIGEST_SIZE, Envelope, MAGIC, VERSION, append_u32, read_u32};
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CryptoResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub error: String,
}

impl CryptoResult {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            success: true,
            data,
            error: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Vec::new(),
            error: error.into(),
        }
    }

    pub fn into_result(self) -> PkiResult<Vec<u8>> {
        if self.success {
            Ok(self.data)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Envelope {
    pub associated_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(self.associated_data.len() + self.ciphertext.len());
        body.extend(&self.associated_data);
        body.extend(&self.ciphertext);
        let digest = blake2b_256(&body);

        let mut out = Vec::with_capacity(4 + 1 + 1 + 2 + 4 + 4 + DIGEST_SIZE + body.len());
        append_u32(&mut out, MAGIC);
        out.push(VERSION);
        out.push(0);
        out.push(0);
        out.push(0);
        append_u32(&mut out, self.associated_data.len() as u32);
        append_u32(&mut out, self.ciphertext.len() as u32);
        out.extend(digest);
        out.extend(body);
        out
    }

    pub fn deserialize(buffer: &[u8]) -> PkiResult<Self> {
        const HEADER_LEN: usize = 4 + 1 + 1 + 2 + 4 + 4 + DIGEST_SIZE;
        if buffer.len() < HEADER_LEN {
            return Err(PkiError::new("key exchange envelope too short"));
        }
        let magic = read_u32(&buffer[0..4]);
        if magic != MAGIC {
            return Err(PkiError::new("invalid key exchange envelope magic"));
        }
        if buffer[4] != VERSION {
            return Err(PkiError::new("unsupported key exchange envelope version"));
        }
        let aad_len = read_u32(&buffer[8..12]) as usize;
        let cipher_len = read_u32(&buffer[12..16]) as usize;
        let expected_len = HEADER_LEN
            .checked_add(aad_len)
            .and_then(|len| len.checked_add(cipher_len))
            .ok_or_else(|| PkiError::new("key exchange envelope length overflow"))?;
        if buffer.len() != expected_len {
            return Err(PkiError::new("invalid key exchange envelope length"));
        }
        let stored_digest = &buffer[16..16 + DIGEST_SIZE];
        let body = &buffer[HEADER_LEN..];
        let computed = blake2b_256(body);
        if stored_digest != computed {
            return Err(PkiError::new("key exchange envelope digest mismatch"));
        }
        Ok(Self {
            associated_data: body[..aad_len].to_vec(),
            ciphertext: body[aad_len..].to_vec(),
        })
    }
}

pub fn create_envelope(payload: &[u8], recipient_public_key: &[u8]) -> CryptoResult {
    create_envelope_with_associated_data(payload, recipient_public_key, &[])
}

pub fn create_envelope_with_associated_data(
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
) -> CryptoResult {
    if recipient_public_key.len() != X25519_PUBLIC_KEY_BYTES {
        return CryptoResult::failure("Recipient public key must be PUBLICKEYBYTES bytes");
    }
    let mut ephemeral_secret = [0u8; X25519_SECRET_KEY_BYTES];
    if let Err(err) = fill_random(&mut ephemeral_secret) {
        return CryptoResult::failure(err.message);
    }
    create_envelope_with_ephemeral_secret(
        payload,
        recipient_public_key,
        associated_data,
        &ephemeral_secret,
    )
}

pub fn create_sealed_box(payload: &[u8], recipient_public_key: &[u8]) -> CryptoResult {
    if recipient_public_key.len() != X25519_PUBLIC_KEY_BYTES {
        return CryptoResult::failure("Invalid public key size");
    }
    let mut ephemeral_secret = [0u8; X25519_SECRET_KEY_BYTES];
    if let Err(err) = fill_random(&mut ephemeral_secret) {
        return CryptoResult::failure(err.message);
    }
    let mut recipient_public = [0u8; X25519_PUBLIC_KEY_BYTES];
    recipient_public.copy_from_slice(recipient_public_key);
    match sealed_box_seal(payload, &recipient_public, &ephemeral_secret) {
        Ok(ciphertext) => CryptoResult::ok(ciphertext),
        Err(err) => CryptoResult::failure(err.message),
    }
}

pub fn open_sealed_box(ciphertext: &[u8], recipient_private_key: &[u8]) -> CryptoResult {
    if recipient_private_key.len() != X25519_PUBLIC_KEY_BYTES + X25519_SECRET_KEY_BYTES {
        return CryptoResult::failure("Invalid private key material");
    }
    if ciphertext.len() < SEALED_BOX_OVERHEAD_BYTES {
        return CryptoResult::failure("Ciphertext too short");
    }
    let recipient_public = &recipient_private_key[..X25519_PUBLIC_KEY_BYTES];
    let recipient_secret = &recipient_private_key[X25519_PUBLIC_KEY_BYTES..];
    match sealed_box_open(ciphertext, recipient_public, recipient_secret) {
        Ok(plaintext) => CryptoResult::ok(plaintext),
        Err(_) => CryptoResult::failure("Decryption failed"),
    }
}

pub fn consume_envelope(buffer: &[u8], recipient_private_key: &[u8]) -> CryptoResult {
    if buffer.is_empty() {
        return CryptoResult::failure("Invalid envelope buffer");
    }
    let env = match Envelope::deserialize(buffer) {
        Ok(env) => env,
        Err(_) => return CryptoResult::failure("Invalid key exchange envelope"),
    };
    if recipient_private_key.len() != X25519_PUBLIC_KEY_BYTES + X25519_SECRET_KEY_BYTES {
        return CryptoResult::failure(
            "Recipient private key must contain public and secret material",
        );
    }
    if env.ciphertext.len() < SEALED_BOX_OVERHEAD_BYTES {
        return CryptoResult::failure("Ciphertext too short");
    }
    let recipient_public = &recipient_private_key[..X25519_PUBLIC_KEY_BYTES];
    let recipient_secret = &recipient_private_key[X25519_PUBLIC_KEY_BYTES..];
    match sealed_box_open(&env.ciphertext, recipient_public, recipient_secret) {
        Ok(plaintext) => CryptoResult::ok(plaintext),
        Err(err) => CryptoResult::failure(err.message),
    }
}

pub fn consume_envelope_with_associated_data(
    buffer: &[u8],
    recipient_private_key: &[u8],
) -> (CryptoResult, Vec<u8>) {
    let mut associated_data = Vec::new();
    let result = consume_envelope_with_associated_data_out(
        buffer,
        recipient_private_key,
        Some(&mut associated_data),
    );
    (result, associated_data)
}

pub fn consume_envelope_with_associated_data_out(
    buffer: &[u8],
    recipient_private_key: &[u8],
    associated_data_out: Option<&mut Vec<u8>>,
) -> CryptoResult {
    let env = match Envelope::deserialize(buffer) {
        Ok(env) => env,
        Err(_) => return CryptoResult::failure("Invalid key exchange envelope"),
    };
    let result = consume_envelope(buffer, recipient_private_key);
    if result.success
        && let Some(out) = associated_data_out
    {
        *out = env.associated_data;
    }
    result
}

pub fn write_envelope_to_file(
    payload: &[u8],
    recipient_public_key: &[u8],
    path: impl AsRef<std::path::Path>,
) -> CryptoResult {
    write_envelope_to_file_with_associated_data(payload, recipient_public_key, path, &[])
}

pub fn write_envelope_to_file_with_associated_data(
    payload: &[u8],
    recipient_public_key: &[u8],
    path: impl AsRef<std::path::Path>,
    associated_data: &[u8],
) -> CryptoResult {
    let env = create_envelope_with_associated_data(payload, recipient_public_key, associated_data);
    if !env.success {
        return env;
    }
    match std::fs::write(path, &env.data) {
        Ok(()) => CryptoResult::ok(Vec::new()),
        Err(_) => CryptoResult::failure("Unable to open envelope file for writing"),
    }
}

pub fn read_envelope_from_file(
    path: impl AsRef<std::path::Path>,
    recipient_private_key: &[u8],
) -> CryptoResult {
    match read_binary_bytes(path) {
        Ok(buffer) if !buffer.is_empty() => consume_envelope(&buffer, recipient_private_key),
        Ok(_) => CryptoResult::failure("Envelope file empty"),
        Err(_) => CryptoResult::failure("Unable to open envelope file for reading"),
    }
}

pub fn read_envelope_from_file_with_associated_data(
    path: impl AsRef<std::path::Path>,
    recipient_private_key: &[u8],
) -> (CryptoResult, Vec<u8>) {
    match read_binary_bytes(path) {
        Ok(buffer) if !buffer.is_empty() => {
            consume_envelope_with_associated_data(&buffer, recipient_private_key)
        }
        Ok(_) => (CryptoResult::failure("Envelope file empty"), Vec::new()),
        Err(_) => (
            CryptoResult::failure("Unable to open envelope file for reading"),
            Vec::new(),
        ),
    }
}

pub fn read_envelope_from_file_with_associated_data_out(
    path: impl AsRef<std::path::Path>,
    recipient_private_key: &[u8],
    associated_data_out: Option<&mut Vec<u8>>,
) -> CryptoResult {
    match read_binary_bytes(path) {
        Ok(buffer) if !buffer.is_empty() => consume_envelope_with_associated_data_out(
            &buffer,
            recipient_private_key,
            associated_data_out,
        ),
        Ok(_) => CryptoResult::failure("Envelope file empty"),
        Err(_) => CryptoResult::failure("Unable to open envelope file for reading"),
    }
}

pub fn write_envelope_to_memory(
    dest: &mut [u8],
    written: &mut usize,
    payload: &[u8],
    recipient_public_key: &[u8],
) -> CryptoResult {
    write_envelope_to_memory_with_associated_data(dest, written, payload, recipient_public_key, &[])
}

pub fn write_envelope_to_memory_with_associated_data(
    dest: &mut [u8],
    written: &mut usize,
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
) -> CryptoResult {
    match try_write_envelope_to_memory_with_associated_data(
        dest,
        payload,
        recipient_public_key,
        associated_data,
    ) {
        Ok(count) => {
            *written = count;
            CryptoResult::ok(Vec::new())
        }
        Err(result) => {
            *written = 0;
            result
        }
    }
}

pub fn write_envelope_to_memory_result(
    dest: &mut [u8],
    payload: &[u8],
    recipient_public_key: &[u8],
) -> (CryptoResult, usize) {
    write_envelope_to_memory_result_with_associated_data(dest, payload, recipient_public_key, &[])
}

pub fn write_envelope_to_memory_result_with_associated_data(
    dest: &mut [u8],
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
) -> (CryptoResult, usize) {
    match try_write_envelope_to_memory_with_associated_data(
        dest,
        payload,
        recipient_public_key,
        associated_data,
    ) {
        Ok(written) => (CryptoResult::ok(Vec::new()), written),
        Err(result) => (result, 0),
    }
}

fn try_write_envelope_to_memory_with_associated_data(
    dest: &mut [u8],
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
) -> Result<usize, CryptoResult> {
    let env = create_envelope_with_associated_data(payload, recipient_public_key, associated_data);
    if !env.success {
        return Err(env);
    }
    if env.data.len() > dest.len() {
        return Err(CryptoResult::failure(
            "Shared memory region too small for envelope",
        ));
    }
    dest[..env.data.len()].copy_from_slice(&env.data);
    Ok(env.data.len())
}

pub fn write_envelope_to_memory_with_written(
    dest: &mut [u8],
    written: &mut usize,
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
) -> CryptoResult {
    write_envelope_to_memory_with_associated_data(
        dest,
        written,
        payload,
        recipient_public_key,
        associated_data,
    )
}

pub fn read_envelope_from_memory(src: &[u8], recipient_private_key: &[u8]) -> CryptoResult {
    consume_envelope(src, recipient_private_key)
}

pub fn read_envelope_from_memory_with_associated_data_out(
    src: &[u8],
    recipient_private_key: &[u8],
    associated_data_out: Option<&mut Vec<u8>>,
) -> CryptoResult {
    consume_envelope_with_associated_data_out(src, recipient_private_key, associated_data_out)
}

pub fn x25519_public_key(secret_key: &[u8]) -> PkiResult<[u8; X25519_PUBLIC_KEY_BYTES]> {
    if secret_key.len() != X25519_SECRET_KEY_BYTES {
        return Err(PkiError::new("X25519 secret key must be 32 bytes"));
    }
    let mut secret = [0u8; X25519_SECRET_KEY_BYTES];
    secret.copy_from_slice(secret_key);
    let secret = X25519StaticSecret::from(secret);
    Ok(X25519PublicKey::from(&secret).to_bytes())
}

pub fn create_envelope_with_ephemeral_secret(
    payload: &[u8],
    recipient_public_key: &[u8],
    associated_data: &[u8],
    ephemeral_secret_key: &[u8],
) -> CryptoResult {
    if recipient_public_key.len() != X25519_PUBLIC_KEY_BYTES {
        return CryptoResult::failure("Recipient public key must be PUBLICKEYBYTES bytes");
    }
    if ephemeral_secret_key.len() != X25519_SECRET_KEY_BYTES {
        return CryptoResult::failure("Ephemeral secret key must be X25519_SECRET_KEY_BYTES bytes");
    }

    let mut recipient_public = [0u8; X25519_PUBLIC_KEY_BYTES];
    recipient_public.copy_from_slice(recipient_public_key);
    let mut ephemeral_secret = [0u8; X25519_SECRET_KEY_BYTES];
    ephemeral_secret.copy_from_slice(ephemeral_secret_key);

    match sealed_box_seal(payload, &recipient_public, &ephemeral_secret) {
        Ok(ciphertext) => CryptoResult::ok(
            Envelope {
                associated_data: associated_data.to_vec(),
                ciphertext,
            }
            .serialize(),
        ),
        Err(err) => CryptoResult::failure(err.message),
    }
}

pub fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_le_bytes());
}

pub fn read_u32(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

pub fn blake2b_256(input: &[u8]) -> [u8; DIGEST_SIZE] {
    let digest =
        keylock::hash::blake2b::hash(input, DIGEST_SIZE).expect("valid BLAKE2b output size");
    let mut out = [0u8; DIGEST_SIZE];
    out.copy_from_slice(&digest);
    out
}

fn fill_random(out: &mut [u8]) -> PkiResult<()> {
    super::random::fill_random(out)
}

fn sealed_box_seal(
    payload: &[u8],
    recipient_public_key: &[u8; X25519_PUBLIC_KEY_BYTES],
    ephemeral_secret_key: &[u8; X25519_SECRET_KEY_BYTES],
) -> PkiResult<Vec<u8>> {
    let ephemeral_public_key = x25519_public_key(ephemeral_secret_key)?;
    let shared = x25519(ephemeral_secret_key, recipient_public_key);
    if is_all_zero(&shared) {
        return Err(PkiError::new("X25519 shared key is all zero"));
    }
    let box_key = hsalsa20(&[0u8; 16], &shared);
    let nonce = sealed_box_nonce(&ephemeral_public_key, recipient_public_key);
    let boxed = secretbox_seal(payload, &nonce, &box_key);

    let mut out = Vec::with_capacity(SEALED_BOX_OVERHEAD_BYTES + payload.len());
    out.extend(ephemeral_public_key);
    out.extend(boxed);
    Ok(out)
}

fn sealed_box_open(
    ciphertext: &[u8],
    recipient_public_key: &[u8],
    recipient_secret_key: &[u8],
) -> PkiResult<Vec<u8>> {
    if recipient_public_key.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(PkiError::new(
            "Recipient public key must be X25519_PUBLIC_KEY_BYTES bytes",
        ));
    }
    if recipient_secret_key.len() != X25519_SECRET_KEY_BYTES {
        return Err(PkiError::new(
            "Recipient secret key must be X25519_SECRET_KEY_BYTES bytes",
        ));
    }
    if ciphertext.len() < SEALED_BOX_OVERHEAD_BYTES {
        return Err(PkiError::new("Ciphertext too short"));
    }
    let mut ephemeral_public = [0u8; X25519_PUBLIC_KEY_BYTES];
    ephemeral_public.copy_from_slice(&ciphertext[..X25519_PUBLIC_KEY_BYTES]);
    let mut recipient_public = [0u8; X25519_PUBLIC_KEY_BYTES];
    recipient_public.copy_from_slice(recipient_public_key);
    let mut recipient_secret = [0u8; X25519_SECRET_KEY_BYTES];
    recipient_secret.copy_from_slice(recipient_secret_key);

    let shared = x25519(&recipient_secret, &ephemeral_public);
    if is_all_zero(&shared) {
        return Err(PkiError::new("X25519 shared key is all zero"));
    }
    let box_key = hsalsa20(&[0u8; 16], &shared);
    let nonce = sealed_box_nonce(&ephemeral_public, &recipient_public);
    secretbox_open(&ciphertext[X25519_PUBLIC_KEY_BYTES..], &nonce, &box_key)
}

fn sealed_box_nonce(
    ephemeral_public_key: &[u8; X25519_PUBLIC_KEY_BYTES],
    recipient_public_key: &[u8; X25519_PUBLIC_KEY_BYTES],
) -> [u8; 24] {
    let mut nonce_material = [0u8; 64];
    nonce_material[..32].copy_from_slice(ephemeral_public_key);
    nonce_material[32..].copy_from_slice(recipient_public_key);
    let digest = blake2b_256(&nonce_material);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, byte| acc | byte) == 0
}

fn x25519(secret_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let secret = X25519StaticSecret::from(*secret_key);
    let public = X25519PublicKey::from(*public_key);
    secret.diffie_hellman(&public).to_bytes()
}

fn secretbox_seal(payload: &[u8], nonce: &[u8; 24], key: &[u8; 32]) -> Vec<u8> {
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("fixed-size secretbox key");
    let mut encrypted = cipher
        .encrypt(XSalsa20Nonce::from_slice(nonce), payload)
        .expect("XSalsa20-Poly1305 encryption should not fail for slice payloads");
    let tag = encrypted.split_off(encrypted.len() - 16);
    let mut out = Vec::with_capacity(tag.len() + encrypted.len());
    out.extend(tag);
    out.extend(encrypted);
    out
}

fn secretbox_open(boxed: &[u8], nonce: &[u8; 24], key: &[u8; 32]) -> PkiResult<Vec<u8>> {
    if boxed.len() < 16 {
        return Err(PkiError::new("Ciphertext too short"));
    }
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("fixed-size secretbox key");
    let mut encrypted = Vec::with_capacity(boxed.len());
    encrypted.extend(&boxed[16..]);
    encrypted.extend(&boxed[..16]);
    cipher
        .decrypt(XSalsa20Nonce::from_slice(nonce), encrypted.as_ref())
        .map_err(|_| PkiError::new("Failed to decrypt key exchange envelope"))
}

fn hsalsa20(nonce: &[u8; 16], key: &[u8; 32]) -> [u8; 32] {
    let mut state = salsa20_state(key, &nonce[..8].try_into().unwrap(), 0);
    state[8] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
    state[9] = u32::from_le_bytes(nonce[12..16].try_into().unwrap());
    salsa20_rounds(&mut state);
    let words = [
        state[0], state[5], state[10], state[15], state[6], state[7], state[8], state[9],
    ];
    let mut out = [0u8; 32];
    for (idx, word) in words.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn salsa20_state(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> [u32; 16] {
    let constants = *b"expand 32-byte k";
    [
        u32::from_le_bytes(constants[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(constants[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        counter as u32,
        (counter >> 32) as u32,
        u32::from_le_bytes(constants[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        u32::from_le_bytes(constants[12..16].try_into().unwrap()),
    ]
}

fn salsa20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        salsa20_quarter_round(state, 0, 4, 8, 12);
        salsa20_quarter_round(state, 5, 9, 13, 1);
        salsa20_quarter_round(state, 10, 14, 2, 6);
        salsa20_quarter_round(state, 15, 3, 7, 11);
        salsa20_quarter_round(state, 0, 1, 2, 3);
        salsa20_quarter_round(state, 5, 6, 7, 4);
        salsa20_quarter_round(state, 10, 11, 8, 9);
        salsa20_quarter_round(state, 15, 12, 13, 14);
    }
}

fn salsa20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[b] ^= state[a].wrapping_add(state[d]).rotate_left(7);
    state[c] ^= state[b].wrapping_add(state[a]).rotate_left(9);
    state[d] ^= state[c].wrapping_add(state[b]).rotate_left(13);
    state[a] ^= state[d].wrapping_add(state[c]).rotate_left(18);
}
