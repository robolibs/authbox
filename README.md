# authbox

Pure-Rust PKI and DID toolkit, translated from `robolibs_cpp/authbox`. Provides
X.509 certificate / CSR / CRL build-parse-verify, a DID resolver with built-in
`did:key`, `did:jwk`, `did:dns`, `did:peer`, `did:pkh`, and `did:web` methods,
and an in-process certificate verification service.

**Crypto boundary.** Every cryptographic primitive — keygen, signing, verifying,
hashing, AEAD, RNG — lives in the sibling
[`keylock`](https://codeberg.org/robolibs/keylock) crate. authbox itself
contains only PKI / DID / JSON framing. authbox does **not** re-export keylock;
consumers must add keylock as their own direct dependency and import primitives
from it directly: `keylock::generate_*_keypair()` for keys, `keylock::keccak256`
/ `keylock::hash::*` for hashes, and `keylock::crypto::*` for everything else.

```text
authbox                                      keylock
  │                                            │
  ├─ pki/   ──depends on────────────────►      ├─ crypto/  (Ed25519, Ed448,
  ├─ did/                                      │            ECDSA P-256/384/521,
  ├─ json/                                     │            secp256k1, RSA,
  └─ io/                                       │            X25519, AEAD, RNG)
                                               ├─ hash/    (SHA-2/3, BLAKE2,
                                               │            KMAC, HKDF, HMAC,
                                               │            Keccak-256, SHAKE,
                                               │            KMAC, …)
                                               └─ kdf/     (Argon2)
```

The C++ tree stays checked in under `xtra/authbox/` as the translation source.

## Quick start

```toml
[dependencies]
authbox = { git = "https://codeberg.org/robolibs/authbox.git" }
keylock = { git = "https://codeberg.org/robolibs/keylock.git", tag = "0.1.0" }
```

authbox itself pins keylock to the same codeberg tag, so the two crates always
resolve to one shared version of every primitive.

### Generate and sign a self-signed Ed25519 certificate

```rust
use keylock::generate_ed25519_keypair;
use authbox::pki::{CertificateBuilder, DerTime, key_usage};

let key = generate_ed25519_keypair()?;
let cert = CertificateBuilder::new()
    .set_subject_from_string("CN=Example,O=Example,C=US")?
    .set_subject_public_key_ed25519(key.public_key.clone())
    .set_validity(
        DerTime { year: 2024, month: 1, day: 1, hour: 0, minute: 0, second: 0 },
        DerTime { year: 2025, month: 1, day: 1, hour: 0, minute: 0, second: 0 },
    )
    .set_basic_constraints(false, None)?
    .set_key_usage(key_usage::DIGITAL_SIGNATURE)?
    .build_ed25519_with_self_signed(&key, true)?;

println!("{}", cert.to_pem());
```

### Resolve a `did:key`

```rust
use authbox::did::{encode_ed25519_did_key, parse_did_key, resolve_did_key_document_json};
use keylock::generate_ed25519_keypair;

let key = generate_ed25519_keypair()?;
let public: [u8; 32] = key.public_key.as_slice().try_into()?;
let did = encode_ed25519_did_key(public)?;
println!("did:key: {did}");
println!("{}", resolve_did_key_document_json(&did)?);
```

### Resolve a `did:web` document over HTTPS

```rust
use authbox::did::{WebFetchOptions, make_web_http11_resolver_with_options};

let resolver = make_web_http11_resolver_with_options(WebFetchOptions::default());
let resolved = resolver.resolve("did:web:example.com")?;
println!("{}", resolved.raw_document_json);
```

## What's in the crate

**PKI (`authbox::pki`)**

- X.509 certificate, CSR, and CRL builders and parsers with `PemResult` /
  `CertificateResult` / `CertValidationReport` wrappers.
- Extension surface: `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`,
  `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`, `SubjectAltName`, plus
  enterprise extensions (Issuer Alternative Name, Policy Mappings,
  Policy Constraints, Inhibit Any-Policy).
- Signature support: Ed25519, Ed448, ECDSA P-256/P-384/P-521 with matching
  SHA-2 hashes, RSA PKCS#1 v1.5 (SHA-256/384/512), and RSA-PSS with variable
  salt lengths. Sign and verify across certs/CSRs/CRLs.
- Trust store: PEM/DER auto-detect loader, structural chain validation,
  revocation callbacks, system-bundle discovery.
- Verify service: in-process `RequestProcessor` / `DirectTransport`, wire-format
  codec, Ed25519-signed responses, processor-failure catch boundary.
- Key utilities: SPKI encode/decode for every supported curve, SEC1
  encode/decode for P-256/P-384/P-521, PKCS#8 + PEM `ENCRYPTED PRIVATE KEY`
  helpers via the `pkcs8` crate, RSA PKCS#1 ↔ PKCS#8 conversions. Keygen
  itself is delegated to keylock; `authbox::pki::generate_*_keypair` is a
  thin shim around `keylock::generate_*_keypair` and `authbox::pki::KeyPair`
  is a re-export of `keylock::crypto::KeyPair`.

**DID (`authbox::did`)**

- `parse`, `parse_url`, dereferencing, document parsing and validation.
- Built-in methods: `did:key`, `did:jwk`, `did:dns` (with DNSSEC filtering),
  `did:peer`, `did:pkh` (with Ethereum-signature recovery through
  `keylock::keccak256` + secp256k1), `did:web`.
- `Resolver` with a method registry and a pluggable fetcher.
- DID-RPC JSON codecs with loopback service and client.
- `did:web` certificate binding (SAN ↔ DID URI), DID-document generation from
  X.509 certificates.
- No DID-side crypto: `did/` modules never reach into `authbox::pki` for
  primitives; everything they need (Ed25519 keygen, keccak256, secp256k1
  recovery) comes from keylock.

**JSON (`authbox::json`)**

- Thin wrapper over `serde_json` for strict JSON and `json5` for permissive
  JSON5-shaped input, plus DID/PKI-facing helpers (`json_string`, `json_array`,
  `to_compact_string`, `to_pretty_string`, `escape`).

**IO (`authbox::io`)**

- Compatibility binary file helpers (`read_binary`, `write_binary`,
  `BinaryReadResult`).

## Examples

Runnable examples mirror the C++ `xtra/authbox/examples/` layout.

```sh
cargo run --example simple_example
cargo run --example did_key_roundtrip
cargo run --example did_jwk_roundtrip
cargo run --example did_rpc_loopback
cargo run --example did_web_from_x509
cargo run --example did_web_resolve_live -- did:web:example.com
cargo run --example cert_generate_self_signed
cargo run --example cert_generate_ca
cargo run --example cert_parse_and_print
cargo run --example cert_sign_csr
cargo run --example cert_verify_chain
cargo run --example csr_generate
cargo run --example enterprise
cargo run --example simple_verify_client
cargo run --example simple_verify_server
cargo run --example trust_store_usage
cargo run --example verify_direct
```

`make run EXAMPLE=<name>` is equivalent.

## Cargo features

| Feature   | Effect                                |
| --------- | ------------------------------------- |
| `tracing` | Reserved hook for tracing integration |
| `config`  | Reserved hook for runtime config      |

The default feature set is empty; all PKI/DID surface is unconditional.

## Verification

Use the Makefile lanes for local checks:

```sh
make fmt
make fmt-check
make clippy
make test
make test-feature FEATURES="tracing config"
make check
make build
make docs
make run
```

`make run` defaults to `simple_example`; pass `EXAMPLE=<name>` for any of the
examples above. CI runs fmt, clippy, the full test matrix, doc builds, and
`cargo-deny` (advisories, licenses, sources, bans) on every PR.

## Security

- RSA primitives ultimately come from the pure-Rust `rsa` crate (via keylock),
  which carries an unpatched timing sidechannel (RUSTSEC-2023-0071, "Marvin
  Attack"). authbox uses RSA primarily for signing and verification, where
  attacker-controlled decryption inputs do not apply. Callers that decrypt
  attacker-controlled RSA-OAEP ciphertexts should treat the timing leak as a
  residual risk. CI ignores this single advisory; all other `cargo audit` /
  `cargo deny` advisories are enforced.
- DER/ASN.1 parsing rejects indefinite lengths, overflowing long-form lengths,
  and value lengths that exceed the input buffer.
- DID document fetch enforces a max response size, disables redirect following
  on the HTTPS path to match raw HTTP/1.1 behavior, and refuses plain HTTP
  unless `allow_insecure_http` is set by the caller.
- The C++ netpipe transport is intentionally not ported; HTTPS goes through
  `reqwest`/`rustls` and HTTP/1.1 over `std::net`.

## License

MIT.
