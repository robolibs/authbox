#ifndef AUTHBOX_H
#define AUTHBOX_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Borrowed byte view used by the C ABI.
 */
typedef struct {
  const uint8_t *ptr;
  uintptr_t len;
} AuthboxBytes;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Returns a pointer to the last error message, or NULL if there is none.
 * The pointer is valid until the next FFI call on this thread.
 */
const char *authbox_last_error_message(void);

/**
 * Free an owned C string returned by authbox.
 */
void authbox_string_free(char *value);

/**
 * Crate version, as a static NUL-terminated string.
 */
const char *authbox_version(void);

/**
 * Return whether `did_uri` is syntactically a DID URI.
 */
bool authbox_did_is_uri(const char *did_uri);

/**
 * Convert a did:web URI to its HTTPS document URL. Caller frees with authbox_string_free.
 */
char *authbox_did_web_document_url(const char *did_uri);

/**
 * Encode a 32-byte Ed25519 public key as did:key. Caller frees with authbox_string_free.
 */
char *authbox_did_key_encode_ed25519(const uint8_t *public_key, uintptr_t public_key_len);

/**
 * Resolve a did:key DID document as JSON. Caller frees with authbox_string_free.
 */
char *authbox_did_key_resolve_document_json(const char *did_uri);

/**
 * Compute SHA-256 into a caller-owned 32-byte output buffer.
 */
bool authbox_sha256(const uint8_t *input, uintptr_t input_len, uint8_t *out, uintptr_t out_len);

/**
 * Compute Keccak-256 into a caller-owned 32-byte output buffer.
 */
bool authbox_keccak256(const uint8_t *input, uintptr_t input_len, uint8_t *out, uintptr_t out_len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* AUTHBOX_H */
