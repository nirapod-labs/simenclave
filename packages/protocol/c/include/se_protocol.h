// SimEnclave wire protocol, C side (see ../../SPEC.md and ../../protocol.cddl).
// The interposer encodes requests and decodes responses with this; the Swift
// helper is the other end. The codec is hand-written and byte-matches the Swift
// one, and it stays hand-written through M1: the surface is small, the two are
// each other's byte-for-byte oracle, and rejecting duplicate keys and non-
// shortest-form encodings is something a hand-written reader guarantees directly.
#ifndef SE_PROTOCOL_H
#define SE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SE_MAX_FRAME (1 << 20)

typedef enum {
  SE_OK = 0,
  SE_ERR_TRUNCATED,
  SE_ERR_MALFORMED,
  SE_ERR_TYPE,
  SE_ERR_OPCODE,
  SE_ERR_STATUS,
  SE_ERR_MISSING,
  SE_ERR_BUFFER,
} se_status;

typedef enum {
  SE_RESP_GENERATED,
  SE_RESP_SIGNED,
  SE_RESP_PUBKEY,
  SE_RESP_DELETED,
  SE_RESP_HELLO,
  SE_RESP_FOUND,
  SE_RESP_ERROR,
} se_resp_kind;

typedef struct {
  se_resp_kind kind;
  uint8_t handle[64];
  size_t handle_len;
  uint8_t public_key[133];
  size_t public_key_len;
  uint8_t signature[256];
  size_t signature_len;
  char error[256];
  int error_code;   // the helper's OSStatus on an error response, 0 otherwise
  int error_domain; // the error-domain selector (key 13) on an error: 0 = OSStatus
  uint64_t version; // the protocol version on a HELLO response
} se_response;

// Encode a GENERATE request payload (CBOR, no frame), carrying the capability
// token. Returns bytes written, or -1 if the buffer is too small.
int se_encode_generate(const uint8_t *token, size_t token_len, uint8_t *out, size_t cap);

// Encode a GENERATE request that carries an access-control descriptor: the key class
// (biometry adds key 9), the raw SecAccessControlCreateFlags (key 11), and the
// protection constant relayed verbatim as text (key 12). The plain se_encode_generate
// stays the no-access-control form, so its bytes are unchanged.
int se_encode_generate_ac(const uint8_t *token, size_t token_len, int biometry, uint64_t flags,
                          const uint8_t *protection, size_t protection_len, uint8_t *out,
                          size_t cap);

// Encode a SIGN request payload carrying the token, the handle, and a 32-byte
// digest.
int se_encode_sign(const uint8_t *token, size_t token_len, const uint8_t *handle, size_t handle_len,
                   const uint8_t *digest, size_t digest_len, uint8_t *out, size_t cap);

// Encode a GET_PUBKEY request payload carrying the token and a handle.
int se_encode_get_pubkey(const uint8_t *token, size_t token_len, const uint8_t *handle,
                         size_t handle_len, uint8_t *out, size_t cap);

// Encode a DELETE request payload carrying the token and a handle.
int se_encode_delete(const uint8_t *token, size_t token_len, const uint8_t *handle,
                     size_t handle_len, uint8_t *out, size_t cap);

// Encode a HELLO request payload carrying the token and the protocol version.
int se_encode_hello(const uint8_t *token, size_t token_len, uint64_t version, uint8_t *out,
                    size_t cap);

// Encode a FIND_BY_TAG request payload carrying the token, the simulator UDID (text),
// and the application tag (bytes), to look up a persisted key by tag.
int se_encode_find_by_tag(const uint8_t *token, size_t token_len, const uint8_t *udid,
                          size_t udid_len, const uint8_t *app_tag, size_t app_tag_len,
                          uint8_t *out, size_t cap);

// Decode a response payload into out, dispatching on op and status.
se_status se_decode_response(const uint8_t *payload, size_t len, se_response *out);

// Framing (se_framing.c). se_frame writes a 4-byte big-endian length prefix then
// the payload; se_payload_length parses a prefix, returning the length or -1 if
// it exceeds SE_MAX_FRAME.
int se_frame(const uint8_t *payload, size_t len, uint8_t *out, size_t cap);
long se_payload_length(const uint8_t prefix[4]);

#endif
