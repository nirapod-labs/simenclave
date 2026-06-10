// SimEnclave wire protocol, C side (see ../../SPEC.md and ../../protocol.cddl).
// The interposer encodes requests and decodes responses with this; the Swift
// helper is the other end. M0's codec is hand-written for the two messages it
// carries and byte-matches the Swift one; tinycbor is the planned library when
// the protocol grows at M1.
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
} se_response;

// Encode a GENERATE request payload (CBOR, no frame). Returns bytes written, or
// -1 if the buffer is too small.
int se_encode_generate(uint8_t *out, size_t cap);

// Encode a SIGN request payload carrying the handle and a 32-byte digest.
int se_encode_sign(const uint8_t *handle, size_t handle_len, const uint8_t *digest,
                   size_t digest_len, uint8_t *out, size_t cap);

// Decode a response payload into out, dispatching on op and status.
se_status se_decode_response(const uint8_t *payload, size_t len, se_response *out);

// Framing (se_framing.c). se_frame writes a 4-byte big-endian length prefix then
// the payload; se_payload_length parses a prefix, returning the length or -1 if
// it exceeds SE_MAX_FRAME.
int se_frame(const uint8_t *payload, size_t len, uint8_t *out, size_t cap);
long se_payload_length(const uint8_t prefix[4]);

#endif
