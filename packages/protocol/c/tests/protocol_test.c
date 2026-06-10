// Unit checks for the C codec. Interop with the Swift end is proven for real by
// the mechanism-C harness, where this code talks to the Swift helper.
#include <stdio.h>
#include <string.h>

#include "se_protocol.h"

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
  do {                                                                                             \
    if (!(cond)) {                                                                                 \
      printf("FAIL: %s\n", msg);                                                                   \
      fails++;                                                                                     \
    }                                                                                              \
  } while (0)

int main(void) {
  uint8_t buf[512];
  uint8_t token[32];
  memset(token, 0xAB, sizeof(token));

  // GENERATE { 0:2, 7:token } must equal the canonical bytes the Swift codec emits.
  int n = se_encode_generate(token, sizeof(token), buf, sizeof(buf));
  uint8_t gen_prefix[] = {0xA2, 0x00, 0x02, 0x07, 0x58, 0x20};
  CHECK(n == 38 && memcmp(buf, gen_prefix, sizeof(gen_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0,
        "generate bytes");

  // SIGN { 0:4, 2:handle(4), 4:digest(32), 7:token(32) } in canonical form.
  uint8_t handle[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  uint8_t digest[32];
  memset(digest, 0x5A, sizeof(digest));
  n = se_encode_sign(token, sizeof(token), handle, 4, digest, 32, buf, sizeof(buf));
  uint8_t sign_prefix[] = {0xA4, 0x00, 0x04, 0x02, 0x44, 0xAA, 0xAA, 0xAA, 0xAA, 0x04, 0x58, 0x20};
  CHECK(n == 79 && memcmp(buf, sign_prefix, sizeof(sign_prefix)) == 0, "sign bytes");

  // Decode a GENERATE-ok response.
  uint8_t gen_resp[] = {0xA4, 0x00, 0x02, 0x01, 0x00, 0x02, 0x44, 1, 2,
                        3,    4,    0x03, 0x45, 9,    8,    7,    6, 5};
  se_response resp;
  CHECK(se_decode_response(gen_resp, sizeof(gen_resp), &resp) == SE_OK, "decode generated rc");
  CHECK(resp.kind == SE_RESP_GENERATED && resp.handle_len == 4 && resp.public_key_len == 5,
        "generated fields");

  // Decode a SIGN-ok response.
  uint8_t sign_resp[] = {0xA3, 0x00, 0x04, 0x01, 0x00, 0x05, 0x46, 10, 11, 12, 13, 14, 15};
  CHECK(se_decode_response(sign_resp, sizeof(sign_resp), &resp) == SE_OK, "decode signed rc");
  CHECK(resp.kind == SE_RESP_SIGNED && resp.signature_len == 6, "signed fields");

  // GET_PUBKEY { 0:3, 2:handle(4), 7:token(32) } in canonical form.
  n = se_encode_get_pubkey(token, sizeof(token), handle, 4, buf, sizeof(buf));
  uint8_t getpub_prefix[] = {0xA3, 0x00, 0x03, 0x02, 0x44, 0xAA,
                             0xAA, 0xAA, 0xAA, 0x07, 0x58, 0x20};
  CHECK(n == 44 && memcmp(buf, getpub_prefix, sizeof(getpub_prefix)) == 0 &&
            memcmp(buf + 12, token, 32) == 0,
        "get_pubkey bytes");

  // DELETE { 0:5, 2:handle(4), 7:token(32) } in canonical form, same shape, op 5.
  n = se_encode_delete(token, sizeof(token), handle, 4, buf, sizeof(buf));
  uint8_t delete_prefix[] = {0xA3, 0x00, 0x05, 0x02, 0x44, 0xAA,
                             0xAA, 0xAA, 0xAA, 0x07, 0x58, 0x20};
  CHECK(n == 44 && memcmp(buf, delete_prefix, sizeof(delete_prefix)) == 0 &&
            memcmp(buf + 12, token, 32) == 0,
        "delete bytes");

  // Decode a GET_PUBKEY-ok response { 0:3, 1:0, 3:pubkey(5) }.
  uint8_t pub_resp[] = {0xA3, 0x00, 0x03, 0x01, 0x00, 0x03, 0x45, 9, 8, 7, 6, 5};
  CHECK(se_decode_response(pub_resp, sizeof(pub_resp), &resp) == SE_OK, "decode pubkey rc");
  CHECK(resp.kind == SE_RESP_PUBKEY && resp.public_key_len == 5, "pubkey fields");

  // Decode a DELETE-ok response { 0:5, 1:0 }, status only.
  uint8_t del_resp[] = {0xA2, 0x00, 0x05, 0x01, 0x00};
  CHECK(se_decode_response(del_resp, sizeof(del_resp), &resp) == SE_OK, "decode deleted rc");
  CHECK(resp.kind == SE_RESP_DELETED, "deleted kind");

  // HELLO { 0:1, 7:token(32), 8:1 } in canonical form.
  n = se_encode_hello(token, sizeof(token), 1, buf, sizeof(buf));
  uint8_t hello_prefix[] = {0xA3, 0x00, 0x01, 0x07, 0x58, 0x20};
  CHECK(n == 40 && memcmp(buf, hello_prefix, sizeof(hello_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0 && buf[38] == 0x08 && buf[39] == 0x01,
        "hello bytes");

  // Decode a HELLO-ok response { 0:1, 1:0, 8:1 }.
  uint8_t hello_resp[] = {0xA3, 0x00, 0x01, 0x01, 0x00, 0x08, 0x01};
  CHECK(se_decode_response(hello_resp, sizeof(hello_resp), &resp) == SE_OK, "decode hello rc");
  CHECK(resp.kind == SE_RESP_HELLO && resp.version == 1, "hello fields");

  // Decode an ERROR response carrying "no".
  uint8_t err_resp[] = {0xA3, 0x00, 0x02, 0x01, 0x01, 0x06, 0x62, 'n', 'o'};
  CHECK(se_decode_response(err_resp, sizeof(err_resp), &resp) == SE_OK, "decode error rc");
  CHECK(resp.kind == SE_RESP_ERROR && strcmp(resp.error, "no") == 0, "error field");

  // An error response with a negative OSStatus in key 10 decodes: the code is
  // accepted (CBOR major 1) and the reason still reads.
  uint8_t err_code[] = {0xA4, 0x00, 0x02, 0x01, 0x01, 0x06, 0x62, 'n', 'o', 0x0A, 0x39, 0x62, 0xCC};
  CHECK(se_decode_response(err_code, sizeof(err_code), &resp) == SE_OK &&
            resp.kind == SE_RESP_ERROR && strcmp(resp.error, "no") == 0 &&
            resp.error_code == -25293,
        "decode error with osstatus");

  // Framing.
  uint8_t framed[8];
  uint8_t pay[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  CHECK(se_frame(pay, 4, framed, sizeof(framed)) == 8, "frame len");
  uint8_t want[] = {0, 0, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF};
  CHECK(memcmp(framed, want, 8) == 0, "frame bytes");
  uint8_t prefix[4] = {0, 0, 1, 0};
  CHECK(se_payload_length(prefix) == 256, "payload length");

  // Hardening: a map with a duplicate key is rejected.
  uint8_t dup_key[] = {0xA2, 0x00, 0x02, 0x00, 0x03};
  CHECK(se_decode_response(dup_key, sizeof(dup_key), &resp) != SE_OK, "reject duplicate key");

  // Hardening: a non-shortest-form integer (5 in the 1-byte form) is rejected.
  uint8_t non_canon[] = {0xA1, 0x00, 0x18, 0x05};
  CHECK(se_decode_response(non_canon, sizeof(non_canon), &resp) != SE_OK, "reject non-canonical");

  // Hardening: trailing bytes after a complete map are rejected.
  uint8_t trailing[] = {0xA1, 0x00, 0x02, 0xFF};
  CHECK(se_decode_response(trailing, sizeof(trailing), &resp) != SE_OK, "reject trailing bytes");

  printf(fails ? "C CODEC: %d failure(s)\n" : "C CODEC: ok\n", fails);
  return fails ? 1 : 0;
}
