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

  // GENERATE must equal the canonical bytes the Swift codec emits.
  int n = se_encode_generate(buf, sizeof(buf));
  uint8_t gen_expect[] = {0xA1, 0x00, 0x02};
  CHECK(n == 3 && memcmp(buf, gen_expect, 3) == 0, "generate bytes");

  // SIGN { 0:4, 2:handle(4), 4:digest(32) } in canonical form.
  uint8_t handle[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  uint8_t digest[32];
  memset(digest, 0x5A, sizeof(digest));
  n = se_encode_sign(handle, 4, digest, 32, buf, sizeof(buf));
  uint8_t sign_prefix[] = {0xA3, 0x00, 0x04, 0x02, 0x44, 0xAA, 0xAA, 0xAA, 0xAA, 0x04, 0x58, 0x20};
  CHECK(n == 44 && memcmp(buf, sign_prefix, sizeof(sign_prefix)) == 0, "sign bytes");

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

  // Decode an ERROR response carrying "no".
  uint8_t err_resp[] = {0xA3, 0x00, 0x02, 0x01, 0x01, 0x06, 0x62, 'n', 'o'};
  CHECK(se_decode_response(err_resp, sizeof(err_resp), &resp) == SE_OK, "decode error rc");
  CHECK(resp.kind == SE_RESP_ERROR && strcmp(resp.error, "no") == 0, "error field");

  // Framing.
  uint8_t framed[8];
  uint8_t pay[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  CHECK(se_frame(pay, 4, framed, sizeof(framed)) == 8, "frame len");
  uint8_t want[] = {0, 0, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF};
  CHECK(memcmp(framed, want, 8) == 0, "frame bytes");
  uint8_t prefix[4] = {0, 0, 1, 0};
  CHECK(se_payload_length(prefix) == 256, "payload length");

  printf(fails ? "C CODEC: %d failure(s)\n" : "C CODEC: ok\n", fails);
  return fails ? 1 : 0;
}
