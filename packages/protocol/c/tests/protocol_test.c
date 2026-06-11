/**
 * @file protocol_test.c
 * @brief Unit checks for the C codec.
 *
 * @details
 * Interop with the Swift end is proven for real by the mechanism-C harness,
 * where this code talks to the Swift helper.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
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
  int n = se_encode_generate(token, sizeof(token), NULL, 0, NULL, 0, 0, buf, sizeof(buf));
  uint8_t gen_prefix[] = {0xA2, 0x00, 0x02, 0x07, 0x58, 0x20};
  CHECK(n == 38 && memcmp(buf, gen_prefix, sizeof(gen_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0,
        "generate bytes");

  // GENERATE with an app id adds key 14 at the end: { 0:2, 7:token, 14:"hi" }, map(3).
  n = se_encode_generate(token, sizeof(token), (const uint8_t *)"hi", 2, NULL, 0, 0, buf,
                         sizeof(buf));
  CHECK(n == 42 && buf[0] == 0xA3 && buf[38] == 0x0E && buf[39] == 0x62 && buf[40] == 'h' &&
            buf[41] == 'i',
        "generate app id bytes");

  // GENERATE with an access control, biometry: { 0:2, 7:token, 9:1, 11:flags, 12:"ak" }.
  n = se_encode_generate_ac(token, sizeof(token), 1, 5, (const uint8_t *)"ak", 2, NULL, 0, NULL, 0,
                            0, buf, sizeof(buf));
  uint8_t gen_ac_prefix[] = {0xA5, 0x00, 0x02, 0x07, 0x58, 0x20};
  CHECK(n == 46 && memcmp(buf, gen_ac_prefix, sizeof(gen_ac_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0 && buf[38] == 0x09 && buf[39] == 0x01 &&
            buf[40] == 0x0B && buf[41] == 0x05 && buf[42] == 0x0C && buf[43] == 0x62 &&
            buf[44] == 'a' && buf[45] == 'k',
        "generate_ac bytes");

  // A silent key with an access control omits key 9: map(4) { 0:2, 7:token, 11, 12 }.
  n = se_encode_generate_ac(token, sizeof(token), 0, 5, (const uint8_t *)"ak", 2, NULL, 0, NULL, 0,
                            0, buf, sizeof(buf));
  CHECK(n == 44 && buf[0] == 0xA4 && buf[38] == 0x0B && buf[39] == 0x05 && buf[40] == 0x0C,
        "generate_ac silent bytes");

  // SIGN { 0:4, 2:handle(4), 4:input(32), 7:token(32), 19:algorithm } in canonical form.
  uint8_t handle[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  uint8_t digest[32];
  memset(digest, 0x5A, sizeof(digest));
  const char *sign_algo = "algid:sign:ECDSA:digest-X962:SHA-256"; // 36 bytes, text(0x78,0x24)
  n = se_encode_sign(token, sizeof(token), handle, 4, (const uint8_t *)sign_algo, strlen(sign_algo),
                     digest, 32, buf, sizeof(buf));
  uint8_t sign_prefix[] = {0xA5, 0x00, 0x04, 0x02, 0x44, 0xAA, 0xAA, 0xAA, 0xAA, 0x04, 0x58, 0x20};
  // 1 + 2 + 6 + 35 + 35 + (1 key + 2 text-head + 36) = 118; the algorithm field follows the token.
  CHECK(n == 118 && memcmp(buf, sign_prefix, sizeof(sign_prefix)) == 0 && buf[79] == 0x13 &&
            buf[80] == 0x78 && buf[81] == 0x24 && buf[82] == 'a',
        "sign bytes");

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

  // HELLO { 0:1, 7:token(32), 8:1 } in canonical form, no identity.
  n = se_encode_hello(token, sizeof(token), 1, NULL, 0, NULL, 0, buf, sizeof(buf));
  uint8_t hello_prefix[] = {0xA3, 0x00, 0x01, 0x07, 0x58, 0x20};
  CHECK(n == 40 && memcmp(buf, hello_prefix, sizeof(hello_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0 && buf[38] == 0x08 && buf[39] == 0x01,
        "hello bytes");

  // HELLO carrying identity: { 0:1, 7:token, 8:1, 14:"a", 28:"App" }. The map header grows to
  // 5 fields and the two identity keys follow version in ascending order.
  n = se_encode_hello(token, sizeof(token), 1, (const uint8_t *)"a", 1, (const uint8_t *)"App", 3,
                      buf, sizeof(buf));
  // map(5): 0xA5. After the 40-byte no-identity body: 14,"a" (0x0E 0x61 0x61), 28,"App"
  // (0x18 0x1C 0x63 'A' 'p' 'p').
  uint8_t hi_tail[] = {0x0E, 0x61, 0x61, 0x18, 0x1C, 0x63, 'A', 'p', 'p'};
  CHECK(n == 40 + (int)sizeof(hi_tail) && buf[0] == 0xA5 &&
            memcmp(buf + 40, hi_tail, sizeof(hi_tail)) == 0,
        "hello identity bytes");

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

  // FIND_BY_TAG { 0:6, 7:token(32), 15:udid("AB"), 16:appTag(2) } in canonical form.
  uint8_t app_tag[2] = {0x01, 0x02};
  n = se_encode_find_by_tag(token, sizeof(token), (const uint8_t *)"AB", 2, app_tag, 2, buf,
                            sizeof(buf));
  uint8_t find_prefix[] = {0xA4, 0x00, 0x06, 0x07, 0x58, 0x20};
  CHECK(n == 46 && memcmp(buf, find_prefix, sizeof(find_prefix)) == 0 &&
            memcmp(buf + 6, token, 32) == 0 && buf[38] == 0x0F && buf[39] == 0x62 &&
            buf[40] == 'A' && buf[41] == 'B' && buf[42] == 0x10 && buf[43] == 0x42 &&
            buf[44] == 0x01 && buf[45] == 0x02,
        "find_by_tag bytes");

  // Decode a FIND_BY_TAG-ok (found) response { 0:6, 1:0, 2:handle(4), 3:pubkey(5) }.
  uint8_t found_resp[] = {0xA4, 0x00, 0x06, 0x01, 0x00, 0x02, 0x44, 1, 2,
                          3,    4,    0x03, 0x45, 9,    8,    7,    6, 5};
  CHECK(se_decode_response(found_resp, sizeof(found_resp), &resp) == SE_OK, "decode found rc");
  CHECK(resp.kind == SE_RESP_FOUND && resp.handle_len == 4 && resp.public_key_len == 5,
        "found fields");

  // An error response carrying the error domain in key 13 decodes both code and domain.
  uint8_t err_dom[] = {0xA5, 0x00, 0x02, 0x01, 0x01, 0x06, 0x62, 'n',
                       'o',  0x0A, 0x39, 0x62, 0xCC, 0x0D, 0x01};
  CHECK(se_decode_response(err_dom, sizeof(err_dom), &resp) == SE_OK &&
            resp.kind == SE_RESP_ERROR && resp.error_code == -25293 && resp.error_domain == 1,
        "decode error with domain");

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

  // Hardening (M4 security review): a hostile 64-bit byte-string length must be
  // rejected as truncated; the additive bound r->off + va would wrap and pass.
  // map(1) { 2: bytes(len 2^64 - 1) } with no bytes following.
  uint8_t wrap_len[] = {0xA1, 0x02, 0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  CHECK(se_decode_response(wrap_len, sizeof(wrap_len), &resp) == SE_ERR_TRUNCATED,
        "reject wrapping length");

  printf(fails ? "C CODEC: %d failure(s)\n" : "C CODEC: ok\n", fails);
  return fails ? 1 : 0;
}
