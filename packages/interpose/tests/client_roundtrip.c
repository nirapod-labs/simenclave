/**
 * @file client_roundtrip.c
 * @brief Client round-trip: the transport drives every op against a live helper.
 *
 * @details
 * The interposer's transport drives GENERATE, GET_PUBKEY, SIGN, and DELETE
 * against a live helper, with no hooks in the picture. This is the C codec
 * and client proving they match the Swift helper end to end.
 * run-mechanism-c.sh starts the helper and points SIMENCLAVE_PORT and
 * SIMENCLAVE_TOKEN at it.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#include "client.h"

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
  do {                                                                                             \
    if (!(cond)) {                                                                                 \
      printf("FAIL: %s\n", msg);                                                                   \
      fails++;                                                                                     \
    }                                                                                              \
  } while (0)

static SecKeyRef public_key_from(const uint8_t *x963, size_t len) {
  CFDataRef data = CFDataCreate(NULL, x963, (CFIndex)len);
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
  const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, bitsRef};
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);
  SecKeyRef key = SecKeyCreateWithData(data, attrs, NULL);
  if (data) CFRelease(data);
  if (bitsRef) CFRelease(bitsRef);
  if (attrs) CFRelease(attrs);
  return key;
}

int main(void) {
  // HELLO first: the doctor handshake negotiates the protocol version.
  se_response hello;
  CHECK(se_client_hello(1, NULL, 0, NULL, 0, &hello) == SE_OK &&
            hello.kind == SE_RESP_HELLO && hello.version == 1,
        "hello negotiates v1");

  se_response gen;
  CHECK(se_client_generate(NULL, 0, NULL, 0, 0, &gen) == SE_OK && gen.kind == SE_RESP_GENERATED,
        "generate");
  if (fails) {
    printf("CLIENT ROUNDTRIP: helper unreachable?\n");
    return 1;
  }

  // GET_PUBKEY for the handle returns the same public key GENERATE handed back.
  se_response pk;
  CHECK(se_client_get_pubkey(gen.handle, gen.handle_len, &pk) == SE_OK && pk.kind == SE_RESP_PUBKEY,
        "get_pubkey");
  CHECK(pk.public_key_len == gen.public_key_len &&
            memcmp(pk.public_key, gen.public_key, gen.public_key_len) == 0,
        "get_pubkey matches generate");

  // SIGN a digest under the real SecKeyAlgorithm constant (read from the SDK, not hard-coded),
  // so the helper signs under the same algorithm the verify below checks; it verifies under
  // that public key.
  char sign_algo[160];
  CFStringGetCString(kSecKeyAlgorithmECDSASignatureDigestX962SHA256, sign_algo, sizeof(sign_algo),
                     kCFStringEncodingUTF8);
  const size_t sign_algo_len = strlen(sign_algo);
  const char *message = "client roundtrip";
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(message, (CC_LONG)strlen(message), digest);
  se_response sig;
  CHECK(se_client_sign(gen.handle, gen.handle_len, (const uint8_t *)sign_algo, sign_algo_len, digest,
                       sizeof(digest), &sig) == SE_OK &&
            sig.kind == SE_RESP_SIGNED,
        "sign");
  SecKeyRef pub = public_key_from(gen.public_key, gen.public_key_len);
  if (pub && sig.kind == SE_RESP_SIGNED) {
    CFDataRef digestData = CFDataCreate(NULL, digest, sizeof(digest));
    CFDataRef sigData = CFDataCreate(NULL, sig.signature, (CFIndex)sig.signature_len);
    Boolean ok = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                       digestData, sigData, NULL);
    CHECK(ok, "signature verifies");
    if (digestData) CFRelease(digestData);
    if (sigData) CFRelease(sigData);
  } else {
    CHECK(0, "build public key");
  }
  if (pub) CFRelease(pub);

  // DELETE removes the key; a sign after delete must not succeed.
  se_response del;
  CHECK(se_client_delete(gen.handle, gen.handle_len, &del) == SE_OK && del.kind == SE_RESP_DELETED,
        "delete");
  se_response after;
  se_status as = se_client_sign(gen.handle, gen.handle_len, (const uint8_t *)sign_algo,
                                sign_algo_len, digest, sizeof(digest), &after);
  CHECK(!(as == SE_OK && after.kind == SE_RESP_SIGNED), "sign after delete fails");

  printf(fails ? "CLIENT ROUNDTRIP: %d failure(s)\n" : "CLIENT ROUNDTRIP: ok\n", fails);
  return fails ? 1 : 0;
}
