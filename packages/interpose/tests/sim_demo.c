/**
 * @file sim_demo.c
 * @brief The in-simulator demo: a standard SE key request, bridged or failing.
 *
 * @details
 * It makes a standard Secure Enclave key request, copies the public key,
 * signs a digest, and verifies. It links no interposer: the interposer is
 * injected by DYLD_INSERT_LIBRARIES. Without injection the first call fails,
 * because the simulator has no SEP; with injection it succeeds against the
 * host helper. So a verify of 1 is mechanism D.
 *

 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const void *keys[] = {kSecAttrTokenID};
  const void *values[] = {kSecAttrTokenIDSecureEnclave};
  CFDictionaryRef parameters = CFDictionaryCreate(
      NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  CFErrorRef error = NULL;
  SecKeyRef key = SecKeyCreateRandomKey(parameters, &error);
  if (!key) {
    printf("SIM: SecKeyCreateRandomKey failed (no SEP, no interposer)\n");
    return 2;
  }

  SecKeyRef pub = SecKeyCopyPublicKey(key);
  if (!pub) {
    printf("SIM: SecKeyCopyPublicKey failed\n");
    return 3;
  }

  const char *message = "mechanism D in the simulator";
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(message, (CC_LONG)strlen(message), digest);
  CFDataRef digestData = CFDataCreate(NULL, digest, CC_SHA256_DIGEST_LENGTH);

  CFErrorRef signError = NULL;
  CFDataRef signature = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                              digestData, &signError);
  if (!signature) {
    printf("SIM: SecKeyCreateSignature failed\n");
    return 4;
  }

  CFErrorRef verifyError = NULL;
  Boolean verified = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                           digestData, signature, &verifyError);
  printf("SIM VERIFY: %d\n", verified);
  return verified ? 0 : 5;
}
