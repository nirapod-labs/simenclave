/**
 * @file passthrough_test.c
 * @brief The passthrough invariant as a first-class test.
 *
 * @details
 * A non-Secure-Enclave keychain call returns identically with and without the
 * interposer's hooks installed. Two shapes are probed, each before and after
 * install: a class the hooks ignore outright (a generic password) and the
 * class they inspect but for a tag that is not theirs (a key query). Both
 * must reach the real keychain unchanged. The test also asserts the
 * fail-closed basis of the whole design: a public key, which is exactly what
 * the shadow carrier is, cannot sign.
 *
 * No helper is involved; every operation here passes through to the real
 * Security framework, so this runs as a plain ctest.
 *

 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#include "simenclave_interpose.h"

#include <Security/Security.h>
#include <stdint.h>
#include <stdio.h>

static int fails = 0;
#define CHECK(cond, msg)                                                                           \
  do {                                                                                             \
    if (!(cond)) {                                                                                 \
      printf("FAIL: %s\n", msg);                                                                   \
      fails++;                                                                                     \
    }                                                                                              \
  } while (0)

// A query for a generic password that does not exist. The hooks ignore this class
// entirely, so it must pass straight through.
static CFDictionaryRef password_query(void) {
  const void *k[] = {kSecClass, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
  const void *v[] = {kSecClassGenericPassword, CFSTR("simenclave-absent-account"), kCFBooleanTrue,
                     kSecMatchLimitOne};
  return CFDictionaryCreate(NULL, k, v, 4, &kCFTypeDictionaryKeyCallBacks,
                            &kCFTypeDictionaryValueCallBacks);
}

// A key query with a tag the registry never issued. The hooks inspect this shape,
// miss in the registry, and must pass through.
static CFDictionaryRef foreign_key_query(void) {
  CFDataRef tag = CFDataCreate(NULL, (const uint8_t *)"not-ours", 8);
  const void *k[] = {kSecClass, kSecAttrApplicationTag, kSecReturnRef, kSecMatchLimit};
  const void *v[] = {kSecClassKey, tag, kCFBooleanTrue, kSecMatchLimitOne};
  CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 4, &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
  CFRelease(tag);
  return q;
}

static OSStatus probe(CFDictionaryRef q, int *got_result) {
  CFTypeRef out = NULL;
  OSStatus rc = SecItemCopyMatching(q, &out);
  *got_result = (out != NULL);
  if (out) CFRelease(out);
  return rc;
}

int main(void) {
  CFDictionaryRef pq = password_query();
  CFDictionaryRef kq = foreign_key_query();

  // Baseline, before any hooks are installed.
  int pr1 = 0, kr1 = 0;
  OSStatus pw1 = probe(pq, &pr1);
  OSStatus kw1 = probe(kq, &kr1);

  int failed = simenclave_install_hooks();
  CHECK(failed == 0, "hooks install");

  // After install, the same non-SE queries must return the same status and the
  // same absence of a result.
  int pr2 = 0, kr2 = 0;
  OSStatus pw2 = probe(pq, &pr2);
  OSStatus kw2 = probe(kq, &kr2);
  printf("password passthrough: rc %d==%d, result %d==%d\n", (int)pw1, (int)pw2, pr1, pr2);
  CHECK(pw1 == pw2 && pr1 == pr2, "generic password query is byte-identical");
  printf("foreign key passthrough: rc %d==%d, result %d==%d\n", (int)kw1, (int)kw2, kr1, kr2);
  CHECK(kw1 == kw2 && kr1 == kr2, "non-our key query is byte-identical");

  // The fail-closed basis: a public key, which is what the carrier is, cannot
  // sign, hooked or not. A software key created here passes through to a real key.
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *gk[] = {kSecAttrKeyType, kSecAttrKeySizeInBits};
  const void *gv[] = {kSecAttrKeyTypeECSECPrimeRandom, bitsRef};
  CFDictionaryRef gp = CFDictionaryCreate(NULL, gk, gv, 2, &kCFTypeDictionaryKeyCallBacks,
                                          &kCFTypeDictionaryValueCallBacks);
  SecKeyRef sk = SecKeyCreateRandomKey(gp, NULL);
  SecKeyRef pub = sk ? SecKeyCopyPublicKey(sk) : NULL;
  CHECK(pub != NULL, "obtained a public key");
  if (pub) {
    int can = SecKeyIsAlgorithmSupported(pub, kSecKeyOperationTypeSign,
                                         kSecKeyAlgorithmECDSASignatureDigestX962SHA256);
    CHECK(!can, "a public key reports it cannot sign");
    uint8_t d[32] = {0};
    CFDataRef dd = CFDataCreate(NULL, d, sizeof(d));
    CFDataRef sig =
        SecKeyCreateSignature(pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, dd, NULL);
    CHECK(sig == NULL, "a public key cannot produce a signature");
    if (sig) CFRelease(sig);
    if (dd) CFRelease(dd);
  }
  if (pub) CFRelease(pub);
  if (sk) CFRelease(sk);
  if (bitsRef) CFRelease(bitsRef);
  if (gp) CFRelease(gp);
  CFRelease(pq);
  CFRelease(kq);

  printf(fails ? "PASSTHROUGH: %d failure(s)\n" : "PASSTHROUGH: ok\n", fails);
  return fails ? 1 : 0;
}
