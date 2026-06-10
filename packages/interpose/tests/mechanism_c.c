// Mechanism C. The interposer's hooks, installed in a host process, route a
// standard SecKey key-generate, public-key, and sign to the helper, and the
// returned signature verifies under the public key the hooked path handed back.
// The stats prove the hooks fired, so the verifying signature came from the
// helper's SEP and not from a passthrough. This is the whole bridge minus the
// in-simulator injection.
#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

#include "simenclave_interpose.h"

int main(void) {
  int fails = 0;

  int failed = simenclave_install_hooks();
  printf("install: %d hook(s) failed\n", failed);
  if (failed) return 1;

  const void *keys[] = {kSecAttrTokenID};
  const void *values[] = {kSecAttrTokenIDSecureEnclave};
  CFDictionaryRef parameters = CFDictionaryCreate(
      NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  CFErrorRef error = NULL;
  SecKeyRef key = SecKeyCreateRandomKey(parameters, &error);
  if (!key) {
    printf("FAIL: SecKeyCreateRandomKey returned NULL\n");
    return 1;
  }

  SecKeyRef pub = SecKeyCopyPublicKey(key);
  if (!pub) {
    printf("FAIL: SecKeyCopyPublicKey returned NULL\n");
    return 1;
  }

  const char *message = "mechanism C";
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(message, (CC_LONG)strlen(message), digest);
  CFDataRef digestData = CFDataCreate(NULL, digest, CC_SHA256_DIGEST_LENGTH);

  CFErrorRef signError = NULL;
  CFDataRef signature = SecKeyCreateSignature(
      key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, &signError);
  if (!signature) {
    printf("FAIL: SecKeyCreateSignature returned NULL (is the helper running?)\n");
    return 1;
  }

  CFErrorRef verifyError = NULL;
  bool verified = SecKeyVerifySignature(
      pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, signature, &verifyError);
  printf("verify: %d\n", verified);
  if (!verified) fails++;

  simenclave_hook_stats stats = simenclave_get_hook_stats();
  printf("stats: create=%d pubkey=%d sign=%d\n",
         stats.create_random_key, stats.copy_public_key, stats.create_signature);
  if (stats.create_random_key < 1 || stats.copy_public_key < 1 || stats.create_signature < 1) {
    fails++;
  }

  printf(fails ? "MECHANISM C: %d failure(s)\n" : "MECHANISM C: ok\n", fails);
  return fails ? 1 : 0;
}
