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
  CFDataRef signature = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                              digestData, &signError);
  if (!signature) {
    printf("FAIL: SecKeyCreateSignature returned NULL (is the helper running?)\n");
    return 1;
  }

  CFErrorRef verifyError = NULL;
  Boolean verified = SecKeyVerifySignature(pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                           digestData, signature, &verifyError);
  printf("verify: %d\n", verified);
  if (!verified) fails++;

  // Passthrough: a non-SE key is created and used by the real implementation,
  // untouched. It verifies under its own public key, and the SE counters below
  // must not move for it, which is the passthrough invariant in miniature.
  int sw_bits = 256;
  CFNumberRef sw_bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &sw_bits);
  const void *sw_keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits};
  const void *sw_values[] = {kSecAttrKeyTypeECSECPrimeRandom, sw_bitsRef};
  CFDictionaryRef sw_params =
      CFDictionaryCreate(NULL, sw_keys, sw_values, 2, &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks);
  SecKeyRef sw_key = SecKeyCreateRandomKey(sw_params, NULL);
  if (sw_key) {
    SecKeyRef sw_pub = SecKeyCopyPublicKey(sw_key);
    CFDataRef sw_sig = SecKeyCreateSignature(sw_key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                             digestData, NULL);
    Boolean sw_ok =
        sw_sig && SecKeyVerifySignature(sw_pub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                        digestData, sw_sig, NULL);
    printf("passthrough verify: %d\n", sw_ok);
    if (!sw_ok) fails++;
    if (sw_pub) CFRelease(sw_pub);
    if (sw_sig) CFRelease(sw_sig);
    CFRelease(sw_key);
  } else {
    printf("FAIL: software-key passthrough create returned NULL\n");
    fails++;
  }
  if (sw_bitsRef) CFRelease(sw_bitsRef);
  if (sw_params) CFRelease(sw_params);

  // Allowlist: an RFC4754 (raw r||s) algorithm on the SE key is refused, because
  // the wire carries only the X9.62 DER form. The hook returns NULL, not a guess.
  CFDataRef rejected = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256,
                                             digestData, NULL);
  printf("rfc4754 refused: %d\n", rejected == NULL);
  if (rejected) {
    fails++;
    CFRelease(rejected);
  }

  // The SE counters moved exactly once each: the software key's create, copy, and
  // sign passed through and were not counted, and the refused algorithm did not
  // reach the host. That is the passthrough invariant, measured.
  simenclave_hook_stats stats = simenclave_get_hook_stats();
  printf("stats: create=%d pubkey=%d sign=%d\n", stats.create_random_key, stats.copy_public_key,
         stats.create_signature);
  if (stats.create_random_key != 1 || stats.copy_public_key != 1 || stats.create_signature != 1) {
    fails++;
  }

  // Biometry-gated create. The harness builds an access control with a user-presence
  // constraint (which needs no specific biometric hardware to create), the
  // SecAccessControlCreateWithFlags hook captures it, and the create relays the flags
  // and protection so the helper builds a matching gate in the SEP. The create returns
  // a key and a public key without prompting, since only key use prompts, which proves
  // the host accepted the relayed flags across the iOS-to-macOS boundary.
  SecAccessControlRef bioAccess = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, NULL);
  if (bioAccess) {
    const void *bio_priv_keys[] = {kSecAttrAccessControl};
    const void *bio_priv_values[] = {bioAccess};
    CFDictionaryRef bio_priv =
        CFDictionaryCreate(NULL, bio_priv_keys, bio_priv_values, 1, &kCFTypeDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);
    const void *bio_keys[] = {kSecAttrTokenID, kSecPrivateKeyAttrs};
    const void *bio_values[] = {kSecAttrTokenIDSecureEnclave, bio_priv};
    CFDictionaryRef bio_params =
        CFDictionaryCreate(NULL, bio_keys, bio_values, 2, &kCFTypeDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);
    SecKeyRef bio_key = SecKeyCreateRandomKey(bio_params, NULL);
    SecKeyRef bio_pub = bio_key ? SecKeyCopyPublicKey(bio_key) : NULL;
    printf("biometry create: %d\n", bio_key != NULL && bio_pub != NULL);
    if (!bio_key || !bio_pub) fails++;
    if (bio_pub) CFRelease(bio_pub);
    if (bio_key) CFRelease(bio_key);
    if (bio_priv) CFRelease(bio_priv);
    if (bio_params) CFRelease(bio_params);
    CFRelease(bioAccess);
  } else {
    printf("FAIL: building a user-presence access control returned NULL\n");
    fails++;
  }

  // Fully-nested idiom: both the SE token and the access control sit inside
  // kSecPrivateKeyAttrs. The token detector and the access-control extractor must both
  // resolve the nested form, so this create routes and returns a key like the
  // top-level-token shape above does.
  SecAccessControlRef nestedAccess = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence, NULL);
  if (nestedAccess) {
    const void *n_priv_keys[] = {kSecAttrTokenID, kSecAttrAccessControl};
    const void *n_priv_values[] = {kSecAttrTokenIDSecureEnclave, nestedAccess};
    CFDictionaryRef n_priv =
        CFDictionaryCreate(NULL, n_priv_keys, n_priv_values, 2, &kCFTypeDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);
    const void *n_keys[] = {kSecPrivateKeyAttrs};
    const void *n_values[] = {n_priv};
    CFDictionaryRef n_params = CFDictionaryCreate(
        NULL, n_keys, n_values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecKeyRef n_key = SecKeyCreateRandomKey(n_params, NULL);
    printf("nested-attrs create: %d\n", n_key != NULL);
    if (!n_key) fails++;
    if (n_key) CFRelease(n_key);
    if (n_priv) CFRelease(n_priv);
    if (n_params) CFRelease(n_params);
    CFRelease(nestedAccess);
  } else {
    printf("FAIL: building a nested user-presence access control returned NULL\n");
    fails++;
  }

  // SecItem tag round-trip: a key created permanent with a tag is found by that
  // tag, signs through the host, is deleted by tag, and is gone afterward.
  uint8_t tag_bytes[] = {'s', 'e', '.', 'r', 'o', 'u', 'n', 'd'};
  CFDataRef tag = CFDataCreate(NULL, tag_bytes, sizeof(tag_bytes));
  const void *priv_keys[] = {kSecAttrIsPermanent, kSecAttrApplicationTag};
  const void *priv_values[] = {kCFBooleanTrue, tag};
  CFDictionaryRef priv =
      CFDictionaryCreate(NULL, priv_keys, priv_values, 2, &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks);
  const void *perm_keys[] = {kSecAttrTokenID, kSecPrivateKeyAttrs};
  const void *perm_values[] = {kSecAttrTokenIDSecureEnclave, priv};
  CFDictionaryRef perm_params =
      CFDictionaryCreate(NULL, perm_keys, perm_values, 2, &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks);
  SecKeyRef perm_key = SecKeyCreateRandomKey(perm_params, NULL);
  if (!perm_key) {
    printf("FAIL: permanent SE create returned NULL\n");
    fails++;
  }

  const void *q_keys[] = {kSecClass, kSecAttrApplicationTag, kSecReturnRef, kSecMatchLimit};
  const void *q_values[] = {kSecClassKey, tag, kCFBooleanTrue, kSecMatchLimitOne};
  CFDictionaryRef query = CFDictionaryCreate(
      NULL, q_keys, q_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecKeyRef found = NULL;
  OSStatus findRc = SecItemCopyMatching(query, (CFTypeRef *)&found);
  printf("find by tag: %d\n", findRc == errSecSuccess && found != NULL);
  if (findRc != errSecSuccess || !found) {
    fails++;
  } else {
    SecKeyRef foundPub = SecKeyCopyPublicKey(found);
    CFDataRef foundSig = SecKeyCreateSignature(
        found, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digestData, NULL);
    Boolean foundOk =
        foundSig && SecKeyVerifySignature(foundPub, kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                          digestData, foundSig, NULL);
    printf("found key signs: %d\n", foundOk);
    if (!foundOk) fails++;
    if (foundPub) CFRelease(foundPub);
    if (foundSig) CFRelease(foundSig);
  }
  if (found) CFRelease(found);

  const void *d_keys[] = {kSecClass, kSecAttrApplicationTag};
  const void *d_values[] = {kSecClassKey, tag};
  CFDictionaryRef del_query = CFDictionaryCreate(
      NULL, d_keys, d_values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  OSStatus delRc = SecItemDelete(del_query);
  printf("delete by tag: %d\n", delRc == errSecSuccess);
  if (delRc != errSecSuccess) fails++;

  SecKeyRef gone = NULL;
  OSStatus goneRc = SecItemCopyMatching(query, (CFTypeRef *)&gone);
  printf("gone after delete: %d\n", goneRc != errSecSuccess && gone == NULL);
  if (goneRc == errSecSuccess && gone) fails++;
  if (gone) CFRelease(gone);

  if (perm_key) CFRelease(perm_key);
  if (tag) CFRelease(tag);
  if (priv) CFRelease(priv);
  if (perm_params) CFRelease(perm_params);
  if (query) CFRelease(query);
  if (del_query) CFRelease(del_query);

  printf(fails ? "MECHANISM C: %d failure(s)\n" : "MECHANISM C: ok\n", fails);
  return fails ? 1 : 0;
}
