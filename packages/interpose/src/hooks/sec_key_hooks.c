// The M0 hook set. A Secure Enclave key request routes to the host helper and
// comes back as a shadow ref; the shadow's public-key and signature calls route
// to the host. Every non-SE call passes through to the saved original. M2 splits
// these per symbol and adds the SecItem persistence hooks.
#include "../../include/simenclave_interpose.h"
#include "../backend/hook_backend.h"
#include "../registry/shadow_ref.h"
#include "../transport/client.h"

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>

typedef SecKeyRef (*create_random_key_fn)(CFDictionaryRef, CFErrorRef *);
typedef SecKeyRef (*copy_public_key_fn)(SecKeyRef);
typedef CFDataRef (*create_signature_fn)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);

static create_random_key_fn orig_create_random_key;
static copy_public_key_fn orig_copy_public_key;
static create_signature_fn orig_create_signature;

static simenclave_hook_stats g_stats = {0, 0, 0};

static int requests_secure_enclave(CFDictionaryRef parameters) {
  if (!parameters) return 0;
  const void *token = CFDictionaryGetValue(parameters, kSecAttrTokenID);
  return token != NULL && CFEqual(token, kSecAttrTokenIDSecureEnclave);
}

static SecKeyRef make_host_public_key(const uint8_t *x963, size_t len) {
  CFDataRef data = CFDataCreate(NULL, x963, (CFIndex)len);
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
  const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, bitsRef};
  CFDictionaryRef attributes = CFDictionaryCreate(
      NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFErrorRef error = NULL;
  SecKeyRef key = SecKeyCreateWithData(data, attributes, &error);
  if (data) CFRelease(data);
  if (bitsRef) CFRelease(bitsRef);
  if (attributes) CFRelease(attributes);
  if (error) CFRelease(error);
  return key;
}

// An inert software key, used only as the opaque ref the app holds. Its own key
// material is never used; the hooks route to the host instead.
static SecKeyRef make_shadow(CFErrorRef *error) {
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits};
  const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, bitsRef};
  CFDictionaryRef attributes = CFDictionaryCreate(
      NULL, keys, values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecKeyRef shadow = orig_create_random_key(attributes, error);
  if (bitsRef) CFRelease(bitsRef);
  if (attributes) CFRelease(attributes);
  return shadow;
}

static SecKeyRef hook_create_random_key(CFDictionaryRef parameters, CFErrorRef *error) {
  if (!requests_secure_enclave(parameters)) {
    return orig_create_random_key(parameters, error);
  }
  se_response response;
  if (se_client_generate(&response) != SE_OK || response.kind != SE_RESP_GENERATED) {
    return orig_create_random_key(parameters, error);
  }
  SecKeyRef host_public = make_host_public_key(response.public_key, response.public_key_len);
  SecKeyRef shadow = make_shadow(error);
  if (!shadow) {
    if (host_public) CFRelease(host_public);
    return NULL;
  }
  se_registry_add(shadow, response.handle, response.handle_len, host_public);
  if (host_public) CFRelease(host_public);
  g_stats.create_random_key++;
  return shadow;
}

static SecKeyRef hook_copy_public_key(SecKeyRef key) {
  uint8_t handle[64];
  size_t handle_len = 0;
  SecKeyRef host_public = NULL;
  if (se_registry_lookup(key, handle, sizeof(handle), &handle_len, &host_public) && host_public) {
    g_stats.copy_public_key++;
    CFRetain(host_public);
    return host_public;
  }
  return orig_copy_public_key(key);
}

static CFDataRef hook_create_signature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                       CFDataRef dataToSign, CFErrorRef *error) {
  uint8_t handle[64];
  size_t handle_len = 0;
  SecKeyRef host_public = NULL;
  if (!se_registry_lookup(key, handle, sizeof(handle), &handle_len, &host_public)) {
    return orig_create_signature(key, algorithm, dataToSign, error);
  }

  uint8_t computed[CC_SHA256_DIGEST_LENGTH];
  const uint8_t *digest;
  size_t digest_len;
  if (CFEqual(algorithm, kSecKeyAlgorithmECDSASignatureDigestX962SHA256)) {
    digest = CFDataGetBytePtr(dataToSign);
    digest_len = (size_t)CFDataGetLength(dataToSign);
  } else {
    CC_SHA256(CFDataGetBytePtr(dataToSign), (CC_LONG)CFDataGetLength(dataToSign), computed);
    digest = computed;
    digest_len = CC_SHA256_DIGEST_LENGTH;
  }

  se_response response;
  if (se_client_sign(handle, handle_len, digest, digest_len, &response) != SE_OK ||
      response.kind != SE_RESP_SIGNED) {
    return NULL;
  }
  g_stats.create_signature++;
  return CFDataCreate(NULL, response.signature, (CFIndex)response.signature_len);
}

int simenclave_install_hooks(void) {
  const se_hook_backend *backend = se_default_backend();
  struct {
    const char *name;
    void *replacement;
    void **original;
  } table[] = {
      {"SecKeyCreateRandomKey", (void *)hook_create_random_key, (void **)&orig_create_random_key},
      {"SecKeyCopyPublicKey", (void *)hook_copy_public_key, (void **)&orig_copy_public_key},
      {"SecKeyCreateSignature", (void *)hook_create_signature, (void **)&orig_create_signature},
  };
  int failures = 0;
  for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
    void *address = backend->resolve(table[i].name);
    if (!address || backend->install(address, table[i].replacement, table[i].original) != 0) {
      failures++;
    }
  }
  return failures;
}

simenclave_hook_stats simenclave_get_hook_stats(void) { return g_stats; }
