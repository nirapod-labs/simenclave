// The M2 hook set. A Secure Enclave key request routes to the host helper and
// comes back as a public-key-only shadow ref; the shadow's public-key and
// signature calls route to the host. Every non-SE call passes through to the
// saved original. The shadow cannot sign, so a routing miss fails loud rather
// than ever emitting a software signature. M2 slice 3 adds the SecItem hooks.
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

// A CFError so a routed failure looks like a device's: SecKey failures always
// populate the error out-parameter, and an app may read or unwrap it.
static void set_error(CFErrorRef *error, OSStatus code) {
  if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, code, NULL);
}

// Whether a dictionary asks for a Secure Enclave key.
static int dict_has_se_token(CFDictionaryRef d) {
  if (!d) return 0;
  const void *token = CFDictionaryGetValue(d, kSecAttrTokenID);
  return token != NULL && CFEqual(token, kSecAttrTokenIDSecureEnclave);
}

// The Secure Enclave token can sit at the top of the parameters or inside
// kSecPrivateKeyAttrs. Missing the nested form would pass an SE create through to
// a software create, the one false negative that defeats fail-closed at create
// time, so both are checked. Conservative: any non-positive result passes through.
static int requests_secure_enclave(CFDictionaryRef parameters) {
  if (!parameters) return 0;
  if (dict_has_se_token(parameters)) return 1;
  const void *priv = CFDictionaryGetValue(parameters, kSecPrivateKeyAttrs);
  if (priv && CFGetTypeID(priv) == CFDictionaryGetTypeID()) {
    return dict_has_se_token((CFDictionaryRef)priv);
  }
  return 0;
}

// Build a public SecKeyRef from a 65-byte uncompressed X9.63 point. The length
// and 0x04 lead byte are validated so a malformed point fails closed (NULL),
// never a half-built key.
static SecKeyRef make_public_key(const uint8_t *x963, size_t len) {
  if (len != 65 || x963[0] != 0x04) return NULL;
  CFDataRef data = CFDataCreate(NULL, x963, (CFIndex)len);
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits};
  const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, bitsRef};
  CFDictionaryRef attributes = CFDictionaryCreate(
      NULL, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecKeyRef key = SecKeyCreateWithData(data, attributes, NULL);
  if (data) CFRelease(data);
  if (bitsRef) CFRelease(bitsRef);
  if (attributes) CFRelease(attributes);
  return key;
}

// The shadow stands in for the host private key but is a public key, so it cannot
// sign. Assert that, so a carrier that reports it can sign is refused rather than
// registered: the fail-closed invariant is checked, not believed.
static int carrier_cannot_sign(SecKeyRef carrier) {
  return !SecKeyIsAlgorithmSupported(carrier, kSecKeyOperationTypeSign,
                                     kSecKeyAlgorithmECDSASignatureDigestX962SHA256);
}

static SecKeyRef hook_create_random_key(CFDictionaryRef parameters, CFErrorRef *error) {
  if (!orig_create_random_key) { // install-window guard, fail closed with an error
    set_error(error, errSecNotAvailable);
    return NULL;
  }
  if (!requests_secure_enclave(parameters)) {
    return orig_create_random_key(parameters, error);
  }

  se_response response;
  se_status st = se_client_generate(&response);
  if (st != SE_OK || response.kind != SE_RESP_GENERATED) {
    // An SE create yields a host-backed key or fails; it never falls through to a
    // software create, which would defeat fail-closed at create time.
    OSStatus code = (st == SE_OK && response.kind == SE_RESP_ERROR && response.error_code != 0)
                        ? response.error_code
                        : errSecNotAvailable;
    set_error(error, code);
    return NULL;
  }

  SecKeyRef shadow = make_public_key(response.public_key, response.public_key_len);
  SecKeyRef host_public = make_public_key(response.public_key, response.public_key_len);
  if (!shadow || !host_public || !carrier_cannot_sign(shadow)) {
    if (shadow) CFRelease(shadow);
    if (host_public) CFRelease(host_public);
    set_error(error, errSecInternalComponent);
    return NULL;
  }

  se_registry_add(shadow, response.handle, response.handle_len, host_public);
  CFRelease(host_public); // the registry holds its own reference
  g_stats.create_random_key++;
  return shadow; // +1 to the app; the registry holds a second reference
}

static SecKeyRef hook_copy_public_key(SecKeyRef key) {
  if (!orig_copy_public_key) return NULL; // install-window guard
  uint8_t handle[64];
  size_t handle_len = 0;
  SecKeyRef host_public = NULL;
  if (se_registry_lookup(key, handle, sizeof(handle), &handle_len, &host_public) && host_public) {
    g_stats.copy_public_key++;
    return host_public; // already +1 from the lookup, handed to the caller
  }
  return orig_copy_public_key(key);
}

// The signing algorithms M2 maps: the X9.62 (DER) SHA-256 pair. Digest forwards
// the caller's 32 bytes after a length check; message hashes first. Every other
// algorithm, including the RFC4754 raw-encoding variants the wire cannot carry, is
// refused, because guessing a hash or an encoding forges over the wrong bytes.
static int reduce_to_digest(SecKeyAlgorithm algorithm, CFDataRef dataToSign, uint8_t *out,
                            size_t *out_len) {
  if (!dataToSign) return -1;
  if (CFEqual(algorithm, kSecKeyAlgorithmECDSASignatureDigestX962SHA256)) {
    if (CFDataGetLength(dataToSign) != CC_SHA256_DIGEST_LENGTH) return -1;
    memcpy(out, CFDataGetBytePtr(dataToSign), CC_SHA256_DIGEST_LENGTH);
    *out_len = CC_SHA256_DIGEST_LENGTH;
    return 0;
  }
  if (CFEqual(algorithm, kSecKeyAlgorithmECDSASignatureMessageX962SHA256)) {
    CC_SHA256(CFDataGetBytePtr(dataToSign), (CC_LONG)CFDataGetLength(dataToSign), out);
    *out_len = CC_SHA256_DIGEST_LENGTH;
    return 0;
  }
  return -1;
}

static CFDataRef hook_create_signature(SecKeyRef key, SecKeyAlgorithm algorithm,
                                       CFDataRef dataToSign, CFErrorRef *error) {
  if (!orig_create_signature) { // install-window guard, fail closed with an error
    set_error(error, errSecNotAvailable);
    return NULL;
  }
  uint8_t handle[64];
  size_t handle_len = 0;
  if (!se_registry_lookup(key, handle, sizeof(handle), &handle_len, NULL)) {
    return orig_create_signature(key, algorithm, dataToSign, error);
  }

  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  size_t digest_len = 0;
  if (reduce_to_digest(algorithm, dataToSign, digest, &digest_len) != 0) {
    set_error(error, errSecParam); // unsupported algorithm or wrong digest length
    return NULL;
  }

  se_response response;
  se_status st = se_client_sign(handle, handle_len, digest, digest_len, &response);
  if (st != SE_OK) {
    set_error(error, errSecNotAvailable); // could not reach the helper
    return NULL;
  }
  if (response.kind != SE_RESP_SIGNED) {
    OSStatus code = (response.kind == SE_RESP_ERROR && response.error_code != 0)
                        ? response.error_code
                        : errSecInternalComponent;
    set_error(error, code);
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
