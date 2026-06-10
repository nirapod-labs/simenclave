/**
 * @file sec_key_hooks.c
 * @brief The hook set: SecKey, SecItem, and SecAccessControl interception.
 *
 * @details
 * A Secure Enclave key request routes to the host helper and comes back as a
 * public-key-only shadow ref; the shadow's public-key and signature calls
 * route to the host. Every non-SE call passes through to the saved original.
 * The shadow cannot sign, so a routing miss fails loud rather than ever
 * emitting a software signature. The SecItem hooks persist a key by tag
 * within the session; durable persistence across relaunches is M5.
 *

 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#include "../../include/simenclave_interpose.h"
#include "../backend/hook_backend.h"
#include "../registry/access_control.h"
#include "../registry/shadow_ref.h"
#include "../transport/client.h"

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <string.h>

typedef SecKeyRef (*create_random_key_fn)(CFDictionaryRef, CFErrorRef *);
typedef SecKeyRef (*copy_public_key_fn)(SecKeyRef);
typedef CFDataRef (*create_signature_fn)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
typedef CFDictionaryRef (*copy_attributes_fn)(SecKeyRef);
typedef CFDataRef (*copy_external_representation_fn)(SecKeyRef, CFErrorRef *);
typedef SecAccessControlRef (*ac_create_with_flags_fn)(CFAllocatorRef, CFTypeRef,
                                                       SecAccessControlCreateFlags, CFErrorRef *);

static create_random_key_fn orig_create_random_key;
static copy_public_key_fn orig_copy_public_key;
static create_signature_fn orig_create_signature;
static copy_attributes_fn orig_copy_attributes;
static copy_external_representation_fn orig_copy_external_representation;
static ac_create_with_flags_fn orig_ac_create_with_flags;

// The access-control flags that make a key require a prompt at sign time: any
// biometric or user-presence constraint. A key carrying any of these is the biometry
// class on the wire (key 9); a key with none is silent. kSecAccessControlWatch is left
// out on purpose: it is unavailable to an iOS guest. The class bit only drives the
// prompt UX; the SEP gate itself is rebuilt from the raw relayed flags, so a class-bit
// miss never weakens the gate.
static const SecAccessControlCreateFlags SE_PROMPT_FLAGS =
    kSecAccessControlUserPresence | kSecAccessControlBiometryAny |
    kSecAccessControlBiometryCurrentSet | kSecAccessControlDevicePasscode;

static simenclave_hook_stats g_stats = {0, 0, 0};

// A CFError so a routed failure looks like a device's: SecKey failures always
// populate the error out-parameter, and an app may read or unwrap it.
static void set_error(CFErrorRef *error, OSStatus code) {
  if (error) *error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, code, NULL);
}

// Build a CFError in the domain the helper named (wire key 13), so a routed biometric
// failure looks like the device's: most failures are kCFErrorDomainOSStatus, a biometric
// one may be the LocalAuthentication domain. Selector 1 is LocalAuthentication; anything
// else is the OSStatus domain, the default and the unchanged behavior.
static void set_error_in_domain(CFErrorRef *error, OSStatus code, int domain_selector) {
  if (!error) return;
  CFStringRef domain =
      domain_selector == 1 ? CFSTR("com.apple.LocalAuthentication") : kCFErrorDomainOSStatus;
  *error = CFErrorCreate(NULL, domain, code, NULL);
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

// If the create asks for a permanent key with an application tag, return that tag
// (borrowed) so the registry can find the key later by tag. The attributes live in
// kSecPrivateKeyAttrs for a key creation, with the top level as a fallback.
static CFDataRef extract_permanent_tag(CFDictionaryRef parameters) {
  if (!parameters) return NULL;
  CFDictionaryRef attrs = parameters;
  const void *priv = CFDictionaryGetValue(parameters, kSecPrivateKeyAttrs);
  if (priv && CFGetTypeID(priv) == CFDictionaryGetTypeID()) attrs = (CFDictionaryRef)priv;
  const void *perm = CFDictionaryGetValue(attrs, kSecAttrIsPermanent);
  if (!perm || !CFEqual(perm, kCFBooleanTrue)) return NULL;
  const void *tag = CFDictionaryGetValue(attrs, kSecAttrApplicationTag);
  if (tag && CFGetTypeID(tag) == CFDataGetTypeID()) return (CFDataRef)tag;
  return NULL;
}

// The kSecAttrAccessControl an SE create passes lives in kSecPrivateKeyAttrs, with the
// top level as a fallback. Returns the ref (borrowed) or NULL.
static SecAccessControlRef extract_access_control(CFDictionaryRef parameters) {
  if (!parameters) return NULL;
  CFDictionaryRef attrs = parameters;
  const void *priv = CFDictionaryGetValue(parameters, kSecPrivateKeyAttrs);
  if (priv && CFGetTypeID(priv) == CFDictionaryGetTypeID()) attrs = (CFDictionaryRef)priv;
  const void *ac = CFDictionaryGetValue(attrs, kSecAttrAccessControl);
  if (ac && CFGetTypeID(ac) == SecAccessControlGetTypeID()) return (SecAccessControlRef)ac;
  return NULL;
}

// The guest app's bundle id, for the approval prompt. Copies it into buf (UTF8) and
// returns its length, or 0 if there is no main bundle id. Guest-reported, so it names the
// app but is not an access boundary; the token is.
static size_t current_app_id(char *buf, size_t cap) {
  CFBundleRef bundle = CFBundleGetMainBundle();
  CFStringRef id = bundle ? CFBundleGetIdentifier(bundle) : NULL;
  if (id && CFStringGetCString(id, buf, (CFIndex)cap, kCFStringEncodingUTF8)) {
    return strlen(buf);
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

// Capture the (protection, flags) the app passed to SecAccessControlCreateWithFlags,
// keyed by the returned ref, so the create hook can read the otherwise-opaque access
// control later. Always returns the real result untouched; the capture is a side
// effect, so passthrough holds for every caller, Secure Enclave create or not.
static SecAccessControlRef hook_ac_create_with_flags(CFAllocatorRef allocator, CFTypeRef protection,
                                                     SecAccessControlCreateFlags flags,
                                                     CFErrorRef *error) {
  if (!orig_ac_create_with_flags) { // install-window guard, fail closed with an error
    set_error(error, errSecNotAvailable);
    return NULL;
  }
  SecAccessControlRef ac = orig_ac_create_with_flags(allocator, protection, flags, error);
  if (ac && protection && CFGetTypeID(protection) == CFStringGetTypeID()) {
    se_ac_capture(ac, (CFStringRef)protection, flags);
  }
  return ac;
}

static SecKeyRef hook_create_random_key(CFDictionaryRef parameters, CFErrorRef *error) {
  if (!orig_create_random_key) { // install-window guard, fail closed with an error
    set_error(error, errSecNotAvailable);
    return NULL;
  }
  if (!requests_secure_enclave(parameters)) {
    return orig_create_random_key(parameters, error);
  }

  // Read the app's access control, if it passed one whose policy was captured at its
  // source (the SecAccessControlCreateWithFlags hook). The flags pick the key class
  // for the prompt, and the flags and protection are relayed verbatim so the helper
  // rebuilds the same gate. An access control that was not captured is a miss, and the
  // create routes as a plain silent key rather than guessing a gate.
  // The guest app id rides the generate, so the helper's approval prompt can name the
  // connecting app. Guest-reported, so it names the app but gates nothing.
  char app_id[256];
  size_t app_id_len = current_app_id(app_id, sizeof(app_id));

  se_response response;
  se_status st;
  SecAccessControlRef ac = extract_access_control(parameters);
  SecAccessControlCreateFlags flags = 0;
  CFStringRef protection = NULL;
  if (ac && se_ac_lookup(ac, &flags, &protection)) {
    char prot[64];
    size_t prot_len = 0;
    if (protection && CFStringGetCString(protection, prot, sizeof(prot), kCFStringEncodingUTF8)) {
      prot_len = strlen(prot);
    }
    int biometry = (flags & SE_PROMPT_FLAGS) != 0;
    st = se_client_generate_ac(biometry, (uint64_t)flags, (const uint8_t *)prot, prot_len,
                               (const uint8_t *)app_id, app_id_len, &response);
    if (protection) CFRelease(protection); // se_ac_lookup returned it +1
  } else {
    st = se_client_generate((const uint8_t *)app_id, app_id_len, &response);
  }
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

  CFDataRef tag = extract_permanent_tag(parameters); // borrowed; the registry retains it
  se_registry_add(shadow, response.handle, response.handle_len, host_public, tag);
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
    // A biometric failure carries the device's error domain (key 13), so the rebuilt
    // CFError matches what a device returns; other failures stay in the OSStatus domain.
    set_error_in_domain(error, code, response.error_domain);
    return NULL;
  }
  g_stats.create_signature++;
  return CFDataCreate(NULL, response.signature, (CFIndex)response.signature_len);
}

// --- Fidelity hooks: the shadow reads like a device SE private key under introspection ---

// A device's SE private key reports the Secure Enclave token and the private key class
// under SecKeyCopyAttributes. The public-key carrier, unhooked, would report class public
// and no token, the tell that it is a stand-in. So for a registered shadow the hook
// synthesizes the attributes a real SE private key returns; anything else passes through.
// The core attributes (token, class, type, size) are knowable and asserted; the
// exhaustive dictionary is device-reference work to be captured before M4.
static CFDictionaryRef hook_copy_attributes(SecKeyRef key) {
  if (!orig_copy_attributes) return NULL; // install-window guard
  if (!se_registry_is_shadow(key)) return orig_copy_attributes(key);
  int bits = 256;
  CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  const void *keys[] = {kSecAttrKeyType, kSecAttrKeyClass, kSecAttrKeySizeInBits, kSecAttrTokenID};
  const void *values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPrivate, bitsRef,
                          kSecAttrTokenIDSecureEnclave};
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 4, &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);
  if (bitsRef) CFRelease(bitsRef);
  return attrs; // +1 to the caller, as a Copy function returns
}

// A device's SE private key is not exportable: SecKeyCopyExternalRepresentation returns
// NULL with an error. The carrier is a public key, so unhooked it would succeed and hand
// back the point, the wrong behavior for something claiming to be a private SE key. So a
// registered shadow gets that not-exportable error; the shadow's public key is not a
// registered shadow, so it passes through and exports as a device's public key does. The
// exact error code is device-reference work; errSecParam is the seed until a device run.
static CFDataRef hook_copy_external_representation(SecKeyRef key, CFErrorRef *error) {
  if (!orig_copy_external_representation) { // install-window guard, fail closed with an error
    set_error(error, errSecNotAvailable);
    return NULL;
  }
  if (!se_registry_is_shadow(key)) return orig_copy_external_representation(key, error);
  set_error(error, errSecParam); // a device refuses to export an SE private key
  return NULL;
}

// --- SecItem hooks: persistence by tag, in-session ---

typedef OSStatus (*item_add_fn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*item_copy_matching_fn)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*item_delete_fn)(CFDictionaryRef);

static item_add_fn orig_item_add;
static item_copy_matching_fn orig_item_copy_matching;
static item_delete_fn orig_item_delete;

// A query naming one of our keys: class key, returning a ref, at most one match,
// with an application tag. Anything else is out of M2's scope and passes through,
// so non-SE keychain traffic is never perturbed. Whether the tag is actually ours
// is decided by the registry, not here, so an unknown tag still passes through.
static int is_se_key_ref_query(CFDictionaryRef query) {
  if (!query) return 0;
  const void *cls = CFDictionaryGetValue(query, kSecClass);
  if (!cls || !CFEqual(cls, kSecClassKey)) return 0;
  const void *ret = CFDictionaryGetValue(query, kSecReturnRef);
  if (!ret || !CFEqual(ret, kCFBooleanTrue)) return 0;
  const void *limit = CFDictionaryGetValue(query, kSecMatchLimit);
  if (limit && !CFEqual(limit, kSecMatchLimitOne)) return 0; // absent means one
  const void *tag = CFDictionaryGetValue(query, kSecAttrApplicationTag);
  return tag != NULL && CFGetTypeID(tag) == CFDataGetTypeID();
}

// A delete query naming one of our keys: class key with a tag. Return type and
// match limit do not apply to a delete.
static int is_se_key_delete(CFDictionaryRef query) {
  if (!query) return 0;
  const void *cls = CFDictionaryGetValue(query, kSecClass);
  if (!cls || !CFEqual(cls, kSecClassKey)) return 0;
  const void *tag = CFDictionaryGetValue(query, kSecAttrApplicationTag);
  return tag != NULL && CFGetTypeID(tag) == CFDataGetTypeID();
}

static OSStatus hook_item_add(CFDictionaryRef attributes, CFTypeRef *result) {
  if (!orig_item_add) return errSecNotAvailable; // install-window guard
  // The explicit persist of a key we issued: attach its tag and report success,
  // since the key lives in the host SEP, not the guest keychain. Anything else
  // passes through untouched.
  if (attributes) {
    const void *ref = CFDictionaryGetValue(attributes, kSecValueRef);
    const void *tag = CFDictionaryGetValue(attributes, kSecAttrApplicationTag);
    if (ref && se_registry_is_shadow((SecKeyRef)ref) && tag &&
        CFGetTypeID(tag) == CFDataGetTypeID()) {
      se_registry_set_tag((SecKeyRef)ref, (CFDataRef)tag);
      return errSecSuccess;
    }
  }
  return orig_item_add(attributes, result);
}

static OSStatus hook_item_copy_matching(CFDictionaryRef query, CFTypeRef *result) {
  if (!orig_item_copy_matching) return errSecNotAvailable; // install-window guard
  if (is_se_key_ref_query(query)) {
    CFDataRef tag = (CFDataRef)CFDictionaryGetValue(query, kSecAttrApplicationTag);
    SecKeyRef shadow = NULL;
    uint8_t handle[64];
    size_t handle_len = 0;
    if (se_registry_find_by_tag(tag, &shadow, handle, sizeof(handle), &handle_len)) {
      if (result) {
        *result = shadow; // +1 from find_by_tag, handed to the caller
      } else if (shadow) {
        CFRelease(shadow);
      }
      return errSecSuccess;
    }
  }
  return orig_item_copy_matching(query, result); // saved original, never the symbol
}

static OSStatus hook_item_delete(CFDictionaryRef query) {
  if (!orig_item_delete) return errSecNotAvailable; // install-window guard
  if (is_se_key_delete(query)) {
    CFDataRef tag = (CFDataRef)CFDictionaryGetValue(query, kSecAttrApplicationTag);
    SecKeyRef shadow = NULL;
    uint8_t handle[64];
    size_t handle_len = 0;
    if (se_registry_find_by_tag(tag, &shadow, handle, sizeof(handle), &handle_len)) {
      se_response response;
      se_status st = se_client_delete(handle, handle_len, &response);
      se_registry_remove(shadow);
      CFRelease(shadow); // find_by_tag retained it
      if (st != SE_OK) return errSecNotAvailable;
      if (response.kind != SE_RESP_DELETED) {
        return (response.kind == SE_RESP_ERROR && response.error_code != 0)
                   ? response.error_code
                   : errSecInternalComponent;
      }
      return errSecSuccess;
    }
  }
  return orig_item_delete(query); // saved original, never the symbol
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
      {"SecKeyCopyAttributes", (void *)hook_copy_attributes, (void **)&orig_copy_attributes},
      {"SecKeyCopyExternalRepresentation", (void *)hook_copy_external_representation,
       (void **)&orig_copy_external_representation},
      {"SecAccessControlCreateWithFlags", (void *)hook_ac_create_with_flags,
       (void **)&orig_ac_create_with_flags},
      {"SecItemAdd", (void *)hook_item_add, (void **)&orig_item_add},
      {"SecItemCopyMatching", (void *)hook_item_copy_matching, (void **)&orig_item_copy_matching},
      {"SecItemDelete", (void *)hook_item_delete, (void **)&orig_item_delete},
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
