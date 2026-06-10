// The shadow-ref registry. A host SEP key is represented to the app by an inert
// software SecKeyRef; this maps that ref to the host handle and the cached host
// public key, so the hooks can consult it and route private operations to the
// host.
#ifndef SE_SHADOW_REF_H
#define SE_SHADOW_REF_H

#include <Security/Security.h>
#include <stddef.h>
#include <stdint.h>

// Register a shadow ref. Retains host_public; copies the handle bytes.
void se_registry_add(SecKeyRef shadow, const uint8_t *handle, size_t handle_len,
                     SecKeyRef host_public);

// If key is a known shadow, copy its handle and lend its host public key.
// Returns 1 on hit, 0 otherwise.
int se_registry_lookup(SecKeyRef key, uint8_t *handle, size_t cap, size_t *handle_len,
                       SecKeyRef *host_public);

// Whether key is a registered shadow ref.
int se_registry_is_shadow(SecKeyRef key);

#endif
