// The shadow-ref registry. A host SEP key is represented to the app by an inert
// software SecKeyRef; this maps that ref to the host handle and the cached host
// public key, so the hooks can consult it and route private operations to the
// host.
#ifndef SE_SHADOW_REF_H
#define SE_SHADOW_REF_H

#include <Security/Security.h>
#include <stddef.h>
#include <stdint.h>

// Register a shadow ref. Retains both the shadow and the host public key, and
// copies the handle bytes. The registry owns its references until
// se_registry_remove or process exit, so a registered shadow's address cannot be
// freed and reused by a non-SE key, which would otherwise misroute it.
void se_registry_add(SecKeyRef shadow, const uint8_t *handle, size_t handle_len,
                     SecKeyRef host_public);

// If key is a known shadow, copy its handle out. When host_public is non-NULL,
// return a +1-retained reference to the cached host public key, which the caller
// releases; the retain happens under the lock so a concurrent remove cannot free
// it in the gap. Returns 1 on hit, 0 otherwise.
int se_registry_lookup(SecKeyRef key, uint8_t *handle, size_t cap, size_t *handle_len,
                       SecKeyRef *host_public);

// Whether key is a registered shadow ref.
int se_registry_is_shadow(SecKeyRef key);

// Remove a shadow, releasing the registry's references to it and its cached
// public key. A no-op if the key is not registered.
void se_registry_remove(SecKeyRef shadow);

#endif
