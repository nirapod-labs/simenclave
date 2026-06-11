/**
 * @file shadow_ref.h
 * @brief The shadow-ref registry: maps each inert shadow SecKeyRef to its host
 *        handle and cached host public key.
 *
 * @details
 * A host SEP key is represented to the app by an inert software SecKeyRef (a
 * public-key-only carrier that cannot sign), and this registry is what the
 * hooks consult to route private operations to the host. The registry retains
 * everything it holds until ::se_registry_remove or process exit, so a
 * registered shadow's address cannot be freed and reused by a non-SE key,
 * which would otherwise misroute it.
 *
 * All functions are safe to call from any thread; the table is guarded by one
 * internal lock.
 *
 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#ifndef SE_SHADOW_REF_H
#define SE_SHADOW_REF_H

#include <Security/Security.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup se_registry Shadow-ref registry
 * @brief The map from shadow SecKeyRef to host handle, public key, and tag.
 * @{
 */

/**
 * @brief Register a shadow ref.
 *
 * Retains the shadow, the host public key, and the optional SecItem tag, and
 * copies the handle bytes. The registry owns its references until
 * ::se_registry_remove or process exit.
 *
 * @param[in] shadow      The inert carrier SecKeyRef handed to the app.
 * @param[in] handle      Host handle bytes from the GENERATE response.
 * @param[in] handle_len  Length of @p handle.
 * @param[in] host_public The host public key as a SecKeyRef, for verify-side reuse.
 * @param[in] tag         Application tag from the create, or NULL.
 */
void se_registry_add(SecKeyRef shadow, const uint8_t *handle, size_t handle_len,
                     SecKeyRef host_public, CFDataRef tag);

/**
 * @brief Look a shadow up and copy its handle out.
 *
 * When @p host_public is non-NULL, returns a +1-retained reference to the
 * cached host public key, which the caller releases; the retain happens under
 * the lock so a concurrent remove cannot free it in the gap.
 *
 * @param[in]  key         The SecKeyRef to test.
 * @param[out] handle      Buffer the handle is copied into.
 * @param[in]  cap         Capacity of @p handle.
 * @param[out] handle_len  Meaningful bytes written to @p handle.
 * @param[out] host_public +1-retained cached public key, or skipped when NULL.
 * @return 1 on a hit, 0 when @p key is not a registered shadow.
 */
int se_registry_lookup(SecKeyRef key, uint8_t *handle, size_t cap, size_t *handle_len,
                       SecKeyRef *host_public);

/**
 * @brief Whether @p key is a registered shadow ref.
 *
 * @param[in] key The SecKeyRef to test.
 * @return 1 if registered, 0 otherwise.
 */
int se_registry_is_shadow(SecKeyRef key);

/**
 * @brief Find a shadow by its application tag (set at create or via ::se_registry_set_tag).
 *
 * @param[out] shadow     On a hit, a +1-retained shadow ref the caller releases.
 * @param[in]  tag        The application tag to search.
 * @param[out] handle     Buffer the handle is copied into.
 * @param[in]  cap        Capacity of @p handle.
 * @param[out] handle_len Meaningful bytes written to @p handle.
 * @return 1 on a hit, 0 otherwise.
 */
int se_registry_find_by_tag(CFDataRef tag, SecKeyRef *shadow, uint8_t *handle, size_t cap,
                            size_t *handle_len);

/**
 * @brief Attach an application tag to an already-registered shadow.
 *
 * For an explicit SecItemAdd of a key created without one. A no-op if @p shadow
 * is not registered.
 *
 * @param[in] shadow The registered shadow ref.
 * @param[in] tag    The application tag to attach; retained.
 */
void se_registry_set_tag(SecKeyRef shadow, CFDataRef tag);

/**
 * @brief Remove a shadow, releasing the registry's references to it, its cached
 *        public key, and its tag.
 *
 * A no-op if @p shadow is not registered.
 *
 * @param[in] shadow The shadow ref to remove.
 */
void se_registry_remove(SecKeyRef shadow);

/** @} */

#endif
