/**
 * @file simenclave_interpose.h
 * @brief The injected interposer's entry points: hook installation and the
 *        hook-fire counters.
 *
 * @details
 * The dylib's constructor calls ::simenclave_install_hooks at load when the
 * environment is configured (SIMENCLAVE_PORT or SIMENCLAVE_TOKEN present) and
 * stays inert otherwise. The stats exist so a host harness can confirm the
 * hooks fired rather than inferring it from behavior.
 *
 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#ifndef SIMENCLAVE_INTERPOSE_H
#define SIMENCLAVE_INTERPOSE_H

/**
 * @defgroup se_interpose Interposer entry points
 * @brief What the dylib exposes beyond the hooks themselves.
 * @{
 */

/**
 * @brief Install the SecKey hooks through the hook backend.
 *
 * @return The number of hooks that failed to install; 0 means every hook is in
 *         place.
 */
int simenclave_install_hooks(void);

/** How many times each routed hook has fired since install. */
typedef struct {
  int create_random_key; ///< SecKeyCreateRandomKey calls routed to the helper.
  int copy_public_key;   ///< SecKeyCopyPublicKey calls answered from the registry.
  int create_signature;  ///< SecKeyCreateSignature calls routed to the helper.
} simenclave_hook_stats;

/**
 * @brief Read the hook-fire counters.
 *
 * @return A copy of the counters at the time of the call.
 */
simenclave_hook_stats simenclave_get_hook_stats(void);

/** @} */

#endif
