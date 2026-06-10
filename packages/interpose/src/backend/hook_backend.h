/**
 * @file hook_backend.h
 * @brief The swappable inline-hook seam the interposer installs hooks through.
 *
 * @details
 * The default backend is Dobby; nothing else in the interposer names a hook
 * library, so a different backend (a maintained fishhook fork, Apple's
 * __interpose) drops in here without touching the hooks, the registry, or the
 * transport. The seam exists because no single hooking library is allowed to
 * be load-bearing for the project.
 *
 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#ifndef SE_HOOK_BACKEND_H
#define SE_HOOK_BACKEND_H

/**
 * @defgroup se_backend Hook backend seam
 * @brief Resolve-and-install, behind a struct of two function pointers.
 * @{
 */

/** An inline-hook backend: how symbols resolve and how patches install. */
typedef struct {
  /// Resolve a function symbol to its address, or NULL when not found.
  void *(*resolve)(const char *symbol);
  /// Patch @p target so calls land in @p replacement; the original entry is
  /// returned via @p original for passthrough. Returns 0 on success.
  int (*install)(void *target, void *replacement, void **original);
} se_hook_backend;

/**
 * @brief The compiled-in default backend (Dobby).
 *
 * @return A static backend instance; never NULL, never freed.
 */
const se_hook_backend *se_default_backend(void);

/** @} */

#endif
