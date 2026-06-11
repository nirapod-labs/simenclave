/**
 * @file dobby_backend.c
 * @brief Default hook backend: Dobby inline hooking.
 *
 * @details
 * Inline hooking patches the resolved function, so it is independent of the
 * symbol-binding format and works in the simulator where code-signing is
 * relaxed. Dobby itself is Apache-2.0, fetched and pinned by CMake.
 *
 * @see hook_backend.h for the seam this implements.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#include "hook_backend.h"

#include <stddef.h>

#include "dobby.h"

static void *dobby_resolve(const char *symbol) { return DobbySymbolResolver(NULL, symbol); }

static int dobby_install(void *target, void *replacement, void **original) {
  return DobbyHook(target, replacement, original);
}

static const se_hook_backend kDobbyBackend = {dobby_resolve, dobby_install};

const se_hook_backend *se_default_backend(void) { return &kDobbyBackend; }
