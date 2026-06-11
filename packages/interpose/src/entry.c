/**
 * @file entry.c
 * @brief The dylib constructor: installs the hooks at load, inert without configuration.
 *
 * @details
 * dyld runs the constructor when the dylib loads, before the app's main, so
 * the SecKey hooks are in place before any signer call. Loaded only via the
 * debug scheme's DYLD_INSERT_LIBRARIES; never bundled in a release build.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#include "../include/simenclave_interpose.h"

#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) static void simenclave_load(void) {
  // Inert without configuration: a stray DYLD_INSERT_LIBRARIES outside a wired dev
  // scheme installs nothing, which shrinks the blast radius of an accidental
  // injection. This is not the fence; a release build bundles no dylib at all.
  if (!getenv("SIMENCLAVE_PORT") && !getenv("SIMENCLAVE_TOKEN")) return;
  int failures = simenclave_install_hooks();
  if (failures != 0) {
    fprintf(stderr, "[simenclave] %d hook(s) failed to install\n", failures);
  }
}
