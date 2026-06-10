// dyld runs this constructor when the dylib loads, before the app's main, so the
// SecKey hooks are in place before any signer call. Loaded only via the debug
// scheme's DYLD_INSERT_LIBRARIES; never bundled in a release build.
#include "../include/simenclave_interpose.h"

#include <stdio.h>

__attribute__((constructor)) static void simenclave_load(void) {
  int failures = simenclave_install_hooks();
  if (failures != 0) {
    fprintf(stderr, "[simenclave] %d SecKey hook(s) failed to install\n", failures);
  }
}
