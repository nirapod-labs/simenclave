// The injected interposer's entry points. The constructor calls
// simenclave_install_hooks at load; the stats are exposed so a host harness can
// confirm the hooks fired.
#ifndef SIMENCLAVE_INTERPOSE_H
#define SIMENCLAVE_INTERPOSE_H

// Install the SecKey hooks through the hook backend. Returns the number of hooks
// that failed to install, so 0 means success.
int simenclave_install_hooks(void);

typedef struct {
  int create_random_key;
  int copy_public_key;
  int create_signature;
} simenclave_hook_stats;

simenclave_hook_stats simenclave_get_hook_stats(void);

#endif
