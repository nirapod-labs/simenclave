// The swappable inline-hook seam. The default is Dobby; nothing else in the
// interposer names a hook library, so a different backend drops in here without
// touching the hooks, the registry, or the transport.
#ifndef SE_HOOK_BACKEND_H
#define SE_HOOK_BACKEND_H

typedef struct {
  // Resolve a function symbol to its address, or NULL.
  void *(*resolve)(const char *symbol);
  // Patch target so it lands in replacement; return the original via *original.
  // Returns 0 on success.
  int (*install)(void *target, void *replacement, void **original);
} se_hook_backend;

const se_hook_backend *se_default_backend(void);

#endif
