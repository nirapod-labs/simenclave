#include "shadow_ref.h"

#include <pthread.h>
#include <string.h>

// M0 holds a small fixed table; the dev loop generates a handful of keys. M2
// grows this with the SecItem tag mapping for persistence.
#define SE_MAX_SHADOWS 64

typedef struct {
  SecKeyRef shadow;
  uint8_t handle[64];
  size_t handle_len;
  SecKeyRef host_public;
} shadow_entry;

static shadow_entry g_entries[SE_MAX_SHADOWS];
static size_t g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void se_registry_add(SecKeyRef shadow, const uint8_t *handle, size_t handle_len, SecKeyRef host_public) {
  if (handle_len > sizeof(((shadow_entry *)0)->handle)) return;
  pthread_mutex_lock(&g_lock);
  if (g_count < SE_MAX_SHADOWS) {
    shadow_entry *e = &g_entries[g_count++];
    e->shadow = shadow;
    memcpy(e->handle, handle, handle_len);
    e->handle_len = handle_len;
    e->host_public = host_public;
    if (host_public) CFRetain(host_public);
  }
  pthread_mutex_unlock(&g_lock);
}

int se_registry_lookup(SecKeyRef key, uint8_t *handle, size_t cap, size_t *handle_len, SecKeyRef *host_public) {
  int found = 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].shadow == key) {
      if (g_entries[i].handle_len <= cap) {
        memcpy(handle, g_entries[i].handle, g_entries[i].handle_len);
        *handle_len = g_entries[i].handle_len;
        if (host_public) *host_public = g_entries[i].host_public;
        found = 1;
      }
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return found;
}

int se_registry_is_shadow(SecKeyRef key) {
  int found = 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].shadow == key) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return found;
}
