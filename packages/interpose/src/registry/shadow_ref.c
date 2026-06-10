/**
 * @file shadow_ref.c
 * @brief Shadow-ref registry implementation: a small table behind one lock.
 *
 * @details
 *
 * @see shadow_ref.h for the API documentation.
 *

 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#include "shadow_ref.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

// A small fixed table; a dev session generates a handful of keys, not millions.
// The registry owns a reference to each shadow, its cached public key, and its
// optional SecItem tag, until the key is removed or the process exits.
#define SE_MAX_SHADOWS 64

typedef struct {
  SecKeyRef shadow;
  uint8_t handle[64];
  size_t handle_len;
  SecKeyRef host_public;
  CFDataRef tag; // the SecItem application tag, or NULL
} shadow_entry;

static shadow_entry g_entries[SE_MAX_SHADOWS];
static size_t g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void se_registry_add(SecKeyRef shadow, const uint8_t *handle, size_t handle_len,
                     SecKeyRef host_public, CFDataRef tag) {
  if (handle_len > sizeof(((shadow_entry *)0)->handle)) return;
  pthread_mutex_lock(&g_lock);
  int full = g_count >= SE_MAX_SHADOWS;
  if (!full) {
    shadow_entry *e = &g_entries[g_count++];
    e->shadow = shadow;
    if (shadow) CFRetain(shadow);
    memcpy(e->handle, handle, handle_len);
    e->handle_len = handle_len;
    e->host_public = host_public;
    if (host_public) CFRetain(host_public);
    e->tag = tag;
    if (tag) CFRetain(tag);
  }
  pthread_mutex_unlock(&g_lock);
  // Diagnose a full table after releasing the lock, so stderr I/O never serializes
  // other registrations. Fail-closed-safe but confusing: an unregistered shadow's
  // later sign misses the registry and the public carrier refuses.
  if (full) {
    fprintf(stderr, "[simenclave] shadow registry full (%d); key unusable\n", SE_MAX_SHADOWS);
  }
}

int se_registry_lookup(SecKeyRef key, uint8_t *handle, size_t cap, size_t *handle_len,
                       SecKeyRef *host_public) {
  int found = 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].shadow == key) {
      if (g_entries[i].handle_len <= cap) {
        memcpy(handle, g_entries[i].handle, g_entries[i].handle_len);
        *handle_len = g_entries[i].handle_len;
        if (host_public && g_entries[i].host_public) {
          *host_public = g_entries[i].host_public;
          CFRetain(g_entries[i].host_public); // +1 under the lock; caller releases
        }
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

int se_registry_find_by_tag(CFDataRef tag, SecKeyRef *shadow, uint8_t *handle, size_t cap,
                            size_t *handle_len) {
  int found = 0;
  if (!tag) return 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].tag && CFEqual(g_entries[i].tag, tag) && g_entries[i].handle_len <= cap) {
      memcpy(handle, g_entries[i].handle, g_entries[i].handle_len);
      *handle_len = g_entries[i].handle_len;
      if (shadow) {
        *shadow = g_entries[i].shadow;
        if (g_entries[i].shadow) CFRetain(g_entries[i].shadow); // +1 under the lock
      }
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return found;
}

void se_registry_set_tag(SecKeyRef shadow, CFDataRef tag) {
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].shadow == shadow) {
      if (g_entries[i].tag) CFRelease(g_entries[i].tag);
      g_entries[i].tag = tag;
      if (tag) CFRetain(tag);
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
}

void se_registry_remove(SecKeyRef shadow) {
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].shadow == shadow) {
      if (g_entries[i].shadow) CFRelease(g_entries[i].shadow);
      if (g_entries[i].host_public) CFRelease(g_entries[i].host_public);
      if (g_entries[i].tag) CFRelease(g_entries[i].tag);
      g_entries[i] = g_entries[--g_count]; // move the last entry into the gap
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
}
