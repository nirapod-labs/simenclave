/**
 * @file access_control.c
 * @brief Access-control capture implementation: a bounded ring behind one lock.
 *
 * @details
 *
 * @see access_control.h for the API documentation.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#include "access_control.h"

#include <pthread.h>

// Transient refs, so a small ring is enough. The oldest entry is evicted when full;
// this is a bound, not a cache, because the capture-to-create window is tiny.
#define SE_MAX_AC 32

typedef struct {
  SecAccessControlRef ac;
  CFStringRef protection;
  SecAccessControlCreateFlags flags;
} ac_entry;

static ac_entry g_entries[SE_MAX_AC];
static size_t g_count = 0;
static size_t g_oldest = 0; // ring cursor: the next slot to evict once full
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void se_ac_capture(SecAccessControlRef ac, CFStringRef protection,
                   SecAccessControlCreateFlags flags) {
  if (!ac) return;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].ac == ac) { // a reused ref: refresh in place, no new slot
      if (g_entries[i].protection) CFRelease(g_entries[i].protection);
      g_entries[i].protection = protection;
      if (protection) CFRetain(protection);
      g_entries[i].flags = flags;
      pthread_mutex_unlock(&g_lock);
      return;
    }
  }
  ac_entry *e;
  if (g_count < SE_MAX_AC) {
    e = &g_entries[g_count++];
  } else {
    e = &g_entries[g_oldest];
    g_oldest = (g_oldest + 1) % SE_MAX_AC;
    if (e->ac) CFRelease(e->ac);
    if (e->protection) CFRelease(e->protection);
  }
  e->ac = ac;
  CFRetain(ac);
  e->protection = protection;
  if (protection) CFRetain(protection);
  e->flags = flags;
  pthread_mutex_unlock(&g_lock);
}

int se_ac_lookup(SecAccessControlRef ac, SecAccessControlCreateFlags *flags,
                 CFStringRef *protection) {
  int found = 0;
  if (!ac) return 0;
  pthread_mutex_lock(&g_lock);
  for (size_t i = 0; i < g_count; i++) {
    if (g_entries[i].ac == ac) {
      if (flags) *flags = g_entries[i].flags;
      if (protection) {
        *protection = g_entries[i].protection;
        if (g_entries[i].protection) CFRetain(g_entries[i].protection); // +1 under the lock
      }
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return found;
}
