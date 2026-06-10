// A side table that captures the (protection, flags) an app passed to
// SecAccessControlCreateWithFlags, keyed by the returned SecAccessControlRef. The ref
// is opaque (no public API reads its flags back), so the interposer catches the policy
// at its source, by hooking the one public constructor. The table retains each ref it
// captures, which closes the freed-and-reused-address hazard the same way the shadow
// registry does, and the capture-to-create TOCTOU besides: while the table holds a
// reference, the object cannot be freed and its address cannot be recycled. It is
// bounded by a small ring, oldest evicted first, because a SecAccessControlRef is
// transient and has no delete event to evict on.
#ifndef SE_ACCESS_CONTROL_H
#define SE_ACCESS_CONTROL_H

#include <Security/Security.h>
#include <stddef.h>

// Record the (protection, flags) for an access-control ref. Retains ac and protection;
// refreshes in place if ac is already known; evicts the oldest entry when full.
void se_ac_capture(SecAccessControlRef ac, CFStringRef protection,
                   SecAccessControlCreateFlags flags);

// If ac was captured, copy its flags out and, when protection is non-NULL, return a
// +1-retained protection string the caller releases. The retain happens under the lock
// so a concurrent capture cannot free it in the gap. Returns 1 on a hit, 0 otherwise.
int se_ac_lookup(SecAccessControlRef ac, SecAccessControlCreateFlags *flags,
                 CFStringRef *protection);

#endif
