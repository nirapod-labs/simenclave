/**
 * @file access_control.h
 * @brief Side table capturing the (protection, flags) an app passed to
 *        SecAccessControlCreateWithFlags, keyed by the returned ref.
 *
 * @details
 * A SecAccessControlRef is opaque: no public API reads its flags back. The
 * interposer therefore catches the policy at its source, by hooking the one
 * public constructor, and the create hook looks the policy up here to relay it
 * verbatim to the helper. The table retains each ref it captures, which closes
 * the freed-and-reused-address hazard the same way the shadow registry does,
 * and the capture-to-create TOCTOU besides: while the table holds a reference,
 * the object cannot be freed and its address cannot be recycled. It is bounded
 * by a small ring, oldest evicted first, because a SecAccessControlRef is
 * transient and has no delete event to evict on.
 *
 * Both functions are safe to call from any thread; the ring is guarded by one
 * internal lock.
 *
 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#ifndef SE_ACCESS_CONTROL_H
#define SE_ACCESS_CONTROL_H

#include <Security/Security.h>
#include <stddef.h>

/**
 * @defgroup se_access_control Access-control capture
 * @brief The bounded ring that remembers each SecAccessControlRef's policy.
 * @{
 */

/**
 * @brief Record the (protection, flags) for an access-control ref.
 *
 * Retains @p ac and @p protection; refreshes in place if @p ac is already
 * known; evicts the oldest entry when the ring is full.
 *
 * @param[in] ac         The ref SecAccessControlCreateWithFlags returned.
 * @param[in] protection The protection-class constant the app passed, retained.
 * @param[in] flags      The raw SecAccessControlCreateFlags, stored verbatim.
 */
void se_ac_capture(SecAccessControlRef ac, CFStringRef protection,
                   SecAccessControlCreateFlags flags);

/**
 * @brief Look a captured ref up and copy its policy out.
 *
 * When @p protection is non-NULL, returns a +1-retained protection string the
 * caller releases. The retain happens under the lock so a concurrent capture
 * cannot free it in the gap.
 *
 * @param[in]  ac         The ref to look up.
 * @param[out] flags      The captured flags on a hit.
 * @param[out] protection +1-retained protection constant, or skipped when NULL.
 * @return 1 on a hit, 0 when @p ac was never captured (or was evicted).
 */
int se_ac_lookup(SecAccessControlRef ac, SecAccessControlCreateFlags *flags,
                 CFStringRef *protection);

/** @} */

#endif
