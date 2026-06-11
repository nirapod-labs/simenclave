/**
 * @file app_icon.h
 * @brief The guest app's own icon, rendered to a small PNG for the helper to show.
 *
 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#ifndef SE_APP_ICON_H
#define SE_APP_ICON_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Render the running app's own icon into @p buf as PNG bytes.
 *
 * Downscaled to a small square so the PNG is a few KB and fits the HELLO frame. Implemented over
 * UIKit in the simulator slice; a stub returning 0 on the macOS host slice, where there is no app
 * icon to read. The result is guest-controlled and the helper validates it before showing it.
 *
 * @param[out] buf Buffer the PNG is written to.
 * @param[in]  cap Capacity of @p buf.
 * @return Bytes written, or 0 when there is no icon or it would not fit.
 */
size_t se_copy_app_icon_png(uint8_t *buf, size_t cap);

#endif
