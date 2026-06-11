// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// The guest app's own icon, rendered to a small PNG for the helper's connected-apps list. UIKit is
// present only in the simulator slice; on the macOS host slice this is a stub, since there is no
// app icon to read there. See app_icon.h.

#include "app_icon.h"

#include <string.h>

#if __has_include(<UIKit/UIKit.h>)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

size_t se_copy_app_icon_png(uint8_t *buf, size_t cap) {
  @autoreleasepool {
    // The primary icon's largest file name, the way an app's own icon is resolved at runtime.
    NSDictionary *icons = NSBundle.mainBundle.infoDictionary[@"CFBundleIcons"];
    NSString *name = [[[icons objectForKey:@"CFBundlePrimaryIcon"]
        objectForKey:@"CFBundleIconFiles"] lastObject];
    UIImage *icon = name ? [UIImage imageNamed:name] : nil;
    if (!icon) icon = [UIImage imageNamed:@"AppIcon"];
    if (!icon) return 0;

    // Downscale to 64x64 so the PNG is a few KB and rides inside the 8 KiB HELLO frame.
    CGSize target = CGSizeMake(64, 64);
    UIGraphicsImageRendererFormat *format = UIGraphicsImageRendererFormat.preferredFormat;
    format.scale = 1;
    format.opaque = NO;
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc] initWithSize:target
                                                                               format:format];
    UIImage *small = [renderer imageWithActions:^(UIGraphicsImageRendererContext *_Nonnull ctx) {
      (void)ctx;
      [icon drawInRect:CGRectMake(0, 0, target.width, target.height)];
    }];

    NSData *png = UIImagePNGRepresentation(small);
    if (!png || png.length == 0 || png.length > cap) return 0;
    memcpy(buf, png.bytes, png.length);
    return png.length;
  }
}
#else
size_t se_copy_app_icon_png(uint8_t *buf, size_t cap) {
  (void)buf;
  (void)cap;
  return 0;  // no UIKit on the host slice, so there is no app icon to render
}
#endif
