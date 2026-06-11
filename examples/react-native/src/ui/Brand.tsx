// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { Host, Image as SymbolImage } from "@expo/ui/swift-ui";
import { Image, useColorScheme } from "react-native";

// The SimEnclave brand lockup and the React Native badge. The shipped wordmark PNG already carries
// the mark plus the "SimEnclave" wordmark, so one image is the whole lockup, pixel-faithful without
// bundling DM Sans. The badge is the SF Symbol "atom" in React blue, drawn natively through @expo/ui
// so it tints and stays crisp.

const WORDMARK = {
  light: require("../../assets/brand/wordmark-light.png"),
  dark: require("../../assets/brand/wordmark-dark.png"),
};
const WORDMARK_RATIO = 1291 / 320; // the shipped wordmark PNG aspect ratio

/** The SimEnclave lockup (mark + wordmark) as the shipped PNG, sized by height. */
export function SimEnclaveLockup({ height = 26 }: { height?: number }) {
  const dark = useColorScheme() === "dark";
  return (
    <Image
      source={dark ? WORDMARK.dark : WORDMARK.light}
      style={{ width: height * WORDMARK_RATIO, height }}
      resizeMode="contain"
    />
  );
}

/** The React Native badge: the SF Symbol "atom" in React blue, in a fixed-size native host. */
export function ReactNativeBadge({ size = 24 }: { size?: number }) {
  return (
    <Host style={{ width: size + 4, height: size + 4 }}>
      <SymbolImage systemName="atom" size={size} color="#61DAFB" />
    </Host>
  );
}
