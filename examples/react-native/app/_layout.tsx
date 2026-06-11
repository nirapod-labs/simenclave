// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import { Host, Image as SymbolImage } from "@expo/ui/swift-ui";
import { Stack, router } from "expo-router";
import { Pressable, useColorScheme } from "react-native";

import { ConsoleProvider } from "../src/se/store";
import { ReactNativeBadge, SimEnclaveLockup } from "../src/ui/Brand";

// The native navigation header carries the brand: the shipped SimEnclave lockup PNG centered as the
// title, the React Native badge on the left, and an About button on the right that presents the
// About sheet as a native form sheet. The native stack owns the safe area and the tab bar lives in
// the (tabs) group below it.

function HeaderAbout() {
  const dark = useColorScheme() === "dark";
  return (
    <Pressable
      onPress={() => router.push("/about")}
      hitSlop={12}
      accessibilityRole="button"
      accessibilityLabel="About SimEnclave"
    >
      <Host style={{ width: 30, height: 30 }}>
        <SymbolImage systemName="info.circle" size={23} color={dark ? "#0a84ff" : "#007aff"} />
      </Host>
    </Pressable>
  );
}

export default function RootLayout() {
  return (
    <ConsoleProvider>
      <Stack>
        <Stack.Screen
          name="(tabs)"
          options={{
            headerBackground() {},
            headerTitleAlign: "center",
            headerTitle: () => <SimEnclaveLockup height={26} />,
            headerLeft: () => <ReactNativeBadge size={24} />,
            headerRight: () => <HeaderAbout />,
          }}
        />
        <Stack.Screen
          name="about"
          options={{
            presentation: "formSheet",
            sheetGrabberVisible: true,
            sheetAllowedDetents: [0.6, 1.0],
            headerShown: false,
          }}
        />
      </Stack>
    </ConsoleProvider>
  );
}
