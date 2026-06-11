// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import { NativeTabs } from "expo-router/unstable-native-tabs";

// The four tabs as a real UITabBar with SF Symbols. The brand header and the store live in the
// root stack one level up, so every tab inherits the same nav bar and console state.
export default function TabsLayout() {
  return (
    <NativeTabs>
      <NativeTabs.Trigger name="index">
        <NativeTabs.Trigger.Icon sf="key" />
        <NativeTabs.Trigger.Label>Key</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="sign">
        <NativeTabs.Trigger.Icon sf="signature" />
        <NativeTabs.Trigger.Label>Sign</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="keychain">
        <NativeTabs.Trigger.Icon sf="key.viewfinder" />
        <NativeTabs.Trigger.Label>Keychain</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
      <NativeTabs.Trigger name="history">
        <NativeTabs.Trigger.Icon sf="clock.arrow.circlepath" />
        <NativeTabs.Trigger.Label>History</NativeTabs.Trigger.Label>
      </NativeTabs.Trigger>
    </NativeTabs>
  );
}
