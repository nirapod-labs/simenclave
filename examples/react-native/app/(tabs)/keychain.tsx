// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import {
  Button,
  ContentUnavailableView,
  Form,
  Host,
  Section,
  Text,
  TextField,
  useNativeState,
} from "@expo/ui/swift-ui";
import { tint } from "@expo/ui/swift-ui/modifiers";
import { StyleSheet, View } from "react-native";

import { useConsole } from "../../src/se/store";
import { SelectedKeyRow } from "../../src/ui/SelectedKeyRow";
import { ToastHost } from "../../src/ui/Toast";
import { STATUS } from "../../src/ui/sui";

export default function KeychainScreen() {
  const c = useConsole();
  const tag = useNativeState("my.app.key");
  const key = c.selectedKey;
  const supported = c.provider.capabilities.keychain;

  return (
    <View style={styles.screen}>
      <Host style={styles.host} useViewportSizeMeasurement>
        <Form>
          {!supported ? (
            <Section>
              <ContentUnavailableView
                title="Keychain by tag unsupported"
                systemImage="key.viewfinder"
                description={`${c.provider.name} does not expose SecItem add/find/delete. Switch to Raw SecKey on the Key tab.`}
              />
            </Section>
          ) : (
            <>
              {key && (
                <Section>
                  <SelectedKeyRow record={key} />
                </Section>
              )}

              <Section
                title="Keychain by tag"
                footer={
                  <Text>SecItem stores and finds the key under this tag for the session.</Text>
                }
              >
                <TextField text={tag} placeholder="Application tag" />
                <Button
                  label="Save current key"
                  systemImage="tray.and.arrow.down"
                  onPress={() => c.keychainAdd(tag.value)}
                />
                <Button
                  label="Find key by tag"
                  systemImage="magnifyingglass"
                  onPress={() => c.keychainFind(tag.value)}
                />
                <Button
                  label="Delete key by tag"
                  systemImage="trash"
                  role="destructive"
                  modifiers={[tint(STATUS.red)]}
                  onPress={() => c.keychainDelete(tag.value)}
                />
              </Section>
            </>
          )}
        </Form>
      </Host>
      <ToastHost />
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  host: { flex: 1 },
});
