// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import {
  Button,
  Form,
  HStack,
  Host,
  Image,
  Label,
  Picker,
  Section,
  Spacer,
  Text,
  Toggle,
  VStack,
} from "@expo/ui/swift-ui";
import { buttonStyle, frame, pickerStyle, tag } from "@expo/ui/swift-ui/modifiers";
import { useState } from "react";
import { StyleSheet, View } from "react-native";

import { useConsole } from "../../src/se/store";
import { KEY_GATES, type KeyGate, PROTECTIONS, type Protection } from "../../src/se/types";
import { ToastHost } from "../../src/ui/Toast";
import {
  STATUS,
  fillWidth,
  gateColor,
  gateLabel,
  gateSymbol,
  secondary,
  subtitle,
} from "../../src/ui/sui";

export default function KeyScreen() {
  const c = useConsole();
  const [gate, setGate] = useState<KeyGate>("silent");
  const [protection, setProtection] = useState<Protection>("whenUnlockedThisDevice");

  return (
    <View style={styles.screen}>
      <Host style={styles.host} useViewportSizeMeasurement>
        <Form>
          <Section
            title="Create a key"
            footer={
              <Text>
                {c.persist
                  ? "A stored key persists in the keychain and reloads next launch, like a real app's signing key."
                  : "An ephemeral key lives only while the app is open."}
              </Text>
            }
          >
            <Picker
              label="Access gate"
              selection={gate}
              onSelectionChange={(g) => setGate(g as KeyGate)}
              modifiers={[pickerStyle("segmented")]}
            >
              {KEY_GATES.map((g) => (
                <Text key={g.id} modifiers={[tag(g.id)]}>
                  {g.label}
                </Text>
              ))}
            </Picker>
            {c.provider.capabilities.protection && (
              <Picker
                label="Protection"
                selection={protection}
                onSelectionChange={(p) => setProtection(p as Protection)}
                modifiers={[pickerStyle("menu")]}
              >
                {PROTECTIONS.map((p) => (
                  <Text key={p.id} modifiers={[tag(p.id)]}>
                    {p.label}
                  </Text>
                ))}
              </Picker>
            )}
            {c.provider.capabilities.persist && (
              <Toggle
                isOn={c.persist}
                onIsOnChange={c.setPersist}
                label="Store in keychain"
                systemImage="internaldrive"
              />
            )}
            <Button
              onPress={() => c.generate(gate, protection)}
              modifiers={[buttonStyle("borderedProminent")]}
            >
              <Label title="Generate hardware key" systemImage="key.fill" modifiers={[fillWidth]} />
            </Button>
          </Section>

          <Section title={c.keys.length ? `Keys (${c.keys.length})` : "Keys"}>
            {c.keys.length === 0 ? (
              <Text modifiers={[secondary]}>No keys yet. Generate one above.</Text>
            ) : (
              c.keys.map((k) => (
                <Button
                  key={k.id}
                  modifiers={[buttonStyle("plain")]}
                  onPress={() => c.select(k.id)}
                >
                  <HStack spacing={12}>
                    <Image
                      systemName={gateSymbol(k.gate)}
                      size={17}
                      color={gateColor(k.gate)}
                      modifiers={[frame({ width: 28 })]}
                    />
                    <VStack alignment="leading" spacing={2}>
                      <HStack spacing={5}>
                        <Text>Key {k.seq}</Text>
                        {k.tag != null && (
                          <Image systemName="internaldrive" size={11} color={gateColor("silent")} />
                        )}
                      </HStack>
                      <Text modifiers={subtitle}>
                        {gateLabel(k.gate)} · {k.publicKeyHex.slice(0, 12)}…
                      </Text>
                    </VStack>
                    <Spacer />
                    {k.id === c.selectedId && (
                      <Image systemName="checkmark.circle.fill" color={STATUS.blue} />
                    )}
                  </HStack>
                </Button>
              ))
            )}
          </Section>
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
