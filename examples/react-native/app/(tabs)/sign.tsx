// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import {
  Button,
  ContentUnavailableView,
  Form,
  HStack,
  Host,
  Label,
  Picker,
  Section,
  Spacer,
  Text,
  TextField,
  VStack,
  useNativeState,
} from "@expo/ui/swift-ui";
import {
  background,
  buttonStyle,
  frame,
  padding,
  pickerStyle,
  shapes,
  tag,
  tint,
} from "@expo/ui/swift-ui/modifiers";
import * as Clipboard from "expo-clipboard";
import { useState } from "react";
import { StyleSheet, View } from "react-native";

import { useConsole } from "../../src/se/store";
import { SIGN_MODES, type SignMode } from "../../src/se/types";
import { SelectedKeyRow } from "../../src/ui/SelectedKeyRow";
import { ToastHost } from "../../src/ui/Toast";
import { STATUS, fillWidth, monoFootnote, subtitle } from "../../src/ui/sui";

export default function SignScreen() {
  const c = useConsole();
  const message = useNativeState("hello secure enclave");
  const [mode, setMode] = useState<SignMode>("digest");
  const key = c.selectedKey;
  const sig = c.signature;

  return (
    <View style={styles.screen}>
      <Host style={styles.host} useViewportSizeMeasurement>
        <Form>
          {!key ? (
            <Section>
              <ContentUnavailableView
                title="No key selected"
                systemImage="key.slash"
                description="Generate or select a key on the Key tab."
              />
            </Section>
          ) : (
            <>
              <Section>
                <SelectedKeyRow record={key} />
              </Section>

              <Section
                title="Message"
                footer={
                  <Text>
                    {mode === "digest"
                      ? "Digest mode signs the SHA-256 of your message."
                      : "Message mode hands the raw message to the SEP to hash and sign."}
                  </Text>
                }
              >
                <TextField text={message} placeholder="Message to sign" />
                <Picker
                  label="Mode"
                  selection={mode}
                  onSelectionChange={(m) => setMode(m as SignMode)}
                  modifiers={[pickerStyle("segmented")]}
                >
                  {SIGN_MODES.filter((m) => c.provider.capabilities.signModes.includes(m.id)).map(
                    (m) => (
                      <Text key={m.id} modifiers={[tag(m.id)]}>
                        {m.label}
                      </Text>
                    ),
                  )}
                </Picker>
                <Button
                  onPress={() => c.sign(message.value, mode)}
                  modifiers={[buttonStyle("borderedProminent")]}
                >
                  <Label title="Sign message" systemImage="signature" modifiers={[fillWidth]} />
                </Button>
              </Section>

              {sig && (
                <Section title="Signature">
                  <VStack alignment="leading" spacing={12}>
                    <HStack>
                      <Text modifiers={subtitle}>
                        {sig.bytes} B · DER · {modeLabel(sig.mode)}
                      </Text>
                      <Spacer />
                      <VerifiedBadge verified={sig.verified} />
                    </HStack>
                    <Text
                      modifiers={[
                        monoFootnote,
                        frame({ maxWidth: 100000, alignment: "leading" }),
                        padding({ all: 12 }),
                        background("#7676801f", shapes.roundedRectangle({ cornerRadius: 10 })),
                      ]}
                    >
                      {grouped(sig.derHex)}
                    </Text>
                    <HStack spacing={12}>
                      <Button
                        systemImage="doc.on.doc"
                        modifiers={[buttonStyle("borderless")]}
                        onPress={() => Clipboard.setStringAsync(sig.derHex)}
                      />
                      <Spacer />
                      <Button
                        label="Verify"
                        systemImage="checkmark.seal"
                        modifiers={[buttonStyle("bordered"), tint(STATUS.blue)]}
                        onPress={() => c.verify(false)}
                      />
                      <Button
                        label="Tamper"
                        systemImage="exclamationmark.triangle"
                        modifiers={[buttonStyle("bordered"), tint(STATUS.orange)]}
                        onPress={() => c.verify(true)}
                      />
                    </HStack>
                  </VStack>
                </Section>
              )}
            </>
          )}
        </Form>
      </Host>
      <ToastHost />
    </View>
  );
}

function VerifiedBadge({ verified }: { verified: boolean | null }) {
  if (verified === true)
    return <Label title="Verified" systemImage="checkmark.seal.fill" color={STATUS.green} />;
  if (verified === false)
    return <Label title="Failed" systemImage="xmark.seal.fill" color={STATUS.red} />;
  return <Label title="Not verified" systemImage="seal" />;
}

function modeLabel(mode: SignMode): string {
  return SIGN_MODES.find((m) => m.id === mode)?.label ?? mode;
}

function grouped(hex: string): string {
  return (hex.match(/.{1,2}/g) ?? []).join(" ");
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  host: { flex: 1 },
});
