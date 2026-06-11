// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import {
  Button,
  Form,
  HStack,
  Host,
  Label,
  Section,
  Spacer,
  Text,
  VStack,
} from "@expo/ui/swift-ui";
import { buttonStyle, font } from "@expo/ui/swift-ui/modifiers";
import { router } from "expo-router";
import { StyleSheet, View } from "react-native";

import { fillWidth, secondary, subtitle } from "../src/ui/sui";

// The About panel, presented as a native form sheet from the header. What the project is, that this
// is the React Native example, and the Nirapod Labs credit and license.

const title2Bold = font({ textStyle: "title2", weight: "bold" });

export default function AboutScreen() {
  return (
    <View style={styles.screen}>
      <Host style={styles.host} useViewportSizeMeasurement>
        <Form>
          <Section>
            <VStack alignment="leading" spacing={4}>
              <Text modifiers={[title2Bold]}>SimEnclave</Text>
              <Text modifiers={subtitle}>Real hardware Secure Enclave for the iOS Simulator.</Text>
            </VStack>
          </Section>

          <Section title="About">
            <Text>
              SimEnclave injects a small interposer into a simulated app, catches its SecKey calls,
              and routes the Secure Enclave ones to your Mac's real SEP over an authenticated
              loopback channel. The app signs with genuine hardware P-256. No mock, no software key.
            </Text>
          </Section>

          <Section title="This example">
            <Text>
              React Native, on Expo and @expo/ui. The same console as the native app, reaching the
              same host Secure Enclave, so the bridge is framework-agnostic.
            </Text>
          </Section>

          <Section footer={<Text>© 2026 Nirapod Labs</Text>}>
            <Row label="Built by" value="Nirapod Labs" />
            <Row label="License" value="Apache-2.0" />
            <Row label="Status" value="Early" />
          </Section>
        </Form>
      </Host>
    </View>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <HStack>
      <Text>{label}</Text>
      <Spacer />
      <Text modifiers={[secondary]}>{value}</Text>
    </HStack>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  host: { flex: 1 },
});
