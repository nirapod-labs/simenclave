// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import {
  Button,
  ContentUnavailableView,
  Form,
  HStack,
  Host,
  Image,
  Section,
  Spacer,
  Text,
  VStack,
} from "@expo/ui/swift-ui";
import { tint } from "@expo/ui/swift-ui/modifiers";
import { StyleSheet, View } from "react-native";

import { useConsole } from "../../src/se/store";
import { STATUS, calloutFont, caption2Font, secondary, sf } from "../../src/ui/sui";

export default function HistoryScreen() {
  const c = useConsole();

  return (
    <View style={styles.screen}>
      <Host style={styles.host} useViewportSizeMeasurement>
        <Form>
          {c.history.length === 0 ? (
            <Section>
              <ContentUnavailableView
                title="No activity yet"
                systemImage="clock.arrow.circlepath"
                description="Run an operation and it shows up here."
              />
            </Section>
          ) : (
            <Section title={`Activity (${c.history.length})`}>
              {c.history.map((line) => (
                <HStack key={line.id} alignment="top" spacing={12}>
                  <Image systemName={sf(statusSymbol(line.ok))} color={statusColor(line.ok)} />
                  <VStack alignment="leading" spacing={2}>
                    <Text modifiers={[calloutFont]}>{line.text}</Text>
                    <Text modifiers={[caption2Font, secondary]}>
                      {new Date(line.time).toLocaleTimeString()}
                    </Text>
                  </VStack>
                  <Spacer />
                </HStack>
              ))}
              <Button
                label="Clear"
                systemImage="trash"
                role="destructive"
                modifiers={[tint(STATUS.red)]}
                onPress={c.clearHistory}
              />
            </Section>
          )}
        </Form>
      </Host>
    </View>
  );
}

function statusSymbol(ok: boolean | null): string {
  return ok === true
    ? "checkmark.circle.fill"
    : ok === false
      ? "xmark.circle.fill"
      : "info.circle.fill";
}
function statusColor(ok: boolean | null): string {
  return ok === true ? STATUS.green : ok === false ? STATUS.red : STATUS.blue;
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  host: { flex: 1 },
});
