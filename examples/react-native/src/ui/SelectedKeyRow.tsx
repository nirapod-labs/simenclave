// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { HStack, Image, Spacer, Text, VStack } from "@expo/ui/swift-ui";

import { type KeyRecord, PROTECTIONS } from "../se/types";
import { STATUS, gateColor, gateLabel, gateSymbol, subheadlineSemibold, subtitle } from "./sui";

// The selected key's status as a standard grouped row: hardware-backed (green) or software
// (orange), with the gate on the trailing edge. The same row the native console puts at the top of
// Sign and Keychain.
export function SelectedKeyRow({ record }: { record: KeyRecord }) {
  const protectionShort = PROTECTIONS.find((p) => p.id === record.protection)?.short ?? "";
  return (
    <HStack spacing={12}>
      <Image
        systemName={
          record.hardwareBacked ? "checkmark.shield.fill" : "exclamationmark.triangle.fill"
        }
        size={22}
        color={record.hardwareBacked ? STATUS.green : STATUS.orange}
      />
      <VStack alignment="leading" spacing={2}>
        <Text modifiers={[subheadlineSemibold]}>
          {record.hardwareBacked ? "Hardware Secure Enclave" : "Software fallback"}
        </Text>
        <Text modifiers={subtitle}>
          Key {record.seq} · {gateLabel(record.gate)} · {protectionShort}
        </Text>
      </VStack>
      <Spacer />
      <Image systemName={gateSymbol(record.gate)} color={gateColor(record.gate)} />
    </HStack>
  );
}
