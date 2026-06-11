// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { font, foregroundStyle, frame } from "@expo/ui/swift-ui/modifiers";

import type { KeyGate } from "../se/types";

// JSON cannot carry Infinity (it serializes to null over the JS->native bridge), so
// .frame(maxWidth: .infinity) is expressed with a width larger than any screen; SwiftUI clamps it
// to the container, which fills the row. This is what makes a prominent button full-width.
export const fillWidth = frame({ maxWidth: 100000 });

// Shared SwiftUI modifiers and palette so every screen renders with the same type hierarchy and
// colors the native SwiftUI console uses. The native app leans on system fonts (.body, .caption,
// .subheadline) and the hierarchical .secondary foreground; these reproduce that exactly, so a row
// here is indistinguishable from the same row on the native side.

/** The hierarchical .secondary foreground, for subtitles and de-emphasized rows. */
export const secondary = foregroundStyle({ type: "hierarchical", style: "secondary" });

export const bodyFont = font({ textStyle: "body" });
export const bodyMedium = font({ textStyle: "body", weight: "medium" });
export const calloutFont = font({ textStyle: "callout" });
export const captionFont = font({ textStyle: "caption" });
export const caption2Font = font({ textStyle: "caption2" });
export const subheadlineSemibold = font({ textStyle: "subheadline", weight: "semibold" });
export const monoFootnote = font({ textStyle: "footnote", design: "monospaced" });

/** Title + caption pair, the standard two-line row used across the console. */
export const subtitle = [captionFont, secondary];

/** The gate accent colors, matching KeyGate.color in the native console. */
export const GATE_COLOR: Record<KeyGate, string> = {
  silent: "#8e8e93", // .secondary
  biometry: "#0a84ff", // .blue
  presence: "#5856d6", // .indigo
  passcode: "#30b0c7", // .teal
};

/** The gate SF Symbols, matching KeyGate.symbol. Literal types so they satisfy Image's prop. */
export const GATE_SYMBOL = {
  silent: "lock",
  biometry: "faceid",
  presence: "hand.raised",
  passcode: "number",
} as const satisfies Record<KeyGate, string>;

/** System status colors (green/red/orange/blue), matching the native .green/.red/.orange/.blue. */
export const STATUS = {
  green: "#34c759",
  red: "#ff3b30",
  orange: "#ff9500",
  blue: "#0a84ff",
} as const;

/** Cast a dynamic symbol name to whatever the @expo/ui Image prop expects. */
export function sf(name: string) {
  return name as never;
}

// Keys persisted by the native example app carry a capitalized gate ("Silent"), keys from this app
// carry the lowercase id ("silent"); both land in the same keychain prefix. Normalize so a row
// renders an icon either way, and show the capitalized label the native console shows.
const GATE_LABEL: Record<KeyGate, string> = {
  silent: "Silent",
  biometry: "Biometry",
  presence: "Presence",
  passcode: "Passcode",
};

function normalizeGate(gate: string): KeyGate {
  return gate.toLowerCase() as KeyGate;
}

export function gateSymbol(gate: string) {
  return sf(GATE_SYMBOL[normalizeGate(gate)] ?? "key");
}
export function gateColor(gate: string): string {
  return GATE_COLOR[normalizeGate(gate)] ?? GATE_COLOR.silent;
}
export function gateLabel(gate: string): string {
  return GATE_LABEL[normalizeGate(gate)] ?? gate;
}
