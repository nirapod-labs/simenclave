// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import { useEffect } from "react";
import { StyleSheet, Text, View } from "react-native";

import { useConsole } from "../se/store";

// A transient toast pinned to the top, auto-dismissing, mirroring the native console. Rendered
// per screen because @expo/ui has no toast component and the native tabs leave no room for a
// single overlay above them.
export function ToastHost() {
  const { toast, dismissToast } = useConsole();

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(dismissToast, 1900);
    return () => clearTimeout(timer);
  }, [toast, dismissToast]);

  if (!toast) return null;
  const tint =
    toast.kind === "success" ? "#1a7f37" : toast.kind === "error" ? "#cf222e" : "#0969da";

  return (
    <View pointerEvents="none" style={styles.wrap}>
      <View style={[styles.pill, { borderColor: `${tint}40` }]}>
        <Text style={[styles.text, { color: tint }]}>{toast.text}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { position: "absolute", top: 10, left: 0, right: 0, alignItems: "center", zIndex: 1000 },
  pill: {
    backgroundColor: "rgba(250,250,252,0.96)",
    borderWidth: 1,
    borderRadius: 22,
    paddingHorizontal: 16,
    paddingVertical: 10,
    shadowColor: "#000",
    shadowOpacity: 0.12,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 3 },
  },
  text: { fontSize: 14, fontWeight: "600" },
});
