// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import * as Haptics from "expo-haptics";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

import type { SecureEnclaveProvider } from "./provider";
import { secureEnclaveProvider } from "./registry";
import type { KeyGate, KeyRecord, Protection, SignMode, SignatureRecord } from "./types";

// The React equivalent of the native SEConsole: it holds every key minted this session, the
// selected key, the last signature, a history trail, and a transient toast, and it drives the
// raw-SecKey provider's real native calls against the hardware Secure Enclave.

export interface ToastState {
  kind: "success" | "error" | "info";
  text: string;
  id: number;
}

export interface LogLine {
  id: number;
  ok: boolean | null;
  text: string;
  time: number;
}

interface ConsoleValue {
  provider: SecureEnclaveProvider;

  available: boolean | null;
  keys: KeyRecord[];
  selectedId: string | null;
  selectedKey: KeyRecord | null;
  signature: SignatureRecord | null;
  history: LogLine[];
  toast: ToastState | null;
  persist: boolean;

  setPersist: (on: boolean) => void;
  select: (id: string) => void;
  generate: (gate: KeyGate, protection: Protection) => Promise<void>;
  deleteKey: (id: string) => Promise<void>;
  sign: (message: string, mode: SignMode) => Promise<void>;
  verify: (tamper: boolean) => Promise<void>;
  keychainAdd: (tag: string) => Promise<void>;
  keychainFind: (tag: string) => Promise<void>;
  keychainDelete: (tag: string) => Promise<void>;
  clearHistory: () => void;
  dismissToast: () => void;
}

const ConsoleContext = createContext<ConsoleValue | null>(null);

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const provider = secureEnclaveProvider;

  const [available, setAvailable] = useState<boolean | null>(null);
  const [keys, setKeys] = useState<KeyRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [signature, setSignature] = useState<SignatureRecord | null>(null);
  const [history, setHistory] = useState<LogLine[]>([]);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [persist, setPersist] = useState(true);

  // Off-render counters for stable log/toast ids and the last signing context for verify.
  const counterRef = useRef(0);
  const lastSign = useRef<{ message: string; mode: SignMode } | null>(null);

  const note = useCallback((ok: boolean | null, text: string) => {
    counterRef.current += 1;
    setHistory((h) => [{ id: counterRef.current, ok, text, time: Date.now() }, ...h]);
    if (ok === true) Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    else if (ok === false) Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
  }, []);

  const showToast = useCallback((kind: ToastState["kind"], text: string) => {
    counterRef.current += 1;
    setToast({ kind, text, id: counterRef.current });
  }, []);

  const refresh = useCallback(
    async (p: SecureEnclaveProvider) => {
      try {
        setAvailable(await p.isAvailable());
      } catch {
        setAvailable(false);
      }
      try {
        const loaded = await p.loadKeys();
        setKeys(loaded);
        setSelectedId(loaded[0]?.id ?? null);
        if (loaded.length)
          note(null, `Loaded ${loaded.length} key${loaded.length === 1 ? "" : "s"}`);
      } catch {
        setKeys([]);
        setSelectedId(null);
      }
    },
    [note],
  );

  useEffect(() => {
    setSignature(null);
    refresh(provider);
  }, [provider, refresh]);

  const value: ConsoleValue = {
    provider,
    available,
    keys,
    selectedId,
    selectedKey: keys.find((k) => k.id === selectedId) ?? null,
    signature,
    history,
    toast,
    persist,
    setPersist,
    select: (id) => {
      setSelectedId(id);
      setSignature(null);
    },
    generate: async (gate, protection) => {
      try {
        const k = await provider.generate({ gate, protection, persist });
        setKeys((ks) => [k, ...ks]);
        setSelectedId(k.id);
        setSignature(null);
        if (k.hardwareBacked) {
          note(true, `Generated Key ${k.seq}, a ${k.tag ? "permanent" : "ephemeral"} ${gate} key`);
          showToast("success", `Key ${k.seq} created`);
        } else {
          note(false, "Generated a software key (exportable, not hardware)");
          showToast("error", "Software key, not hardware");
        }
      } catch (e) {
        note(false, `Generate failed: ${String(e)}`);
        showToast("error", "Generate failed");
      }
    },
    deleteKey: async (id) => {
      const seq = keys.find((k) => k.id === id)?.seq;
      try {
        await provider.deleteKey(id);
      } catch {
        /* surfaced below regardless */
      }
      setKeys((ks) => ks.filter((k) => k.id !== id));
      setSelectedId((cur) => (cur === id ? (keys.find((k) => k.id !== id)?.id ?? null) : cur));
      note(null, `Deleted Key ${seq ?? "?"}`);
      showToast("info", `Key ${seq ?? "?"} deleted`);
    },
    sign: async (message, mode) => {
      if (!selectedId) return;
      try {
        const s = await provider.sign({ keyId: selectedId, message, mode });
        lastSign.current = { message, mode };
        setSignature(s);
        note(true, `Signed ${s.bytes} B in ${mode} mode`);
        showToast("success", "Signed");
      } catch (e) {
        note(false, `Sign failed: ${String(e)}`);
        showToast("error", "Sign failed");
      }
    },
    verify: async (tamper) => {
      if (!selectedId || !signature || !lastSign.current) return;
      const { message, mode } = lastSign.current;
      const ok = await provider.verify({
        keyId: selectedId,
        message,
        mode,
        signatureDerHex: signature.derHex,
        tamper,
      });
      if (tamper) {
        note(!ok, ok ? "Tampered input wrongly verified" : "Tampered input correctly rejected");
        showToast(ok ? "error" : "success", ok ? "Tamper not caught" : "Tamper rejected");
      } else {
        setSignature((s) => (s ? { ...s, verified: ok } : s));
        note(ok, ok ? "Signature verifies" : "Signature did not verify");
        showToast(ok ? "success" : "error", ok ? "Verified" : "Did not verify");
      }
    },
    keychainAdd: async (tag) => {
      if (!selectedId || !provider.keychainAdd) return;
      try {
        await provider.keychainAdd(selectedId, tag);
        note(true, `Add "${tag}"`);
        showToast("success", `Add "${tag}"`);
      } catch (e) {
        note(false, `Add "${tag}" failed: ${String(e)}`);
        showToast("error", `Add "${tag}" failed`);
      }
    },
    keychainFind: async (tag) => {
      if (!provider.keychainFind) return;
      try {
        const found = await provider.keychainFind(tag);
        if (!found) {
          note(false, `Find "${tag}": not found`);
          return showToast("error", `"${tag}" not found`);
        }
        const existing = keys.find((k) => k.publicKeyHex === found.publicKeyHex);
        if (existing) {
          setSelectedId(existing.id);
          note(true, `Found "${tag}", already loaded as Key ${existing.seq}`);
          showToast("info", `Selected Key ${existing.seq}`);
        } else {
          setKeys((ks) => [found, ...ks]);
          setSelectedId(found.id);
          note(true, `Found "${tag}", loaded as Key ${found.seq}`);
          showToast("success", `Loaded Key ${found.seq}`);
        }
      } catch (e) {
        note(false, `Find "${tag}" failed: ${String(e)}`);
      }
    },
    keychainDelete: async (tag) => {
      if (!provider.keychainDelete) return;
      try {
        await provider.keychainDelete(tag);
        note(true, `Delete "${tag}"`);
        showToast("success", `Delete "${tag}"`);
      } catch (e) {
        note(false, `Delete "${tag}" failed: ${String(e)}`);
        showToast("error", `Delete "${tag}" failed`);
      }
    },
    clearHistory: () => setHistory([]),
    dismissToast: () => setToast(null),
  };

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>;
}

export function useConsole(): ConsoleValue {
  const value = useContext(ConsoleContext);
  if (!value) throw new Error("useConsole must be used inside ConsoleProvider");
  return value;
}
