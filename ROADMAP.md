# SimEnclave roadmap

SimEnclave gives the iOS Simulator a real Secure Enclave. It injects a `SecKey` interposer that catches Secure Enclave calls in a simulated app and routes them to your Mac's actual SEP over an authenticated loopback channel. The app signs with real hardware P-256. No mock, no software key, and nothing for the app to import.

This file is the plan. The mechanism, protocol, and security model are settled, and code follows the design.

Dates are targets, not promises. v1.0 lands end of July 2026 if nothing slips. One thing up front: the release gate is M4, not M5. Parity and the fence have to be green before anything ships, even if the packaging and docs aren't done. Polish doesn't go out ahead of the safety proof.

## What 1.0 actually is

A notarized macOS helper you install with `brew`, plus an injected interposer, that lets any iOS app whose signer uses the `SecKey` C API get real Mac-SEP P-256 signatures in the Simulator. The signatures verify exactly like a device's, to any verifier. The whole thing drives from a JSON CLI, so a person or an agent can run it headless. And it can't ship to production, by construction.

Two tests decide whether we're done. Parity: a signature made in the simulator through SimEnclave verifies and is accepted by any P-256 verifier exactly as a device's signature is, and the `SecKey` API behaves identically. The fence: a release build can't load the interposer at all. Both green, and 1.0 is real.

## Milestones

### Phase 0: bootstrap

Status: in progress. Target: by 2026-06-11.

Stand up the repo so every later milestone is a PR on green CI. Nothing here touches keys or signing. It's all scaffolding.

- [ ] Create the repo, Apache-2.0, `main` protected
- [ ] pnpm workspace and turbo; lefthook and commitlint; biome; swiftlint and swiftformat; clang-format and clang-tidy
- [ ] CI skeleton: a portable lane (any runner), a hardware lane (self-hosted Mac with a real SE), a fence check, a release workflow
- [ ] PR template, CODEOWNERS, CONTRIBUTING, and a SECURITY.md that leads with "dev-only, never ships"
- [ ] XcodeGen `project.yml` stubs for the helper and the example apps

Done when CI is green on an empty scaffold and branch protection plus conventional commits are enforced.

### M0: prove it

Status: done (2026-06-10). This one was a spike. Target was 2026-06-12 to 06-17.

Before any polish, show the one thing that matters works: a hooked SecKey call in the simulator gets a signature from the Mac's real Secure Enclave.

- [x] Helper generates a P-256 key in the Mac SEP and signs a 32-byte digest, via the `SecKey` C API (`host-core`)
- [x] A length-framed CBOR loopback protocol, `GENERATE` and `SIGN`, no auth yet (`protocol`)
- [x] Interposer inline-hooks `SecKeyCreateRandomKey`, `SecKeyCopyPublicKey`, and `SecKeyCreateSignature` with Dobby and routes to the helper (`interpose`)
- [x] The returned signature verifies against the host public key, on the host (`run-mechanism-c.sh`) and in the simulator (`run-mechanism-d.sh`)

Done: a hooked `SecKeyCreateSignature` in the simulator returns a Mac-SEP signature that verifies, with the stock no-SEP failure as the control. That was the whole bar.

SimEnclave targets the `SecKey` C API, which hooks cleanly, and the M0 demo uses it directly. Apps that use CryptoKit's `SecureEnclave.P256` are not bridged: M2 found it falls back to a software key in the simulator rather than bottoming out in the hooked `SecKey` path. Test those paths through the `SecKey` C API or on a real device.

### M1: the helper, for real

Status: done (2026-06-10). Target was 2026-06-18 to 06-27. Design: `docs/design/m1-helper.md`.

- [x] Full SE service: `GENERATE` for both key classes (silent and biometry), `SIGN`, `GET_PUBKEY`, `DELETE`
- [x] Capability token, minted per session, written `0600`; `AuthGate` checks it on every call, constant-time, one value per key. Injection rides the mechanism scripts' `SIMCTL_CHILD_*` handoff today; the per-app `simenclavectl init` is M2 and M5
- [x] Handle store, one flat namespace per session, handles unguessable so test runs stay reproducible (per-UDID isolation and durable persistence are M3)
- [x] Menubar UI with a status line and a kill switch that clears the token. The per-app approval prompt moves to M2: it has to name the connecting app, and only the interposer can report that, so it cannot be built helper-side first
- [x] Wire protocol v1: CBOR with length framing, plus `SPEC.md` and a CDDL schema. `HELLO` is specified on the wire; the helper dispatches it in M2, when the `doctor` handshake that calls it exists
- [ ] A signed, notarized `.app` for distribution (deferred to M5). The Secure Enclave needs no entitlement, proved in M0 and the key-class work, so M1 ships the menubar above as an ad-hoc accessory app; `com.apple.application-identifier` is for keychain persistence (M3)

Done: the helper generates, signs, reads, deletes, and authenticates over loopback, with the Swift and C suites green on a Mac that has a real Secure Enclave. Two listed items moved to M2 with cause, the approval prompt and `HELLO` dispatch, both noted above; the signed `.app` stays M5.

### M2: the interposer

Status: done (2026-06-10). Target was 2026-06-28 to 07-09. Design: `docs/design/m2-interposer.md`.

The heart of the tool, and the most code. M0 scaffolded the shape, the seam, the three `SecKey` hooks, a basic registry, and the token transport; M2 turned that spike into the real client.

- [x] The `HookBackend` seam (`resolve`/`install`, Dobby behind it) is in from M0; every hook names the seam, no library directly
- [x] Hooks for `SecKeyCreateRandomKey`, `SecKeyCreateSignature`, `SecKeyCopyPublicKey`, with the shadow hardened to a public-key-only carrier (asserted unable to sign) so a routing miss fails loud, never a silent software signature, and an `X962` SHA-256 algorithm allowlist that refuses what it cannot map
- [x] Hooks for `SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`, so keys persist by tag (in-session; durable across relaunches is M3)
- [x] Passthrough: only Secure Enclave ops get redirected, every other call goes straight to the saved original, byte-identical, with a first-class invariant test
- [x] The shadow-ref registry retains its shadows so a freed ref's address cannot be reused and misrouted, maps each `SecKeyRef` to its host handle and cached public key, and carries the `SecItem` tag (the key class rides M3, since the create-time access control is opaque to the interposer)
- [x] The transport client grows `GET_PUBKEY` and `DELETE`, and the C codec catches up to the helper
- [x] `HELLO` dispatch in the helper and the handshake that exercises it; the polished `simenclavectl doctor` is M5
- [x] Scheme injection of `DYLD_INSERT_LIBRARIES`, via `scripts/set-scheme-env.sh`; the `simenclavectl init` polish is M5
- [x] The constructor is inert without configuration, defense in depth around the fence

Done: the passthrough invariant holds (a first-class test and mechanism C), a tag round-trips through `SecItem`, and the `SecKey` C API is caught end to end (mechanism D). The probe found CryptoKit's `SecureEnclave.P256` is not bridged in the simulator, it falls back to a software key, so the `SecKey` C API is the supported real-hardware path. The per-app approval prompt moved to M3, where it pairs with the biometry prompt as foreground GUI.

### M3: fidelity and biometry

Status: not started. Target: 2026-07-10 to 07-16. Design: `docs/design/m3-fidelity-biometry.md`.

- [ ] Biometry-gated keys: the interposer captures the access control at its source (it hooks `SecAccessControlCreateWithFlags`, since the `SecAccessControlRef` is opaque) and relays it, and the helper brings itself foreground and runs `LAContext`, so a biometric sign raises a real Mac Touch ID prompt
- [ ] Error parity: the helper classifies its macOS failure and maps it to the exact `(domain, code)` a device returns, from a committed device-reference table, so `do/catch` written for the device behaves the same here
- [ ] Persistence across relaunches via permanent, namespaced keychain keys and a `FIND_BY_TAG` lookup, so a known fixture key is still there next run, with keychain confinement (the helper never touches a key that is not its own) and per-UDID namespacing for hygiene, not as a security boundary
- [ ] The secondary hooks that keep the shadow ref honest: `SecKeyCopyExternalRepresentation` returns the not-exportable error a real SE key does, and `SecKeyCopyAttributes` reports the SE token and the private key class
- [ ] The menubar's per-app approval prompt, keyed on an app id the interposer reports, foreground GUI that pairs with the biometric prompt here (moved from M2; a convenience, not an access boundary)

Done when a biometric sign prompts Mac Touch ID, a cancel surfaces the device error, and a key generated last run is still usable this run.

### M4: parity and the fence

Status: not started. Target: 2026-07-17 to 07-23. This is the release gate.

Nothing ships until this is green.

- [ ] Parity test: the same digest signed on a device and through the interposed simulator both verify under the same P-256 verifier, and the `SecKey` API behaves identically across them
- [ ] Fence test: a release build sets no env var and bundles no dylib, and with the var unset the simulator shows the stock failing-SE behavior, which proves the app isn't coupled to the tool
- [ ] Hook unit tests: the backend installs the hooks, and the passthrough invariant holds
- [ ] A self-hosted bare-metal Apple Silicon runner for the hardware CI lane (hosted runners are VMs with no SEP, so they can't do this)
- [ ] A security review of the interposer and the channel

Done when parity is green on both a real device and the sim, the fence is green on a release build, and the security review is signed off.

### M5: ship 1.0

Status: not started. Target: 2026-07-24 to 07-30.

- [ ] Developer ID signing and notarization for the helper, stapled
- [ ] A Homebrew cask (or a tap) and a GitHub release carrying the helper and the dylib
- [ ] The `simenclavectl` agent CLI: `doctor`, `init`, `keys`, `sign`, `parity`, `token`, `status`, all JSON with real exit codes
- [ ] Docs: how to integrate (use the `SecKey` C API, set the scheme env), install, the protocol, the security model, troubleshooting
- [ ] Two example apps, one native and one React Native

Done when `brew install` followed by `simenclavectl doctor` comes back green, an example app signs in the simulator with the real Secure Enclave, and 1.0 is tagged.

## After 1.0

Worth doing once the core is solid, roughly in order of how much they'd help:

- More hook backends behind the seam (a maintained fishhook fork, Apple's `__interpose`), so a stalled dependency is a config change
- More of the `SecKey` surface, as real apps hit calls we haven't hooked yet
- Stronger channel auth: peer code-signature or audit-token checks, where the platform gives us a way to do them on a loopback socket
- Guidance for the on-device-only paths, and maybe a small helper that records a real device attestation for server-side checks (App Attest can't run on macOS, so this can't be faked)
- A look at Android StrongBox, which is a different mechanism and probably a sibling tool, not a backend here
- Protocol v2, and the ergonomics of more than one helper or simulator at once

## What this is not

- Not a secrets vault, a CI secret store, or a multi-user key service
- Not an attestation provider, because App Attest doesn't exist on macOS
- Not, ever, a production signing path. The fence is the proof, not a promise.
- Not a replacement for a real device on the paths only a device can do: attestation, and the invalidation you get when biometric enrollment changes

## Decisions still open

- Whether token-only channel auth is enough, or we add peer verification later. Fine to defer until the dev threat model actually tightens.
- One repo, or a separate Homebrew tap for distribution.

## How we run it

Everything is a PR. Each checkbox should be small enough to review in one sitting, and the milestones map to GitHub milestones and labels. A maintainer approves; nothing self-merges. v1.0 is gated on M4, not M5, so packaging that's ready early still waits if parity or the fence isn't green.
