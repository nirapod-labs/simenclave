# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What SimEnclave is

A developer tool that gives the iOS Simulator a real Secure Enclave. It injects an interposer into a simulated app that hooks the `SecKey` C API and routes Secure Enclave operations to the host Mac's real SEP over an authenticated loopback channel, so the simulated app signs with genuine hardware P-256. It is simulator-only and never ships in a production app.

## Two ideas that shape the whole codebase

- **Faithfulness.** SimEnclave must be indistinguishable from a real device Secure Enclave. It relays the real SEP's behavior and adds nothing of its own: no signature canonicalization, no app-specific logic. Anything app-specific (a particular signature canonicalization, or a canonical hash the app computes) belongs in the consuming app, so the same app code runs identically in the simulator and on a device. Do not add app-specific behavior here.
- **The fence.** The tool must be unable to run in a shipped app. The interposer loads only through `DYLD_INSERT_LIBRARIES` set in a debug simulator scheme; release builds bundle no interposer and set no variable, and CI asserts both. Treat this as a safety invariant, not a convention.

## Build and test

`host-core` is a SwiftPM package. Its tests use XCTest, which ships with Xcode and not the Command Line Tools, so run them through the Xcode toolchain:

```sh
cd packages/host-core
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift test
```

`swift build` compiles on the Command Line Tools alone (XCTest is only needed for the tests). Tests that exercise a real Secure Enclave skip where there is no SEP (a hosted CI VM), so they pass anywhere and actually run on a self-hosted Apple Silicon machine.

JavaScript tooling is a pnpm workspace: `pnpm install`, then `pnpm lint` (biome). Run `lefthook install` once to enable the commit-message and formatting hooks.

## Architecture

Three deployables and one shared contract, each under its own directory:

- `packages/host-core` (Swift) drives the Mac's Secure Enclave: generate a P-256 key in the SEP, sign, fetch the public key. The host side.
- `apps/helper` is a signed macOS menubar app that owns the SEP key and answers requests over loopback. It must be a signed `.app` rather than a CLI, because using the Secure Enclave needs the `com.apple.application-identifier` entitlement.
- `packages/interpose` is the injected dylib. It inline-hooks the `SecKey` C API in a simulated app, redirects Secure Enclave operations to the helper, and passes every other call straight through to the real Security framework. It holds the shadow-ref registry (each `SecKeyRef` mapped to a host handle and public key) and the loopback client.
- `packages/protocol` is the wire contract: one spec (CBOR with a length prefix) and two codecs, Swift for the helper and C for the interposer.
- `tools/simenclavectl` is the CLI: JSON output and real exit codes, so a person or an agent can drive it.

The signing path: a simulated app calls `SecKeyCreateSignature`, the interposer's hook catches it, sends the request over a token-authenticated loopback socket to the helper, the helper signs in the Mac SEP, and the signature comes back. The private key never leaves the SEP; only a handle, a public key, a digest, and a signature cross the wire.

Why an interposer and not a registered provider: a camera can be a virtual device the OS enumerates, but the Secure Enclave is reached through a reserved token id that no third party can claim, so the redirect has to be active interception inside the guest process. Inline hooking (patching the resolved function) is the default because it is independent of the symbol-binding format, and the hook backend sits behind a small seam so no single library is load-bearing.

## Conventions

- PR-driven. Branch, open a PR, let CI go green, a maintainer merges. `main` is protected and rejects direct pushes.
- Conventional commits, enforced by commitlint (`.commitlintrc.json`): the type and scope are restricted to the lists there, and the subject is lowercase and at most 50 characters. CI runs commitlint on every PR. A squash merge uses the PR title as the subject and GitHub appends ` (#N)`, so the PR title itself must be a valid conventional subject of about 45 characters.
- Formatting: Swift via swiftformat and swiftlint, C via clang-format and clang-tidy, JS and JSON via biome.

See `ROADMAP.md` for the milestone plan and `SECURITY.md` for the dev-only scope and the fence.
