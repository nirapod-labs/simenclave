# Security

Read this first, because it changes how you should think about the whole tool.

## SimEnclave is a development tool, and only that

It runs in the iOS Simulator on a developer's Mac. It operates on that developer's own Secure Enclave keys. It never touches a real user's keys or funds, because there aren't any on this path. It is not, and will never be, a production signing path.

## Why it can't ship

The interposer loads one way only: through the `DYLD_INSERT_LIBRARIES` environment variable, set in the debug Simulator scheme. A release build doesn't bundle the interposer dylib and doesn't set that variable, so there's nothing to load. CI asserts both on every release: no env var, no bundled dylib. With the variable unset, a simulated app gets the normal failing-Secure-Enclave behavior, which is the proof that the app has no dependency on this tool.

There's no app code to remove and no library linked into the app. Nothing about SimEnclave reaches a user's device.

## What crosses the channel

A handle, a public key, a digest, and a signature. The private key is generated inside the Mac's Secure Enclave and never leaves it. That's the same contract an app has with the Secure Enclave on a real device.

## Threat model, briefly

The channel is a loopback socket bound to localhost, authenticated with a per-session token that only the developer's own session can read. A process that can already read that token is a process running as the developer, which is full host compromise and out of scope for a dev tool. The interposer hooks only the Secure Enclave calls. Every other keychain or crypto call in the process passes straight through, untouched.

## Reporting

Until the repo is public, raise anything security-relevant privately with the maintainers. A coordinated-disclosure address will be added here when the project opens up.
