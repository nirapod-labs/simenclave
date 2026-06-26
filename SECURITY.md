# Security

Read this first, because it changes how you should think about the whole tool.

## SimEnclave is a development tool, and only that

It runs in the iOS and watchOS Simulators on a developer's Mac. It operates on that developer's own Secure Enclave keys. It never touches a real user's keys or funds, because there aren't any on this path. It is not, and will never be, a production signing path.

## Why it can't ship

Each interposer is a simulator-slice binary, one per simulator platform (iOS, watchOS), so dyld on a real device refuses to load it. It reaches a Simulator app only through `DYLD_INSERT_LIBRARIES` set in a debug scheme, a release build wires nothing, and on a device library validation blocks the injection anyway. Nothing to guard against, because nothing could run.

CI keeps it honest on every PR. `scripts/fence-check.sh` asserts that any scheme carrying the variable is Debug-only, that no Xcode project links the dylib, that the variable stays in a reviewed allowlist, and that every interposer the helper ships is a simulator slice (it fails closed on any device platform).

There's no app code to remove and no library linked into the app. Nothing about SimEnclave reaches a user's device.

## What crosses the channel

A handle, a public key, a digest, and a signature. The private key is generated inside the Mac's Secure Enclave and never leaves it. That's the same contract an app has with the Secure Enclave on a real device.

## Threat model, briefly

The channel is a loopback socket bound to localhost, authenticated with a per-session token that only the developer's own session can read. A process that can already read that token is a process running as the developer, which is full host compromise and out of scope for a dev tool. The interposer hooks only the Secure Enclave calls. Every other keychain or crypto call in the process passes straight through, untouched.

## Reporting

Report a vulnerability through GitHub's private vulnerability reporting. Open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to [the advisory form](https://github.com/nirapod-labs/simenclave/security/advisories/new). That opens a private advisory only the maintainers can see, so nothing is disclosed before a fix is ready.

Scope is SimEnclave's own code and configuration: the helper, the interposer, the protocol, the CLI, and the fence. A finding in a third-party dependency belongs upstream with that project, though a note here is welcome if SimEnclave's use of it is what creates the risk.

We aim to acknowledge a report within a few days and to agree a disclosure timeline with you from there. The tool never touches a real user's keys or funds, so there's no production custody at stake. The fence is the invariant that matters most: a way to make SimEnclave load in a shipped app is exactly the kind of thing worth reporting.
