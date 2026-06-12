# Security

Read this first, because it changes how you should think about the whole tool.

## SimEnclave is a development tool, and only that

It runs in the iOS Simulator on a developer's Mac. It operates on that developer's own Secure Enclave keys. It never touches a real user's keys or funds, because there aren't any on this path. It is not, and will never be, a production signing path.

## Why it can't ship

The interposer is a simulator-slice binary, so dyld on a real device refuses to load it: it can only run inside a Simulator process. It reaches a consuming app one way only, through the `DYLD_INSERT_LIBRARIES` environment variable set in a debug Simulator scheme. A release build of that app sets no such variable and references nothing, so there's nothing to load, and on a real device iOS library validation blocks the injection outright.

That claim is asserted in code, on three layers. The static fence (`scripts/fence-check.sh`, run by CI on every PR and push, and again by the release workflow before any packaging) asserts that any Xcode scheme carrying the variable launches the Debug configuration, that no Xcode project wires the interposer dylib into a build, and that the variable itself appears only in a reviewed allowlist of dev tooling. The runtime fence (`run-mechanism-d.sh`, on a Mac with a simulator) asserts that an app with no injection and an app with the interposer injected but unconfigured both show the identical stock failing-Secure-Enclave behavior, which is the proof that the app has no dependency on this tool. The helper itself carries the interposer, because it is the tool that injects it; the release workflow's helper check (`fence-check.sh --helper`) asserts that payload is simulator-slice, so the only thing the tool ships can never run anywhere but the Simulator.

There's no app code to remove and no library linked into the app. Nothing about SimEnclave reaches a user's device.

## What crosses the channel

A handle, a public key, a digest, and a signature. The private key is generated inside the Mac's Secure Enclave and never leaves it. That's the same contract an app has with the Secure Enclave on a real device.

## Threat model, briefly

The channel is a loopback socket bound to localhost, authenticated with a per-session token that only the developer's own session can read. A process that can already read that token is a process running as the developer, which is full host compromise and out of scope for a dev tool. The interposer hooks only the Secure Enclave calls. Every other keychain or crypto call in the process passes straight through, untouched.

## Reporting

Report a vulnerability through GitHub's private vulnerability reporting. Open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to [the advisory form](https://github.com/nirapod-labs/simenclave/security/advisories/new). That opens a private advisory only the maintainers can see, so nothing is disclosed before a fix is ready.

Scope is SimEnclave's own code and configuration: the helper, the interposer, the protocol, the CLI, and the fence. A finding in a third-party dependency belongs upstream with that project, though a note here is welcome if SimEnclave's use of it is what creates the risk.

We aim to acknowledge a report within a few days and to agree a disclosure timeline with you from there. The tool never touches a real user's keys or funds, so there's no production custody at stake. The fence is the invariant that matters most: a way to make SimEnclave load in a shipped app is exactly the kind of thing worth reporting.
