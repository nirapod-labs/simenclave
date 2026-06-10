# SimEnclave

SimEnclave gives the iOS Simulator a real Secure Enclave. It injects a small interposer into a simulated app, catches the `SecKey` calls, and routes the Secure Enclave ones to your Mac's actual SEP over a local channel. The app signs with real hardware P-256. No mock, no software key, and the app itself imports nothing.

It exists because the iOS Simulator has no Secure Enclave. That means the one thing hardware-backed signing depends on, a key that never leaves the chip, can't run where you develop all day, forcing a physical device for every signing change. SimEnclave fixes that without weakening the security property and without ever becoming something that could ship.

> Status: early. The design is settled, and the code is being built milestone by milestone. See [ROADMAP.md](ROADMAP.md).

## How it works, in one paragraph

Your Mac has a real Secure Enclave. A menubar helper owns a P-256 key inside it. When a simulated app calls `SecKeyCreateSignature`, an injected interposer, loaded only through a debug scheme environment variable, sends the digest to the helper over an authenticated loopback socket. The helper signs in the Mac's SEP and the signature comes back. The private key never leaves the chip. The only things that cross the wire are a handle, a public key, a digest, and a signature, which is exactly what an app on a real device already handles.

## Scope

This is a development tool. It runs only in the Simulator, it signs only with your own Mac's Secure Enclave, and it can't run in a shipped app: a release build doesn't bundle it and doesn't set the variable that loads it. It is not a production component and never will be. See [SECURITY.md](SECURITY.md).

## Using it

Coming as the milestones land. The short version once it's ready: `brew install` the helper, run `simenclavectl init` to point your scheme at the interposer, and your existing `SecKey` code works in the Simulator against real hardware. The CLI is built to be driven by a person or an agent, with JSON output and real exit codes throughout.

## Developing

`make bootstrap` then `make build` and `make test`. The toolchain, the VSCode setup, and the build are in [docs/development.md](docs/development.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
