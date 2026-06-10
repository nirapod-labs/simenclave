# tests

Cross-cutting suites that don't belong to a single package.

- `parity` proves an interposed simulator signature verifies and is accepted by the same P-256 verifier as a device signature, and that the `SecKey` API behaves identically across the two.
- `fence` proves a release build can't load the interposer.
- `hook` proves the backend installs the hooks and the passthrough invariant holds.

Built out across M2 and M4.
