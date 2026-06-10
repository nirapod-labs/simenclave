# tests

Cross-cutting suites that don't belong to a single package.

- `parity` proves an interposed simulator signature is accepted by the TON `P256_CHKSIGNU` low-s check, the same as a device signature.
- `fence` proves a release build can't load the interposer.
- `hook` proves the backend installs the hooks and the passthrough invariant holds.

Built out across M2 and M4.
