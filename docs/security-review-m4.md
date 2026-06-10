# M4 security review

The release-gate review of the interposer and the channel, run 2026-06-11 as two
independent adversarial passes in fresh contexts: one over the guest side (the
interposer, its hooks, registries, transport, and the C codec), one over the host side
(the helper, the token machinery, the listener, the gates, and the Swift codec). Both
were instructed to refute the safety claims, not confirm them. This page records what
they found, what was fixed, and what was confirmed.

## Findings and dispositions

| Severity | Where | Finding | Disposition |
| --- | --- | --- | --- |
| BLOCKER | `CBOR.swift` | A hostile 64-bit CBOR length or count argument trapped `Int(UInt64)` (and the checked `offset + count` add), crashing the helper pre-auth: `Wire.token` fully decodes the map before the AuthGate, so a tokenless ~12-byte frame killed the process. Two further trap sites in `CBORMap.int` on integers outside `Int64`. | Fixed. Length and count arguments are bounded against the remaining input before any `Int` conversion (`lengthArgument`); out-of-range integers throw `.malformed`. Regression tests cover the 2^64-1 length, the `Int.max` edge, the hostile map count, and both integer overflows. |
| MAJOR | `se_protocol.c` | The C mirror: `r->off + va > r->len` wraps for a hostile 64-bit length, defeating the bound; safety rested on downstream fixed-buffer caps. | Fixed in subtraction form (`va > r->len - r->off`), the byte-reader bound too. Regression test crafts the wrapping length and demands `SE_ERR_TRUNCATED`. |
| MAJOR | `LoopbackListener.swift` | No receive deadline on accepted connections: a connect-then-stall peer parked a serve thread forever, and threads are unbounded, so a stalled-client flood exhausts them. | Fixed. `SO_RCVTIMEO` and `SO_SNDTIMEO` (30 s) are set on every accepted fd before its serve thread spawns; a timed-out read drops the connection through the existing teardown. |
| MAJOR | `simenclave-helper/main.swift` | The CLI helper never removed its token file: the session credential outlived the session, and the `O_EXCL` create then refused the next start. The menubar had this hygiene; the CLI did not. | Fixed. SIGINT/SIGTERM handlers and an `atexit` hook remove the token file. A SIGKILL still leaves the file; the next start refuses loudly with the stale path, never truncates, which is the M1 design's decision kept intact. |
| MINOR | `sec_key_hooks.c` | A `kSecAttrApplicationTag` colliding between a registered shadow and a real keychain item shadows the real item in lookup and delete, a passthrough deviation. | Documented at the predicate: tags name at most one key; a colliding setup is a developer bug, and the deviation is now stated where the routing decision is made. |
| MINOR | `LoopbackListener.swift` | `start` mutated `worker`/`port` outside the lifecycle lock; racy only under a concurrent start/stop no current caller performs. | Fixed. All lifecycle state mutates under the lock and a double `start` throws. |
| NOTE | `shadow_ref.c` | At `SE_MAX_SHADOWS` (64) a new key silently registers nothing; fail-closed-safe but a confusing dev failure. | Fixed: a stderr line names the condition when the table is full. |
| NOTE | `sec_key_hooks.c` | `(CC_LONG)CFDataGetLength` truncates a >4 GiB message in the message-algorithm branch. | Fixed: refused before the hash. |
| NOTE | `se_framing.c` | The length-prefix assembly was 64-bit-`long`-clean only. | Fixed: assembled in `uint32_t`. |
| NOTE | `RequestRouter.swift` | `String(describing: error)` in failure messages is hygiene-fragile as errors grow richer. Today no token byte can reach it (traced through every error type). | Tracked for M5, where keychain errors arrive. |
| NOTE | `docs/design/m2-interposer.md` | Says the fidelity hooks are not hooked; M3 hooked them. The M3 design is the current description. | Noted here; design docs are point-in-time records. |

## Invariants confirmed, with evidence

Both reviewers confirmed, against the code rather than the docs:

- **Fail-closed.** The only shadow constructor builds public-key-only carriers, asserted
  unable to sign before registration; the only passthrough sign on a registry miss hands
  the original a key that either is the app's own software key (correct passthrough) or
  cannot sign. No path yields a software signature for an SE request.
- **Passthrough.** Non-SE calls reach the saved originals; the invariant is a first-class
  ctest.
- **The token gates every request** before the op is interpreted, compared constant-time
  over fixed 32 bytes, never logged on either side; with the BLOCKER fixed, the decode
  ahead of the gate can no longer be made to crash.
- **The token file** is 0600, `O_CREAT | O_EXCL | O_NOFOLLOW`, `fchmod`ed, in a directory
  verified owned, not a symlink, not group or world writable; reads are `O_NOFOLLOW`.
- **Biometry fails closed**: a prompted key with no gate installed throws rather than
  silently signing, and the prompt requirement derives from the flags actually built,
  not the class bit.
- **The private key never leaves the SEP**: only handle, public key, digest, and
  signature exist in any structure on either side of the wire.
- **The listener binds 127.0.0.1 only**; prompts serialize through one lock acquired
  after the handle-store lock is released, so no lock-ordering deadlock.
- **The approval prompt is a convenience over the token**, runs after the gate, defaults
  open with no approver, and fails the request with `errSecUserCanceled` on denial.

## Out-of-model observations

The guest client does not authenticate the helper's responses; a port-squatting local
process could feed forged public material (never private keys, never software signatures
accepted as SE ones). This matches the stated threat model and the roadmap's deferred
"stronger channel auth" item. The codec hardening above is what bounds the parser that
faces those bytes.

## Verdict

Both reviews returned NEEDS-CHANGES; every blocking item is fixed and regression-tested
in the same change. With those fixes the review is a sign-off, subject to the standing
hardware gate: the `device-confirm` parity captures and the prompt-binding confirmation
still need a real device before M4 closes.
