# M1: the helper, for real

M0 proved the bridge: a hooked `SecKeyCreateSignature` in the simulator gets a
signature from the Mac's Secure Enclave, and it verifies. It did that with no
authentication and two operations. M1 turns that spike into a real helper.

This is the helper-side design. The wire it speaks is in
[`packages/protocol/SPEC.md`](../../packages/protocol/SPEC.md), and the security
posture and the fence are in [`SECURITY.md`](../../SECURITY.md). This doc covers
what the helper does behind the socket: how it authenticates a caller, how it
holds keys, and where the M1 line is drawn against M2 and M3. The architecture is
already settled (FOUNDATION-ADR-001, the injected-interposer Option A), so
nothing here reopens it. This is the design that the M1 code follows.

## The connection model

M0's transport client opens one connection per request: connect, write the
framed request, read the framed response, close. M1 keeps that. Each operation is
its own short-lived connection, and the capability token rides on every request.

The alternative was a persistent authenticated session: open once, `HELLO` once,
then many operations on the held connection. It buys fewer round trips, and it
costs a stateful connection lifecycle on both ends, reconnect logic, and a reason
for the token to be a session fact rather than a per-call one. On a loopback
socket the round trip is microseconds, so the saving is not real, and the
stateless model is simpler and harder to get wrong. So the token authenticates
each request, not a connection, which is also exactly what "the `AuthGate` checks
it on every call" means. A persistent session is a post-1.0 option if a workload
ever makes the round trips matter.

`HELLO` is therefore not a per-connection ritual. It is a one-time compatibility
check, run by `simenclavectl doctor` or at first contact, that confirms the
helper speaks the interposer's version before real work starts. It is an ordinary
authenticated operation that happens to negotiate the version.

## The capability token

The token is what makes the channel the developer's own. Only the developer's
session can read it, so only the developer's session can drive the helper.

**Mint.** The helper generates one token per session: 32 bytes from the system
CSPRNG (`SecRandomCopyBytes`). That is the credential a caller presents, and it
is also unguessable. An attacker who somehow reached the socket without the file
would have, over $q$ online attempts, a success probability of at most

$$ q \cdot 2^{-256} $$

which is negligible for any $q$ a socket could serve. The real control is the
file permission below; the token's unguessability just means the socket itself
offers no shortcut around it.

**Store.** The token is written to a file with mode `0600`, owned by the
developer, under a per-user path (`~/Library/Application Support/SimEnclave/`).
It is held as 64 lowercase hex characters so it survives an environment variable.
`0600` is the boundary: another user on the Mac cannot read it.

**Inject.** `simenclavectl init` reads the token and the helper's loopback port
and sets `SIMENCLAVE_TOKEN` and `SIMENCLAVE_PORT` into the debug Simulator
scheme's environment. This is the same channel that already loads the interposer
through `DYLD_INSERT_LIBRARIES`, so the token reaches the guest exactly where the
tool already reaches it, and nowhere a release build does. The interposer decodes
the hex to 32 bytes and puts them in key `7` on every request.

**Verify.** The helper keeps the session token in memory. On each request the
`AuthGate` runs first, before it parses the operation:

```
on request frame:
  if token field absent or its length != 32      -> reject
  if not constant_time_equal(token, session)     -> reject (errSecAuthFailed)
  otherwise                                       -> dispatch the operation
```

The compare is constant time. `memcmp` returns early on the first differing byte,
which leaks where two tokens diverge through timing; a fixed-time equality does
not. The attacker here is same-user, so a timing oracle is not the live threat,
but a constant-time compare is one cheap line that removes the whole class, and
it is the kind of thing an audit expects to find. The gate runs before the
operation is parsed, so a caller without the token learns nothing about the
operation surface, not even that its bytes were well formed.

**Lifetime.** A token lives for one helper session. Restarting the helper mints a
new one, which is why a stale scheme has to re-run `init`. The menubar kill switch
clears the session token, so every token in flight stops working at once, and the
helper answers nothing until it is brought back. Rotation is not on a timer in
M1; restart and the kill switch are the rotation events.

## Key classes

`GENERATE` takes a key class. A **silent** key (class `0`) is usable without user
presence. A **biometry** key (class `1`) is created with an access control that
requires biometry to use the private key. M1 generates both, records the class
with the handle, and returns the handle and public key the same way for each.

What M1 does not do yet is drive the prompt. A real Touch ID prompt needs the
helper to bring itself foreground and run `LAContext`, and it needs a cancel or a
failed match to map to the exact `OSStatus` a device returns. That is M3, the
fidelity-and-biometry milestone. In M1 a biometry key exists, is tagged, and is
honest about its class; making it prompt and fail like a device is the next
milestone's job. The class is in the wire now so the helper and the store carry
it from the start and M3 adds behavior, not schema.

## The handle store

A handle is an opaque byte string. The interposer treats it as nothing but a
token for a key and never looks inside it. The helper maps each handle to the
SEP key behind it, the key class, and the simulator that created it.

Keys are namespaced per simulator UDID. Two simulators running the same test
fixture get separate keys, so one run does not see or clobber another's, and a
test is reproducible. The UDID comes from the spawn environment that `simctl`
sets, recorded with the handle when the key is made, and checked on `GET_PUBKEY`,
`SIGN`, and `DELETE` so a handle only resolves inside the simulator that owns it.

M1's store is the live handle map plus that per-UDID isolation. Durable
persistence, a fixture key still present after the helper restarts, is M3, where
it pairs with the biometry and parity work. Keeping the handle opaque is what lets
the store's representation change between milestones without touching the wire.

## The error model

A failure carries a status, a numeric `errorCode`, and a human reason. The code
is an `OSStatus`, so a `do/catch` written for a device reads the same value here.
M1 lands the code field and the cases it can already produce cleanly: a bad token
is `errSecAuthFailed` (-25293), an unknown handle is `errSecItemNotFound`
(-25300), and anything else is a generic failure with its reason. The complete
device-to-code table, the one that makes a cancelled biometric prompt return what
a device returns, belongs to M3 with the biometry path. The reason string is for
logs and is never load-bearing.

## Threat model, M1

This sits under [`SECURITY.md`](../../SECURITY.md), which is the canonical
statement; here is what M1 specifically relies on.

The channel is a loopback socket and a per-session token in a `0600` file. The
defended boundary is other users and other sessions on the same Mac: they cannot
read the token, so they cannot drive the helper. The boundary it does not defend,
on purpose, is a process already running as the developer. Such a process can
read the token file, but a process running as you is full host compromise, which
is out of scope for a development tool.

M1 does not verify the connecting peer's code signature or audit token. That peer
verification is deferred (it is in the roadmap's open decisions), and it is fine
to defer because a loopback socket gives the platform little to identify a peer
by, and the token already gates to the developer's own session. If the dev threat
model ever tightens, peer checks layer on top of the token rather than replacing
it.

None of this is the production story, because there is no production path. The
fence in `SECURITY.md`, no env var and no bundled dylib in a release build, is
orthogonal to all of the above and stays the release gate.

## What is M1, and what is not

M1 is done when the helper generates, signs, reads, deletes, and authenticates
over loopback, with unit tests green on a Mac that has a real Secure Enclave:

- The full SE service: `GENERATE` for both key classes, `SIGN`, `GET_PUBKEY`, `DELETE`
- The capability token and the `AuthGate` on every request
- The handle store, namespaced per simulator UDID
- The menubar with a status line, a kill switch, and per-app approval
- Wire protocol v1: `HELLO` negotiation, the token, and this `SPEC.md` plus the CDDL
- The signed `.app` carrying `com.apple.application-identifier`, the only way to reach the Mac SE

Deferred, and to where:

- The interposer's full hook surface and the passthrough invariant: M2
- Durable persistence, biometric prompts, and the full `OSStatus` parity table: M3
- Parity and fence tests, and the security review of the channel: M4
- Signing, notarization, the Homebrew cask, and the example apps: M5
- Peer code-signature or audit-token verification on the socket: after 1.0
