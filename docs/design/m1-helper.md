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

The helper serves on a single accept loop, so each framed read carries a timeout.
A peer that opens a socket and then stalls cannot pin the loop and starve the
other connections. A same-user process flooding the developer's own helper is an
annoyance rather than a boundary, and the kill switch ends it, but the per-read
timeout is one line that keeps a single stuck simulator from blocking the rest.

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

The way that file is created is load-bearing, so it is pinned here rather than
left to the implementer. The directory is created `0700`, and if it already
exists the helper checks that the real uid owns it, that it is not a symlink, and
that it is not group or world writable before it writes anything inside. The file
is opened `O_CREAT | O_EXCL | O_NOFOLLOW`, and its mode is set with `fchmod` on
the descriptor, not a `chmod` after the write, so there is no window at a wider
mode and no dependence on the umask. An exclusive-create failure is fatal: the
helper never unlinks or truncates a path that is already there, because a file or
symlink sitting at that path is either a stale session to refuse loudly or
something planted. The threat this closes is not another user reading the token,
which is out of scope, but a same-user lower-trust step, a malicious postinstall
in the developer's own toolchain or a CI job, winning the create race or planting
a symlink to redirect the write.

**Inject.** `simenclavectl init` reads the token and the helper's loopback port
and sets `SIMENCLAVE_TOKEN` and `SIMENCLAVE_PORT` into the debug Simulator
scheme's environment. This is the same channel that already loads the interposer
through `DYLD_INSERT_LIBRARIES`, so the token reaches the guest exactly where the
tool already reaches it, and nowhere a release build does. The interposer decodes
the hex to 32 bytes and puts them in key `7` on every request.

Because it rides an environment variable, the token is inherited by every
descendant of the simulated app, not the interposer alone, and environments get
dumped where a file does not: CI prints them on failure, crash reporters capture
them, dyld debug flags echo the launch environment. That is all same-user and
within scope to read, but a token sitting in a CI log outlives the session and
travels with the log, so the helper and `simenclavectl` never log or echo it, and
the answer to a suspected leak is a helper restart. The per-session lifetime is
what makes that cheap: a leaked token is already dead at the next mint.

**Verify.** The helper holds the session token in memory as 32 raw bytes; the
hex is only the transport form, on disk and in the environment. On every request,
and inside the per-frame serve loop rather than once per connection, the
`AuthGate` runs first, before it interprets the operation:

```
on each request frame:
  decode the CBOR map structure
  require exactly one key 7, a bstr of length 32     else reject (errSecAuthFailed)
  if not fixed_time_equal_32(key7_bytes, session)    else reject (errSecAuthFailed)
  only now interpret key 0 and dispatch
```

The length gate comes first and rejects fast, which is fine because a token's
length is not secret. The equality then runs over a fixed 32 bytes with a
primitive that does not branch on the bytes, one that ORs the differences across
all 32, not `memcmp`, not `Data ==`, and not a comparison of the hex strings.
`memcmp` and `==` return early on the first differing byte, which leaks where two
tokens diverge through timing, and the hex form is the wrong operand at twice the
length. The attacker here is same-user, so a timing oracle is not the live
threat, but the primitive is one cheap helper-side line that removes the class,
and an audit expects to find it. The gate decodes only the map framing to reach
key 7, and it interprets the operation in key 0 only after the token matches, so
a caller without the token learns nothing about the operation surface.

For that gate to be exact, the framing it decodes has to be unambiguous, so the
decoder rejects a map with duplicate keys, rejects any integer or length that is
not in shortest form, and rejects trailing bytes after the map. Without that, two
encodings could disagree on which key 7 is the token, which is the one field the
gate turns on. The wire rules are in [`SPEC.md`](../../packages/protocol/SPEC.md),
and the helper depends on them here.

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

A handle is an opaque byte string, the 16 random bytes the helper returns from
`GENERATE`. The interposer treats it as nothing but a token for a key and never
looks inside it. The helper maps each handle to the SEP key behind it and its key
class.

M1 keeps one flat handle namespace per helper session. Handles are unguessable
and unique, so two simulators running the same fixture get different handles and
do not collide, which is what makes a test run reproducible. That uniqueness is
not a security boundary, though. Within a session the token is the boundary: a
caller that holds the token can name any handle the helper has issued. That is
the same-user surface the threat model already places out of scope, so M1 does
not pretend a handle is walled off from a token holder.

Per-simulator isolation and durable persistence across relaunches are both M3,
with the biometry and parity work. When M3 adds isolation it has to carry a UDID,
and a UDID a guest reports over loopback is guest-supplied, so it separates
cooperating test runs, not an adversary that holds the token. Real isolation
against a token holder means identifying the connecting peer, which is the same
gap peer verification defers (see the threat model below); that circularity is
why M1 does not claim it. Keeping the handle opaque is what lets the store grow
this way without touching the wire.

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

The menubar shows a per-app approval prompt, and it is a convenience, not an
access-control boundary. The helper has no trustworthy way to identify the
connecting app over a loopback socket, so the prompt can only key on something
the guest reports, which a token holder can forge. The token is the boundary. The
prompt is there so a developer sees what is asking and can say no, not because it
stops anything the token already allows.

None of this is the production story, because there is no production path. The
fence in `SECURITY.md`, no env var and no bundled dylib in a release build, is
orthogonal to all of the above and stays the release gate.

## What is M1, and what is not

M1 is done when the helper generates, signs, reads, deletes, and authenticates
over loopback, with unit tests green on a Mac that has a real Secure Enclave:

- The full SE service: `GENERATE` for both key classes, `SIGN`, `GET_PUBKEY`, `DELETE`
- The capability token and the `AuthGate` on every request, with a constant-time compare and a decoder that admits exactly one value per key
- The handle store, one flat namespace per session (per-UDID isolation is M3)
- The menubar: a status line, a kill switch, and a per-app approval prompt (a convenience, not an access boundary)
- Wire protocol v1: `HELLO` negotiation, the token, and this `SPEC.md` plus the CDDL
- The signed `.app` carrying `com.apple.application-identifier`, the only way to reach the Mac SE

Deferred, and to where:

- The interposer's full hook surface and the passthrough invariant: M2
- Durable persistence, biometric prompts, and the full `OSStatus` parity table: M3
- Parity and fence tests, and the security review of the channel: M4
- Signing, notarization, the Homebrew cask, and the example apps: M5
- Peer code-signature or audit-token verification on the socket: after 1.0
