# M2: the interposer, for real

M1 made the helper real: the full Secure Enclave service behind a capability
token, on a Mac with a real SEP. M2 makes the other end real. The interposer is
the guest side of the bridge, the code that lives inside the simulated app, catches
its `SecKey` calls, and decides which ones belong to the host's Secure Enclave.

This is the interposer-side design. The wire it speaks is in
[`packages/protocol/SPEC.md`](../../packages/protocol/SPEC.md); the helper it talks
to is in [`docs/design/m1-helper.md`](m1-helper.md); the dev-only scope and the
fence are in [`SECURITY.md`](../../SECURITY.md). The architecture is settled,
FOUNDATION-ADR-001 chose the injected interposer (Option A) over a registered
provider, and the rationale is recorded in [`CLAUDE.md`](../../CLAUDE.md): the
Secure Enclave is reached through a reserved token id no third party can claim, so
the redirect has to be active interception inside the guest. Nothing here reopens
that. This is the design the M2 code follows.

## What M0 already built

M2 is not a blank page. The M0 spike laid down the file shape and proved the path,
so this doc is mostly about turning a spike into something an audit would pass.
What is already in `packages/interpose`:

- **The hook backend seam.** [`backend/hook_backend.h`](../../packages/interpose/src/backend/hook_backend.h)
  is a two-function vtable, `resolve(symbol) -> address` and
  `install(target, replacement, &original) -> int`, and
  [`backend/dobby_backend.c`](../../packages/interpose/src/backend/dobby_backend.c)
  is the Dobby implementation behind it. The hooks already call `se_default_backend()`,
  never Dobby by name. The roadmap's "no single library is load-bearing" is already
  true; M2 keeps it true and adds nothing here except a teardown path for tests.
- **Three `SecKey` hooks.** [`hooks/sec_key_hooks.c`](../../packages/interpose/src/hooks/sec_key_hooks.c)
  hooks `SecKeyCreateRandomKey`, `SecKeyCopyPublicKey`, and `SecKeyCreateSignature`,
  with the passthrough shape already in place: a non-SE create or a non-shadow key
  falls through to the saved original.
- **A first cut at message-versus-digest.** The signature hook forwards a digest
  algorithm's bytes and `CC_SHA256`-reduces everything else, which M2 has to make
  precise (see the algorithm section, this is where the spike is least correct).
- **A basic registry.** [`registry/shadow_ref.c`](../../packages/interpose/src/registry/shadow_ref.c)
  maps a shadow `SecKeyRef` to a host handle and a cached host public key.
- **The token transport.** [`transport/client.c`](../../packages/interpose/src/transport/client.c)
  connects to `SIMENCLAVE_PORT`, reads the token from `SIMENCLAVE_TOKEN`, and runs
  one framed request per call.

So M2's job is four things the spike does not do: make the stand-in key
**fail-closed**, make the registry and passthrough **exact**, grow the guest wire to
the **full op set**, and add **`SecItem`** so keys persist by tag. Everything else is
hardening around those.

## The shadow ref: a public-key-only carrier

When the app asks for a Secure Enclave key, the real call returns a `SecKeyRef`
backed by the SEP. We do not have that; the key lives in the host's SEP. So the
interposer hands back a stand-in `SecKeyRef`, the shadow, and every later operation
on it (`SecKeyCreateSignature`, `SecKeyCopyPublicKey`, and so on) is recognized and
routed to the host.

The stand-in cannot be a bare pointer. Apps and CryptoKit retain, release, and
type-check the `SecKeyRef`; CryptoKit's `SecureEnclave.P256` holds one and the
framework calls `CFRetain`/`CFGetTypeID` on it. So the shadow must be a real
`SecKeyRef`, a genuine CoreFoundation object with the right type id and memory
semantics. The only question is which one.

M0 makes the shadow a **software private key**:
[`make_shadow`](../../packages/interpose/src/hooks/sec_key_hooks.c) calls the
original `SecKeyCreateRandomKey` with no Secure Enclave attribute, gets back a
usable P-256 software key, and uses it purely as the opaque handle. That works
while every operation is intercepted. It is the wrong default the moment one is not.

Consider the failure mode. Suppose a future hook, or a `SecKey` entry point M2 has
not hooked, reaches the saved original `SecKeyCreateSignature` with a shadow whose
registry lookup missed. With a software-key shadow, the original signs, with the
shadow's own software key, and returns a perfectly valid signature. The app
verifies it, the test passes, and the developer believes they exercised the Secure
Enclave. They did not. A tool whose entire purpose is "this is real hardware"
silently produced software crypto. That is the one outcome SimEnclave must never
have.

**So M2's shadow is a public-key-only `SecKeyRef`, built from the host's public key.**
The primitive already exists,
[`make_host_public_key`](../../packages/interpose/src/hooks/sec_key_hooks.c) turns
the 65-byte X9.63 point into a public `SecKeyRef` via `SecKeyCreateWithData`. The
shadow is one such object; the cached public key the registry lends out is another
with the same bytes, kept distinct so the shadow and its public key are separate
objects, as a private key and its public key are on a device.

The property this buys is worth stating exactly. Let $S$ be the set of signatures
the interposer can cause the app to observe. A public-key carrier cannot sign,
because the key has no private operation, so `SecKeyCreateSignature` on it fails.
The Security headers do not document that for the public-key case, so M2 does not
lean on it as a contract; it turns it into a checked invariant. At carrier creation
the interposer asserts `SecKeyIsAlgorithmSupported(carrier, kSecKeyOperationTypeSign, ...)`
is false and refuses to register a carrier that reports it can sign, and an M4 test
calls `SecKeyCreateSignature` on a bare carrier and asserts a null return. The
assumption is enforced, not believed. So the only path that yields a signature is
`route`, which ends in either a host SEP signature or an error. Therefore

$$ S = S_{\text{host SEP}}, \qquad S_{\text{software}} = \varnothing. $$

Any routing bug, any unhooked path, any future mistake, lands in the empty set: an
error, never a software signature. The tool fails loud. That is the design's
custody-equivalent: the interposer can be wrong, but it cannot lie about whether the
hardware signed.

The cost is a fidelity gap. A public carrier reports key class `public`, where a
device's SE key reports `private`. In M2 this is invisible on the hooked paths
(sign, copy-public, create, delete) because the hook answers before the class is
read. It becomes visible only to introspection M2 does not hook yet,
`SecKeyCopyAttributes` and `SecKeyCopyExternalRepresentation`, which is exactly M3's
fidelity work. M3 closes it the right way: it hooks `SecKeyCopyAttributes` to report
the Secure Enclave token and class `private`, so the carrier reads as a private SE
key without ever holding usable private material. Fail-closed in M2, faithful in M3,
and the two do not fight.

## The registry

The registry is the source of truth for "is this ref ours, and what host key does it
name." M0 keys it on pointer identity, which is exact and fast, with one hazard M2
has to close.

M0 does not retain the shadow. The app owns it; the registry only records the
pointer. If the app releases its last reference, CoreFoundation can free the object
and **reuse that address** for the next allocation. A subsequent non-SE
`SecKeyRef` could land on the freed address, and `se_registry_lookup` would report a
hit. The interposer would then route a genuine software key's signature to the host
under a stale handle. That is a passthrough violation and a correctness bug, born
from the registry trusting an address it does not own.

M2 fixes it by ownership: **the registry retains every shadow it holds.** While a
shadow is registered its address cannot be reused, so pointer identity is exact, not
probabilistic. The registry releases the shadow when the key is deleted (see
`SecItemDelete` below) or when the session ends. The table grows from M0's fixed 64
to a small dynamic structure, but the model stays a flat per-session namespace, the
same one the helper keeps (M1's handle store), with per-UDID isolation deferred to
M3 for the same reason it is deferred there.

Each entry grows from M0's `{shadow, handle, host_public}` to carry the **key class**
(silent or biometry, so the shadow can later answer attribute queries honestly) and
the **`SecItem` tag** when the key was created permanent (so a later
`SecItemCopyMatching` by tag can find it). The handle stays the helper's 16 opaque
bytes; their uniqueness is the helper's property, argued in [`m1-helper.md`](m1-helper.md),
and the interposer does not lean on it, because it keys on pointer identity, not on
the handle.

Two lifecycle details the spike gets wrong and M2 fixes. The lent public key is the
first: `se_registry_lookup` hands back the cached `host_public` pointer and the
caller retains it after the lock is released, so a concurrent `SecItemDelete` can
free it in that window. M2 retains the public key inside the lock before returning
it, and the caller balances with a release, so the lookup never lends a pointer that
can die under it. The second is honesty about reclamation: retain-until-delete
sounds like the common case, but the common dev case is create, use, exit, with no
explicit delete, so in practice the registry holds its shadows until the session
ends. That is the intended lifecycle, bounded by the handful of keys a fixture
makes, and the test teardown path releases every entry so a test process does not
accumulate them across cases.

## The passthrough invariant

This is the property M4 tests and the one the interposer exists to not break. Let
$H$ be the set of hooked symbols and let $\mathrm{SE}(c)$ be the predicate "call $c$
targets the Secure Enclave." For every call $c$ to a symbol in $H$,

$$ \lnot\,\mathrm{SE}(c) \;\Longrightarrow\; r_{\text{interposed}}(c) = r_{\text{native}}(c), $$

bit for bit, where $r(c)$ is the full observable result: the return value, every
out-parameter, and the error. A keychain call that is not about the Secure Enclave
must be indistinguishable from one made with no interposer present.

Three rules make that hold, and each is a rule because the spike or a naive
implementation gets it subtly wrong.

**Every hook is `SE(c) ? route(c) : original(c)`.** The replacement does its own
work only in the SE case; otherwise it returns the saved original's result
untouched. No logging, no copying, no normalization on the passthrough branch,
nothing that could perturb a byte or a timing the app could observe.

**Passthrough calls the saved original, never the public symbol.** The original
captured at install time is Dobby's trampoline to the real implementation. A hook
that "passes through" by calling the public `SecItemCopyMatching` would call
*itself*, since that symbol is hooked, and recurse forever. This is not hypothetical
for the `SecItem` hooks, whose whole job involves the same functions they replace.
The rule is absolute: passthrough is a call through `orig_*`, the function pointer,
not the name.

**The predicate is conservative and total.** `SE(c)` must decide every input
without side effects and default to "not Secure Enclave" whenever it is unsure. For
key creation the signal is positive and precise: the attributes carry
`kSecAttrTokenID == kSecAttrTokenIDSecureEnclave`. For key use the signal is
registry membership, which is exact once shadows are retained. For `SecItem` it is
the constrained match below. Anything that is not a positive SE signal passes
through. The invariant is preserved by making redirect the exception, never the
default.

The decision point differs by call. Creation decides per-call on the attributes:
an SE generate routes, a software generate passes through. Use decides per-key on
the registry: a shadow routes, any other key passes through. The split matters
because it is why a software key created right next to an SE key in the same app is
untouched, which is the invariant's first and simplest test.

Three more rules keep the hooks from breaking themselves or the app's error
handling, and they are where the spike is silent.

**Hook-internal Security calls use unhooked entry points.** The create hook builds
the carrier with `SecKeyCreateWithData`, which M2 commits to never hooking, so
carrier construction cannot re-enter. Any keychain work a routed path needs goes
through a saved original, never a hooked symbol. M3, when it hooks
`SecKeyCopyAttributes`, inherits the same rule: the validation step must not call a
function it hooks.

**A hook called before its original is captured fails closed.** The constructor
installs hooks one symbol at a time. Under the Dobby backend each symbol's original
is captured before that symbol is patched, so a hook never runs with a null
original in normal operation. The null-check is insurance for a non-atomic backend
behind the seam: if a hook ever fired before its original were set, it returns a
populated-error failure rather than dereferencing null, which is safe and fails
closed rather than crashing or silently substituting.

**A routed failure is a faithful failure.** A native `SecKeyCreateSignature` failure
always populates its `CFErrorRef`; the M0 routed path returns null and leaves
`*error` untouched, which diverges from a device and can crash an app that unwraps
the error. M2 builds a `CFError` from the helper's `OSStatus` (the wire already
carries it in key `10`) on every routed failure, so a failure looks like a device's,
code and all, and never hands back an empty error.

## The `SecKey` hooks

The three from M0 stay, with the carrier change above:

- **`SecKeyCreateRandomKey`.** An SE request routes to the host `GENERATE` and comes
  back as the public-key carrier. The SE signal is
  `kSecAttrTokenID == kSecAttrTokenIDSecureEnclave`, checked both at the top of the
  parameters and inside `kSecPrivateKeyAttrs`, because a create that nests the token
  is still an SE create and missing it is the one false negative that could pass an
  SE key through to a software create. If the helper is unreachable, or the host
  returns no key, or the carrier cannot be built from the returned point (it is
  validated as a 65-byte `0x04`-led X9.63 value), the hook returns an error and
  registers nothing; it never falls through to the original with a software result.
  That is the create-time form of fail-closed: an SE create either yields a
  host-backed shadow or fails. A non-SE create passes through untouched. If the
  request is permanent (`kSecAttrIsPermanent` with a `kSecAttrApplicationTag`), the
  tag is recorded on the registry entry so the key is findable later by `SecItem`.
- **`SecKeyCopyPublicKey`.** A shadow returns a retained copy of its cached host
  public key; anything else passes through. Already correct in M0.
- **`SecKeyCreateSignature`.** A shadow routes to the host `SIGN` after mapping the
  algorithm to a digest (next section); anything else passes through. The carrier
  change makes the passthrough-on-miss case fail-closed.

`SecKeyCopyExternalRepresentation` and `SecKeyCopyAttributes` are **not** hooked in
M2. On a device they return, respectively, the not-exportable error for an SE
private key and the SE token attributes; making the shadow answer the same way is
the fidelity work M3 owns. In M2 a call to either on a shadow falls through to the
original and sees the public carrier, which is a fidelity gap, not a safety one: it
can only ever expose the public key, which is public. The gap is named here so M3
knows its boundary.

## Two axes: message versus digest, and the signature encoding

`SecKeyCreateSignature` takes an algorithm that varies on two independent axes, and
the interposer has to get both right. This is where the M0 spike is least correct,
so M2 makes it precise.

The first axis is **message versus digest**. ECDSA signs a 32-byte digest. A digest
algorithm means the caller already hashed; a message algorithm means the API hashes
first. The wire is digest-only by design: the helper's job is always a pure digest
sign, and [`SPEC.md`](../../packages/protocol/SPEC.md) fixes key `4` at 32 bytes. So
the interposer is the only place that knows the difference. It forwards a digest
algorithm's bytes after a length check, never re-hashing them, and it reduces a
message algorithm with that algorithm's own hash before sending.

The second axis is the **signature encoding**, and it is easy to miss. The `X962`
algorithms return a DER-encoded X9.62 signature (variable length); the `RFC4754`
algorithms return a raw `r || s` pair (fixed length). They are not interchangeable,
and the wire and the helper speak only the DER form. So an `RFC4754` request would
need a DER-to-raw re-encoding on the way back, which is a transform on the signature,
which faithfulness forbids the bridge from doing silently.

M2 resolves both axes by an **allowlist, not a catch-all**. It maps exactly the
`X962` SHA-256 pair: `kSecKeyAlgorithmECDSASignatureDigestX962SHA256` forwards the
32-byte digest, and `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` is SHA-256
reduced then sent. Every other algorithm, including every `RFC4754` variant and
every other digest width, is an error from the interposer, no signature emitted.
This is a deliberate change from the M0 code, whose `else` branch
([`sec_key_hooks.c`](../../packages/interpose/src/hooks/sec_key_hooks.c)) hashes
anything it does not recognize with SHA-256 and returns DER, which would re-hash an
already-hashed `RFC4754` digest and hand back the wrong encoding. A wrong hash or a
wrong encoding forges a signature over the wrong bytes or one a verifier rejects, so
the interposer refuses what it cannot map exactly rather than guessing.

The signature it does return is the X9.62 DER `SecKeyCreateSignature` produces on a
device, forwarded verbatim: no `s`-normalization, no low-s, no re-encoding.
Faithfulness is the rule (see [`CLAUDE.md`](../../CLAUDE.md)); anything app-specific,
including a canonical signature form, belongs in the app so the same code runs
identically in the simulator and on a device. Wider algorithm coverage is additive
and lands, as an allowlist entry plus any encoding transform it honestly requires,
when an app reaches for it.

## The `SecItem` hooks

Persistence is how a fixture key survives. The common device pattern is not a
separate `SecItemAdd`: a key is made permanent at creation (`kSecAttrIsPermanent`
plus a `kSecAttrApplicationTag`), then retrieved later with `SecItemCopyMatching`
by that tag and removed with `SecItemDelete`. M2 hooks the trio around that tag
namespace.

The predicate has to be tighter than "the tag is ours," because a `SecItem` query
is a conjunction and the wrong reduction corrupts non-SE traffic. M2 routes a query
only when all of these hold: `kSecClass` is `kSecClassKey`, the
`kSecAttrApplicationTag` is one the registry knows, the match limit is one
(`kSecMatchLimitOne` or absent), and the return type is a ref (`kSecReturnRef`).
Anything else, a different class, an unknown tag, `kSecMatchLimitAll`, or a
`kSecReturnData` / `kSecReturnAttributes` / `kSecReturnPersistentRef` request, is
outside M2's scope and passes through to the saved original unchanged. M2 supports
the create-permanent-then-fetch-ref-by-tag shape, which is what SE keys actually
use, and says so rather than pretending to answer every query shape.

- **`SecItemAdd`.** If the item carries the Secure Enclave token id, route to the
  host and register the tag; otherwise pass through. Most SE keys persist at
  creation, so this hook mostly passes through; it exists so an explicit add of an
  SE key is also caught.
- **`SecItemCopyMatching`.** For a query that matches the routed shape above on a
  known tag, return the registry's existing carrier for that tag, retained, the
  *same* object every time, not a freshly minted one. Returning a new carrier per
  lookup would both break the `CFEqual` identity an app expects across two fetches of
  one key and, with the registry retaining every shadow, leak one entry per call.
  Same tag, same carrier. An unknown tag or an out-of-scope shape passes through, and
  the real keychain answers exactly as it would, including `errSecItemNotFound`.
- **`SecItemDelete`.** A delete matching a known tag routes to the host `DELETE`,
  then releases and removes the registry entry, closing the retain. An unknown tag
  passes through.

Two scope lines. First, M2's tag namespace is **in-session**: the registry caches
tag to carrier and handle for the life of the helper session, which is enough for a
create-then-find-then-sign round trip, the roadmap's M2 exit. **Durable persistence
across relaunches is M3**, where the host gains a real tag store and the interposer
queries it rather than a local cache; that store runs on macOS, where returning key
refs needs `kSecUseDataProtectionKeychain`, so M3 inherits that constraint. Second,
the byte-identical guarantee is sharpest here, because `SecItem` carries the most
varied traffic, passwords and certificates and software keys, so the first `SecItem`
test is the passthrough-invariant test, not a feature test.

## The transport client and the C codec

M0's client speaks `GENERATE` and `SIGN` with the token. M2 grows it to the full op
set the helper already answers since M1:

- the C codec ([`packages/protocol/c`](../../packages/protocol/c)) gains
  `GET_PUBKEY` and `DELETE` encoders and the matching response decoding; it was left
  at the M0 subset because the interposer did not yet call the new ops, which is the
  expand-then-use discipline the M1 slices followed,
- the client ([`transport/client.h`](../../packages/interpose/src/transport/client.h))
  gains `se_client_get_pubkey` and `se_client_delete`,
- `HELLO` encoding lands with the doctor handshake below.

The connection model stays M1's: one short-lived connection per request, the token
on every request, no held session. On a loopback socket the round trip is
microseconds, so the stateless model costs nothing and is harder to get wrong. The
client keeps fixed bounded buffers and refuses an over-long frame rather than
allocating. Its current receive buffer is far below the protocol's 1 MiB `MAX_FRAME`,
which is ample for M2's responses (a DER signature is about seventy bytes, a public
key sixty-five), but M3's larger responses will need it raised, so the ceiling is
named here rather than discovered later.

One reachability rule. If `SIMENCLAVE_PORT` is unset or the helper does not answer,
a routed call returns an error carrying a `CFError` built as above, and the hook
surfaces it the way an unavailable SEP does, a null result with a populated error.
The tool degrades to no-bridge behavior rather than crashing the app, and that
degradation is also what the fence relies on: with nothing configured, the app
behaves as if the interposer were not there.

## The constructor, and the fence

[`entry.c`](../../packages/interpose/src/entry.c) is the `dyld` constructor; it runs
before the app's `main` and installs the hooks. M2 keeps that and adds one piece of
defense in depth: if neither `SIMENCLAVE_PORT` nor `SIMENCLAVE_TOKEN` is set, the
constructor installs nothing and returns. A dylib that finds no configuration makes
itself fully inert, so a stray `DYLD_INSERT_LIBRARIES` outside a wired dev scheme
changes nothing about the process.

That is defense in depth, not the fence. The fence is unchanged and orthogonal: the
interposer loads only through `DYLD_INSERT_LIBRARIES` set in a debug simulator
scheme, a release build bundles no dylib and sets no variable, and CI asserts both
(M4). M2 adds no new way in. The constructor no-op reduces the blast radius of an
accidental injection, a dylib present without the wired env does nothing, but it is
not a second fence: a stray or planted env var could supply what the no-op checks
for, so the release-build assertion of no bundled dylib and no variable stays the
sole gate.

## `HELLO` and the doctor handshake

`HELLO` is specified on the wire but the M1 helper does not dispatch it, because
nothing calls it yet. M2 gives it a caller. The interposer, or a `doctor` command,
sends `HELLO` with the version it speaks; the helper answers with the version it
speaks or an error on mismatch, so a future wire break is caught at the handshake
rather than mid-operation. This is the moved-from-M1 item: dispatch lands on both
sides (the helper's `Request` and router gain the case, the C codec gains the
encoder) the moment the handshake exists to exercise it. It is an ordinary
authenticated operation that happens to negotiate the version; like every other op
it carries the token.

## CryptoKit, and what the probe found

The assumption going in, from M0, was that CryptoKit's `SecureEnclave.P256` bottoms
out in the same `SecKey` C API, so the existing hooks would catch it for free. The
M2 probe disproved that on the current simulator.

`run-cryptokit-probe.sh` runs a CryptoKit `SecureEnclave.P256` create-sign-verify in
the simulator two ways. With no interposer it verifies. Injected against a dead
helper port it still verifies. Contrast the `SecKey` C API (`sim_demo`, mechanism
D), which fails outright in the simulator without the bridge, and fails again when
the helper is unreachable. The asymmetry is conclusive: CryptoKit's `SecureEnclave`
does not fail in the simulator, so it is not going through the SE path that fails. It
falls back to a software key, and the interposer's hooks never see it.

So M2 does not bridge CryptoKit's `SecureEnclave.P256`, and it cannot by hooking the
`SecKey` C API, because that is not where CryptoKit's SecureEnclave bottoms out in
the simulator. The supported real-hardware path is the `SecKey` C API directly,
which mechanism D proves end to end. CryptoKit code that calls the `SecKey` C API,
rather than the `SecureEnclave` wrapper, still goes through the hooks and is caught.

The sharper implication is worth stating plainly: a developer testing
`CryptoKit.SecureEnclave` in the simulator is exercising a software key whether or
not SimEnclave is present. SimEnclave does not make that worse, and it cannot
silently make it right, so the honest answer is to test those paths through the
`SecKey` C API or on a real device. The probe is committed so the finding is
reproducible and re-checkable when the OS changes.

## The menubar approval prompt

Moved from M1. The prompt shows which app is asking and lets the developer say no.
It could not be built helper-side first, because over a loopback socket the helper
has no trustworthy way to name the connecting app; the name has to come from the
interposer, which M2 introduces. So the interposer reports an app identifier on
connect and the menubar surfaces an approval. It stays what M1's design said it is:
a convenience, not an access-control boundary, because the identifier is
guest-reported and a token holder could forge it. The token is the boundary; the
prompt is there so the developer sees what is asking. Because it is non-load-bearing
and a foreground GUI affordance, it moved to M3, where it pairs with the biometry
prompt; the M2 exit criterion does not include it.

## Threat model and custody, M2

This sits under [`SECURITY.md`](../../SECURITY.md). M2 adds the interposer running
inside the guest, so here is the delta.

**Custody gate.** SimEnclave custodies no user funds and holds no user keys. The
keys are the developer's own test keys in their own Mac's SEP, and the private key
never leaves it; only a handle, a public key, a digest, and a signature cross the
wire. So the Nirapod custody linchpin (no server moves a user's keys or funds) is
not the live property here, because this is a dev tool, not the wallet. The
analogous linchpin is three properties, and M2 strengthens rather than weakens each:

1. **Fail-closed.** The public-key carrier makes a software signature impossible to
   emit, and the carrier is checked at creation to be unable to sign. An SE create
   whose helper is unreachable errors rather than minting a software key, and the
   create predicate catches the Secure Enclave token even when it is nested, so the
   line holds at both create and sign time. This is the M2 addition that matters
   most.
2. **Passthrough.** Every non-SE call is byte-identical, enforced by the rules
   above: redirect is the exception, passthrough goes through the saved original, the
   predicate is conservative, hooks do not re-enter, and a routed failure carries a
   faithful error. The registry retain closes the address-reuse path that could have
   misrouted a real key.
3. **The fence.** Dev-only, loaded one way, asserted off in release. M2 adds no new
   load path and makes an unconfigured load inert.

The interposer holds the token in the guest's environment, which M1's threat model
already covers: same-user, out of scope to defend against, never logged. The
interposer does not log it either. None of this is a production story, because there
is no production path; the fence is the proof.

## What is M2, and what is not

M2 is done when the passthrough invariant holds, a tag round-trips through `SecItem`,
and CryptoKit that reaches the `SecKey` C API is caught (the probe found CryptoKit's
`SecureEnclave.P256` is not bridged in the simulator), with the native C and Swift
suites green on a Mac with a real Secure Enclave:

- The full `SecKey` hook set, with the public-key carrier, the `X962` SHA-256
  algorithm allowlist, and a fail-closed routing miss at both create and sign
- The `SecItem` trio over an in-session tag namespace, so a key created permanent is
  found and signed and deleted by tag, with the constrained match predicate
- The passthrough invariant: conservative predicate, saved-original passthrough,
  no re-entrancy, faithful routed errors, byte-identical non-SE behavior, with the
  registry retaining its shadows and retaining the public key under the lock
- The transport and C codec grown to `GET_PUBKEY`, `DELETE`, and `HELLO`
- Scheme injection via `scripts/set-scheme-env.sh`, and `HELLO` dispatch with the
  `doctor` handshake
- The menubar's per-app approval prompt over the interposer-reported app id (a
  convenience; may slip to M3)

Deferred, and to where:

- Durable persistence across relaunches, the `SecKeyCopyExternalRepresentation` and
  `SecKeyCopyAttributes` fidelity hooks, biometric prompts, and the full `OSStatus`
  parity table: M3
- The parity test, the fence test, the hook unit tests, and the security review of
  the interposer and channel: M4
- The `simenclavectl` CLI that wraps scheme injection, and the example apps: M5
- Per-UDID isolation, and peer code-signature or audit-token verification on the
  socket: M3 and after 1.0 respectively
- Algorithm coverage beyond `X962` SHA-256, including any `RFC4754` raw-encoding
  support and its conversion: when an app needs it

## The slices

Each slice is a PR that stays green, in the M1 rhythm. The order puts the wire and
the safety spine first, then features, then the dev ergonomics.

1. **The wire catches up.** Grow the C codec and client to `GET_PUBKEY` and `DELETE`,
   matching the helper. No hook changes. Green when a C-level test drives all of
   generate, get-pubkey, sign, delete against the helper.
2. **The fail-closed registry and carrier.** Replace the software-key shadow with the
   public-key carrier, assert at creation that the carrier cannot sign, retain
   shadows in the registry (and the lent public key under the lock), add removal, and
   carry the class. Tighten the sign path to the `X962` SHA-256 allowlist and the
   create predicate to catch the nested token. Green when a software key created
   beside an SE key is untouched, a routing miss errors rather than signs, and an
   unmapped or `RFC4754` algorithm errors rather than guessing.
3. **The `SecItem` hooks.** Add `SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`
   over the in-session tag namespace, with the constrained match predicate, the
   same-carrier-per-tag rule, and `DELETE` routing through the registry removal.
   Green when a tag round-trips and a non-SE `SecItem` call is byte-identical with
   and without the interposer.
4. **The invariant and the CryptoKit probe.** Land the passthrough invariant test as
   a first-class test, the bare-carrier-cannot-sign assertion, and the CryptoKit
   probe. Green when the invariant test passes, a bare carrier returns null when
   asked to sign, and the probe documents that CryptoKit's `SecureEnclave.P256` falls
   back to software in the simulator and so is not bridged.
5. **Scheme injection, HELLO, and the inert load.** `scripts/set-scheme-env.sh`
   emits the scheme environment (the dylib, the port, the token) from a running
   helper; `HELLO` dispatch lands and the client round-trip exercises the handshake;
   the constructor is inert without configuration. The polished `simenclavectl
   init`/`doctor` and an example app are M5, and the approval prompt moved to M3.
   Green when `HELLO` negotiates the version over the loopback channel and the C and
   Swift suites stay green.
