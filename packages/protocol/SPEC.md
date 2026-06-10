# Wire protocol

The contract between the interposer (inside a simulated app) and the helper (on
the host). One request, one response, synchronous, over a loopback TCP socket.
`protocol.cddl` is the machine-checkable companion to this prose, and `VERSION`
holds the single protocol version.

This is **version 1**. M0 carried a subset of it: a 4-byte length prefix plus
one CBOR map per message, with two operations, GENERATE and SIGN, and no
authentication. M1 completes the version. It adds a capability token on every
request, a `HELLO` that negotiates the version, and the `GET_PUBKEY` and
`DELETE` operations. None of this changes the framing, and the M0 GENERATE and
SIGN messages keep their exact bytes, so an M1 helper still answers them.

## Framing

Every message, both directions, is a length-prefixed frame:

```
+------------------+------------------------+
| length: u32 (BE) | payload: length bytes  |
+------------------+------------------------+
```

`length` is the CBOR payload size in bytes, big-endian, not counting the four
length bytes. A reader refuses any frame whose length exceeds `MAX_FRAME`
(1 MiB) and treats that as a protocol error rather than allocating.

## Authentication

Every request carries the capability token in key `7`, a byte string. The helper
mints one 32-byte token per session, the developer's session is the only one
that can read it, and the interposer presents it on every call. The helper's
`AuthGate` compares the presented token against the session token in constant
time and rejects any request that does not match, before it does anything else,
including before it parses the rest of the operation. A reply never contains the
token.

`HELLO` is authenticated too. There is no unauthenticated operation, so an
endpoint that cannot present the token cannot even probe the helper's version.
The token model, its lifetime, and what it does and does not defend against are
in `docs/design/m1-helper.md` and `SECURITY.md`. The wire only needs to carry it
and the helper only needs to check it.

## Payload

The payload is a single CBOR map with unsigned-integer keys. Integer keys keep it
compact, and emitting them in ascending order keeps the encoding canonical, which
matters because two codecs, Swift in the helper and C in the interposer, must
agree byte for byte. The keys:

| Key | Field       | Direction | Type                       |
| --- | ----------- | --------- | -------------------------- |
| 0   | `op`        | both      | uint                       |
| 1   | `status`    | response  | uint                       |
| 2   | `handle`    | both      | bstr                       |
| 3   | `publicKey` | response  | bstr                       |
| 4   | `digest`    | request   | bstr (32)                  |
| 5   | `signature` | response  | bstr                       |
| 6   | `error`     | response  | tstr                       |
| 7   | `token`     | request   | bstr (32), the capability token |
| 8   | `version`   | both      | uint, HELLO only           |
| 9   | `keyClass`  | request   | uint, GENERATE only        |
| 10  | `errorCode` | response  | int, an `OSStatus`         |

Operations: `1` HELLO, `2` GENERATE, `3` GET_PUBKEY, `4` SIGN, `5` DELETE.
Status: `0` OK, `1` ERROR. Key class: `0` silent, `1` biometry. Version: `1`.

### Requests

Every request includes the token in key `7`. The examples below show it as
`<token>`.

`HELLO` negotiates the protocol version before any real work. The interposer
sends the version it speaks, and a mismatch comes back as an error, so a future
break is detected at the handshake rather than mid-operation:

```
{ 0: 1, 7: <token>, 8: 1 }
```

`GENERATE` asks the helper to mint a key in the Mac SEP. Key class `0` is a
silent key, class `1` is gated on biometry at sign time:

```
{ 0: 2, 7: <token>, 9: 0 }
```

`GET_PUBKEY` returns the public key for a handle a prior `GENERATE` gave back,
without signing anything:

```
{ 0: 3, 2: <handle>, 7: <token> }
```

`SIGN` asks the helper to sign a digest with the key behind a handle:

```
{ 0: 4, 2: <handle>, 4: <digest>, 7: <token> }
```

`digest` is a 32-byte SHA-256 value. M1, like M0, signs in digest form, which is
what `SecKeyCreateSignature` does for the `ecdsaSignatureDigestX962SHA256`
algorithm. The interposer reduces a message-algorithm input to this digest
before sending, so the helper's job is always a pure digest sign.

`DELETE` removes the key behind a handle from the SEP and the helper's store:

```
{ 0: 5, 2: <handle>, 7: <token> }
```

### Responses

A response echoes the operation in key `0` and carries the status in key `1`. It
never carries a token.

`HELLO` confirms the version the helper speaks:

```
{ 0: 1, 1: 0, 8: 1 }
```

`GENERATE` returns the handle and the public key in X9.63 uncompressed form (65
bytes, a `0x04` lead byte then the two coordinates), the same bytes
`SecKeyCopyExternalRepresentation` gives on a device:

```
{ 0: 2, 1: 0, 2: <handle>, 3: <publicKey> }
```

`GET_PUBKEY` returns just that public key:

```
{ 0: 3, 1: 0, 3: <publicKey> }
```

`SIGN` returns the signature in the X9.62 DER form `SecKeyCreateSignature`
returns on a device, with no `s` normalization applied, because canonicalization
is the app's concern and not the bridge's:

```
{ 0: 4, 1: 0, 5: <signature> }
```

`DELETE` confirms the removal with status alone:

```
{ 0: 5, 1: 0 }
```

An error echoes the failing op, sets status `1`, and carries both a numeric code
and a human-readable reason:

```
{ 0: <op>, 1: 1, 6: "<reason>", 10: <osstatus> }
```

`errorCode` is an `OSStatus`. The point is parity: a `do/catch` written against
a device reads the same code here, so a bad token comes back as `errSecAuthFailed`
(-25293), a missing key as `errSecItemNotFound` (-25300), and so on. M1 lands the
code field and the auth and not-found cases. The full device-to-code table, the
one that makes a cancelled biometric prompt indistinguishable from a device's, is
M3, where the biometry path is built. The reason stays human-readable for logs
and is never load-bearing.

## Versioning

`VERSION` is a single integer, currently `1`, and the whole of M0 and M1 is that
one version. `HELLO` negotiates it: the interposer announces the version it
speaks, the helper accepts or returns an error. A later wire break bumps
`VERSION` and both codecs move together. Because every message is a
self-describing map, an additive change, a new key or a new operation, does not
need a bump as long as the existing messages keep their bytes.

## Why CBOR and not a bare layout

A fixed binary layout would carry these few fields too, but the protocol grew
from M0 to M1, a handshake and a token and three more operations, and a
self-describing map absorbed that without a format break, where a hand-rolled
layout would have needed versioned offsets. CBOR is a small, well-specified
encoding. M0 carried it with a compact hand-written codec on each side, the
Swift one in the helper and the C one in the interposer, which byte-match because
both emit the shortest form. M1's larger operation set is where the C side moves
to tinycbor, with the hand-written encoder kept as the byte-for-byte oracle the
library is tested against.
