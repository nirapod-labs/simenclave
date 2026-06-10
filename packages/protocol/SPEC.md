# Wire protocol

The contract between the interposer (inside a simulated app) and the helper (on
the host). One request, one response, synchronous, over a loopback TCP socket.
`protocol.cddl` is the machine-checkable companion to this prose; `VERSION` holds
the single protocol version.

This is **version 1**: a 4-byte length prefix plus one CBOR map per message. M0
defines two operations, GENERATE and SIGN, with no authentication. M1 adds a
`HELLO` handshake that negotiates the version and presents a capability token,
plus GET_PUBKEY and DELETE. Those extend the map; the framing below does not
change.

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

## Payload

The payload is a single CBOR map with unsigned-integer keys. Integer keys keep it
compact, and emitting them in ascending order keeps the encoding canonical, which
matters because two codecs (Swift in the helper, C in the interposer) must agree
byte for byte. The keys:

| Key | Field       | Type             |
| --- | ----------- | ---------------- |
| 0   | `op`        | uint             |
| 1   | `status`    | uint (responses) |
| 2   | `handle`    | bstr             |
| 3   | `publicKey` | bstr             |
| 4   | `digest`    | bstr             |
| 5   | `signature` | bstr             |
| 6   | `error`     | tstr             |

Operations: `1` HELLO (M1), `2` GENERATE, `3` GET_PUBKEY (M1), `4` SIGN, `5`
DELETE (M1). Status: `0` OK, `1` ERROR.

### Requests

GENERATE asks the helper to mint a key in the Mac SEP:

```
{ 0: 2 }
```

SIGN asks it to sign a digest with a key a prior GENERATE returned:

```
{ 0: 4, 2: <handle>, 4: <digest> }
```

`digest` is a 32-byte SHA-256 value. M0 signs in digest form, which is what
`SecKeyCreateSignature` does for the `ecdsaSignatureDigestX962SHA256` algorithm;
the interposer reduces a message-algorithm input to this digest before sending,
so the helper's job is always a pure digest sign.

### Responses

GENERATE returns the handle and the public key in X9.63 uncompressed form (65
bytes, a `0x04` lead byte then the two coordinates), the same bytes
`SecKeyCopyExternalRepresentation` gives on a device:

```
{ 0: 2, 1: 0, 2: <handle>, 3: <publicKey> }
```

SIGN returns the signature in the X9.62 DER form `SecKeyCreateSignature` returns
on a device, with no `s` normalization applied; canonicalization is the app's
concern, not the bridge's:

```
{ 0: 4, 1: 0, 5: <signature> }
```

An error echoes the failing op and carries a reason:

```
{ 0: <op>, 1: 1, 6: "<reason>" }
```

M0 leaves the reason free-form. M1's schema closes it to the device's `OSStatus`
set so a `do/catch` written against the device behaves identically here.

## Why CBOR and not a bare layout

A fixed binary layout would carry these few fields too, but the protocol grows at
M1 (a handshake, a token, more operations) and a self-describing map absorbs that
without a format break, while a hand-rolled layout would need versioned offsets.
CBOR is a small, well-specified encoding. M0 carries it with a compact
hand-written codec on each side, the Swift one in the helper and the C one in the
interposer, which byte-match because both emit the shortest form. tinycbor is the
planned C library for when M1 grows the operation set.
