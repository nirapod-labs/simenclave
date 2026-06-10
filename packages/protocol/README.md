# protocol

The wire protocol between the interposer and the helper: CBOR messages with a 4-byte length prefix. `SPEC.md` is the prose source of truth, `protocol.cddl` the machine-checkable schema, `VERSION` the single protocol version.

One spec, two codecs: Swift (`swift/`) for the helper, C (`c/`) for the interposer, kept in agreement by emitting canonical CBOR and proven against each other when the C interposer talks to the Swift helper. M0 defines `GENERATE` and `SIGN`; the `HELLO` handshake with a capability token, plus `GET_PUBKEY` and `DELETE`, are M1.
