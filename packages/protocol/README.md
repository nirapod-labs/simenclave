# protocol

The wire protocol between the interposer and the helper: CBOR messages with a length prefix, a `HELLO` version handshake, and the `GENERATE`, `SIGN`, `GET_PUBKEY`, and `DELETE` operations.

One spec, two codecs. Swift for the helper, C for the interposer, with `SPEC.md` and a CDDL schema as the source of truth and a cross-language round-trip test so they can't drift. Built out in M1.
