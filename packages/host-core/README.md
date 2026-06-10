# host-core

A Swift package that drives the real Secure Enclave: generate a P-256 key, sign a digest, return the public key, delete. It also does the low-s normalization and the DER encoding, so signatures match what the TON contract accepts. The helper uses it. Built out in M0 and M1.
