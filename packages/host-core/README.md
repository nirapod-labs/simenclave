# host-core

A Swift package that drives the real Secure Enclave: generate a P-256 key, sign a digest, return the public key, delete. It presents the signature in the form the `SecKey` API returns it and adds no canonicalization of its own; that stays in the consuming app. The helper uses it. Built out in M0 and M1.
