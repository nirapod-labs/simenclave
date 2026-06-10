# interpose

The injected dylib, loaded into a simulated app through `DYLD_INSERT_LIBRARIES`. It inline-hooks the `SecKey` C API (default backend: Dobby), redirects the Secure Enclave calls to the helper over loopback, and passes everything else straight through to the real Security framework.

It holds the shadow-ref registry (each `SecKeyRef` mapped to a host handle and public key) and the transport client. This is the heart of the tool. Built out in M2.
