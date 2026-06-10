# interpose

The injected dylib, loaded into a simulated app through `DYLD_INSERT_LIBRARIES`. It inline-hooks the `SecKey` C API (default backend: Dobby), redirects the Secure Enclave calls to the helper over loopback, and passes everything else straight through to the real Security framework.

It holds the shadow-ref registry (each `SecKeyRef` mapped to a host handle and public key) and the transport client. This is the heart of the tool.

M0 hooks `SecKeyCreateRandomKey`, `SecKeyCopyPublicKey`, and `SecKeyCreateSignature`, enough to route a key generate, public-key read, and sign to the host SEP end to end. `tests/run-mechanism-c.sh` proves it in a host process, `tests/run-mechanism-d.sh` in the simulator. CMake fetches and builds the hook backend (Dobby) as part of the native build. The `SecItem` persistence hooks and the full passthrough surface are M2.
