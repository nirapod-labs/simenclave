# native-demo

A minimal native iOS app that signs with the `SecKey` C API. It proves the zero-app-code path: with the interposer injected through the scheme, these unmodified `SecKey` calls hit the host Secure Enclave. The XcodeGen `project.yml` and the scheme env land in M5.
