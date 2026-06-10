# helper

The host process that owns the Secure Enclave key and answers requests from the simulator over loopback. It runs the listener, the request router, and the SE service.

M0 builds it as a SwiftPM command-line executable (`simenclave-helper`) over a reusable `SimEnclaveHelperKit`, so the loopback signing path is provable against the real SEP from an ad-hoc binary. M1 wraps that kit in the signed menubar app in `project.yml`: it carries the `com.apple.application-identifier` entitlement (the only form that can touch the Mac SE for distribution), and adds the capability-token auth gate, the biometric prompt, and the handle store.
