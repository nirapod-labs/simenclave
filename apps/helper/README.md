# helper

The macOS menubar app that owns the Secure Enclave key and answers requests from the simulator over loopback. It runs the listener, the auth gate, the SE service, the biometric prompt, and the handle store.

Built with XcodeGen, see `project.yml`. It needs the `com.apple.application-identifier` entitlement, which is why it has to be a signed `.app` and not a command-line tool. Built out in M1.
