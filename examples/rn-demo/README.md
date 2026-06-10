# rn-demo

A React Native demo that mirrors the real Nirapod shape: a native signer module calling `SecKey`, with the interposer injected through the scheme. It shows that SimEnclave needs nothing React-Native-specific, since it hooks the native `SecKey` calls the module already makes. Built out in M5.
