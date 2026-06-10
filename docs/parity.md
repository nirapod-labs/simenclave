# Parity

Parity is half of the M4 release gate (the fence is the other half). The claim: a
signature made in the simulator through SimEnclave verifies and is accepted by any P-256
verifier exactly as a device's signature is, and the `SecKey` API behaves identically
across the two. This page says which parts of that claim are asserted by the suite on any
Mac with a Secure Enclave, and which parts only a real device can settle.

## Asserted on the host, today

| Claim | Test |
| --- | --- |
| The DER signature verifies under the framework verifier | `SecureEnclaveServiceTests.testGeneratedSignatureVerifiesUnderExportedKey` |
| The same signature verifies under an independent implementation (CryptoKit: its own DER parser, its own verify) | `ParityTests.testSignatureVerifiesUnderCryptoKit` |
| The DER carries exactly two 32-byte scalars, the shape a device emits | `ParityTests.testSignatureRawFormIsTwoScalars` |
| The exported X9.63 public key imports into an independent implementation | `ParityTests.testPublicKeyImportsIntoCryptoKit` |
| A shadow ref reports SE-token, private-class attributes | mechanism C, `shadow attrs are SE private` |
| A shadow ref refuses export the way a device SE key does; its public key still exports | mechanism C, `shadow refuses export` / `public key still exports` |
| Non-SE calls are byte-identical with and without the hooks | `passthrough` ctest |
| All hooks install | `passthrough` ctest, `hooks install`; the backend mechanism itself is `hook_smoke` |
| A biometric failure surfaces as the device error envelope (code, domain) over the wire | `LoopbackRoundTripTests.testBiometricFailureSurfacesTheDeviceEnvelope` |
| End to end in the simulator: hooked create, sign, verify; stock failure without the tool | `run-mechanism-d.sh` |

The cross-verifier test is the load-bearing one. Every older test verifies through
`SecKeyVerifySignature`, the same framework that produced the signature, so a defect the
framework is symmetric about would pass. CryptoKit disagrees by construction.

## Only a device can settle these

The error parity table (`DeviceError.swift`) and the fidelity hooks' reference values are
seeded from Apple's documentation and flagged `device-confirm` in the source. The numbers
are not trusted until captured on real hardware. The capture run is one scratch app on one
device; record each value and clear the flag where it lands.

1. **Biometric failure codes.** On a device, create an SE key with
   `.privateKeyUsage + .biometryCurrentSet`, call `SecKeyCreateSignature`, and capture the
   `CFError` `(domain, code)` for each outcome: user cancel, failed match, lockout (five
   bad attempts), biometry not enrolled, biometry unavailable. Lands in
   `apps/helper/Sources/SimEnclaveHelperKit/DeviceError.swift`.
2. **Export refusal.** `SecKeyCopyExternalRepresentation` on the SE private key; capture
   the error `(domain, code)`. Compare with what the fidelity hook returns in
   `packages/interpose/src/hooks/sec_key_hooks.c`.
3. **Attributes reference.** `SecKeyCopyAttributes` on the SE private key; record the full
   dictionary (token id, key class, size, accessibility, and which keys are present at
   all). Compare with the shadow's dictionary asserted in mechanism C.
4. **A golden vector.** Sign a fixed message with a silent SE key on the device; record
   the message, the DER signature, and the X9.63 public key. Run the vector through the
   `ParityTests` verifiers; both implementations must accept it and the simulator-made
   signatures alike.
5. **The prompt binding.** The M3 design flagged the exact `LAContext` binding for a
   custom prompt reason as a spike. Confirm on the device which API surface attributes
   the sheet, and reconcile `AppKitBiometricGate` if the menubar's binding differs.

## Running it

```sh
make test          # ctest + the three Swift suites (ParityTests ride host-core) + fence + mechanism C
make mechanism-d   # the simulator end-to-end, with the fence legs asserted
```

The hardware-only tests skip on a Mac without a Secure Enclave, so the suite is green on a
hosted VM and meaningful on a developer Mac or the self-hosted runner.
