// A probe, not a bridge demo. CryptoKit's SecureEnclave.P256 is expected to verify
// in the simulator even with no interposer and no helper, which shows it falls back
// to a software key rather than bottoming out in the hooked SecKey Secure Enclave
// path. Contrast sim_demo.c with run-mechanism-d.sh, where the SecKey C API
// genuinely fails without the bridge. See run-cryptokit-probe.sh, which probes
// this CryptoKit fallback directly.
import CryptoKit
import Foundation

do {
  let key = try SecureEnclave.P256.Signing.PrivateKey()
  let data = Data("simenclave cryptokit probe".utf8)
  let sig = try key.signature(for: data)
  let ok = key.publicKey.isValidSignature(sig, for: data)
  print("SIM CRYPTOKIT VERIFY: \(ok ? 1 : 0)")
  exit(ok ? 0 : 1)
} catch {
  print("SIM CRYPTOKIT: \(error)")
  exit(2)
}
