// Dobby smoke test. Part A hooks a local function (proves the inline-hook
// mechanism on this toolchain). Part B tries the real SecKeyCreateSignature in
// the shared cache, which the host protects and the simulator does not.
#include <Security/Security.h>
#include <stdio.h>

#include "dobby.h"

__attribute__((noinline)) static int add(int a, int b) { return a + b; }
static int (*orig_add)(int, int);
static int hooked_add(int a, int b) { return orig_add(a, b) + 1000; }

static CFDataRef (*orig_sign)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static int sign_hook_fired = 0;
static CFDataRef hooked_sign(SecKeyRef k, SecKeyAlgorithm a, CFDataRef d, CFErrorRef *e) {
  sign_hook_fired = 1;
  return orig_sign(k, a, d, e);
}

int main(void) {
  int fails = 0;

  if (DobbyHook((void *)add, (void *)hooked_add, (void **)&orig_add) != 0) {
    printf("A FAIL: DobbyHook(add)\n");
    fails++;
  } else {
    int r = add(2, 3);
    printf("A: add(2,3) through hook = %d (want 1005)\n", r);
    if (r != 1005) fails++;
  }

  void *addr = DobbySymbolResolver(NULL, "SecKeyCreateSignature");
  printf("B: SecKeyCreateSignature @ %p\n", addr);
  if (addr && DobbyHook(addr, (void *)hooked_sign, (void **)&orig_sign) == 0) {
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    int bits = 256;
    CFNumberRef bitsRef = CFNumberCreate(NULL, kCFNumberIntType, &bits);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bitsRef);
    CFErrorRef e = NULL;
    SecKeyRef priv = SecKeyCreateRandomKey(attrs, &e);
    if (priv) {
      unsigned char zero[32] = {0};
      CFDataRef dg = CFDataCreate(NULL, zero, 32);
      CFErrorRef se = NULL;
      CFDataRef sig =
          SecKeyCreateSignature(priv, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, dg, &se);
      printf("B: produced=%d hook_fired=%d\n", sig != NULL, sign_hook_fired);
      if (!sign_hook_fired) fails++;
    } else {
      printf("B WARN: local keygen failed\n");
    }
  } else {
    printf("B FAIL: could not hook SecKeyCreateSignature on the host\n");
    fails++;
  }

  printf(fails ? "SMOKE: %d failure(s)\n" : "SMOKE: ok\n", fails);
  return fails ? 1 : 0;
}
