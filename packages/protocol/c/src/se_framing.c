// The 4-byte big-endian length prefix shared by both ends (see SPEC.md).
#include "se_protocol.h"

#include <string.h>

int se_frame(const uint8_t *payload, size_t len, uint8_t *out, size_t cap) {
  if (len > SE_MAX_FRAME) return -1;
  if (cap < len + 4) return -1;
  out[0] = (uint8_t)(len >> 24);
  out[1] = (uint8_t)(len >> 16);
  out[2] = (uint8_t)(len >> 8);
  out[3] = (uint8_t)len;
  memcpy(out + 4, payload, len);
  return (int)(len + 4);
}

long se_payload_length(const uint8_t prefix[4]) {
  long len =
      ((long)prefix[0] << 24) | ((long)prefix[1] << 16) | ((long)prefix[2] << 8) | (long)prefix[3];
  if (len > SE_MAX_FRAME) return -1;
  return len;
}
