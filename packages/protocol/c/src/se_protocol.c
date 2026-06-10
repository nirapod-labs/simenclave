// Minimal CBOR for the two M0 messages: unsigned ints, byte strings, text
// strings, and a definite-length map with unsigned-integer keys. Emits the
// shortest form, the canonical encoding, so it byte-matches the Swift codec.
#include "se_protocol.h"

#include <string.h>

// keys
enum { K_OP = 0, K_STATUS = 1, K_HANDLE = 2, K_PUBKEY = 3, K_DIGEST = 4, K_SIG = 5, K_ERR = 6 };
// ops and status
enum { OP_GENERATE = 2, OP_SIGN = 4, ST_OK = 0, ST_ERROR = 1 };

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t pos;
  int overflow;
} writer;

static void w_head(writer *w, uint8_t major, uint64_t value) {
  uint8_t tag = (uint8_t)(major << 5);
  uint8_t tmp[9];
  size_t n = 0;
  if (value < 24) {
    tmp[n++] = (uint8_t)(tag | value);
  } else if (value < 0x100) {
    tmp[n++] = (uint8_t)(tag | 24);
    tmp[n++] = (uint8_t)value;
  } else if (value < 0x10000) {
    tmp[n++] = (uint8_t)(tag | 25);
    tmp[n++] = (uint8_t)(value >> 8);
    tmp[n++] = (uint8_t)value;
  } else if (value < 0x100000000ULL) {
    tmp[n++] = (uint8_t)(tag | 26);
    tmp[n++] = (uint8_t)(value >> 24);
    tmp[n++] = (uint8_t)(value >> 16);
    tmp[n++] = (uint8_t)(value >> 8);
    tmp[n++] = (uint8_t)value;
  } else {
    tmp[n++] = (uint8_t)(tag | 27);
    for (int s = 56; s >= 0; s -= 8) tmp[n++] = (uint8_t)(value >> s);
  }
  if (w->pos + n > w->cap) {
    w->overflow = 1;
    return;
  }
  memcpy(w->buf + w->pos, tmp, n);
  w->pos += n;
}

static void w_bytes(writer *w, uint8_t major, const uint8_t *data, size_t len) {
  w_head(w, major, len);
  if (w->overflow) return;
  if (w->pos + len > w->cap) {
    w->overflow = 1;
    return;
  }
  memcpy(w->buf + w->pos, data, len);
  w->pos += len;
}

int se_encode_generate(uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, 5, 1); // map(1)
  w_head(&w, 0, K_OP);
  w_head(&w, 0, OP_GENERATE);
  return w.overflow ? -1 : (int)w.pos;
}

int se_encode_sign(const uint8_t *handle, size_t handle_len, const uint8_t *digest,
                   size_t digest_len, uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, 5, 3); // map(3)
  w_head(&w, 0, K_OP);
  w_head(&w, 0, OP_SIGN);
  w_head(&w, 0, K_HANDLE);
  w_bytes(&w, 2, handle, handle_len);
  w_head(&w, 0, K_DIGEST);
  w_bytes(&w, 2, digest, digest_len);
  return w.overflow ? -1 : (int)w.pos;
}

typedef struct {
  const uint8_t *p;
  size_t len;
  size_t off;
} reader;

static se_status r_head(reader *r, uint8_t *major, uint64_t *arg) {
  if (r->off >= r->len) return SE_ERR_TRUNCATED;
  uint8_t b = r->p[r->off++];
  *major = b >> 5;
  uint8_t info = b & 0x1F;
  if (info < 24) {
    *arg = info;
    return SE_OK;
  }
  size_t n;
  if (info == 24) {
    n = 1;
  } else if (info == 25) {
    n = 2;
  } else if (info == 26) {
    n = 4;
  } else if (info == 27) {
    n = 8;
  } else {
    return SE_ERR_MALFORMED;
  }
  if (r->off + n > r->len) return SE_ERR_TRUNCATED;
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) v = (v << 8) | r->p[r->off++];
  *arg = v;
  return SE_OK;
}

// One decoded map entry: a key and a value that is a uint or a byte/text span.
typedef struct {
  uint64_t key;
  uint8_t major;
  uint64_t uintval;
  const uint8_t *span;
  size_t span_len;
} entry;

static se_status r_map(reader *r, entry *entries, size_t max, size_t *count) {
  uint8_t major;
  uint64_t n;
  se_status st = r_head(r, &major, &n);
  if (st != SE_OK) return st;
  if (major != 5) return SE_ERR_TYPE;
  if (n > max) return SE_ERR_BUFFER;
  for (uint64_t i = 0; i < n; i++) {
    uint8_t km;
    uint64_t kv;
    st = r_head(r, &km, &kv);
    if (st != SE_OK) return st;
    if (km != 0) return SE_ERR_TYPE; // keys are uints
    uint8_t vm;
    uint64_t va;
    st = r_head(r, &vm, &va);
    if (st != SE_OK) return st;
    entry *e = &entries[i];
    e->key = kv;
    e->major = vm;
    if (vm == 0) {
      e->uintval = va;
      e->span = NULL;
      e->span_len = 0;
    } else if (vm == 2 || vm == 3) {
      if (r->off + va > r->len) return SE_ERR_TRUNCATED;
      e->span = r->p + r->off;
      e->span_len = (size_t)va;
      r->off += (size_t)va;
    } else {
      return SE_ERR_TYPE;
    }
  }
  *count = (size_t)n;
  return r->off == r->len ? SE_OK : SE_ERR_MALFORMED;
}

static const entry *find(const entry *entries, size_t count, uint64_t key) {
  for (size_t i = 0; i < count; i++)
    if (entries[i].key == key) return &entries[i];
  return NULL;
}

static se_status copy_span(const entry *e, uint8_t *dst, size_t cap, size_t *out_len) {
  if (!e || e->major != 2) return SE_ERR_MISSING;
  if (e->span_len > cap) return SE_ERR_BUFFER;
  memcpy(dst, e->span, e->span_len);
  *out_len = e->span_len;
  return SE_OK;
}

se_status se_decode_response(const uint8_t *payload, size_t len, se_response *out) {
  reader r = {payload, len, 0};
  entry entries[8];
  size_t count = 0;
  se_status st = r_map(&r, entries, 8, &count);
  if (st != SE_OK) return st;

  const entry *status = find(entries, count, K_STATUS);
  const entry *op = find(entries, count, K_OP);
  if (!status || status->major != 0 || !op || op->major != 0) return SE_ERR_MISSING;

  if (status->uintval == ST_ERROR) {
    out->kind = SE_RESP_ERROR;
    const entry *msg = find(entries, count, K_ERR);
    size_t n = 0;
    if (msg && msg->major == 3) {
      n = msg->span_len < sizeof(out->error) - 1 ? msg->span_len : sizeof(out->error) - 1;
      memcpy(out->error, msg->span, n);
    }
    out->error[n] = '\0';
    return SE_OK;
  }
  if (status->uintval != ST_OK) return SE_ERR_STATUS;

  if (op->uintval == OP_GENERATE) {
    out->kind = SE_RESP_GENERATED;
    st = copy_span(find(entries, count, K_HANDLE), out->handle, sizeof(out->handle),
                   &out->handle_len);
    if (st != SE_OK) return st;
    return copy_span(find(entries, count, K_PUBKEY), out->public_key, sizeof(out->public_key),
                     &out->public_key_len);
  }
  if (op->uintval == OP_SIGN) {
    out->kind = SE_RESP_SIGNED;
    return copy_span(find(entries, count, K_SIG), out->signature, sizeof(out->signature),
                     &out->signature_len);
  }
  return SE_ERR_OPCODE;
}
