/**
 * @file se_protocol.c
 * @brief Hand-written canonical CBOR: the request encoders and the response decoder.
 *
 * @details
 * Minimal CBOR for the protocol's messages: unsigned ints, byte strings, text
 * strings, and a definite-length map with unsigned-integer keys. Emits the
 * shortest form, the canonical encoding, so it byte-matches the Swift codec.
 *
 * @see se_protocol.h for the API documentation.
 *

 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#include "se_protocol.h"

#include <limits.h>
#include <string.h>

// keys
enum {
  K_OP = 0,
  K_STATUS = 1,
  K_HANDLE = 2,
  K_PUBKEY = 3,
  K_DIGEST = 4,
  K_SIG = 5,
  K_ERR = 6,
  K_TOKEN = 7,
  K_VERSION = 8,
  K_CLASS = 9,
  K_ERR_CODE = 10,
  K_ACCESS_FLAGS = 11,
  K_PROTECTION = 12,
  K_ERR_DOMAIN = 13,
  K_APP_ID = 14,
  K_UDID = 15,
  K_APP_TAG = 16,
};
// ops and status
enum {
  OP_HELLO = 1,
  OP_GENERATE = 2,
  OP_GET_PUBKEY = 3,
  OP_SIGN = 4,
  OP_DELETE = 5,
  OP_FIND_BY_TAG = 6,
  ST_OK = 0,
  ST_ERROR = 1
};
// CBOR major types (RFC 8949 3.1): uint, negative int, byte string, text, map
enum { CBOR_UINT = 0, CBOR_NEGINT = 1, CBOR_BYTES = 2, CBOR_TEXT = 3, CBOR_MAP = 5 };

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

int se_encode_generate(const uint8_t *token, size_t token_len, const uint8_t *app_id,
                       size_t app_id_len, uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  int has_app = app_id && app_id_len > 0;
  w_head(&w, CBOR_MAP, has_app ? 3 : 2);
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, OP_GENERATE);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  if (has_app) {
    w_head(&w, CBOR_UINT, K_APP_ID);
    w_bytes(&w, CBOR_TEXT, app_id, app_id_len);
  }
  return w.overflow ? -1 : (int)w.pos;
}

int se_encode_generate_ac(const uint8_t *token, size_t token_len, int biometry, uint64_t flags,
                          const uint8_t *protection, size_t protection_len, const uint8_t *app_id,
                          size_t app_id_len, uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  int has_app = app_id && app_id_len > 0;
  // map: op, token, [class if biometry], accessFlags, protection, [app id]. Keys ascending.
  w_head(&w, CBOR_MAP, (biometry ? 5 : 4) + (has_app ? 1 : 0));
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, OP_GENERATE);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  if (biometry) {
    w_head(&w, CBOR_UINT, K_CLASS);
    w_head(&w, CBOR_UINT, 1);
  }
  w_head(&w, CBOR_UINT, K_ACCESS_FLAGS);
  w_head(&w, CBOR_UINT, flags);
  w_head(&w, CBOR_UINT, K_PROTECTION);
  w_bytes(&w, CBOR_TEXT, protection, protection_len);
  if (has_app) {
    w_head(&w, CBOR_UINT, K_APP_ID);
    w_bytes(&w, CBOR_TEXT, app_id, app_id_len);
  }
  return w.overflow ? -1 : (int)w.pos;
}

int se_encode_sign(const uint8_t *token, size_t token_len, const uint8_t *handle, size_t handle_len,
                   const uint8_t *digest, size_t digest_len, uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, CBOR_MAP, 4); // map(4)
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, OP_SIGN);
  w_head(&w, CBOR_UINT, K_HANDLE);
  w_bytes(&w, CBOR_BYTES, handle, handle_len);
  w_head(&w, CBOR_UINT, K_DIGEST);
  w_bytes(&w, CBOR_BYTES, digest, digest_len);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  return w.overflow ? -1 : (int)w.pos;
}

// GET_PUBKEY and DELETE share a shape: the op, a handle, and the token.
static int encode_handle_op(uint64_t op, const uint8_t *token, size_t token_len,
                            const uint8_t *handle, size_t handle_len, uint8_t *out, size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, CBOR_MAP, 3); // map(3)
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, op);
  w_head(&w, CBOR_UINT, K_HANDLE);
  w_bytes(&w, CBOR_BYTES, handle, handle_len);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  return w.overflow ? -1 : (int)w.pos;
}

int se_encode_get_pubkey(const uint8_t *token, size_t token_len, const uint8_t *handle,
                         size_t handle_len, uint8_t *out, size_t cap) {
  return encode_handle_op(OP_GET_PUBKEY, token, token_len, handle, handle_len, out, cap);
}

int se_encode_delete(const uint8_t *token, size_t token_len, const uint8_t *handle,
                     size_t handle_len, uint8_t *out, size_t cap) {
  return encode_handle_op(OP_DELETE, token, token_len, handle, handle_len, out, cap);
}

int se_encode_hello(const uint8_t *token, size_t token_len, uint64_t version, uint8_t *out,
                    size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, CBOR_MAP, 3); // map(3): op, token, version
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, OP_HELLO);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  w_head(&w, CBOR_UINT, K_VERSION);
  w_head(&w, CBOR_UINT, version);
  return w.overflow ? -1 : (int)w.pos;
}

int se_encode_find_by_tag(const uint8_t *token, size_t token_len, const uint8_t *udid,
                          size_t udid_len, const uint8_t *app_tag, size_t app_tag_len, uint8_t *out,
                          size_t cap) {
  writer w = {out, cap, 0, 0};
  w_head(&w, CBOR_MAP, 4); // map(4): op, token, udid, app tag, keys ascending
  w_head(&w, CBOR_UINT, K_OP);
  w_head(&w, CBOR_UINT, OP_FIND_BY_TAG);
  w_head(&w, CBOR_UINT, K_TOKEN);
  w_bytes(&w, CBOR_BYTES, token, token_len);
  w_head(&w, CBOR_UINT, K_UDID);
  w_bytes(&w, CBOR_TEXT, udid, udid_len);
  w_head(&w, CBOR_UINT, K_APP_TAG);
  w_bytes(&w, CBOR_BYTES, app_tag, app_tag_len);
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
  uint64_t min;
  if (info == 24) {
    n = 1;
    min = 24;
  } else if (info == 25) {
    n = 2;
    min = 0x100;
  } else if (info == 26) {
    n = 4;
    min = 0x10000;
  } else if (info == 27) {
    n = 8;
    min = 0x100000000ULL;
  } else {
    return SE_ERR_MALFORMED;
  }
  if (r->off + n > r->len) return SE_ERR_TRUNCATED;
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) v = (v << 8) | r->p[r->off++];
  if (v < min) return SE_ERR_MALFORMED; // reject non-shortest-form (canonical)
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
  if (major != CBOR_MAP) return SE_ERR_TYPE;
  if (n > max) return SE_ERR_BUFFER;
  for (uint64_t i = 0; i < n; i++) {
    uint8_t km;
    uint64_t kv;
    st = r_head(r, &km, &kv);
    if (st != SE_OK) return st;
    if (km != CBOR_UINT) return SE_ERR_TYPE; // keys are uints
    for (uint64_t j = 0; j < i; j++) {
      if (entries[j].key == kv) return SE_ERR_MALFORMED; // reject duplicate key
    }
    uint8_t vm;
    uint64_t va;
    st = r_head(r, &vm, &va);
    if (st != SE_OK) return st;
    entry *e = &entries[i];
    e->key = kv;
    e->major = vm;
    if (vm == CBOR_UINT || vm == CBOR_NEGINT) {
      e->uintval = va;
      e->span = NULL;
      e->span_len = 0;
    } else if (vm == CBOR_BYTES || vm == CBOR_TEXT) {
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
  if (!e || e->major != CBOR_BYTES) return SE_ERR_MISSING;
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
  if (!status || status->major != CBOR_UINT || !op || op->major != CBOR_UINT) return SE_ERR_MISSING;

  if (status->uintval == ST_ERROR) {
    out->kind = SE_RESP_ERROR;
    out->error_code = 0;
    out->error_domain = 0;
    const entry *code = find(entries, count, K_ERR_CODE);
    // Bound the attacker-controlled integer before the signed cast: an out-of-range
    // code stays 0, which the hooks treat as "no specific code" and map to a
    // generic failure. No OSStatus is anywhere near these limits.
    if (code && code->major == CBOR_NEGINT && code->uintval < INT_MAX) {
      out->error_code = -(int)(code->uintval + 1); // CBOR negint n encodes -1 - n
    } else if (code && code->major == CBOR_UINT && code->uintval <= INT_MAX) {
      out->error_code = (int)code->uintval;
    }
    const entry *dom = find(entries, count, K_ERR_DOMAIN);
    if (dom && dom->major == CBOR_UINT && dom->uintval <= INT_MAX) {
      out->error_domain = (int)dom->uintval;
    }
    const entry *msg = find(entries, count, K_ERR);
    size_t n = 0;
    if (msg && msg->major == CBOR_TEXT) {
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
  if (op->uintval == OP_GET_PUBKEY) {
    out->kind = SE_RESP_PUBKEY;
    return copy_span(find(entries, count, K_PUBKEY), out->public_key, sizeof(out->public_key),
                     &out->public_key_len);
  }
  if (op->uintval == OP_DELETE) {
    out->kind = SE_RESP_DELETED;
    return SE_OK;
  }
  if (op->uintval == OP_HELLO) {
    out->kind = SE_RESP_HELLO;
    const entry *ver = find(entries, count, K_VERSION);
    out->version = (ver && ver->major == CBOR_UINT) ? ver->uintval : 0;
    return SE_OK;
  }
  if (op->uintval == OP_FIND_BY_TAG) {
    out->kind = SE_RESP_FOUND;
    st = copy_span(find(entries, count, K_HANDLE), out->handle, sizeof(out->handle),
                   &out->handle_len);
    if (st != SE_OK) return st;
    return copy_span(find(entries, count, K_PUBKEY), out->public_key, sizeof(out->public_key),
                     &out->public_key_len);
  }
  return SE_ERR_OPCODE;
}
