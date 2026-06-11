/**
 * @file client.c
 * @brief Loopback client implementation: connect, frame, send, read, decode.
 *
 * @details
 *
 * @see client.h for the API documentation.
 *

 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
 */
#include "client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_helper(void) {
  const char *env = getenv("SIMENCLAVE_PORT");
  if (!env) return -1;
  char *end = NULL;
  long port = strtol(env, &end, 10);
  if (end == env || *end != '\0' || port <= 0 || port > 65535) return -1;

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
  size_t written = 0;
  while (written < len) {
    ssize_t n = send(fd, buf + written, len - written, 0);
    if (n <= 0) return -1;
    written += (size_t)n;
  }
  return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len) {
  size_t read_count = 0;
  while (read_count < len) {
    ssize_t n = recv(fd, buf + read_count, len - read_count, 0);
    if (n <= 0) return -1;
    read_count += (size_t)n;
  }
  return 0;
}

// Send one framed request and read one framed response into a caller buffer, undecoded.
// Used by the fixed-shape requests (decoded into se_response) and by the variable-length
// LIST response (decoded into an se_key_entry array).
static se_status do_request_raw(const uint8_t *payload, int payload_len, uint8_t *resp,
                                size_t resp_cap, size_t *resp_len) {
  if (payload_len < 0) return SE_ERR_BUFFER;

  int fd = connect_helper();
  if (fd < 0) return SE_ERR_TRUNCATED;

  uint8_t frame[8192];
  int frame_len = se_frame(payload, (size_t)payload_len, frame, sizeof(frame));
  if (frame_len < 0 || write_all(fd, frame, (size_t)frame_len) != 0) {
    close(fd);
    return SE_ERR_BUFFER;
  }

  uint8_t prefix[4];
  if (read_all(fd, prefix, 4) != 0) {
    close(fd);
    return SE_ERR_TRUNCATED;
  }
  long response_len = se_payload_length(prefix);
  if (response_len < 0) {
    close(fd);
    return SE_ERR_MALFORMED;
  }
  if ((size_t)response_len > resp_cap) {
    close(fd);
    return SE_ERR_BUFFER;
  }
  if (read_all(fd, resp, (size_t)response_len) != 0) {
    close(fd);
    return SE_ERR_TRUNCATED;
  }
  close(fd);
  *resp_len = (size_t)response_len;
  return SE_OK;
}

static se_status do_request(const uint8_t *payload, int payload_len, se_response *out) {
  uint8_t response[4096];
  size_t response_len = 0;
  se_status st = do_request_raw(payload, payload_len, response, sizeof(response), &response_len);
  if (st != SE_OK) return st;
  return se_decode_response(response, response_len, out);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decode the 32-byte capability token from SIMENCLAVE_TOKEN (64 hex chars).
// Returns 0 on success, -1 if the variable is missing or malformed.
static int read_token(uint8_t out[32]) {
  const char *hex = getenv("SIMENCLAVE_TOKEN");
  if (!hex || strlen(hex) != 64) return -1;
  for (size_t i = 0; i < 32; i++) {
    int hi = hex_nibble(hex[i * 2]);
    int lo = hex_nibble(hex[(i * 2) + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

se_status se_client_generate(const uint8_t *app_id, size_t app_id_len, const uint8_t *key_type,
                             size_t key_type_len, uint64_t key_size, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[320];
  return do_request(payload,
                    se_encode_generate(token, sizeof(token), app_id, app_id_len, key_type,
                                       key_type_len, key_size, payload, sizeof(payload)),
                    out);
}

se_status se_client_generate_ac(int biometry, uint64_t flags, const uint8_t *protection,
                                size_t protection_len, const uint8_t *app_id, size_t app_id_len,
                                const uint8_t *key_type, size_t key_type_len, uint64_t key_size,
                                se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[384];
  return do_request(payload,
                    se_encode_generate_ac(token, sizeof(token), biometry, flags, protection,
                                          protection_len, app_id, app_id_len, key_type, key_type_len,
                                          key_size, payload, sizeof(payload)),
                    out);
}

se_status se_client_generate_persistent(int biometry, uint64_t flags, const uint8_t *protection,
                                        size_t protection_len, const uint8_t *app_id,
                                        size_t app_id_len, const uint8_t *udid, size_t udid_len,
                                        const uint8_t *app_tag, size_t app_tag_len,
                                        const uint8_t *key_type, size_t key_type_len,
                                        uint64_t key_size, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[512];
  return do_request(payload,
                    se_encode_generate_ac_persistent(token, sizeof(token), biometry, flags,
                                                     protection, protection_len, app_id, app_id_len,
                                                     udid, udid_len, app_tag, app_tag_len, key_type,
                                                     key_type_len, key_size, payload,
                                                     sizeof(payload)),
                    out);
}

se_status se_client_find_by_tag(const uint8_t *udid, size_t udid_len, const uint8_t *app_tag,
                                size_t app_tag_len, const uint8_t *app_id, size_t app_id_len,
                                se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[512];
  return do_request(payload,
                    se_encode_find_by_tag(token, sizeof(token), udid, udid_len, app_tag, app_tag_len,
                                          app_id, app_id_len, payload, sizeof(payload)),
                    out);
}

se_status se_client_list(const uint8_t *udid, size_t udid_len, const uint8_t *app_id,
                         size_t app_id_len, se_key_entry *entries, size_t max_entries,
                         size_t *count) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[512];
  int payload_len = se_encode_list_keys(token, sizeof(token), udid, udid_len, app_id, app_id_len,
                                        payload, sizeof(payload));
  // A list response holds every key for the simulator; size for a generous count of keys.
  uint8_t response[16384];
  size_t response_len = 0;
  se_status st = do_request_raw(payload, payload_len, response, sizeof(response), &response_len);
  if (st != SE_OK) return st;
  return se_decode_list_response(response, response_len, entries, max_entries, count);
}

se_status se_client_is_algorithm_supported(const uint8_t *handle, size_t handle_len,
                                           uint64_t operation, const uint8_t *algorithm,
                                           size_t algorithm_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[256];
  return do_request(payload,
                    se_encode_is_algorithm_supported(token, sizeof(token), handle, handle_len,
                                                     operation, algorithm, algorithm_len, payload,
                                                     sizeof(payload)),
                    out);
}

se_status se_client_copy_attributes(const uint8_t *handle, size_t handle_len, uint8_t *blob,
                                    size_t cap, size_t *blob_len) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[128];
  int payload_len =
      se_encode_copy_attributes(token, sizeof(token), handle, handle_len, payload, sizeof(payload));
  uint8_t response[4096];
  size_t response_len = 0;
  se_status st = do_request_raw(payload, payload_len, response, sizeof(response), &response_len);
  if (st != SE_OK) return st;
  return se_decode_attributes_response(response, response_len, blob, cap, blob_len);
}

se_status se_client_decrypt(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                            size_t algorithm_len, const uint8_t *ciphertext, size_t ciphertext_len,
                            se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[2048];
  return do_request(payload,
                    se_encode_decrypt(token, sizeof(token), handle, handle_len, algorithm,
                                      algorithm_len, ciphertext, ciphertext_len, payload,
                                      sizeof(payload)),
                    out);
}

se_status se_client_key_exchange(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                                 size_t algorithm_len, const uint8_t *peer_key, size_t peer_key_len,
                                 const uint8_t *params, size_t params_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[2048];
  return do_request(payload,
                    se_encode_key_exchange(token, sizeof(token), handle, handle_len, algorithm,
                                           algorithm_len, peer_key, peer_key_len, params, params_len,
                                           payload, sizeof(payload)),
                    out);
}

se_status se_client_sign(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                         size_t algorithm_len, const uint8_t *input, size_t input_len,
                         se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[4096];
  return do_request(payload,
                    se_encode_sign(token, sizeof(token), handle, handle_len, algorithm,
                                   algorithm_len, input, input_len, payload, sizeof(payload)),
                    out);
}

se_status se_client_get_pubkey(const uint8_t *handle, size_t handle_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[128];
  return do_request(
      payload,
      se_encode_get_pubkey(token, sizeof(token), handle, handle_len, payload, sizeof(payload)),
      out);
}

se_status se_client_update(const uint8_t *handle, size_t handle_len, const uint8_t *udid,
                           size_t udid_len, const uint8_t *app_tag, size_t app_tag_len,
                           const uint8_t *app_id, size_t app_id_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[512];
  return do_request(payload,
                    se_encode_update(token, sizeof(token), handle, handle_len, udid, udid_len,
                                     app_tag, app_tag_len, app_id, app_id_len, payload,
                                     sizeof(payload)),
                    out);
}

se_status se_client_delete(const uint8_t *handle, size_t handle_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[128];
  return do_request(
      payload, se_encode_delete(token, sizeof(token), handle, handle_len, payload, sizeof(payload)),
      out);
}

se_status se_client_hello(uint64_t version, const uint8_t *app_id, size_t app_id_len,
                          const uint8_t *display_name, size_t display_name_len, se_response *out) {
  uint8_t token[32];
  if (read_token(token) != 0) return SE_ERR_TRUNCATED;
  uint8_t payload[256];
  int n = se_encode_hello(token, sizeof(token), version, app_id, app_id_len, display_name,
                          display_name_len, payload, sizeof(payload));
  return do_request(payload, n, out);
}
