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

static se_status do_request(const uint8_t *payload, int payload_len, se_response *out) {
  if (payload_len < 0) return SE_ERR_BUFFER;

  int fd = connect_helper();
  if (fd < 0) return SE_ERR_TRUNCATED;

  uint8_t frame[4096];
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

  uint8_t response[4096];
  if ((size_t)response_len > sizeof(response)) {
    close(fd);
    return SE_ERR_BUFFER;
  }
  if (read_all(fd, response, (size_t)response_len) != 0) {
    close(fd);
    return SE_ERR_TRUNCATED;
  }
  close(fd);

  return se_decode_response(response, (size_t)response_len, out);
}

se_status se_client_generate(se_response *out) {
  uint8_t payload[16];
  return do_request(payload, se_encode_generate(payload, sizeof(payload)), out);
}

se_status se_client_sign(const uint8_t *handle, size_t handle_len, const uint8_t *digest,
                         size_t digest_len, se_response *out) {
  uint8_t payload[256];
  return do_request(
      payload, se_encode_sign(handle, handle_len, digest, digest_len, payload, sizeof(payload)),
      out);
}
