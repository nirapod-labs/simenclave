// Loopback transport to the helper. Connects to 127.0.0.1 at the port named by
// SIMENCLAVE_PORT, runs one framed request, decodes the response. M1 adds the
// capability token.
#ifndef SE_CLIENT_H
#define SE_CLIENT_H

#include "se_protocol.h"

se_status se_client_generate(se_response *out);
se_status se_client_generate_ac(int biometry, uint64_t flags, const uint8_t *protection,
                                size_t protection_len, se_response *out);
se_status se_client_sign(const uint8_t *handle, size_t handle_len, const uint8_t *digest,
                         size_t digest_len, se_response *out);
se_status se_client_get_pubkey(const uint8_t *handle, size_t handle_len, se_response *out);
se_status se_client_delete(const uint8_t *handle, size_t handle_len, se_response *out);
se_status se_client_hello(uint64_t version, se_response *out);

#endif
