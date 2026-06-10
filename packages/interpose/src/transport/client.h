/**
 * @file client.h
 * @brief Loopback transport to the helper: one framed request per call,
 *        decoded response out.
 *
 * @details
 * Connects to 127.0.0.1 at the port named by SIMENCLAVE_PORT, sends one framed
 * request carrying the capability token from SIMENCLAVE_TOKEN, reads one
 * framed response, and decodes it. One connection per request, mirroring the
 * helper's Swift client. Every function returns the codec's ::se_status;
 * an absent or malformed port or token, a failed connect, and a short read all
 * surface as ::SE_ERR_TRUNCATED, an oversized frame as ::SE_ERR_BUFFER, and a
 * bad length prefix as ::SE_ERR_MALFORMED.
 *
 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#ifndef SE_CLIENT_H
#define SE_CLIENT_H

#include "se_protocol.h"

/**
 * @defgroup se_client Loopback client
 * @brief One-shot request functions the hooks call against the helper.
 * @{
 */

/**
 * @brief Run a silent GENERATE against the helper.
 *
 * @param[in]  app_id     Guest bundle id, UTF-8, or NULL; carried for the approval prompt.
 * @param[in]  app_id_len Length of @p app_id; 0 omits it.
 * @param[out] out        The decoded response; ::SE_RESP_GENERATED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_generate(const uint8_t *app_id, size_t app_id_len, se_response *out);

/**
 * @brief Run a GENERATE that relays a captured access-control policy.
 *
 * @param[in]  biometry       Non-zero requests a biometry-class key.
 * @param[in]  flags          Raw SecAccessControlCreateFlags, relayed verbatim.
 * @param[in]  protection     Protection constant as UTF-8 text.
 * @param[in]  protection_len Length of @p protection.
 * @param[in]  app_id         Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len     Length of @p app_id; 0 omits it.
 * @param[out] out            The decoded response; ::SE_RESP_GENERATED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_generate_ac(int biometry, uint64_t flags, const uint8_t *protection,
                                size_t protection_len, const uint8_t *app_id, size_t app_id_len,
                                se_response *out);

/**
 * @brief Run a SIGN for a handle over a 32-byte digest.
 *
 * @param[in]  handle     Handle a prior GENERATE returned.
 * @param[in]  handle_len Length of @p handle.
 * @param[in]  digest     The SHA-256 digest to sign.
 * @param[in]  digest_len Length of @p digest; the helper only accepts 32.
 * @param[out] out        The decoded response; ::SE_RESP_SIGNED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_sign(const uint8_t *handle, size_t handle_len, const uint8_t *digest,
                         size_t digest_len, se_response *out);

/**
 * @brief Fetch the public key for a handle.
 *
 * @param[in]  handle     Handle a prior GENERATE returned.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] out        The decoded response; ::SE_RESP_PUBKEY on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_get_pubkey(const uint8_t *handle, size_t handle_len, se_response *out);

/**
 * @brief Delete the host key behind a handle.
 *
 * @param[in]  handle     Handle to remove.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] out        The decoded response; ::SE_RESP_DELETED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_delete(const uint8_t *handle, size_t handle_len, se_response *out);

/**
 * @brief Run the HELLO version handshake.
 *
 * @param[in]  version Protocol version this side speaks; currently 1.
 * @param[out] out     The decoded response; ::SE_RESP_HELLO on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_hello(uint64_t version, se_response *out);

/** @} */

#endif
