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
 * @author Nirapod Labs
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nirapod Labs
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
 * @param[in]  key_type     Requested kSecAttrKeyType as UTF-8 text, or NULL to keep the P-256
 *                          default; relayed so the SEP rejects a wrong type with its own error.
 * @param[in]  key_type_len Length of @p key_type.
 * @param[in]  key_size     Requested kSecAttrKeySizeInBits; ignored when @p key_type is NULL.
 * @param[out] out        The decoded response; ::SE_RESP_GENERATED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_generate(const uint8_t *app_id, size_t app_id_len, const uint8_t *key_type,
                             size_t key_type_len, uint64_t key_size, se_response *out);

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
                                const uint8_t *key_type, size_t key_type_len, uint64_t key_size,
                                se_response *out);

/**
 * @brief Run a GENERATE for a permanent key, carrying its persistence tag.
 *
 * Same as ::se_client_generate_ac plus the simulator UDID and application tag, so the
 * helper keeps the key findable by tag and a relaunched app reloads it.
 *
 * @param[in]  biometry       Non-zero requests a biometry-class key.
 * @param[in]  flags          Raw SecAccessControlCreateFlags, relayed verbatim.
 * @param[in]  protection     Protection constant as UTF-8 text.
 * @param[in]  protection_len Length of @p protection.
 * @param[in]  app_id         Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len     Length of @p app_id; 0 omits it.
 * @param[in]  udid           Simulator UDID, UTF-8.
 * @param[in]  udid_len       Length of @p udid.
 * @param[in]  app_tag        Application tag bytes.
 * @param[in]  app_tag_len    Length of @p app_tag.
 * @param[out] out            The decoded response; ::SE_RESP_GENERATED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_generate_persistent(int biometry, uint64_t flags, const uint8_t *protection,
                                        size_t protection_len, const uint8_t *app_id,
                                        size_t app_id_len, const uint8_t *udid, size_t udid_len,
                                        const uint8_t *app_tag, size_t app_tag_len,
                                        const uint8_t *key_type, size_t key_type_len,
                                        uint64_t key_size, se_response *out);

/**
 * @brief Look up a persisted key by application tag, namespaced by simulator UDID.
 *
 * @param[in]  udid        Simulator UDID, UTF-8.
 * @param[in]  udid_len    Length of @p udid.
 * @param[in]  app_tag     Application tag bytes.
 * @param[in]  app_tag_len Length of @p app_tag.
 * @param[out] out         The decoded response; ::SE_RESP_FOUND on a hit, ::SE_RESP_ERROR on a miss.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_find_by_tag(const uint8_t *udid, size_t udid_len, const uint8_t *app_tag,
                                size_t app_tag_len, se_response *out);

/**
 * @brief Enumerate every persisted key for the simulator, for a kSecMatchLimitAll query.
 *
 * @param[in]  udid        Simulator UDID, UTF-8.
 * @param[in]  udid_len    Length of @p udid.
 * @param[out] entries     Caller array filled with up to @p max_entries keys.
 * @param[in]  max_entries Capacity of @p entries.
 * @param[out] count       Number of entries written.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_list(const uint8_t *udid, size_t udid_len, se_key_entry *entries,
                         size_t max_entries, size_t *count);

/**
 * @brief Ask the helper whether the real key supports an operation+algorithm.
 *
 * @param[in]  handle        Handle a prior GENERATE returned.
 * @param[in]  handle_len    Length of @p handle.
 * @param[in]  operation     SecKeyOperationType raw value.
 * @param[in]  algorithm     SecKeyAlgorithm constant as UTF-8 text.
 * @param[in]  algorithm_len Length of @p algorithm.
 * @param[out] out           The decoded response; ::SE_RESP_SUPPORTED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_is_algorithm_supported(const uint8_t *handle, size_t handle_len,
                                           uint64_t operation, const uint8_t *algorithm,
                                           size_t algorithm_len, se_response *out);

/**
 * @brief Fetch the real key's serialized attribute property list.
 *
 * @param[in]  handle     Handle a prior GENERATE returned.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] blob       Caller buffer the serialized plist is copied to.
 * @param[in]  cap        Capacity of @p blob.
 * @param[out] blob_len   Bytes written to @p blob.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_copy_attributes(const uint8_t *handle, size_t handle_len, uint8_t *blob,
                                    size_t cap, size_t *blob_len);

/**
 * @brief ECIES decrypt @p ciphertext with the real key. The decoded response is
 *        ::SE_RESP_RESULT (result holds the plaintext) or ::SE_RESP_ERROR.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_decrypt(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                            size_t algorithm_len, const uint8_t *ciphertext, size_t ciphertext_len,
                            se_response *out);

/**
 * @brief ECDH agreement with @p peer_key (X9.63) and the real key, carrying the caller's
 *        exchange parameters (@p params, a serialized plist; NULL/0 for a raw agreement) so a KDF
 *        variant runs as a device would. The decoded response is ::SE_RESP_RESULT (result holds
 *        the shared secret) or ::SE_RESP_ERROR.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_key_exchange(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                                 size_t algorithm_len, const uint8_t *peer_key, size_t peer_key_len,
                                 const uint8_t *params, size_t params_len, se_response *out);

/**
 * @brief Run a SIGN for a handle under a SecKeyAlgorithm over the input bytes.
 *
 * @param[in]  handle        Handle a prior GENERATE returned.
 * @param[in]  handle_len    Length of @p handle.
 * @param[in]  algorithm     SecKeyAlgorithm constant as UTF-8 text.
 * @param[in]  algorithm_len Length of @p algorithm.
 * @param[in]  input         The bytes to sign: a digest for digest-mode, the raw message for
 *                           message-mode. The helper passes them to the real key under @p algorithm.
 * @param[in]  input_len     Length of @p input.
 * @param[out] out           The decoded response; ::SE_RESP_SIGNED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_sign(const uint8_t *handle, size_t handle_len, const uint8_t *algorithm,
                         size_t algorithm_len, const uint8_t *input, size_t input_len,
                         se_response *out);

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
 * @brief Re-tag the key behind @p handle to a new application tag.
 *
 * @param[in]  handle      Handle of the key to re-tag.
 * @param[in]  handle_len  Length of @p handle.
 * @param[in]  udid        Simulator UDID, UTF-8.
 * @param[in]  udid_len    Length of @p udid.
 * @param[in]  app_tag     New application tag bytes.
 * @param[in]  app_tag_len Length of @p app_tag.
 * @param[out] out         The decoded response; ::SE_RESP_UPDATED on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_update(const uint8_t *handle, size_t handle_len, const uint8_t *udid,
                           size_t udid_len, const uint8_t *app_tag, size_t app_tag_len,
                           se_response *out);

/**
 * @brief Run the HELLO version handshake, announcing the app's identity for display.
 *
 * The identity is optional and best-effort: the bundle id, display name, and a small icon as
 * PNG bytes, each omitted when its pointer is NULL or length is 0. It names the connecting app
 * so the helper can show it and gates nothing; the helper validates the name and icon before use.
 *
 * @param[in]  version          Protocol version this side speaks; currently 1.
 * @param[in]  app_id           Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len       Length of @p app_id; 0 omits it.
 * @param[in]  display_name     Guest display name, UTF-8, or NULL.
 * @param[in]  display_name_len Length of @p display_name; 0 omits it.
 * @param[in]  app_icon         Guest app icon as PNG bytes, or NULL.
 * @param[in]  app_icon_len     Length of @p app_icon; 0 omits it.
 * @param[out] out              The decoded response; ::SE_RESP_HELLO on success.
 * @return ::SE_OK when a response decoded cleanly, an ::se_status error otherwise.
 */
se_status se_client_hello(uint64_t version, const uint8_t *app_id, size_t app_id_len,
                          const uint8_t *display_name, size_t display_name_len,
                          const uint8_t *app_icon, size_t app_icon_len, se_response *out);

/** @} */

#endif
