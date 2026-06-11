/**
 * @file se_protocol.h
 * @brief SimEnclave wire protocol, C side: request encoders, the response
 *        decoder, and the length framing.
 *
 * @details
 * The interposer encodes requests and decodes responses with this; the Swift
 * helper is the other end. The wire is CBOR maps with unsigned-integer keys
 * inside a 4-byte big-endian length-prefixed frame (see SPEC.md and
 * protocol.cddl two directories up). The codec is hand-written and byte-matches
 * the Swift one, and it stays hand-written: the surface is small, the two
 * codecs are each other's byte-for-byte oracle, and rejecting duplicate keys
 * and non-shortest-form encodings is something a hand-written reader
 * guarantees directly.
 *
 * Every encoder writes a complete request payload (CBOR, no frame) into a
 * caller buffer and returns the byte count, or -1 when the buffer is too
 * small. Encoders never allocate.
 *
 * @author SimEnclave Contributors
 * @date 2026
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 SimEnclave Contributors
 */
#ifndef SE_PROTOCOL_H
#define SE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup se_protocol Wire protocol (C codec)
 * @brief Request encoders, the response decoder, and the frame helpers the
 *        interposer speaks to the helper.
 * @{
 */

/** Largest frame either end accepts: 1 MiB, matching the Swift codec. */
#define SE_MAX_FRAME (1 << 20)

/** Decoder result. Anything but ::SE_OK means the payload was rejected. */
typedef enum {
  SE_OK = 0,        ///< Decoded cleanly.
  SE_ERR_TRUNCATED, ///< Payload ended inside a value.
  SE_ERR_MALFORMED, ///< Not canonical CBOR: duplicate key, non-shortest form, or trailing bytes.
  SE_ERR_TYPE,      ///< A value carried the wrong CBOR major type.
  SE_ERR_OPCODE,    ///< The op (key 0) is not one this codec knows.
  SE_ERR_STATUS,    ///< The status (key 1) is neither OK nor ERROR.
  SE_ERR_MISSING,   ///< A field the op requires is absent.
  SE_ERR_BUFFER,    ///< A field exceeds its fixed buffer in ::se_response.
} se_status;

/** Which response the helper sent, after ::se_decode_response dispatches on op and status. */
typedef enum {
  SE_RESP_GENERATED, ///< GENERATE succeeded: handle and public key are set.
  SE_RESP_SIGNED,    ///< SIGN succeeded: signature is set.
  SE_RESP_PUBKEY,    ///< GET_PUBKEY succeeded: public key is set.
  SE_RESP_DELETED,   ///< DELETE succeeded.
  SE_RESP_UPDATED,   ///< UPDATE succeeded.
  SE_RESP_HELLO,     ///< HELLO succeeded: version is set.
  SE_RESP_FOUND,     ///< FIND_BY_TAG succeeded: handle and public key are set.
  SE_RESP_SUPPORTED, ///< IS_ALGO_SUPPORTED succeeded: supported is set.
  SE_RESP_RESULT,    ///< DECRYPT or KEY_EXCHANGE succeeded: result is set.
  SE_RESP_ERROR,     ///< The helper returned an error: error, error_code, error_domain are set.
} se_resp_kind;

/**
 * A decoded response. Fixed buffers, no ownership: the decoder copies out of
 * the payload, and lengths say how much of each buffer is meaningful for the
 * ::se_resp_kind in @c kind.
 */
typedef struct {
  se_resp_kind kind;       ///< Which response this is; selects the fields below.
  uint8_t handle[64];      ///< Key handle bytes (GENERATED, FOUND).
  size_t handle_len;       ///< Meaningful bytes in @c handle.
  uint8_t public_key[133]; ///< X9.63 public key, 65 bytes for P-256 (GENERATED, PUBKEY, FOUND).
  size_t public_key_len;   ///< Meaningful bytes in @c public_key.
  uint8_t signature[256];  ///< DER ECDSA signature, exactly as the SEP returned it (SIGNED).
  size_t signature_len;    ///< Meaningful bytes in @c signature.
  char error[256];  ///< NUL-terminated reason on an error; human-readable, never load-bearing.
  int error_code;   ///< The helper's OSStatus on an error response, 0 otherwise.
  int error_domain; ///< Error-domain selector (key 13) on an error: 0 OSStatus, 1 LAError.
  uint64_t version; ///< Protocol version on a HELLO response.
  int supported;    ///< Whether the algorithm is supported (IS_ALGO_SUPPORTED): 0 or 1.
  uint8_t result[1024]; ///< Plaintext or shared secret (DECRYPT, KEY_EXCHANGE).
  size_t result_len;    ///< Meaningful bytes in @c result.
} se_response;

/**
 * @brief Encode a GENERATE request for a silent key.
 *
 * Carries the capability token (key 7) and, when @p app_id_len is non-zero,
 * the guest app id (key 14) the helper's approval prompt names. With no app id
 * the bytes are identical to the pre-M3 encoding.
 *
 * @param[in]  token      32-byte capability token.
 * @param[in]  token_len  Length of @p token; the helper only accepts 32.
 * @param[in]  app_id     Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len Length of @p app_id; 0 omits key 14.
 * @param[in]  key_type     Requested kSecAttrKeyType as UTF-8 text (key 26), or NULL to keep the
 *                          helper's P-256 default. Relayed so the SEP rejects a wrong type.
 * @param[in]  key_type_len Length of @p key_type.
 * @param[in]  key_size     Requested kSecAttrKeySizeInBits (key 27); ignored when @p key_type is NULL.
 * @param[out] out        Buffer the payload is written to.
 * @param[in]  cap        Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_generate(const uint8_t *token, size_t token_len, const uint8_t *app_id,
                       size_t app_id_len, const uint8_t *key_type, size_t key_type_len,
                       uint64_t key_size, uint8_t *out, size_t cap);

/**
 * @brief Encode a GENERATE request that relays an access-control descriptor.
 *
 * The key class (biometry adds key 9 = 1; silent omits it), the raw
 * SecAccessControlCreateFlags exactly as captured (key 11), the protection
 * constant relayed verbatim as text (key 12), and the guest app id (key 14)
 * when present. The helper rebuilds the access control from these on its side.
 *
 * @param[in]  token          32-byte capability token.
 * @param[in]  token_len      Length of @p token.
 * @param[in]  biometry       Non-zero adds key 9 = 1 (a biometry-class key).
 * @param[in]  flags          Raw SecAccessControlCreateFlags, relayed verbatim.
 * @param[in]  protection     Protection constant as UTF-8 text, e.g. "ak".
 * @param[in]  protection_len Length of @p protection.
 * @param[in]  app_id         Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len     Length of @p app_id; 0 omits key 14.
 * @param[out] out            Buffer the payload is written to.
 * @param[in]  cap            Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_generate_ac(const uint8_t *token, size_t token_len, int biometry, uint64_t flags,
                          const uint8_t *protection, size_t protection_len, const uint8_t *app_id,
                          size_t app_id_len, const uint8_t *key_type, size_t key_type_len,
                          uint64_t key_size, uint8_t *out, size_t cap);

/**
 * @brief Encode a GENERATE that also carries the persistence tag of a permanent key.
 *
 * Same shape as ::se_encode_generate_ac, plus the simulator UDID (key 15) and the
 * application tag (key 16). The helper keeps the minted key findable by this
 * (udid, tag) for its lifetime, so a relaunched app reloads it with FIND_BY_TAG.
 *
 * @param[in]  token          32-byte capability token.
 * @param[in]  token_len      Length of @p token.
 * @param[in]  biometry       Non-zero adds key 9 = 1 (a biometry-class key).
 * @param[in]  flags          Raw SecAccessControlCreateFlags, relayed verbatim.
 * @param[in]  protection     Protection constant as UTF-8 text.
 * @param[in]  protection_len Length of @p protection.
 * @param[in]  app_id         Guest bundle id, UTF-8, or NULL.
 * @param[in]  app_id_len     Length of @p app_id; 0 omits key 14.
 * @param[in]  udid           Simulator UDID, UTF-8 (key 15).
 * @param[in]  udid_len       Length of @p udid.
 * @param[in]  app_tag        Application tag bytes (key 16).
 * @param[in]  app_tag_len    Length of @p app_tag.
 * @param[out] out            Buffer the payload is written to.
 * @param[in]  cap            Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_generate_ac_persistent(const uint8_t *token, size_t token_len, int biometry,
                                     uint64_t flags, const uint8_t *protection, size_t protection_len,
                                     const uint8_t *app_id, size_t app_id_len, const uint8_t *udid,
                                     size_t udid_len, const uint8_t *app_tag, size_t app_tag_len,
                                     const uint8_t *key_type, size_t key_type_len, uint64_t key_size,
                                     uint8_t *out, size_t cap);

/**
 * @brief Encode a SIGN request: token, handle, the SecKeyAlgorithm, and the input bytes.
 *
 * @param[in]  token         32-byte capability token.
 * @param[in]  token_len     Length of @p token.
 * @param[in]  handle        Handle a prior GENERATE returned.
 * @param[in]  handle_len    Length of @p handle.
 * @param[in]  algorithm     SecKeyAlgorithm constant as UTF-8 text; the helper signs under it.
 * @param[in]  algorithm_len Length of @p algorithm.
 * @param[in]  input         The bytes to sign: a digest for digest-mode algorithms, the raw
 *                           message for message-mode. The helper hands them to the real key as-is.
 * @param[in]  input_len     Length of @p input.
 * @param[out] out           Buffer the payload is written to.
 * @param[in]  cap           Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_sign(const uint8_t *token, size_t token_len, const uint8_t *handle, size_t handle_len,
                   const uint8_t *algorithm, size_t algorithm_len, const uint8_t *input,
                   size_t input_len, uint8_t *out, size_t cap);

/**
 * @brief Encode a GET_PUBKEY request: token and handle.
 *
 * @param[in]  token      32-byte capability token.
 * @param[in]  token_len  Length of @p token.
 * @param[in]  handle     Handle a prior GENERATE returned.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] out        Buffer the payload is written to.
 * @param[in]  cap        Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_get_pubkey(const uint8_t *token, size_t token_len, const uint8_t *handle,
                         size_t handle_len, uint8_t *out, size_t cap);

/**
 * @brief Encode a DELETE request: token and the handle to remove.
 *
 * @param[in]  token      32-byte capability token.
 * @param[in]  token_len  Length of @p token.
 * @param[in]  handle     Handle to remove.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] out        Buffer the payload is written to.
 * @param[in]  cap        Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_delete(const uint8_t *token, size_t token_len, const uint8_t *handle,
                     size_t handle_len, uint8_t *out, size_t cap);

/**
 * @brief Encode an UPDATE request: re-tag the key behind @p handle to @p app_tag.
 *
 * Carries the handle (key 2), the simulator UDID (key 15), and the new application tag (key 16),
 * so the helper re-registers the key under the new (udid, tag) and find-by-tag follows the rename.
 *
 * @param[in]  token       32-byte capability token.
 * @param[in]  token_len   Length of @p token.
 * @param[in]  handle      Handle of the key to re-tag.
 * @param[in]  handle_len  Length of @p handle.
 * @param[in]  udid        Simulator UDID, UTF-8.
 * @param[in]  udid_len    Length of @p udid.
 * @param[in]  app_tag     New application tag bytes.
 * @param[in]  app_tag_len Length of @p app_tag.
 * @param[out] out         Buffer the payload is written to.
 * @param[in]  cap         Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_update(const uint8_t *token, size_t token_len, const uint8_t *handle,
                     size_t handle_len, const uint8_t *udid, size_t udid_len,
                     const uint8_t *app_tag, size_t app_tag_len, uint8_t *out, size_t cap);

/**
 * @brief Encode a HELLO request: token and the protocol version this side speaks.
 *
 * @param[in]  token     32-byte capability token.
 * @param[in]  token_len Length of @p token.
 * @param[in]  version   Protocol version offered; currently 1.
 * @param[out] out       Buffer the payload is written to.
 * @param[in]  cap       Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_hello(const uint8_t *token, size_t token_len, uint64_t version, uint8_t *out,
                    size_t cap);

/**
 * @brief Encode a FIND_BY_TAG request: look up a persisted key by application tag.
 *
 * The UDID namespaces tags per simulator as hygiene, not a security boundary
 * (it is guest-reported). Durable persistence lands in M5; until then the
 * helper answers not-found.
 *
 * @param[in]  token       32-byte capability token.
 * @param[in]  token_len   Length of @p token.
 * @param[in]  udid        Simulator UDID, UTF-8 text (key 15).
 * @param[in]  udid_len    Length of @p udid.
 * @param[in]  app_tag     Application tag bytes (key 16).
 * @param[in]  app_tag_len Length of @p app_tag.
 * @param[out] out         Buffer the payload is written to.
 * @param[in]  cap         Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_find_by_tag(const uint8_t *token, size_t token_len, const uint8_t *udid,
                          size_t udid_len, const uint8_t *app_tag, size_t app_tag_len, uint8_t *out,
                          size_t cap);

/**
 * @brief Decode a response payload, dispatching on op and status.
 *
 * Rejects anything that is not canonical CBOR: duplicate keys, non-shortest
 * integer or length forms, and trailing bytes all fail with
 * ::SE_ERR_MALFORMED, so each key has exactly one unambiguous value.
 *
 * @param[in]  payload Response payload (CBOR, no frame).
 * @param[in]  len     Length of @p payload.
 * @param[out] out     Decoded response; meaningful fields depend on @c out->kind.
 * @retval SE_OK             Decoded cleanly; @p out is filled.
 * @retval SE_ERR_TRUNCATED  Payload ended inside a value.
 * @retval SE_ERR_MALFORMED  Not canonical CBOR.
 * @retval SE_ERR_TYPE       Wrong CBOR major type for a known key.
 * @retval SE_ERR_OPCODE     Unknown op.
 * @retval SE_ERR_STATUS     Unknown status.
 * @retval SE_ERR_MISSING    A required field is absent.
 * @retval SE_ERR_BUFFER     A field exceeds its fixed buffer.
 */
se_status se_decode_response(const uint8_t *payload, size_t len, se_response *out);

/** One key in an enumeration (::se_decode_list_response): handle, X9.63 public key, and tag. */
typedef struct {
  uint8_t handle[64];      ///< Key handle bytes.
  size_t handle_len;       ///< Meaningful bytes in @c handle.
  uint8_t public_key[133]; ///< X9.63 public key.
  size_t public_key_len;   ///< Meaningful bytes in @c public_key.
  uint8_t app_tag[256];    ///< Application tag the key is stored under.
  size_t app_tag_len;      ///< Meaningful bytes in @c app_tag.
} se_key_entry;

/**
 * @brief Encode a LIST_KEYS request: enumerate every persisted key for a simulator.
 *
 * @param[in]  token     32-byte capability token.
 * @param[in]  token_len Length of @p token.
 * @param[in]  udid      Simulator UDID, UTF-8 (key 15).
 * @param[in]  udid_len  Length of @p udid.
 * @param[out] out       Buffer the payload is written to.
 * @param[in]  cap       Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_list_keys(const uint8_t *token, size_t token_len, const uint8_t *udid, size_t udid_len,
                        uint8_t *out, size_t cap);

/**
 * @brief Encode an IS_ALGO_SUPPORTED request: does the real key support an operation+algorithm.
 *
 * @param[in]  token         32-byte capability token.
 * @param[in]  token_len     Length of @p token.
 * @param[in]  handle        Handle a prior GENERATE returned.
 * @param[in]  handle_len    Length of @p handle.
 * @param[in]  operation     SecKeyOperationType raw value (key 18).
 * @param[in]  algorithm     SecKeyAlgorithm constant as UTF-8 text (key 19).
 * @param[in]  algorithm_len Length of @p algorithm.
 * @param[out] out           Buffer the payload is written to.
 * @param[in]  cap           Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_is_algorithm_supported(const uint8_t *token, size_t token_len, const uint8_t *handle,
                                     size_t handle_len, uint64_t operation, const uint8_t *algorithm,
                                     size_t algorithm_len, uint8_t *out, size_t cap);

/**
 * @brief Encode a COPY_ATTRIBUTES request: fetch the real key's serialized attribute dictionary.
 *
 * @param[in]  token      32-byte capability token.
 * @param[in]  token_len  Length of @p token.
 * @param[in]  handle     Handle a prior GENERATE returned.
 * @param[in]  handle_len Length of @p handle.
 * @param[out] out        Buffer the payload is written to.
 * @param[in]  cap        Capacity of @p out.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_copy_attributes(const uint8_t *token, size_t token_len, const uint8_t *handle,
                              size_t handle_len, uint8_t *out, size_t cap);

/**
 * @brief Decode an ATTRIBUTES response: the serialized attribute property list (key 21).
 *
 * @param[in]  payload  Response payload (CBOR, no frame).
 * @param[in]  len      Length of @p payload.
 * @param[out] out_blob Caller buffer the serialized plist is copied to.
 * @param[in]  cap      Capacity of @p out_blob.
 * @param[out] out_len  Bytes written to @p out_blob.
 * @retval SE_OK on a clean decode; an ::se_status error otherwise.
 */
se_status se_decode_attributes_response(const uint8_t *payload, size_t len, uint8_t *out_blob,
                                        size_t cap, size_t *out_len);

/**
 * @brief Encode a DECRYPT request: ECIES decrypt of @p ciphertext with the real key.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_decrypt(const uint8_t *token, size_t token_len, const uint8_t *handle,
                      size_t handle_len, const uint8_t *algorithm, size_t algorithm_len,
                      const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out, size_t cap);

/**
 * @brief Encode a KEY_EXCHANGE request: ECDH agreement with @p peer_key (X9.63), carrying the
 *        caller's exchange parameters so a KDF variant runs as a device would.
 *
 * @param[in]  params     Serialized plist of the exchange parameters (requested size, shared
 *                        info), or NULL for a raw agreement.
 * @param[in]  params_len Length of @p params; 0 sends an empty parameters dictionary.
 * @return Bytes written, or -1 if @p cap is too small.
 */
int se_encode_key_exchange(const uint8_t *token, size_t token_len, const uint8_t *handle,
                           size_t handle_len, const uint8_t *algorithm, size_t algorithm_len,
                           const uint8_t *peer_key, size_t peer_key_len, const uint8_t *params,
                           size_t params_len, uint8_t *out, size_t cap);

/**
 * @brief Decode a LISTED response: the helper's packed list of keys (key 17), unpacked into
 *        a caller array.
 *
 * The whole blob is bounds-checked even past @p max_entries, so a hostile or oversized
 * response is rejected rather than read out of bounds. Entries beyond @p max_entries are
 * validated and dropped; @p out_count reports how many were written.
 *
 * @param[in]  payload     Response payload (CBOR, no frame).
 * @param[in]  len         Length of @p payload.
 * @param[out] out_entries Caller array filled with up to @p max_entries keys.
 * @param[in]  max_entries Capacity of @p out_entries.
 * @param[out] out_count   Number of entries written.
 * @retval SE_OK on a clean decode; an ::se_status error otherwise.
 */
se_status se_decode_list_response(const uint8_t *payload, size_t len, se_key_entry *out_entries,
                                  size_t max_entries, size_t *out_count);

/**
 * @brief Frame a payload: a 4-byte big-endian length prefix, then the bytes.
 *
 * @param[in]  payload Payload to frame.
 * @param[in]  len     Length of @p payload; at most ::SE_MAX_FRAME.
 * @param[out] out     Buffer the frame is written to.
 * @param[in]  cap     Capacity of @p out; needs @p len + 4.
 * @return Bytes written (len + 4), or -1 if @p len exceeds ::SE_MAX_FRAME or
 *         @p cap is too small.
 */
int se_frame(const uint8_t *payload, size_t len, uint8_t *out, size_t cap);

/**
 * @brief Parse a 4-byte big-endian length prefix.
 *
 * @param[in] prefix The 4 prefix bytes.
 * @return The payload length, or -1 if it exceeds ::SE_MAX_FRAME.
 */
long se_payload_length(const uint8_t prefix[4]);

/** @} */

#endif
