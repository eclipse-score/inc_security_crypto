/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_ASYMMETRIC_KEY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_ASYMMETRIC_KEY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <cstddef>
#include <functional>
#include <memory>

// Opaque OpenSSL context type; the implementation includes the OpenSSL headers.
struct evp_pkey_ctx_st;
using EVP_PKEY_CTX = evp_pkey_ctx_st;

namespace score::crypto::daemon::provider::openssl::detail
{

/// Frees an EVP_PKEY_CTX; defined out of line so this header needs no OpenSSL include.
struct EvpPkeyCtxDeleter
{
    void operator()(EVP_PKEY_CTX* ctx) const noexcept;
};

/// Owning handle to an OpenSSL EVP_PKEY_CTX.
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

/// Per-algorithm constants for GenerateAsymmetricKey().
struct KeygenSpec
{
    const char* key_type;   ///< OpenSSL key type name, e.g. "EC", "RSA", "ED25519"
    std::size_t key_size;   ///< Handle key_size in bytes
    const char* operation;  ///< Caller name used in log messages
};

/// Generates a key pair of @p spec.key_type and wraps it in an OpenSslKeyHandler.
///
/// @param provider_id Provider that issues the key handle.
/// @param request Catalog row and permissions of the key to generate.
/// @param spec OpenSSL key type, handle key size and log name of the family.
/// @param configure_keygen Runs after EVP_PKEY_keygen_init() to apply algorithm parameters,
///        such as the EC group or the RSA modulus size; returning false fails the generation.
/// @return The generated key pair, or
///         - kAllocationFailed when OpenSSL has no key type @p spec.key_type;
///         - kKeyGenerationFailed when initialisation, @p configure_keygen or the generation fails.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
GenerateAsymmetricKey(
    common::ProviderId provider_id,
    const key_management::KeyGenerationRequest& request,
    const KeygenSpec& spec,
    const std::function<bool(EVP_PKEY_CTX*)>& configure_keygen = [](EVP_PKEY_CTX*) {
        return true;
    });

/// Result of parsing DER key material.
struct ParsedDerKey
{
    EvpPkeyPtr pkey{};             ///< Parsed key, never null on success
    bool has_private_half{false};  ///< True when the DER parsed as a private key, false for SubjectPublicKeyInfo
};

/// Parses DER key material (a private key, PKCS#8 or traditional, or a
/// SubjectPublicKeyInfo) into an EVP_PKEY of @p expected_pkey_type.
///
/// @param request Key material, its format and catalog row.
/// @param expected_pkey_type EVP_PKEY_* id the parsed key must have, e.g. EVP_PKEY_EC.
/// @return The parsed key and whether it carries a private half, or
///         - kInvalidFormat when request.format is not kDer, the bytes parse as neither form or leave trailing bytes;
///         - kInvalidArgument when request.key_data_size does not fit a long;
///         - kIncompatibleKeyType when the parsed key is not of @p expected_pkey_type.
/// @pre request.key_data is non-null and request.key_data_size is non-zero.
[[nodiscard]] ::score::crypto::Expected<ParsedDerKey, ::score::crypto::daemon::common::DaemonErrorCode> ParseDerKey(
    const key_management::KeyImportRequest& request,
    int expected_pkey_type);

/// Wraps a parsed key that the caller has already validated against
/// request.algorithm in an OpenSslKeyHandler.
///
/// A key without a private half gets no private-half permissions, whatever
/// request.permissions grants; request.permissions governs the public half.
/// @param provider_id Provider that issues the key handle.
/// @param request Import request whose catalog row and permissions the handle carries.
/// @param parsed Key returned by ParseDerKey(); the handler takes it over.
/// @param key_size Handle key_size in bytes.
/// @return The handler owning the key.
[[nodiscard]] ::score::crypto::Expected<key_management::IKeyHandler::Sptr,
                                        ::score::crypto::daemon::common::DaemonErrorCode>
CreateImportedAsymmetricKey(common::ProviderId provider_id,
                            const key_management::KeyImportRequest& request,
                            ParsedDerKey parsed,
                            std::size_t key_size);

}  // namespace score::crypto::daemon::provider::openssl::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_KEY_MANAGEMENT_DETAIL_OPENSSL_ASYMMETRIC_KEY_HPP
