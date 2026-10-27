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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_ec_key_pair.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handle.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/core_names.h>  // OSSL_PKEY_PARAM_GROUP_NAME
#include <openssl/evp.h>         // EVP_PKEY_CTX, EVP_PKEY_generate
#include <openssl/params.h>      // OSSL_PARAM
#include <openssl/x509.h>        // d2i_AutoPrivateKey / d2i_PUBKEY

#include "score/mw/log/logging.h"

#include <string>
#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_EC_KEY_PAIR] ";
}  // namespace

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEcKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request)
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{request.algorithm.data(), request.algorithm.size()});
    if (!curve.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: unsupported curve in algorithm '"
                                   << request.algorithm << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: EVP_PKEY_CTX_new_from_name(\"EC\") failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    EVP_PKEY* pkey = nullptr;
    const bool ok = [&]() -> bool {
        if (EVP_PKEY_keygen_init(ctx) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: EVP_PKEY_keygen_init failed";
            return false;
        }

        // OSSL_PARAM takes a non-const char*, but only reads the group name.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group_name = const_cast<char*>(curve->group_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, curve->group_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: failed to select group "
                                       << std::string{curve->group_name};
            return false;
        }

        if (EVP_PKEY_generate(ctx, &pkey) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: EVP_PKEY_generate failed";
            return false;
        }
        return true;
    }();

    EVP_PKEY_CTX_free(ctx);

    // Take ownership immediately so every path below is leak-free.
    EvpPkeyPtr owned_pkey{pkey};

    if (!ok || !owned_pkey)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kKeyGenerationFailed);
    }

    auto handle = detail::MakeKeyHandle(
        provider_id, request.algorithm, request.permissions, curve->field_size, true, owned_pkey.get());

    // One EVP_PKEY holds both halves and one handler serves both the sign and
    // the verify context, so the public half keeps its own permission set.
    handle.public_key_permissions = request.public_key_permissions;

    score::mw::log::LogDebug() << kLogPrefix << "Generated EC key pair on curve " << std::string{curve->name};

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportEcKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request)
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{request.algorithm.data(), request.algorithm.size()});
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    if (request.format != score::crypto::FormatType::kDer)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: only DER-encoded EC keys are supported";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // d2i_AutoPrivateKey advances the pointer it is given, so hand it a copy.
    const unsigned char* der = request.key_data;
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der, static_cast<long>(request.key_data_size));
    const bool has_private_half = (pkey != nullptr);
    if (pkey == nullptr)
    {
        // Fall back to a SubjectPublicKeyInfo blob: a verify-only slot legitimately
        // holds just the public half.
        const unsigned char* spki = request.key_data;
        pkey = d2i_PUBKEY(nullptr, &spki, static_cast<long>(request.key_data_size));
    }

    // Take ownership immediately so every path below is leak-free.
    EvpPkeyPtr owned_pkey{pkey};

    if (!owned_pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: could not parse DER key material";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    if (EVP_PKEY_get_base_id(owned_pkey.get()) != EVP_PKEY_EC)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is not an EC key";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    // The grant describes the slot, not the material that arrived in it. A slot
    // allowing kSign may still deploy a bare SubjectPublicKeyInfo blob, and a
    // handle claiming kSign over a key with no private scalar would satisfy the
    // mediator's check and fail inside OpenSSL instead, where the cause is far
    // less legible. No private half means no private-half operation.
    const auto private_half_permissions =
        has_private_half ? request.permissions : score::crypto::KeyOperationPermission::kNone;

    auto handle = detail::MakeKeyHandle(
        provider_id, request.algorithm, private_half_permissions, curve->field_size, true, owned_pkey.get());

    // An import request carries one permission set for whatever material it
    // contains, so it governs both halves. Leaving this nullopt would mean
    // "public half unrestricted", which is the right default for a generated
    // key but would let an imported key ignore its slot's allowed_operations.
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

}  // namespace score::crypto::daemon::provider::openssl
