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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/core_names.h>  // OSSL_PKEY_PARAM_GROUP_NAME
#include <openssl/crypto.h>      // OPENSSL_cleanse
#include <openssl/evp.h>         // EVP_PKEY_CTX, EVP_PKEY_generate
#include <openssl/params.h>      // OSSL_PARAM
#include <openssl/rand.h>        // RAND_bytes
#include <openssl/x509.h>        // d2i_AutoPrivateKey / d2i_PUBKEY

#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_KEY_FACTORY] ";

/// Builds the key handle metadata shared by every key this factory produces.
key_management::ProviderKeyHandle MakeHandle(common::ProviderId provider_id,
                                             const common::AlgorithmId& algorithm,
                                             score::crypto::KeyOperationPermission permissions,
                                             std::size_t key_size,
                                             bool is_asymmetric) noexcept
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = provider_id;
    handle.permissions = permissions;
    handle.is_asymmetric = is_asymmetric;
    handle.algorithm = algorithm;
    handle.key_size = key_size;
    return handle;
}
}  // namespace

OpenSslKeyFactory::OpenSslKeyFactory(common::ProviderId provider_id) : m_provider_id(provider_id){};

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    if (::score::crypto::daemon::common::IsEcdsaAlgorithm(
            std::string_view{request.algorithm.data(), request.algorithm.size()}))
    {
        return GenerateEcKey(request);
    }

    const std::size_t key_size = DetermineKeySize(request.algorithm);
    if (key_size == 0U)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> key_bytes(key_size);

    if (RAND_bytes(key_bytes.data(), static_cast<int>(key_size)) != 1)
    {
        OPENSSL_cleanse(key_bytes.data(), key_size);
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, key_size, false);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateEcKey(const key_management::KeyGenerationRequest& request)
{
    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{request.algorithm.data(), request.algorithm.size()});
    if (!curve.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: unsupported curve in algorithm '"
                                   << request.algorithm << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: EVP_PKEY_CTX_new_from_name(\"EC\") failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    EVP_PKEY* pkey = nullptr;
    const bool ok = [&]() -> bool {
        if (EVP_PKEY_keygen_init(ctx) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: EVP_PKEY_keygen_init failed";
            return false;
        }

        // OSSL_PARAM takes a non-const char*, but only reads the group name.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group_name = const_cast<char*>(curve->openssl_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, curve->openssl_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: failed to select group "
                                       << std::string{curve->openssl_name};
            return false;
        }

        if (EVP_PKEY_generate(ctx, &pkey) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: EVP_PKEY_generate failed";
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

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, curve->field_size, true);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    // One EVP_PKEY holds both halves, so one handler serves the sign and the
    // verify context — which is exactly why the two permission sets have to
    // travel together rather than being folded into one bitmask here.
    handle.public_key_permissions = request.public_key_permissions;

    score::mw::log::LogDebug() << kLogPrefix << "Generated EC key pair on curve " << std::string{curve->name};

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportKey(const key_management::KeyImportRequest& request)
{
    if ((request.key_data == nullptr) || (request.key_data_size == 0U))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (::score::crypto::daemon::common::IsEcdsaAlgorithm(
            std::string_view{request.algorithm.data(), request.algorithm.size()}))
    {
        return ImportEcKey(request);
    }

    std::vector<std::uint8_t> key_bytes(request.key_data, request.key_data + request.key_data_size);

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, request.key_data_size, false);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportEcKey(const key_management::KeyImportRequest& request)
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

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, curve->field_size, true);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    // An import request carries one permission set for whatever material it
    // contains, so it governs both halves. Leaving this nullopt would mean
    // "public half unrestricted", which is the right default for a generated
    // key but would let an imported key ignore its slot's allowed_operations.
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

// static
std::size_t OpenSslKeyFactory::DetermineKeySize(const common::AlgorithmId& algorithm) noexcept
{
    return ::score::crypto::daemon::common::LookupKeySize(std::string_view{algorithm.data(), algorithm.size()})
        .value_or(0U);
}

}  // namespace score::crypto::daemon::provider::openssl
