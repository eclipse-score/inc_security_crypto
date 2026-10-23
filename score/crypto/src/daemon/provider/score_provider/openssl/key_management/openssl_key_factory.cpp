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
#include <openssl/rsa.h>         // EVP_PKEY_CTX_set_rsa_keygen_bits
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

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateAsymmetricKey(const key_management::KeyGenerationRequest& request,
                                         const KeygenSpec& spec,
                                         const std::function<bool(EVP_PKEY_CTX*)>& configure_keygen)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, spec.key_type, nullptr);
    if (ctx == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation}
                                   << ": EVP_PKEY_CTX_new_from_name failed for " << std::string{spec.key_type};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    if (EVP_PKEY_keygen_init(ctx) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation} << ": EVP_PKEY_keygen_init failed";
        EVP_PKEY_CTX_free(ctx);
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    if (!configure_keygen(ctx))
    {
        EVP_PKEY_CTX_free(ctx);
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    EVP_PKEY* pkey = nullptr;
    const bool generated = EVP_PKEY_generate(ctx, &pkey) == 1;
    if (!generated)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation} << ": EVP_PKEY_generate failed";
    }
    EVP_PKEY_CTX_free(ctx);

    // Take ownership immediately so every path below is leak-free.
    EvpPkeyPtr owned_pkey{pkey};
    if (!generated || !owned_pkey)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, spec.key_size, true);
    handle.public_key_permissions = request.public_key_permissions;
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    score::mw::log::LogDebug() << kLogPrefix << std::string{spec.operation} << ": generated "
                               << std::string{spec.key_type} << " key pair";
    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

OpenSslKeyFactory::OpenSslKeyFactory(common::ProviderId provider_id) : m_provider_id(provider_id) {};

::score::crypto::Expected<OpenSslKeyFactory::ParsedDerKey, common::DaemonErrorCode> OpenSslKeyFactory::ParseDerKey(
    const key_management::KeyImportRequest& request)
{
    using common::DaemonErrorCode;

    if (request.format != score::crypto::FormatType::kDer)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: only DER-encoded keys are supported";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    const auto* end = request.key_data + request.key_data_size;
    const unsigned char* cursor = request.key_data;
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(request.key_data_size));
    bool has_private_half = pkey != nullptr;

    if (pkey != nullptr && cursor != end)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: private-key DER contains trailing data";
        EVP_PKEY_free(pkey);
        pkey = nullptr;
        has_private_half = false;
    }

    if (pkey == nullptr)
    {
        cursor = request.key_data;
        pkey = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(request.key_data_size));
        if (pkey == nullptr || cursor != end)
        {
            if (pkey == nullptr)
            {
                score::mw::log::LogError() << kLogPrefix << "ParseDerKey: could not parse private or public DER key";
            }
            else
            {
                score::mw::log::LogError() << kLogPrefix << "ParseDerKey: public-key DER contains trailing data";
            }
            EVP_PKEY_free(pkey);
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
        }
    }

    return ParsedDerKey{EvpPkeyPtr{pkey}, has_private_half};
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode>
OpenSslKeyFactory::CreateImportedAsymmetricKey(const key_management::KeyImportRequest& request,
                                               ParsedDerKey parsed,
                                               std::size_t key_size)
{
    auto owned_pkey = std::move(parsed.pkey);
    auto permissions = parsed.has_private_half ? request.permissions : score::crypto::KeyOperationPermission::kNone;

    auto handle = MakeHandle(m_provider_id, request.algorithm, permissions, key_size, true);
    handle.public_key_permissions = request.permissions;
    handle.opaque_id = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(owned_pkey.get()));
    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateKey(const key_management::KeyGenerationRequest& request)
{
    if (::score::crypto::daemon::common::IsEcdsaAlgorithm(
            std::string_view{request.algorithm.data(), request.algorithm.size()}))
    {
        return GenerateEcKey(request);
    }

    const auto algorithm = std::string_view{request.algorithm.data(), request.algorithm.size()};
    if (::score::crypto::daemon::common::LookupRsaKeyInfo(algorithm).has_value())
    {
        return GenerateRsaKey(request);
    }
    if (::score::crypto::daemon::common::IsEd25519Algorithm(algorithm))
    {
        return GenerateEd25519Key(request);
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

    const KeygenSpec spec{"EC", curve->field_size, "GenerateEcKey"};
    return GenerateAsymmetricKey(request, spec, [&](EVP_PKEY_CTX* ctx) {
        // OSSL_PARAM takes a non-const char*, but only reads the group name.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group_name = const_cast<char*>(curve->openssl_group_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, curve->openssl_group_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: failed to select group "
                                       << std::string{curve->openssl_group_name.data()};
            return false;
        }
        return true;
    });
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

    const auto algorithm = std::string_view{request.algorithm.data(), request.algorithm.size()};
    if (::score::crypto::daemon::common::LookupRsaKeyInfo(algorithm).has_value() ||
        ::score::crypto::daemon::common::IsEd25519Algorithm(algorithm))
    {
        return ImportAsymmetricKey(request);
    }

    std::vector<std::uint8_t> key_bytes(request.key_data, request.key_data + request.key_data_size);

    auto handle = MakeHandle(m_provider_id, request.algorithm, request.permissions, request.key_data_size, false);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(key_bytes.data()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateRsaKey(const key_management::KeyGenerationRequest& request)
{
    const auto info = ::score::crypto::daemon::common::LookupRsaKeyInfo(
        std::string_view{request.algorithm.data(), request.algorithm.size()});
    if (!info.has_value())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    const KeygenSpec spec{"RSA", info->modulus_size, "GenerateRsaKey"};
    return GenerateAsymmetricKey(request, spec, [bits = info->key_bits](EVP_PKEY_CTX* ctx) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(bits)) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateRsaKey: failed to set key size to " << bits;
            return false;
        }
        return true;
    });
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GenerateEd25519Key(const key_management::KeyGenerationRequest& request)
{
    const KeygenSpec spec{"ED25519", ::score::crypto::daemon::common::kEd25519KeySize, "GenerateEd25519Key"};
    return GenerateAsymmetricKey(request, spec);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportAsymmetricKey(const key_management::KeyImportRequest& request)
{
    auto parsed = ParseDerKey(request);
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportAsymmetricKey: could not parse DER key material";
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (!parsed.value().pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportAsymmetricKey: parsed key is empty";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    const auto algorithm = std::string_view{request.algorithm.data(), request.algorithm.size()};
    const auto rsa_info = ::score::crypto::daemon::common::LookupRsaKeyInfo(algorithm);
    const bool is_rsa_algorithm = rsa_info.has_value();
    const int expected_type = is_rsa_algorithm ? EVP_PKEY_RSA : EVP_PKEY_ED25519;
    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != expected_type)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportAsymmetricKey: parsed key has incompatible type";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }
    if (is_rsa_algorithm && EVP_PKEY_get_bits(parsed.value().pkey.get()) != static_cast<int>(rsa_info->key_bits))
    {
        score::mw::log::LogError() << kLogPrefix << "ImportAsymmetricKey: RSA modulus size is incompatible";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    const std::size_t key_size =
        is_rsa_algorithm ? rsa_info->modulus_size : ::score::crypto::daemon::common::kEd25519KeySize;
    return CreateImportedAsymmetricKey(request, std::move(parsed.value()), key_size);
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

    auto parsed = ParseDerKey(request);
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: could not parse DER key material";
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != EVP_PKEY_EC)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is not an EC key";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    std::string imported_group(curve->openssl_group_name.size() + 1U, '\0');
    std::size_t imported_group_size = 0U;
    const bool group_name_read = EVP_PKEY_get_utf8_string_param(parsed.value().pkey.get(),
                                                                OSSL_PKEY_PARAM_GROUP_NAME,
                                                                imported_group.data(),
                                                                imported_group.size(),
                                                                &imported_group_size) == 1;
    const bool has_trailing_nul = imported_group_size > 0U && imported_group[imported_group_size - 1U] == '\0';
    const std::size_t group_name_size = imported_group_size - (has_trailing_nul ? 1U : 0U);
    if (!group_name_read || std::string_view{imported_group.data(), group_name_size} != curve->openssl_group_name)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is on an incompatible curve";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return CreateImportedAsymmetricKey(request, std::move(parsed.value()), curve->field_size);
}

// static
std::size_t OpenSslKeyFactory::DetermineKeySize(const common::AlgorithmId& algorithm) noexcept
{
    return ::score::crypto::daemon::common::LookupKeySize(std::string_view{algorithm.data(), algorithm.size()})
        .value_or(0U);
}

}  // namespace score::crypto::daemon::provider::openssl
