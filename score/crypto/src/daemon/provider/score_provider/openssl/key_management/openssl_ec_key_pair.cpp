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
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_key_handle.hpp"

#include <openssl/core_names.h>  // OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_PUB_KEY
#include <openssl/evp.h>         // EVP_PKEY_CTX_set_params, EVP_PKEY_fromdata, EVP_PKEY_get_group_name
#include <openssl/params.h>      // OSSL_PARAM

#include "score/mw/log/logging.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_EC_KEY_PAIR] ";

/// The OpenSSL group name and field size of the curve of an ECC row.
struct EcGroup
{
    std::string_view openssl_group_name;
    std::size_t field_size;
};

/// Holds every OpenSSL group name with its terminating NUL; a longer name reads as a mismatch.
constexpr std::size_t kGroupNameBufferSize = 64U;

::score::crypto::Expected<EcGroup, ::score::crypto::daemon::common::DaemonErrorCode> LookupEcGroup(
    const ::score::crypto::AlgorithmDescriptor& algorithm)
{
    if (!IsEcKeySupported(algorithm))
    {
        score::mw::log::LogError() << kLogPrefix << "no supported curve for algorithm '" << algorithm.name << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    return EcGroup{std::string_view{detail::ToOpenSslGroupName(algorithm.curve)},
                   ::score::crypto::daemon::common::EcFieldSize(algorithm)};
}

/// SEC1 tag of an uncompressed EC point; compressed (0x02/0x03) and hybrid (0x06/0x07) points are refused.
constexpr std::uint8_t kUncompressedPointTag = 0x04U;

/// Builds an EC public key on @p group_name from the uncompressed point @p point.
///
/// @return The key, or null when OpenSSL rejects the point or it does not lie on the curve.
EvpPkeyPtr BuildEcPublicKeyFromRawPoint(std::string_view group_name,
                                        const std::uint8_t* point,
                                        std::size_t point_len) noexcept
{
    const detail::EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    if (!ctx || (EVP_PKEY_fromdata_init(ctx.get()) != 1))
    {
        return EvpPkeyPtr{};
    }

    // OSSL_PARAM takes non-const pointers, but only reads the inputs here.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    char* group = const_cast<char*>(group_name.data());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    void* pub = const_cast<std::uint8_t*>(point);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, group_name.size()),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, point_len),
        OSSL_PARAM_construct_end(),
    };

    EVP_PKEY* pkey = nullptr;
    const bool built = EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;
    EvpPkeyPtr owned_pkey{pkey};
    if (!built || !owned_pkey)
    {
        return EvpPkeyPtr{};
    }

    // EVP_PKEY_fromdata accepts the encoding without proving the point lies on
    // the curve, and an off-curve point opens an invalid-curve attack.
    const detail::EvpPkeyCtxPtr check_ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, owned_pkey.get(), nullptr)};
    if (!check_ctx || (EVP_PKEY_public_check(check_ctx.get()) != 1))
    {
        return EvpPkeyPtr{};
    }
    return owned_pkey;
}

/// Imports the uncompressed SEC1 point of a public key on the curve of @p group.
::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportRawEcPublicKey(common::ProviderId provider_id,
                     const key_management::KeyImportRequest& request,
                     const EcGroup& group)
{
    // The length is fixed by the curve, so a compressed or truncated point fails here, before OpenSSL sees it.
    const std::size_t expected_len = 1U + (2U * group.field_size);
    if (request.key_data_size != expected_len)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: expected " << expected_len
                                   << " bytes for an uncompressed " << std::string{group.openssl_group_name}
                                   << " point, got " << request.key_data_size;
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // A hybrid point (0x06/0x07) has the uncompressed length but another encoding.
    if (request.key_data[0] != kUncompressedPointTag)
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "ImportRawEcPublicKey: point is not uncompressed (0x04); lead byte 0x"
                                   << score::mw::log::LogHex8{request.key_data[0]};
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    EvpPkeyPtr owned_pkey =
        BuildEcPublicKeyFromRawPoint(group.openssl_group_name, request.key_data, request.key_data_size);
    if (!owned_pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: point is not a valid public key on curve "
                                   << std::string{group.openssl_group_name};
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // No private scalar arrives, so only the public half carries the slot's grant.
    auto handle = detail::MakeKeyHandle(provider_id,
                                        request.algorithm,
                                        score::crypto::KeyOperationPermission::kNone,
                                        group.field_size,
                                        owned_pkey.get());
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

/// Checks a raw export request: the format, the key family, and kExport on the public half.
::score::crypto::Expected<void, ::score::crypto::daemon::common::DaemonErrorCode> CheckRawEcExport(
    const key_management::ProviderKeyHandle& handle,
    score::crypto::FormatType format)
{
    if (format != score::crypto::FormatType::kRaw)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    if (!handle.is_asymmetric || !IsEcKeySupported(handle.algorithm))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    // An unset public-half grant is unrestricted.
    const auto public_permissions = handle.public_key_permissions.value_or(score::crypto::KeyOperationPermission::kAll);
    if (!score::crypto::HasPermission(public_permissions, score::crypto::KeyOperationPermission::kExport))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }
    return {};
}

/// Duplicates the EVP_PKEY of @p handle with its point format set to uncompressed.
///
/// A key decoded from a compressed encoding keeps that format, so reading its
/// point directly would yield the compressed form.
::score::crypto::Expected<EvpPkeyPtr, ::score::crypto::daemon::common::DaemonErrorCode> PrepareUncompressedEcExport(
    const key_management::ProviderKeyHandle& handle)
{
    if (handle.opaque_id == 0U)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    const auto* pkey = reinterpret_cast<const EVP_PKEY*>(static_cast<std::uintptr_t>(handle.opaque_id));

    EvpPkeyPtr export_pkey{EVP_PKEY_dup(const_cast<EVP_PKEY*>(pkey))};  // NOLINT(cppcoreguidelines-pro-type-const-cast)
    if (!export_pkey)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    constexpr std::string_view kUncompressedFormat = "uncompressed";
    // OSSL_PARAM takes a non-const char*, but only reads the format name.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    char* point_format = const_cast<char*>(kUncompressedFormat.data());
    OSSL_PARAM format_params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, point_format, kUncompressedFormat.size()),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_set_params(export_pkey.get(), format_params) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    return export_pkey;
}

/// Byte length of the public point of @p pkey.
::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode> PublicPointSize(
    const EVP_PKEY* pkey)
{
    std::size_t point_len = 0U;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0U, &point_len) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    return point_len;
}
}  // namespace

bool IsEcKeySupported(const ::score::crypto::AlgorithmDescriptor& algorithm) noexcept
{
    return (algorithm.key_type == ::score::crypto::KeyType::kEcc) &&
           (detail::ToOpenSslGroupName(algorithm.curve) != nullptr);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateEcKeyPair(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request)
{
    const auto group = LookupEcGroup(request.algorithm);
    if (!group.has_value())
    {
        return ::score::crypto::make_unexpected(group.error());
    }
    const std::string_view openssl_group_name = group->openssl_group_name;

    const detail::KeygenSpec spec{"EC", group->field_size, "GenerateEcKeyPair"};
    return detail::GenerateAsymmetricKey(provider_id, request, spec, [openssl_group_name](EVP_PKEY_CTX* ctx) {
        // OSSL_PARAM takes a non-const char*, but only reads the group name.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group_name = const_cast<char*>(openssl_group_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, openssl_group_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKeyPair: failed to select group "
                                       << std::string{openssl_group_name};
            return false;
        }
        return true;
    });
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportEcKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request)
{
    const auto group = LookupEcGroup(request.algorithm);
    if (!group.has_value())
    {
        return ::score::crypto::make_unexpected(group.error());
    }

    if (request.format == score::crypto::FormatType::kRaw)
    {
        return ImportRawEcPublicKey(provider_id, request, *group);
    }

    auto parsed = detail::ParseDerKey(request, EVP_PKEY_EC);
    if (!parsed.has_value())
    {
        return ::score::crypto::make_unexpected(parsed.error());
    }

    std::array<char, kGroupNameBufferSize> imported_group{};
    std::size_t imported_group_size = 0U;
    const bool group_name_read =
        (EVP_PKEY_get_group_name(
             parsed.value().pkey.get(), imported_group.data(), imported_group.size(), &imported_group_size) == 1) &&
        (imported_group_size < imported_group.size());
    if (!group_name_read || (std::string_view{imported_group.data(), imported_group_size} != group->openssl_group_name))
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is on an incompatible curve";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return detail::CreateImportedAsymmetricKey(provider_id, request, std::move(parsed.value()), group->field_size);
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
ExportEcPublicKey(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format)
{
    const auto checked = CheckRawEcExport(handle, format);
    if (!checked.has_value())
    {
        return ::score::crypto::make_unexpected(checked.error());
    }

    const auto export_pkey = PrepareUncompressedEcExport(handle);
    if (!export_pkey.has_value())
    {
        return ::score::crypto::make_unexpected(export_pkey.error());
    }

    auto point_len = PublicPointSize(export_pkey.value().get());
    if (!point_len.has_value())
    {
        return ::score::crypto::make_unexpected(point_len.error());
    }

    key_management::SecureKeyBytes out{*point_len};
    std::size_t written = 0U;
    if (EVP_PKEY_get_octet_string_param(
            export_pkey.value().get(), OSSL_PKEY_PARAM_PUB_KEY, out.bytes.data(), out.bytes.size(), &written) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    out.bytes.resize(written);
    return out;
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode> GetEcPublicKeyExportSize(
    const key_management::ProviderKeyHandle& handle,
    score::crypto::FormatType format)
{
    const auto checked = CheckRawEcExport(handle, format);
    if (!checked.has_value())
    {
        return ::score::crypto::make_unexpected(checked.error());
    }

    // The length comes from the same uncompressed copy ExportEcPublicKey() reads,
    // so the advertised size always matches the exported bytes.
    const auto export_pkey = PrepareUncompressedEcExport(handle);
    if (!export_pkey.has_value())
    {
        return ::score::crypto::make_unexpected(export_pkey.error());
    }
    return PublicPointSize(export_pkey.value().get());
}

}  // namespace score::crypto::daemon::provider::openssl
