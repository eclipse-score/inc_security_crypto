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

/// SEC1 tag of an uncompressed EC point. Compressed (0x02/0x03) and hybrid
/// (0x06/0x07) encodings are deliberately not accepted on the raw import path.
constexpr std::uint8_t kUncompressedPointTag = 0x04U;

/// Build an EC public-key EVP_PKEY from a raw uncompressed SEC1 point.
///
/// @param group_name NIST group designation, e.g. "P-384".
/// @param point      0x04||X||Y, length 1 + 2*field_size (validated by caller).
/// @param point_len  Byte length of @p point.
/// @return An owning EVP_PKEY, or nullptr if the point is not a valid public
///         key on the named curve.
EvpPkeyPtr BuildEcPublicKeyFromRawPoint(std::string_view group_name,
                                        const std::uint8_t* point,
                                        std::size_t point_len) noexcept
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx == nullptr)
    {
        return EvpPkeyPtr{};
    }

    EVP_PKEY* pkey = nullptr;
    const bool ok = [&]() -> bool {
        if (EVP_PKEY_fromdata_init(ctx) != 1)
        {
            return false;
        }

        // OSSL_PARAM takes non-const pointers but only reads the inputs here.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group = const_cast<char*>(group_name.data());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        void* pub = const_cast<std::uint8_t*>(point);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, group_name.size()),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, point_len),
            OSSL_PARAM_construct_end(),
        };

        return EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;
    }();

    EVP_PKEY_CTX_free(ctx);

    EvpPkeyPtr owned_pkey{pkey};
    if (!ok || !owned_pkey)
    {
        return EvpPkeyPtr{};
    }

    // EVP_PKEY_fromdata accepts the point encoding without proving the point
    // lies on the curve; an off-curve public key is a classic avenue for
    // invalid-curve attacks, so verify it explicitly before handing it out.
    EVP_PKEY_CTX* check_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, owned_pkey.get(), nullptr);
    if (check_ctx == nullptr)
    {
        return EvpPkeyPtr{};
    }
    const bool on_curve = EVP_PKEY_public_check(check_ctx) == 1;
    EVP_PKEY_CTX_free(check_ctx);

    if (!on_curve)
    {
        return EvpPkeyPtr{};
    }
    return owned_pkey;
}

/// Recover the EVP_PKEY an asymmetric handle refers to.
///
/// The OpenSSL provider stores the EVP_PKEY address in opaque_id (see
/// GenerateEcKey / ImportEcKey). Interpreting it is the issuing provider's
/// prerogative, as documented on ProviderKeyHandle.
[[nodiscard]] EVP_PKEY* PkeyFromHandle(const key_management::ProviderKeyHandle& handle) noexcept
{
    if (handle.opaque_id == 0U)
    {
        return nullptr;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
    return reinterpret_cast<EVP_PKEY*>(static_cast<std::uintptr_t>(handle.opaque_id));
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
        char* group_name = const_cast<char*>(curve->group_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, curve->group_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: failed to select group "
                                       << std::string{curve->group_name};
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

    // A raw import carries only the public half as an uncompressed SEC1 point,
    // so it follows a dedicated path and never claims a private-half permission.
    if (request.format == score::crypto::FormatType::kRaw)
    {
        return ImportRawEcPublicKey(request, curve.value());
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

    auto handle = MakeHandle(m_provider_id, request.algorithm, private_half_permissions, curve->field_size, true);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

    // An import request carries one permission set for whatever material it
    // contains, so it governs both halves. Leaving this nullopt would mean
    // "public half unrestricted", which is the right default for a generated
    // key but would let an imported key ignore its slot's allowed_operations.
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportRawEcPublicKey(const key_management::KeyImportRequest& request,
                                        const common::EcCurveInfo& curve)
{
    // A raw EC public key is the uncompressed SEC1 point 0x04||X||Y. Its length
    // is fixed by the curve, so a wrong length is the cheapest way to reject a
    // compressed point (1+field_size) or truncated input before touching OpenSSL.
    const std::size_t expected_len = 1U + (2U * curve.field_size);
    if (request.key_data_size != expected_len)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: expected " << expected_len
                                   << " bytes for an uncompressed " << std::string{curve.group_name} << " point, got "
                                   << request.key_data_size;
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // Even at the right length, a 0x02/0x03 (compressed) or 0x06/0x07 (hybrid)
    // lead byte is a different encoding and is rejected rather than reinterpreted.
    if (request.key_data[0] != kUncompressedPointTag)
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "ImportRawEcPublicKey: point is not uncompressed (0x04); lead byte 0x"
                                   << request.key_data[0];
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    EvpPkeyPtr owned_pkey = BuildEcPublicKeyFromRawPoint(curve.group_name, request.key_data, request.key_data_size);
    if (!owned_pkey)
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "ImportRawEcPublicKey: point is not a valid public key on curve "
                                   << std::string{curve.group_name};
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // Raw import delivers no private scalar, so the private half can perform
    // nothing; only the public half carries the slot's grant (verify / export).
    auto handle = MakeHandle(
        m_provider_id, request.algorithm, score::crypto::KeyOperationPermission::kNone, curve.field_size, true);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ExportKey(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format)
{
    const auto curve = CheckRawEcExport(handle, format);
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(curve.error());
    }

    EVP_PKEY* pkey = PkeyFromHandle(handle);
    if (pkey == nullptr)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // OSSL_PKEY_PARAM_PUB_KEY serialises the point in the key's own
    // point-conversion format. A key decoded from a compressed DER encoding
    // keeps that compressed format, so reading it directly would yield e.g. a
    // 49-byte P-384 point — disagreeing with GetExportKeySize (97) and rejected
    // by the raw import path, breaking the round-trip contract. Force
    // uncompressed output on a private duplicate so the shared key other clients
    // may be using concurrently is never mutated.
    EvpPkeyPtr export_pkey{EVP_PKEY_dup(pkey)};
    if (!export_pkey)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    constexpr std::string_view kUncompressedFormat = "uncompressed";
    // OSSL_PARAM takes a non-const char*, but only reads the format string.
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

    // OSSL_PKEY_PARAM_PUB_KEY yields the uncompressed point 0x04||X||Y, which is
    // exactly the raw form this factory imports — so export round-trips import.
    std::size_t out_len = 0U;
    if (EVP_PKEY_get_octet_string_param(export_pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0U, &out_len) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    key_management::SecureKeyBytes out{out_len};
    if (EVP_PKEY_get_octet_string_param(
            export_pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, out.bytes.data(), out_len, &out_len) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    out.bytes.resize(out_len);

    return out;
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GetExportKeySize(const key_management::ProviderKeyHandle& handle, score::crypto::FormatType format)
{
    const auto curve = CheckRawEcExport(handle, format);
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(curve.error());
    }

    // The uncompressed point length is fixed by the curve, so the size query is
    // answered from metadata alone and matches what ExportKey will produce.
    return 1U + (2U * curve->field_size);
}

::score::crypto::Expected<common::EcCurveInfo, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::CheckRawEcExport(const key_management::ProviderKeyHandle& handle,
                                    score::crypto::FormatType format) const
{
    // Only the raw public-point export is implemented; DER/PEM key export stays
    // on the base class's unsupported path.
    if (format != score::crypto::FormatType::kRaw)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    const auto curve = ::score::crypto::daemon::common::LookupEcCurveOfAlgorithm(
        std::string_view{handle.algorithm.data(), handle.algorithm.size()});
    if (!handle.is_asymmetric || !curve.has_value())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    // Exporting a public key is still an export: it is gated by kExport on the
    // public half's grant. A nullopt grant means unrestricted, matching the
    // documented default for a public key.
    const auto public_permissions =
        handle.public_key_permissions.value_or(score::crypto::KeyOperationPermission::kAll);
    if (!score::crypto::HasPermission(public_permissions, score::crypto::KeyOperationPermission::kExport))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kKeyNotExportable);
    }

    return curve.value();
}

// static
std::size_t OpenSslKeyFactory::DetermineKeySize(const common::AlgorithmId& algorithm) noexcept
{
    return ::score::crypto::daemon::common::LookupKeySize(std::string_view{algorithm.data(), algorithm.size()})
        .value_or(0U);
}

}  // namespace score::crypto::daemon::provider::openssl
