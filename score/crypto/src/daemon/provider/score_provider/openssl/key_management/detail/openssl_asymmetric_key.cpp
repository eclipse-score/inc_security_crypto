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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_asymmetric_key.hpp"

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/detail/openssl_key_handle.hpp"

#include <openssl/evp.h>   // EVP_PKEY_CTX, EVP_PKEY_generate
#include <openssl/x509.h>  // d2i_AutoPrivateKey / d2i_PUBKEY

#include "score/mw/log/logging.h"

#include <limits>
#include <memory>
#include <string>
#include <string_view>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_ASYMMETRIC_KEY] ";
}  // namespace

void EvpPkeyCtxDeleter::operator()(EVP_PKEY_CTX* ctx) const noexcept
{
    EVP_PKEY_CTX_free(ctx);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateAsymmetricKey(common::ProviderId provider_id,
                      const key_management::KeyGenerationRequest& request,
                      const KeygenSpec& spec,
                      const std::function<bool(EVP_PKEY_CTX*)>& configure_keygen)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, spec.key_type, nullptr)};
    if (!ctx)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation}
                                   << ": EVP_PKEY_CTX_new_from_name failed for " << std::string{spec.key_type};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation} << ": EVP_PKEY_keygen_init failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    if (!configure_keygen(ctx.get()))
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    EVP_PKEY* pkey = nullptr;
    const bool generated = EVP_PKEY_generate(ctx.get(), &pkey) == 1;

    // Take ownership immediately so every path below is leak-free.
    EvpPkeyPtr owned_pkey{pkey};
    ctx.reset();
    if (!generated || !owned_pkey)
    {
        score::mw::log::LogError() << kLogPrefix << std::string{spec.operation} << ": EVP_PKEY_generate failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyGenerationFailed);
    }

    auto handle = MakeKeyHandle(provider_id, request.algorithm, request.permissions, spec.key_size, owned_pkey.get());

    // One EVP_PKEY holds both halves and one handler serves both the private-
    // and the public-half context, so the public half keeps its own permission set.
    handle.public_key_permissions = request.public_key_permissions;

    score::mw::log::LogDebug() << kLogPrefix << std::string{spec.operation} << ": generated "
                               << std::string{spec.key_type} << " key pair";
    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<ParsedDerKey, ::score::crypto::daemon::common::DaemonErrorCode> ParseDerKey(
    const key_management::KeyImportRequest& request,
    int expected_pkey_type)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    if (request.format != score::crypto::FormatType::kDer)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: only DER-encoded keys are supported";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    if (request.key_data_size > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: key material is too large";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    const auto der_size = static_cast<long>(request.key_data_size);

    // The d2i_* functions advance the cursor they are given; a cursor short of
    // the end means trailing bytes after the DER structure.
    const auto* end = request.key_data + request.key_data_size;
    const unsigned char* cursor = request.key_data;
    EvpPkeyPtr pkey{d2i_AutoPrivateKey(nullptr, &cursor, der_size)};
    bool has_private_half = static_cast<bool>(pkey);

    if (pkey && cursor != end)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: private-key DER contains trailing data";
        pkey.reset();
        has_private_half = false;
    }

    if (!pkey)
    {
        // Fall back to a SubjectPublicKeyInfo blob: a verify-only slot legitimately
        // holds just the public half.
        cursor = request.key_data;
        pkey.reset(d2i_PUBKEY(nullptr, &cursor, der_size));
        if (!pkey)
        {
            score::mw::log::LogError() << kLogPrefix << "ParseDerKey: could not parse private or public DER key";
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
        }
        if (cursor != end)
        {
            score::mw::log::LogError() << kLogPrefix << "ParseDerKey: public-key DER contains trailing data";
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
        }
    }

    if (EVP_PKEY_get_base_id(pkey.get()) != expected_pkey_type)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseDerKey: parsed key is not of the type '"
                                   << request.algorithm.name << "' needs";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    return ParsedDerKey{std::move(pkey), has_private_half};
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
CreateImportedAsymmetricKey(common::ProviderId provider_id,
                            const key_management::KeyImportRequest& request,
                            ParsedDerKey parsed,
                            std::size_t key_size)
{
    auto owned_pkey = std::move(parsed.pkey);

    // The grant describes the slot, not the material that arrived in it. A slot
    // allowing kSign may still deploy a bare SubjectPublicKeyInfo blob, and a
    // handle claiming kSign over a key with no private half would satisfy the
    // mediator's check and fail inside OpenSSL instead, where the cause is far
    // less legible.
    const auto permissions =
        parsed.has_private_half ? request.permissions : score::crypto::KeyOperationPermission::kNone;

    auto handle = MakeKeyHandle(provider_id, request.algorithm, permissions, key_size, owned_pkey.get());

    // An import request carries one permission set for whatever material it
    // contains, so it governs both halves. Leaving this nullopt would mean
    // "public half unrestricted", which is the right default for a generated
    // key but would let an imported key ignore its slot's allowed_operations.
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

}  // namespace score::crypto::daemon::provider::openssl::detail
