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

#include <openssl/bio.h>     // BIO_new_mem_buf
#include <openssl/crypto.h>  // OPENSSL_secure_clear_free
#include <openssl/err.h>     // ERR_clear_error
#include <openssl/evp.h>     // EVP_PKEY_CTX, EVP_PKEY_generate
#include <openssl/pem.h>     // PEM_read_bio_ex
#include <openssl/x509.h>    // d2i_AutoPrivateKey / d2i_PUBKEY

#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

namespace score::crypto::daemon::provider::openssl::detail
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_ASYMMETRIC_KEY] ";

constexpr std::string_view kPemBeginMarker = "-----BEGIN ";
constexpr std::string_view kPemPublicKeyLabel = "PUBLIC KEY";
constexpr std::string_view kPemEncryptedPrivateKeyLabel = "ENCRYPTED PRIVATE KEY";
/// PKCS#8 and the traditional SEC1 / PKCS#1 private-key labels.
constexpr std::string_view kPemPrivateKeyLabels[] = {"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"};

constexpr std::string_view kPemWhitespace = " \t\r\n";

/// Frees a buffer returned by PEM_read_bio_ex with PEM_FLAG_SECURE; a non-zero
/// length also wipes it first.
struct PemSecureFree
{
    long length{0};

    void operator()(void* ptr) const noexcept
    {
        if (length > 0)
        {
            OPENSSL_secure_clear_free(ptr, static_cast<std::size_t>(length));
        }
        else
        {
            OPENSSL_secure_free(ptr);
        }
    }
};

/// Parses DER key material: a PKCS#8 or traditional (SEC1, PKCS#1) private key,
/// or a SubjectPublicKeyInfo. Trailing bytes are rejected.
::score::crypto::Expected<ParsedDerKey, ::score::crypto::daemon::common::DaemonErrorCode> ParseDerBytes(
    const std::uint8_t* data,
    std::size_t size)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    if (size > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    {
        score::mw::log::LogError() << kLogPrefix << "ParseKey: key material is too large";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    const auto der_size = static_cast<long>(size);

    // The d2i_* functions advance the cursor they are given; a cursor short of
    // the end means trailing bytes after the DER structure.
    const auto* end = data + size;
    const unsigned char* cursor = data;
    EvpPkeyPtr pkey{d2i_AutoPrivateKey(nullptr, &cursor, der_size)};
    bool has_private_half = static_cast<bool>(pkey);

    if (pkey && cursor != end)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseKey: private-key DER contains trailing data";
        pkey.reset();
        has_private_half = false;
    }

    if (!pkey)
    {
        // Fall back to a SubjectPublicKeyInfo blob: a verify-only slot legitimately
        // holds just the public half.
        cursor = data;
        pkey.reset(d2i_PUBKEY(nullptr, &cursor, der_size));
        if (!pkey)
        {
            score::mw::log::LogError() << kLogPrefix << "ParseKey: could not parse private or public DER key";
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
        }
        if (cursor != end)
        {
            score::mw::log::LogError() << kLogPrefix << "ParseKey: public-key DER contains trailing data";
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
        }
    }

    return ParsedDerKey{std::move(pkey), has_private_half};
}

/// Parses exactly one unencrypted PEM block labelled PRIVATE KEY, EC PRIVATE KEY,
/// RSA PRIVATE KEY or PUBLIC KEY; its label must agree with the DER body.
::score::crypto::Expected<ParsedDerKey, ::score::crypto::daemon::common::DaemonErrorCode> ParsePemBytes(
    const std::uint8_t* data,
    std::size_t size)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    // PEM_read_bio skips any text before the BEGIN line; refuse it instead, so
    // the input is exactly one PEM block with optional surrounding whitespace.
    const std::string_view text{
        reinterpret_cast<const char*>(data),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        size};
    const std::size_t first = text.find_first_not_of(kPemWhitespace);
    if ((first == std::string_view::npos) || (text.substr(first, kPemBeginMarker.size()) != kPemBeginMarker) ||
        (size > static_cast<std::size_t>(std::numeric_limits<int>::max())))
    {
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: input does not start with a PEM BEGIN line";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    const std::unique_ptr<BIO, decltype(&BIO_free)> bio{
        BIO_new_mem_buf(text.data() + first, static_cast<int>(size - first)), &BIO_free};
    if (!bio)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    // PEM_FLAG_SECURE keeps the decoded body, which may be a private key, on the
    // secure heap and wipes it, and the base64 scratch buffers, when freed.
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* body = nullptr;
    long body_len = 0;
    if (PEM_read_bio_ex(bio.get(), &name, &header, &body, &body_len, PEM_FLAG_SECURE | PEM_FLAG_EAY_COMPATIBLE) != 1)
    {
        ERR_clear_error();
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: malformed PEM block";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }
    const std::unique_ptr<char, PemSecureFree> owned_name{name};
    const std::unique_ptr<char, PemSecureFree> owned_header{header};
    const std::unique_ptr<unsigned char, PemSecureFree> owned_body{body, PemSecureFree{body_len}};

    // Anything after the END line other than whitespace (e.g. a second block) is refused.
    char* tail = nullptr;
    const long tail_len = BIO_get_mem_data(bio.get(), &tail);
    if ((tail_len > 0) && (std::string_view{tail, static_cast<std::size_t>(tail_len)}.find_first_not_of(
                               kPemWhitespace) != std::string_view::npos))
    {
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: data after the PEM END line";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    // RFC 1421 headers (Proc-Type / DEK-Info) only appear on encrypted
    // legacy keys. No passphrase can be supplied through ImportKey, so
    // encrypted PEM of either kind is refused rather than decrypted.
    const std::string_view label{owned_name.get()};
    if ((owned_header && (owned_header.get()[0] != '\0')) || (label == kPemEncryptedPrivateKeyLabel))
    {
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: encrypted PEM keys are not supported";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    const bool is_public_label = (label == kPemPublicKeyLabel);
    const bool is_private_label = std::find(std::begin(kPemPrivateKeyLabels), std::end(kPemPrivateKeyLabels), label) !=
                                  std::end(kPemPrivateKeyLabels);
    if (!is_public_label && !is_private_label)
    {
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: unsupported PEM label '" << label << "'";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    auto parsed = ParseDerBytes(owned_body.get(), static_cast<std::size_t>(body_len));
    if (!parsed.has_value())
    {
        return parsed;
    }
    if (parsed.value().has_private_half != is_private_label)
    {
        score::mw::log::LogError() << kLogPrefix << "ParsePemKey: PEM label '" << label
                                   << "' does not match the encoded key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }
    return parsed;
}
}  // namespace

score::crypto::FormatType ResolveAsymmetricFormat(const key_management::KeyImportRequest& request) noexcept
{
    if (request.format.has_value())
    {
        return request.format.value();
    }
    const std::string_view text{
        reinterpret_cast<const char*>(request.key_data),  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        request.key_data_size};
    const std::size_t first = text.find_first_not_of(kPemWhitespace);
    if ((first != std::string_view::npos) && (text.substr(first, kPemBeginMarker.size()) == kPemBeginMarker))
    {
        return score::crypto::FormatType::kPem;
    }
    constexpr std::uint8_t kUncompressedPointTag{0x04U};
    if ((request.algorithm.key_type == ::score::crypto::KeyType::kEcc) && (request.key_data_size > 0U) &&
        (request.key_data[0] == kUncompressedPointTag))
    {
        return score::crypto::FormatType::kRaw;
    }
    return score::crypto::FormatType::kDer;
}

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

::score::crypto::Expected<ParsedDerKey, ::score::crypto::daemon::common::DaemonErrorCode> ParseKey(
    const key_management::KeyImportRequest& request,
    int expected_pkey_type)
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    ::score::crypto::Expected<ParsedDerKey, DaemonErrorCode> parsed =
        ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    switch (ResolveAsymmetricFormat(request))
    {
        case score::crypto::FormatType::kDer:
            parsed = ParseDerBytes(request.key_data, request.key_data_size);
            break;
        case score::crypto::FormatType::kPem:
            parsed = ParsePemBytes(request.key_data, request.key_data_size);
            break;
        case score::crypto::FormatType::kRaw:
            score::mw::log::LogError() << kLogPrefix << "ParseKey: only DER or PEM encoded keys are supported here";
            break;
    }
    if (!parsed.has_value())
    {
        return parsed;
    }

    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != expected_pkey_type)
    {
        score::mw::log::LogError() << kLogPrefix << "ParseKey: parsed key is not of the type '"
                                   << request.algorithm.name << "' needs";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }
    return parsed;
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
