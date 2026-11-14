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
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/bio.h>         // BIO_new_mem_buf / BIO_get_mem_data
#include <openssl/core_names.h>  // OSSL_PKEY_PARAM_GROUP_NAME
#include <openssl/crypto.h>      // OPENSSL_cleanse
#include <openssl/err.h>         // ERR_clear_error
#include <openssl/evp.h>         // EVP_PKEY_CTX, EVP_PKEY_generate
#include <openssl/params.h>      // OSSL_PARAM
#include <openssl/pem.h>         // PEM_read_bio_ex / PEM_write_bio_PUBKEY
#include <openssl/rand.h>        // RAND_bytes
#include <openssl/rsa.h>         // EVP_PKEY_CTX_set_rsa_keygen_bits
#include <openssl/x509.h>        // d2i_AutoPrivateKey / d2i_PUBKEY / i2d_PUBKEY

#include "score/mw/log/logging.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_KEY_FACTORY] ";

/// Builds the key handle metadata shared by every key this factory produces.
key_management::ProviderKeyHandle MakeHandle(common::ProviderId provider_id,
                                             const AlgorithmDescriptor& algorithm,
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

/// How this factory creates or imports a key of a catalog row.
enum class KeyShape : std::uint8_t
{
    kEc,
    kRsa,
    kEd25519,
    kSymmetric,
};

/// Decided by key type; every KeyType needs a case so a new one forces a choice here.
KeyShape ShapeOf(const AlgorithmDescriptor& algorithm) noexcept
{
    switch (algorithm.key_type)
    {
        case ::score::crypto::KeyType::kEcc:
            return KeyShape::kEc;
        case ::score::crypto::KeyType::kRsa:
            // Only RSA key rows ("RSA-2048") create key pairs; an RSA-PSS
            // signature row takes the symmetric path, which refuses it.
            return (algorithm.category == ::score::crypto::AlgorithmCategory::kKey) ? KeyShape::kRsa
                                                                                    : KeyShape::kSymmetric;
        case ::score::crypto::KeyType::kEd25519:
            return KeyShape::kEd25519;
        case ::score::crypto::KeyType::kNone:
        case ::score::crypto::KeyType::kSecret:
        case ::score::crypto::KeyType::kAes:
            return KeyShape::kSymmetric;
    }
    return KeyShape::kSymmetric;
}

/// SEC1 tag of an uncompressed EC point. Compressed (0x02/0x03) and hybrid
/// (0x06/0x07) encodings are deliberately not accepted on the raw import path.
constexpr std::uint8_t kUncompressedPointTag = 0x04U;

/// Build an EC public-key EVP_PKEY from a raw uncompressed SEC1 point.
///
/// @param group_name OpenSSL group name, e.g. "secp384r1".
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

/// The format asymmetric key material is parsed as. An explicit request.format
/// is kept; without one it is detected from the data: PEM for a BEGIN line after
/// optional whitespace, a raw point for 0x04 on an EC algorithm, DER otherwise.
/// Detection only picks the parser, so every check after parsing still applies.
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

struct BioDeleter
{
    void operator()(BIO* bio) const noexcept
    {
        BIO_free(bio);
    }
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

/// EC public key as the uncompressed SEC1 point 0x04||X||Y.
::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
EncodeRawEcPoint(const EVP_PKEY* pkey)
{
    std::size_t out_len = 0U;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0U, &out_len) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    key_management::SecureKeyBytes out{out_len};
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, out.bytes.data(), out_len, &out_len) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    out.bytes.resize(out_len);
    return out;
}

/// Public key as DER-encoded SubjectPublicKeyInfo.
::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
EncodeSpkiDer(const EVP_PKEY* pkey)
{
    const int der_len = i2d_PUBKEY(pkey, nullptr);
    if (der_len <= 0)
    {
        score::mw::log::LogError() << kLogPrefix << "EncodeSpkiDer: i2d_PUBKEY failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    key_management::SecureKeyBytes out{static_cast<std::size_t>(der_len)};
    unsigned char* cursor = out.bytes.data();
    if (i2d_PUBKEY(pkey, &cursor) != der_len)
    {
        score::mw::log::LogError() << kLogPrefix << "EncodeSpkiDer: i2d_PUBKEY failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }
    return out;
}

/// Public key as PEM ("-----BEGIN PUBLIC KEY-----") SubjectPublicKeyInfo.
::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
EncodeSpkiPem(const EVP_PKEY* pkey)
{
    BioPtr bio{BIO_new(BIO_s_mem())};
    if (!bio)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    if (PEM_write_bio_PUBKEY(bio.get(), pkey) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "EncodeSpkiPem: PEM_write_bio_PUBKEY failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    char* pem_data = nullptr;
    const long pem_len = BIO_get_mem_data(bio.get(), &pem_data);  // NOLINT(google-runtime-int)
    if ((pem_len <= 0) || (pem_data == nullptr))
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    key_management::SecureKeyBytes out{static_cast<std::size_t>(pem_len)};
    std::copy(pem_data, pem_data + pem_len, out.bytes.begin());
    return out;
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

::score::crypto::Expected<OpenSslKeyFactory::ParsedDerKey, common::DaemonErrorCode> OpenSslKeyFactory::ParseKey(
    const key_management::KeyImportRequest& request)
{
    switch (ResolveAsymmetricFormat(request))
    {
        case score::crypto::FormatType::kDer:
            return ParseDerKey(request.key_data, request.key_data_size);
        case score::crypto::FormatType::kPem:
            return ParsePemKey(request.key_data, request.key_data_size);
        case score::crypto::FormatType::kRaw:
            break;
    }
    score::mw::log::LogError() << kLogPrefix << "ParseKey: only DER or PEM encoded keys are supported here";
    return ::score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidFormat);
}

::score::crypto::Expected<OpenSslKeyFactory::ParsedDerKey, common::DaemonErrorCode> OpenSslKeyFactory::ParseDerKey(
    const std::uint8_t* data,
    std::size_t size)
{
    using common::DaemonErrorCode;

    const auto* end = data + size;
    const unsigned char* cursor = data;
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(size));
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
        cursor = data;
        pkey = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(size));
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

::score::crypto::Expected<OpenSslKeyFactory::ParsedDerKey, common::DaemonErrorCode> OpenSslKeyFactory::ParsePemKey(
    const std::uint8_t* data,
    std::size_t size)
{
    using common::DaemonErrorCode;

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

    auto parsed = ParseDerKey(owned_body.get(), static_cast<std::size_t>(body_len));
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
    switch (ShapeOf(request.algorithm))
    {
        case KeyShape::kEc:
            return GenerateEcKey(request);
        case KeyShape::kRsa:
            return GenerateRsaKey(request);
        case KeyShape::kEd25519:
            return GenerateEd25519Key(request);
        case KeyShape::kSymmetric:
            break;
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
    const char* const group =
        ::score::crypto::daemon::provider::openssl::detail::ToOpenSslGroupName(request.algorithm.curve);
    if (group == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: no OpenSSL group for algorithm '"
                                   << request.algorithm.name << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    const std::string_view openssl_group_name{group};

    const KeygenSpec spec{"EC", ::score::crypto::daemon::common::EcFieldSize(request.algorithm), "GenerateEcKey"};
    return GenerateAsymmetricKey(request, spec, [&](EVP_PKEY_CTX* ctx) {
        // OSSL_PARAM takes a non-const char*, but only reads the group name.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
        char* group_name = const_cast<char*>(openssl_group_name.data());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, openssl_group_name.size()),
            OSSL_PARAM_construct_end(),
        };
        if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "GenerateEcKey: failed to select group "
                                       << std::string{openssl_group_name};
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

    switch (ShapeOf(request.algorithm))
    {
        case KeyShape::kEc:
            return ImportEcKey(request);
        case KeyShape::kRsa:
            return ImportRsaKey(request);
        case KeyShape::kEd25519:
            return ImportEd25519Key(request);
        case KeyShape::kSymmetric:
            break;
    }

    const auto valid = ValidateSymmetricImport(request);
    if (!valid.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportKey: " << request.key_data_size
                                   << " bytes are not a valid raw '" << request.algorithm.name << "' key";
        return ::score::crypto::make_unexpected(valid.error());
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
    if (!::score::crypto::daemon::provider::openssl::detail::IsRsaModulusSupported(request.algorithm.key_bits))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    const std::size_t key_bits = request.algorithm.key_bits;
    const std::size_t modulus_size = (key_bits + 7U) / 8U;

    const KeygenSpec spec{"RSA", modulus_size, "GenerateRsaKey"};
    return GenerateAsymmetricKey(request, spec, [bits = key_bits](EVP_PKEY_CTX* ctx) {
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
OpenSslKeyFactory::ImportRsaKey(const key_management::KeyImportRequest& request)
{
    if (!::score::crypto::daemon::provider::openssl::detail::IsRsaModulusSupported(request.algorithm.key_bits))
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    const std::size_t key_bits = request.algorithm.key_bits;
    const std::size_t modulus_size = (key_bits + 7U) / 8U;

    auto parsed = ParseKey(request);
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRsaKey: could not parse key material";
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (!parsed.value().pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRsaKey: parsed key is empty";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != EVP_PKEY_RSA)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRsaKey: parsed key is not an RSA key";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }
    if (EVP_PKEY_get_bits(parsed.value().pkey.get()) != static_cast<int>(key_bits))
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRsaKey: RSA modulus size is incompatible";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return CreateImportedAsymmetricKey(request, std::move(parsed.value()), modulus_size);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportEd25519Key(const key_management::KeyImportRequest& request)
{
    auto parsed = ParseKey(request);
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEd25519Key: could not parse key material";
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (!parsed.value().pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEd25519Key: parsed key is empty";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != EVP_PKEY_ED25519)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEd25519Key: parsed key is not an Ed25519 key";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return CreateImportedAsymmetricKey(
        request, std::move(parsed.value()), ::score::crypto::daemon::common::kEd25519KeySize);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportEcKey(const key_management::KeyImportRequest& request)
{
    const char* const group =
        ::score::crypto::daemon::provider::openssl::detail::ToOpenSslGroupName(request.algorithm.curve);
    if (group == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: no OpenSSL group for algorithm '"
                                   << request.algorithm.name << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    const std::string_view openssl_group_name{group};

    // A raw import carries only the public half as an uncompressed SEC1 point,
    // so it follows a dedicated path and never claims a private-half permission.
    if (ResolveAsymmetricFormat(request) == score::crypto::FormatType::kRaw)
    {
        return ImportRawEcPublicKey(request);
    }

    auto parsed = ParseKey(request);
    if (!parsed.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: could not parse key material";
        return ::score::crypto::make_unexpected(parsed.error());
    }

    if (EVP_PKEY_get_base_id(parsed.value().pkey.get()) != EVP_PKEY_EC)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is not an EC key";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    std::string imported_group(openssl_group_name.size() + 1U, '\0');
    std::size_t imported_group_size = 0U;
    const bool group_name_read = EVP_PKEY_get_utf8_string_param(parsed.value().pkey.get(),
                                                                OSSL_PKEY_PARAM_GROUP_NAME,
                                                                imported_group.data(),
                                                                imported_group.size(),
                                                                &imported_group_size) == 1;
    const bool has_trailing_nul = imported_group_size > 0U && imported_group[imported_group_size - 1U] == '\0';
    const std::size_t group_name_size = imported_group_size - (has_trailing_nul ? 1U : 0U);
    if (!group_name_read || std::string_view{imported_group.data(), group_name_size} != openssl_group_name)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportEcKey: parsed key is on an incompatible curve";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kIncompatibleKeyType);
    }

    return CreateImportedAsymmetricKey(
        request, std::move(parsed.value()), ::score::crypto::daemon::common::EcFieldSize(request.algorithm));
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ImportRawEcPublicKey(const key_management::KeyImportRequest& request)
{
    const char* const group =
        ::score::crypto::daemon::provider::openssl::detail::ToOpenSslGroupName(request.algorithm.curve);
    if (group == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: no OpenSSL group for algorithm '"
                                   << request.algorithm.name << "'";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
    const std::string_view openssl_group_name{group};
    const std::size_t field_size = ::score::crypto::daemon::common::EcFieldSize(request.algorithm);

    // A raw EC public key is the uncompressed SEC1 point 0x04||X||Y. Its length
    // is fixed by the curve, so a wrong length is the cheapest way to reject a
    // compressed point (1+field_size) or truncated input before touching OpenSSL.
    const std::size_t expected_len = 1U + (2U * field_size);
    if (request.key_data_size != expected_len)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: expected " << expected_len
                                   << " bytes for an uncompressed " << std::string{openssl_group_name} << " point, got "
                                   << request.key_data_size;
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // Even at the right length, a 0x02/0x03 (compressed) or 0x06/0x07 (hybrid)
    // lead byte is a different encoding and is rejected rather than reinterpreted.
    if (request.key_data[0] != kUncompressedPointTag)
    {
        score::mw::log::LogError() << kLogPrefix
                                   << "ImportRawEcPublicKey: point is not uncompressed (0x04); lead byte 0x"
                                   << score::mw::log::LogHex8{request.key_data[0]};
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    EvpPkeyPtr owned_pkey = BuildEcPublicKeyFromRawPoint(openssl_group_name, request.key_data, request.key_data_size);
    if (!owned_pkey)
    {
        score::mw::log::LogError() << kLogPrefix << "ImportRawEcPublicKey: point is not a valid public key on curve "
                                   << std::string{openssl_group_name};
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidFormat);
    }

    // Raw import delivers no private scalar, so the private half can perform
    // nothing; only the public half carries the slot's grant (verify / export).
    auto handle =
        MakeHandle(m_provider_id, request.algorithm, score::crypto::KeyOperationPermission::kNone, field_size, true);
    handle.opaque_id = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(owned_pkey.get()));  // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    handle.public_key_permissions = request.permissions;

    return std::make_shared<OpenSslKeyHandler>(std::move(owned_pkey), handle);
}

::score::crypto::Expected<EvpPkeyPtr, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::PrepareUncompressedEcExport(const key_management::ProviderKeyHandle& handle) const
{
    EVP_PKEY* pkey = PkeyFromHandle(handle);
    if (pkey == nullptr)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    // OSSL_PKEY_PARAM_PUB_KEY serialises the point in the key's own point-conversion
    // format. A key decoded from a compressed DER encoding keeps that compressed
    // format, so reading it directly would yield e.g. a 49-byte P-384 point instead
    // of the 97-byte uncompressed form this factory imports and exports.
    // Duplicate the key and pin the export format to uncompressed before reading.
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

    return export_pkey;
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::ExportKey(const key_management::ProviderKeyHandle& handle,
                             std::optional<score::crypto::FormatType> format)
{
    return EncodeExport(handle, format);
}

::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::GetExportKeySize(const key_management::ProviderKeyHandle& handle,
                                    std::optional<score::crypto::FormatType> format)
{
    // Encode with the same code path ExportKey uses, so the advertised size can
    // never disagree with the exported bytes. The encoding is zeroised on return.
    const auto encoded = EncodeExport(handle, format);
    if (!encoded.has_value())
    {
        return ::score::crypto::make_unexpected(encoded.error());
    }
    return encoded.value().bytes.size();
}

::score::crypto::Expected<key_management::SecureKeyBytes, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslKeyFactory::EncodeExport(const key_management::ProviderKeyHandle& handle,
                                std::optional<score::crypto::FormatType> requested_format) const
{
    using ::score::crypto::daemon::common::DaemonErrorCode;

    // Secret and private key material never leaves the daemon in plaintext; it
    // can only be wrapped. Only the public half of a key pair is exported.
    if (!handle.is_asymmetric)
    {
        score::mw::log::LogError() << kLogPrefix << "EncodeExport: secret keys are not exportable";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyNotExportable);
    }

    // Exporting a public key is still an export: it is gated by kExport on the
    // public half's grant. A nullopt grant means unrestricted, matching the
    // documented default for a public key.
    const auto public_permissions = handle.public_key_permissions.value_or(score::crypto::KeyOperationPermission::kAll);
    if (!score::crypto::HasPermission(public_permissions, score::crypto::KeyOperationPermission::kExport))
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kKeyNotExportable);
    }

    // The native format of a public key is DER SubjectPublicKeyInfo.
    const auto format = requested_format.value_or(score::crypto::FormatType::kDer);
    const bool is_ec = handle.algorithm.key_type == ::score::crypto::KeyType::kEcc;
    switch (format)
    {
        case score::crypto::FormatType::kRaw:
            if (!is_ec || (::score::crypto::daemon::provider::openssl::detail::ToOpenSslGroupName(
                               handle.algorithm.curve) == nullptr))
            {
                return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
            }
            break;
        case score::crypto::FormatType::kDer:
        case score::crypto::FormatType::kPem:
            break;
        default:
            return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedOperation);
    }

    EvpPkeyPtr export_pkey{};
    if (is_ec)
    {
        // Pin EC keys to the uncompressed point so raw and SPKI exports carry the
        // same, most interoperable encoding regardless of how the key was imported.
        auto export_res = PrepareUncompressedEcExport(handle);
        if (!export_res.has_value())
        {
            return ::score::crypto::make_unexpected(export_res.error());
        }
        export_pkey = std::move(export_res.value());
    }
    else
    {
        EVP_PKEY* pkey = PkeyFromHandle(handle);
        if ((pkey == nullptr) || (EVP_PKEY_up_ref(pkey) != 1))
        {
            return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        export_pkey.reset(pkey);
    }

    switch (format)
    {
        case score::crypto::FormatType::kRaw:
            return EncodeRawEcPoint(export_pkey.get());
        case score::crypto::FormatType::kDer:
            return EncodeSpkiDer(export_pkey.get());
        case score::crypto::FormatType::kPem:
        default:
            return EncodeSpkiPem(export_pkey.get());
    }
}

// static
std::size_t OpenSslKeyFactory::DetermineKeySize(const AlgorithmDescriptor& algorithm) noexcept
{
    return ::score::crypto::daemon::common::LookupKeySize(algorithm).value_or(0U);
}

}  // namespace score::crypto::daemon::provider::openssl
