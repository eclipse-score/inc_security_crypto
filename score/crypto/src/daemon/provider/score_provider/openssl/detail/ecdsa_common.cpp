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

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include "score/mw/log/logging.h"

#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler::ecdsa
{

using ::score::crypto::daemon::common::DaemonErrorCode;
namespace algo_info = ::score::crypto::daemon::common;

namespace
{
constexpr std::string_view kLogPrefix = "[OPENSSL_ECDSA]";
}  // namespace

bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    // The provider list is the gate; the common table must also resolve the
    // curve and digest because the handlers read field size and digest there.
    const std::string_view algo{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(algo) &&
           algo_info::IsEcdsaAlgorithm(algo) && algo_info::LookupSignatureDigest(algo).has_value();
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

Stream::~Stream()
{
    Free();
}

void Stream::Free() noexcept
{
    if (m_md_ctx != nullptr)
    {
        EVP_MD_CTX_free(m_md_ctx);
        m_md_ctx = nullptr;
    }
}

EVP_PKEY* Stream::Key() const noexcept
{
    if (m_init_params.bound_key_handler == nullptr)
    {
        return nullptr;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) - provider id verified in Bind
    const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
        m_init_params.bound_key_handler);
    return openssl_key->GetPkey();
}

Expected<std::monostate, DaemonErrorCode> Stream::Bind(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params,
    const common::AlgorithmId& algorithm)
{
    if (!IsAlgorithmSupported(algorithm))
    {
        score::mw::log::LogError() << kLogPrefix << "Unsupported algorithm:" << algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    Free();

    if (init_params.bound_key_handler == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "Bind: signature context requires a bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
    if (init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
    {
        score::mw::log::LogError() << kLogPrefix << "Bind: bound key is not an OpenSSL key handler"
                                   << " (key provider_id=" << init_params.bound_key_handler->GetProviderId()
                                   << ", expected=" << init_params.provider_id << ")";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    m_init_params = init_params;

    EVP_PKEY* pkey = Key();
    if (pkey == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "Bind: bound key holds no EC key pair";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC)
    {
        score::mw::log::LogError() << kLogPrefix << "Bind: bound key is not an EC key";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    m_md_ctx = EVP_MD_CTX_new();
    if (m_md_ctx == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "EVP_MD_CTX_new failed";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> Stream::Restart()
{
    Free();
    m_md_ctx = EVP_MD_CTX_new();
    if (m_md_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Signature encoding conversion
//
// OpenSSL speaks DER ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }); the
// stack's wire format is the fixed-length IEEE P1363 concatenation r‖s. The
// two helpers below are the only place that difference exists.
// ---------------------------------------------------------------------------

Expected<common::OwnedBuffer, DaemonErrorCode> DerToP1363(const std::uint8_t* der,
                                                          std::size_t der_len,
                                                          std::size_t field_size)
{
    const std::uint8_t* der_cursor = der;
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &der_cursor, static_cast<long>(der_len));
    if (sig == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);

    common::OwnedBuffer out(field_size * 2U);
    // BN_bn2binpad left-pads with zeros to exactly field_size bytes, which is
    // what makes the P1363 form fixed-length.
    const int r_written = BN_bn2binpad(r, out.data(), static_cast<int>(field_size));
    const int s_written = BN_bn2binpad(s, out.data() + field_size, static_cast<int>(field_size));
    ECDSA_SIG_free(sig);

    if ((r_written < 0) || (s_written < 0))
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return out;
}

Expected<common::OwnedBuffer, DaemonErrorCode> P1363ToDer(const std::uint8_t* raw,
                                                          std::size_t raw_len,
                                                          std::size_t field_size)
{
    if (raw_len != (field_size * 2U))
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    BIGNUM* r = BN_bin2bn(raw, static_cast<int>(field_size), nullptr);
    BIGNUM* s = BN_bin2bn(raw + field_size, static_cast<int>(field_size), nullptr);
    ECDSA_SIG* sig = ECDSA_SIG_new();

    if ((r == nullptr) || (s == nullptr) || (sig == nullptr))
    {
        BN_free(r);
        BN_free(s);
        if (sig != nullptr)
        {
            ECDSA_SIG_free(sig);
        }
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    // ECDSA_SIG_set0 takes ownership of r and s on success.
    if (ECDSA_SIG_set0(sig, r, s) != 1)
    {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    std::uint8_t* der = nullptr;
    const int der_len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);

    if ((der_len <= 0) || (der == nullptr))
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::OwnedBuffer out(der, der + der_len);
    OPENSSL_free(der);
    return out;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler::ecdsa
