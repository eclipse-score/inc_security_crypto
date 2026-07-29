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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/signature/openssl_ecdsa_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include "score/mw/log/logging.h"

#include <cstring>
#include <string>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;
namespace algo_info = ::score::crypto::daemon::common;

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

OpenSslEcdsaHandler::OpenSslEcdsaHandler(std::unique_ptr<operations::signature::SignatureExecutor> executor,
                                         const common::AlgorithmId& algorithm)
    : ScoreSignatureHandler{std::move(executor), algorithm}
{
}

OpenSslEcdsaHandler::~OpenSslEcdsaHandler()
{
    CleanupContext();
}

void OpenSslEcdsaHandler::CleanupContext() noexcept
{
    if (m_md_ctx != nullptr)
    {
        EVP_MD_CTX_free(m_md_ctx);
        m_md_ctx = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

bool OpenSslEcdsaHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view algo{algorithm.data(), algorithm.size()};
    // A *signature* algorithm must name the digest as well as the curve: there
    // is no implied default pairing. Requiring it here means the bare key form
    // ("ECDSA-P256") is rejected at CTX_CREATE rather than surviving until the
    // first Init(), where the failure would be much harder to attribute.
    return algo_info::IsEcdsaAlgorithm(algo) && algo_info::LookupSignatureDigest(algo).has_value();
}

EVP_PKEY* OpenSslEcdsaHandler::GetBoundPkey() const noexcept
{
    if (m_init_params.bound_key_handler == nullptr)
    {
        return nullptr;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) - provider id verified in InitializeContext
    const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
        m_init_params.bound_key_handler);
    return openssl_key->GetPkey();
}

// ---------------------------------------------------------------------------
// Signature encoding conversion
//
// OpenSSL speaks DER ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }); the
// stack's wire format is the fixed-length IEEE P1363 concatenation r‖s. The
// two helpers below are the only place that difference exists.
// ---------------------------------------------------------------------------

::score::crypto::Expected<common::OwnedBuffer, DaemonErrorCode> OpenSslEcdsaHandler::DerToP1363(const std::uint8_t* der,
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

::score::crypto::Expected<common::OwnedBuffer, DaemonErrorCode> OpenSslEcdsaHandler::P1363ToDer(const std::uint8_t* raw,
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

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    if (!IsAlgorithmSupported(m_algorithm))
    {
        score::mw::log::LogError() << LOG_PREFIX << "Unsupported algorithm:" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // Picks up the sign/verify OperationMode from CTX_CREATE param[4].
    auto base_result = ScoreSignatureHandler::InitializeContext(init_params);
    if (!base_result.has_value())
    {
        return base_result;
    }

    CleanupContext();

    if (init_params.bound_key_handler == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: signature context requires a bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
    if (init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key is not an OpenSSL key handler"
                                   << " (key provider_id=" << init_params.bound_key_handler->GetProviderId()
                                   << ", expected=" << init_params.provider_id << ")";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    m_init_params = init_params;

    EVP_PKEY* pkey = GetBoundPkey();
    if (pkey == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key holds no EC key pair";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key is not an EC key";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }

    m_md_ctx = EVP_MD_CTX_new();
    if (m_md_ctx == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_MD_CTX_new failed";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaHandler::Reset()
{
    return InitializeContext(m_init_params);
}

// ---------------------------------------------------------------------------
// ScoreSignatureHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaHandler::InitSignature()
{
    if (m_md_ctx == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSignature: digest context not allocated";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    EVP_PKEY* pkey = GetBoundPkey();
    if (pkey == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSignature: no bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto digest_name = algo_info::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!digest_name.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSignature: no digest for algorithm" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // A fresh EVP_MD_CTX per stream: EVP_DigestSignInit cannot restart a context
    // that already carries accumulated data.
    EVP_MD_CTX_free(m_md_ctx);
    m_md_ctx = EVP_MD_CTX_new();
    if (m_md_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    const std::string digest{digest_name.value()};
    const int rv = (GetOperationMode() == score::crypto::OperationMode::kVerify)
                       ? EVP_DigestVerifyInit_ex(m_md_ctx, nullptr, digest.c_str(), nullptr, nullptr, pkey, nullptr)
                       : EVP_DigestSignInit_ex(m_md_ctx, nullptr, digest.c_str(), nullptr, nullptr, pkey, nullptr);
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSignature: EVP_Digest{Sign,Verify}Init failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaHandler::UpdateSignature(
    const common::RequestParameter& data)
{
    if (m_md_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto dataSpan = CheckAndGetSpan<const std::uint8_t>(data);
    if (!dataSpan.has_value())
    {
        return ::score::crypto::make_unexpected(dataSpan.error());
    }

    const int rv = (GetOperationMode() == score::crypto::OperationMode::kVerify)
                       ? EVP_DigestVerifyUpdate(m_md_ctx, dataSpan.value().data(), dataSpan.value().size())
                       : EVP_DigestSignUpdate(m_md_ctx, dataSpan.value().data(), dataSpan.value().size());
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "UpdateSignature: EVP_Digest{Sign,Verify}Update failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslEcdsaHandler::FinalizeSign(
    score::cpp::span<std::uint8_t> signature)
{
    if (m_md_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto curve = algo_info::LookupEcCurveOfAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // P1363 is r‖s, two field-sized integers, so the length is known before signing.
    const std::size_t p1363_len = 2U * curve->field_size;
    if (signature.size() < p1363_len)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: output buffer holds" << signature.size()
                                   << "bytes, needs" << p1363_len;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    // First call sizes the DER buffer, second fills it.
    std::size_t der_len = 0U;
    if (EVP_DigestSignFinal(m_md_ctx, nullptr, &der_len) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: EVP_DigestSignFinal size query failed";
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    std::vector<std::uint8_t> der(der_len);
    if (EVP_DigestSignFinal(m_md_ctx, der.data(), &der_len) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: EVP_DigestSignFinal failed";
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    der.resize(der_len);

    auto p1363 = DerToP1363(der.data(), der.size(), curve->field_size);
    m_state = StreamOperationState::IDLE;
    if (!p1363.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: DER to P1363 conversion failed";
        return ::score::crypto::make_unexpected(p1363.error());
    }

    std::memcpy(signature.data(), p1363.value().data(), p1363.value().size());
    return p1363.value().size();
}

::score::crypto::Expected<bool, DaemonErrorCode> OpenSslEcdsaHandler::FinalizeVerify(
    const common::RequestParameter& signature)
{
    if (m_md_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto curve = algo_info::LookupEcCurveOfAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    const auto sigSpan = CheckAndGetSpan<const std::uint8_t>(signature);
    if (!sigSpan.has_value())
    {
        return ::score::crypto::make_unexpected(sigSpan.error());
    }

    // A signature of the wrong length is a malformed input rather than a
    // mismatching one, so it is reported as an error, not as "not verified".
    auto der = P1363ToDer(sigSpan.value().data(), sigSpan.value().size(), curve->field_size);
    if (!der.has_value())
    {
        m_state = StreamOperationState::IDLE;
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeVerify: malformed P1363 signature of length"
                                   << sigSpan.value().size();
        return ::score::crypto::make_unexpected(der.error());
    }

    const int rv = EVP_DigestVerifyFinal(m_md_ctx, der.value().data(), der.value().size());
    m_state = StreamOperationState::IDLE;

    // rv == 1 verified, rv == 0 signature mismatch (a normal result), rv < 0 error.
    if (rv < 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeVerify: EVP_DigestVerifyFinal failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return rv == 1;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
