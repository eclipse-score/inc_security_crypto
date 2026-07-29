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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_ecdsa_sign_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"

#include "score/mw/log/logging.h"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;
namespace algo_info = ::score::crypto::daemon::common;

OpenSslEcdsaSignHandler::OpenSslEcdsaSignHandler(
    std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::sign::SignExecutor> executor,
    const common::AlgorithmId& algorithm)
    : ScoreSignHandler{std::move(executor), algorithm}
{
}

OpenSslEcdsaSignHandler::~OpenSslEcdsaSignHandler() = default;

bool OpenSslEcdsaSignHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    return ecdsa::IsAlgorithmSupported(algorithm);
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaSignHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    auto base_result = ScoreSignHandler::InitializeContext(init_params);
    if (!base_result.has_value())
    {
        return base_result;
    }

    auto bound = m_stream.Bind(init_params, m_algorithm);
    if (!bound.has_value())
    {
        return bound;
    }

    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaSignHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

// ---------------------------------------------------------------------------
// ScoreSignHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaSignHandler::InitSign()
{
    EVP_PKEY* pkey = m_stream.Key();
    if (pkey == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSign: no bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto digest_name = algo_info::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!digest_name.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSign: no digest for algorithm" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        return restarted;
    }

    const std::string digest{digest_name.value()};
    if (EVP_DigestSignInit_ex(m_stream.Context(), nullptr, digest.c_str(), nullptr, nullptr, pkey, nullptr) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitSign: EVP_DigestSignInit failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaSignHandler::UpdateSign(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    if (EVP_DigestSignUpdate(m_stream.Context(), data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "UpdateSign: EVP_DigestSignUpdate failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return std::monostate{};
}

namespace
{
/// @brief Writes a DER ECDSA-Sig-Value into @p out as fixed-length P1363 r‖s.
///
/// @param out Already length-checked against 2 * @p field_size.
::score::crypto::Expected<std::size_t, DaemonErrorCode> EmitP1363(const std::vector<std::uint8_t>& der,
                                                                  std::size_t field_size,
                                                                  score::cpp::span<std::uint8_t> out)
{
    auto p1363 = ecdsa::DerToP1363(der.data(), der.size(), field_size);
    if (!p1363.has_value())
    {
        return ::score::crypto::make_unexpected(p1363.error());
    }
    std::memcpy(out.data(), p1363.value().data(), p1363.value().size());
    return p1363.value().size();
}
}  // namespace

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslEcdsaSignHandler::FinalizeSign(
    score::cpp::span<std::uint8_t> signature)
{
    if (m_stream.Context() == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    auto target = ResolveSignatureBuffer(signature);
    if (!target.has_value())
    {
        return ::score::crypto::make_unexpected(target.error());
    }

    // First call sizes the DER buffer, second fills it.
    std::size_t der_len = 0U;
    if (EVP_DigestSignFinal(m_stream.Context(), nullptr, &der_len) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: EVP_DigestSignFinal size query failed";
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    std::vector<std::uint8_t> der(der_len);
    if (EVP_DigestSignFinal(m_stream.Context(), der.data(), &der_len) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: EVP_DigestSignFinal failed";
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    der.resize(der_len);

    m_state = StreamOperationState::IDLE;

    auto written = EmitP1363(der, target.value().field_size, target.value().buffer);
    if (!written.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeSign: DER to P1363 conversion failed";
    }
    return written;
}

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslEcdsaSignHandler::SingleShotSign(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<std::uint8_t> signature)
{
    auto target = ResolveSignatureBuffer(signature);
    if (!target.has_value())
    {
        return ::score::crypto::make_unexpected(target.error());
    }

    // InitSign only binds the key and digest. EVP_DigestSign then does the
    // update and the final together, so no SIGN_UPDATE step runs.
    auto prepared = InitSign();
    if (!prepared.has_value())
    {
        return ::score::crypto::make_unexpected(prepared.error());
    }

    std::size_t der_len = 0U;
    if (EVP_DigestSign(m_stream.Context(), nullptr, &der_len, data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "SingleShotSign: EVP_DigestSign size query failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    std::vector<std::uint8_t> der(der_len);
    if (EVP_DigestSign(m_stream.Context(), der.data(), &der_len, data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "SingleShotSign: EVP_DigestSign failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    der.resize(der_len);

    auto written = EmitP1363(der, target.value().field_size, target.value().buffer);
    if (!written.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "SingleShotSign: DER to P1363 conversion failed";
    }
    return written;
}

::score::crypto::Expected<OpenSslEcdsaSignHandler::SignatureTarget, DaemonErrorCode>
OpenSslEcdsaSignHandler::ResolveSignatureBuffer(score::cpp::span<std::uint8_t> signature) const
{
    const auto curve = algo_info::LookupEcCurveOfAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // P1363 is r‖s, two field-sized integers, so the length is known before signing.
    const std::size_t p1363_len = 2U * curve->field_size;
    if (signature.size() < p1363_len)
    {
        score::mw::log::LogError() << LOG_PREFIX << "signature buffer holds" << signature.size() << "bytes, needs"
                                   << p1363_len;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    return SignatureTarget{signature, curve->field_size};
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
