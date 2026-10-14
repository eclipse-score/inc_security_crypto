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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_ecdsa_verify_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"

#include "score/mw/log/logging.h"

#include <string>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;
namespace algo_info = ::score::crypto::daemon::common;

OpenSslEcdsaVerifyHandler::OpenSslEcdsaVerifyHandler(
    std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::verify::VerifyExecutor> executor,
    const common::AlgorithmId& algorithm)
    : ScoreVerifyHandler{std::move(executor), algorithm}
{
}

OpenSslEcdsaVerifyHandler::~OpenSslEcdsaVerifyHandler() = default;

bool OpenSslEcdsaVerifyHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    return ecdsa::IsAlgorithmSupported(algorithm);
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaVerifyHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    auto base_result = ScoreVerifyHandler::InitializeContext(init_params);
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

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaVerifyHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

// ---------------------------------------------------------------------------
// ScoreVerifyHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaVerifyHandler::InitVerify()
{
    EVP_PKEY* pkey = m_stream.Key();
    if (pkey == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitVerify: no bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto digest_name = algo_info::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!digest_name.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitVerify: no digest for algorithm" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        return restarted;
    }

    const std::string digest{digest_name.value()};
    if (EVP_DigestVerifyInit_ex(m_stream.Context(), nullptr, digest.c_str(), nullptr, nullptr, pkey, nullptr) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitVerify: EVP_DigestVerifyInit failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslEcdsaVerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    if (EVP_DigestVerifyUpdate(m_stream.Context(), data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "UpdateVerify: EVP_DigestVerifyUpdate failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<common::OwnedBuffer, DaemonErrorCode> OpenSslEcdsaVerifyHandler::ToDer(
    score::cpp::span<const std::uint8_t> signature) const
{
    const auto curve = algo_info::LookupEcCurveOfAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    if (!curve.has_value())
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // A signature of the wrong length is a malformed input rather than a
    // mismatching one, so it is reported as an error, not as "not verified".
    auto der = ecdsa::P1363ToDer(signature.data(), signature.size(), curve->field_size);
    if (!der.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "malformed P1363 signature of length" << signature.size();
    }
    return der;
}

::score::crypto::Expected<bool, DaemonErrorCode> OpenSslEcdsaVerifyHandler::FinalizeVerify(
    score::cpp::span<const std::uint8_t> signature)
{
    if (m_stream.Context() == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    auto der = ToDer(signature);
    if (!der.has_value())
    {
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(der.error());
    }

    const int rv = EVP_DigestVerifyFinal(m_stream.Context(), der.value().data(), der.value().size());
    m_state = StreamOperationState::IDLE;

    // rv == 1 verified, rv == 0 signature mismatch (a normal result), rv < 0 error.
    if (rv < 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeVerify: EVP_DigestVerifyFinal failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return rv == 1;
}

::score::crypto::Expected<bool, DaemonErrorCode> OpenSslEcdsaVerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    auto der = ToDer(signature);
    if (!der.has_value())
    {
        return ::score::crypto::make_unexpected(der.error());
    }

    // InitVerify only binds the key and digest. EVP_DigestVerify then does the
    // update and the final together, so no VERIFY_UPDATE step runs.
    auto prepared = InitVerify();
    if (!prepared.has_value())
    {
        return ::score::crypto::make_unexpected(prepared.error());
    }

    const int rv =
        EVP_DigestVerify(m_stream.Context(), der.value().data(), der.value().size(), data.data(), data.size());

    // rv == 1 verified, rv == 0 signature mismatch (a normal result), rv < 0 error.
    if (rv < 0)
    {
        score::mw::log::LogError() << LOG_PREFIX << "SingleShotVerify: EVP_DigestVerify failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return rv == 1;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
