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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_ed25519_sign_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"

#include "score/mw/log/logging.h"

#include <openssl/evp.h>

#include <string_view>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{
constexpr std::string_view kLogPrefix{"[OPENSSL_ED25519_SIGN_HANDLER] "};
}  // namespace

namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;

OpenSslEd25519SignHandler::OpenSslEd25519SignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                                     const common::AlgorithmId& algorithm)
    : ScoreSignHandler{std::move(executor), algorithm}
{
}

OpenSslEd25519SignHandler::~OpenSslEd25519SignHandler() = default;

bool OpenSslEd25519SignHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           algo::IsEd25519Algorithm(value);
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519SignHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    auto base = ScoreSignHandler::InitializeContext(params);
    if (!base.has_value())
    {
        return base;
    }

    const auto input_mode = ::score::crypto::daemon::provider::handler::ParseInputMode(params);
    if (!input_mode.has_value())
    {
        return make_unexpected(input_mode.error());
    }
    if (input_mode.value() == ::score::crypto::SignatureInputMode::kPrehashed)
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeContext: prehashed mode is unsupported for Ed25519";
        return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
    }

    auto bound = m_stream.Bind(params, m_algorithm);
    if (!bound.has_value())
    {
        return bound;
    }
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519SignHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

std::size_t OpenSslEd25519SignHandler::GetSignatureSize() const noexcept
{
    return algo::kEd25519SignatureSize;
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519SignHandler::InitSign()
{
    score::mw::log::LogError() << kLogPrefix << "InitSign: Ed25519 does not support streaming signing";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519SignHandler::UpdateSign(score::cpp::span<const std::uint8_t>)
{
    score::mw::log::LogError() << kLogPrefix << "UpdateSign: Ed25519 does not support streaming signing";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> OpenSslEd25519SignHandler::FinalizeSign(score::cpp::span<std::uint8_t>)
{
    score::mw::log::LogError() << kLogPrefix << "FinalizeSign: Ed25519 does not support streaming signing";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::size_t, DaemonErrorCode> OpenSslEd25519SignHandler::SingleShotSign(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<std::uint8_t> output)
{
    const std::size_t signature_size = GetSignatureSize();
    if (output.size() < signature_size)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: output holds " << output.size() << " bytes, needs "
                                   << signature_size;
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: failed to restart signing stream";
        return make_unexpected(restarted.error());
    }
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: no bound key";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // Ed25519 names no digest: it hashes internally.
    if (EVP_DigestSignInit_ex(m_stream.Context(), nullptr, nullptr, nullptr, nullptr, key, nullptr) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: EVP_DigestSignInit_ex failed";
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    std::size_t written = signature_size;
    const int sign_result = EVP_DigestSign(m_stream.Context(), output.data(), &written, data.data(), data.size());
    m_state = StreamOperationState::IDLE;
    if (sign_result != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: EVP_DigestSign failed";
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return written;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
