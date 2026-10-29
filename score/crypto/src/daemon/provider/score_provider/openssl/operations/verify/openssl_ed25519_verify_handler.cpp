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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_ed25519_verify_handler.hpp"

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
constexpr std::string_view kLogPrefix{"[OPENSSL_ED25519_VERIFY_HANDLER] "};
}  // namespace

namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;

OpenSslEd25519VerifyHandler::OpenSslEd25519VerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                                         const common::AlgorithmId& algorithm)
    : ScoreVerifyHandler{std::move(executor), algorithm}
{
}

OpenSslEd25519VerifyHandler::~OpenSslEd25519VerifyHandler() = default;

bool OpenSslEd25519VerifyHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           algo::IsEd25519Algorithm(value);
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519VerifyHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    auto base = ScoreVerifyHandler::InitializeContext(params);
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

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519VerifyHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

std::size_t OpenSslEd25519VerifyHandler::GetSignatureSize() const noexcept
{
    return algo::kEd25519SignatureSize;
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519VerifyHandler::InitVerify()
{
    score::mw::log::LogError() << kLogPrefix << "InitVerify: Ed25519 does not support streaming verification";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<std::monostate, DaemonErrorCode> OpenSslEd25519VerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t>)
{
    score::mw::log::LogError() << kLogPrefix << "UpdateVerify: Ed25519 does not support streaming verification";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, DaemonErrorCode> OpenSslEd25519VerifyHandler::FinalizeVerify(score::cpp::span<const std::uint8_t>)
{
    score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: Ed25519 does not support streaming verification";
    return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

Expected<bool, DaemonErrorCode> OpenSslEd25519VerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    if (signature.size() != GetSignatureSize())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: signature has " << signature.size()
                                   << " bytes; expected " << GetSignatureSize();
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: failed to restart verification stream";
        return make_unexpected(restarted.error());
    }
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: no bound key";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // Ed25519 names no digest: it hashes internally.
    if (EVP_DigestVerifyInit_ex(m_stream.Context(), nullptr, nullptr, nullptr, nullptr, key, nullptr) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: EVP_DigestVerifyInit_ex failed";
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    const int result =
        EVP_DigestVerify(m_stream.Context(), signature.data(), signature.size(), data.data(), data.size());
    m_state = StreamOperationState::IDLE;
    if (result == 1)
    {
        return true;
    }
    if (result == 0)
    {
        return false;
    }
    score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: EVP_DigestVerify failed";
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
