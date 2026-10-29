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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_rsa_pss_sign_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"

#include "score/mw/log/logging.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{
constexpr std::string_view kLogPrefix{"[OPENSSL_RSA_PSS_SIGN_HANDLER] "};
}  // namespace

namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;

OpenSslRsaPssSignHandler::OpenSslRsaPssSignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                                   const common::AlgorithmId& algorithm)
    : ScoreSignHandler{std::move(executor), algorithm}
{
}

OpenSslRsaPssSignHandler::~OpenSslRsaPssSignHandler() = default;

bool OpenSslRsaPssSignHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           algo::IsRsaPssAlgorithm(value);
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssSignHandler::InitializeContext(
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
    m_prehashed = input_mode.value() == ::score::crypto::SignatureInputMode::kPrehashed;

    auto bound = m_stream.Bind(params, m_algorithm);
    if (!bound.has_value())
    {
        return bound;
    }
    m_buffer.clear();
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssSignHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

std::size_t OpenSslRsaPssSignHandler::GetSignatureSize() const noexcept
{
    const auto key =
        algo::LookupRsaKeyInfoForSignatureAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return key.has_value() ? key->modulus_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssSignHandler::InitSign()
{
    return InitializeSignContext();
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssSignHandler::InitializeSignContext()
{
    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeSignContext: failed to restart signing stream";
        return restarted;
    }
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeSignContext: no bound key";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    if (m_prehashed)
    {
        m_buffer.clear();
        return std::monostate{};
    }
    const auto digest = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    const std::string digest_name = digest.has_value() ? std::string{digest.value()} : std::string{};
    if (EVP_DigestSignInit_ex(m_stream.Context(), nullptr, digest_name.c_str(), nullptr, nullptr, key, nullptr) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeSignContext: EVP_DigestSignInit_ex failed for "
                                   << m_algorithm;
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    m_buffer.clear();
    auto configured = ::score::crypto::daemon::provider::openssl::detail::ConfigureRsaPssContext(
        m_stream.Context(), std::string_view{m_algorithm.data(), m_algorithm.size()}, RSA_PSS_SALTLEN_DIGEST);
    if (!configured.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeSignContext: RSA-PSS context configuration failed for "
                                   << m_algorithm;
        return configured;
    }
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssSignHandler::UpdateSign(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "UpdateSign: signing stream is not initialized";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || m_buffer.size() > expected_digest_size.value() ||
            data.size() > expected_digest_size.value() - m_buffer.size())
        {
            score::mw::log::LogError() << kLogPrefix << "UpdateSign: prehashed input exceeds digest size for "
                                       << m_algorithm << "; buffered=" << m_buffer.size() << ", chunk=" << data.size();
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        m_buffer.insert(m_buffer.end(), data.begin(), data.end());
        return std::monostate{};
    }
    if (EVP_DigestSignUpdate(m_stream.Context(), data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "UpdateSign: EVP_DigestSignUpdate failed for " << m_algorithm;
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssSignHandler::ResolveBuffer(
    score::cpp::span<std::uint8_t> output) const
{
    const auto size = GetSignatureSize();
    if (size == 0U)
    {
        score::mw::log::LogError() << kLogPrefix << "ResolveBuffer: unsupported signature algorithm " << m_algorithm;
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }
    if (output.size() < size)
    {
        score::mw::log::LogError() << kLogPrefix << "ResolveBuffer: output holds " << output.size() << " bytes, needs "
                                   << size;
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }
    return size;
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssSignHandler::FinalizeSign(score::cpp::span<std::uint8_t> output)
{
    auto size = ResolveBuffer(output);
    if (!size.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "FinalizeSign: output buffer resolution failed";
        return make_unexpected(size.error());
    }
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || m_buffer.size() != expected_digest_size.value())
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeSign: prehashed input has " << m_buffer.size()
                                       << " bytes; expected "
                                       << (expected_digest_size.has_value() ? expected_digest_size.value() : 0U);
            m_state = StreamOperationState::IDLE;
            m_buffer.clear();
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(m_stream.Key(), nullptr);
        const auto digest_name = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
        const EVP_MD* digest =
            digest_name.has_value()
                ? ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(digest_name.value())
                : nullptr;
        const bool configured = pctx != nullptr && EVP_PKEY_sign_init(pctx) == 1 &&
                                ::score::crypto::daemon::provider::openssl::detail::ConfigureRsaPssPkeyContext(
                                    pctx, digest, RSA_PSS_SALTLEN_DIGEST) &&
                                EVP_PKEY_CTX_set_signature_md(pctx, digest) == 1;
        std::size_t prehashed_written = output.size();
        const int prehashed_sign_result =
            configured ? EVP_PKEY_sign(pctx, output.data(), &prehashed_written, m_buffer.data(), m_buffer.size()) : 0;
        if (!configured)
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeSign: failed to configure prehashed RSA-PSS signing";
        }
        else if (prehashed_sign_result != 1)
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeSign: EVP_PKEY_sign failed for " << m_algorithm;
        }
        if (pctx != nullptr)
        {
            EVP_PKEY_CTX_free(pctx);
        }
        m_state = StreamOperationState::IDLE;
        m_buffer.clear();
        return prehashed_sign_result == 1 ? Expected<std::size_t, DaemonErrorCode>{prehashed_written}
                                          : Expected<std::size_t, DaemonErrorCode>{
                                                make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
    }
    std::size_t written = size.value();
    const int sign_result = EVP_DigestSignFinal(m_stream.Context(), output.data(), &written);
    m_state = StreamOperationState::IDLE;
    m_buffer.clear();
    if (sign_result != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "FinalizeSign: OpenSSL finalization failed for " << m_algorithm;
    }
    return sign_result == 1
               ? Expected<std::size_t, DaemonErrorCode>{written}
               : Expected<std::size_t, DaemonErrorCode>{make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssSignHandler::SingleShotSign(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<std::uint8_t> output)
{
    auto size = ResolveBuffer(output);
    if (!size.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: output buffer resolution failed";
        return make_unexpected(size.error());
    }
    auto initialized = InitializeSignContext();
    if (!initialized.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: signing initialization failed";
        return make_unexpected(initialized.error());
    }
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || data.size() != expected_digest_size.value())
        {
            score::mw::log::LogError() << kLogPrefix << "SingleShotSign: prehashed input has " << data.size()
                                       << " bytes; expected "
                                       << (expected_digest_size.has_value() ? expected_digest_size.value() : 0U);
            m_state = StreamOperationState::IDLE;
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        m_buffer.assign(data.begin(), data.end());
        return FinalizeSign(output);
    }
    std::size_t written = size.value();
    const int sign_result = EVP_DigestSign(m_stream.Context(), output.data(), &written, data.data(), data.size());
    m_state = StreamOperationState::IDLE;
    if (sign_result != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotSign: EVP_DigestSign failed for " << m_algorithm;
    }
    return sign_result == 1
               ? Expected<std::size_t, DaemonErrorCode>{written}
               : Expected<std::size_t, DaemonErrorCode>{make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
