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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_rsa_pss_verify_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/signature_common.hpp"

#include "score/mw/log/logging.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <string>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{
constexpr std::string_view kLogPrefix{"[OPENSSL_RSA_PSS_VERIFY_HANDLER] "};
}  // namespace

namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;

OpenSslRsaPssVerifyHandler::OpenSslRsaPssVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                                       const common::AlgorithmId& algorithm)
    : ScoreVerifyHandler{std::move(executor), algorithm}
{
}

OpenSslRsaPssVerifyHandler::~OpenSslRsaPssVerifyHandler() = default;

bool OpenSslRsaPssVerifyHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           algo::IsRsaPssAlgorithm(value);
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    auto base = ScoreVerifyHandler::InitializeContext(params);
    if (!base.has_value())
    {
        return base;
    }

    const auto input_mode = ::score::crypto::daemon::common::ParseInputMode(params.context_creation_params);
    if (!input_mode.has_value())
    {
        return make_unexpected(input_mode.error());
    }
    m_prehashed = input_mode.value() == ::score::crypto::SignatureInputMode::kPrehashed;
    m_digest_size = 0U;
    if (m_prehashed)
    {
        const auto digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        m_digest_size = digest_size.value_or(0U);
    }

    auto bound = m_stream.Bind(params, m_algorithm);
    if (!bound.has_value())
    {
        return bound;
    }
    m_buffer.clear();
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

std::size_t OpenSslRsaPssVerifyHandler::GetSignatureSize() const noexcept
{
    const auto key =
        algo::LookupRsaKeyInfoForSignatureAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return key.has_value() ? key->modulus_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::InitVerify()
{
    return InitializeVerifyContext();
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::InitializeVerifyContext()
{
    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeVerifyContext: failed to restart verification stream";
        return restarted;
    }
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeVerifyContext: no bound key";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    if (m_prehashed)
    {
        m_buffer.clear();
        return std::monostate{};
    }
    const auto digest = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    const std::string digest_name = digest.has_value() ? std::string{digest.value()} : std::string{};
    if (EVP_DigestVerifyInit_ex(m_stream.Context(), nullptr, digest_name.c_str(), nullptr, nullptr, key, nullptr) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeVerifyContext: EVP_DigestVerifyInit_ex failed for "
                                   << m_algorithm;
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    m_buffer.clear();
    // AUTO accepts any legal salt length recovered from the signature, instead of
    // requiring it to match this provider's own (fixed) signing default.
    auto configured = signature::ConfigureRsaPssContext(
        m_stream.Context(), std::string_view{m_algorithm.data(), m_algorithm.size()}, RSA_PSS_SALTLEN_AUTO);
    if (!configured.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeVerifyContext: RSA-PSS context configuration failed for "
                                   << m_algorithm;
        return configured;
    }
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "UpdateVerify: verification stream is not initialized";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    if (m_prehashed)
    {
        if (m_digest_size == 0U || m_buffer.size() > m_digest_size || data.size() > m_digest_size - m_buffer.size())
        {
            score::mw::log::LogError() << kLogPrefix << "UpdateVerify: prehashed input exceeds digest size for "
                                       << m_algorithm << "; buffered=" << m_buffer.size() << ", chunk=" << data.size();
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        m_buffer.insert(m_buffer.end(), data.begin(), data.end());
        return std::monostate{};
    }
    if (EVP_DigestVerifyUpdate(m_stream.Context(), data.data(), data.size()) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "UpdateVerify: EVP_DigestVerifyUpdate failed for " << m_algorithm;
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssVerifyHandler::CheckSignature(
    score::cpp::span<const std::uint8_t> signature) const
{
    if (signature.size() != GetSignatureSize())
    {
        score::mw::log::LogError() << kLogPrefix << "CheckSignature: signature has " << signature.size()
                                   << " bytes; expected " << GetSignatureSize();
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    return std::monostate{};
}

Expected<bool, DaemonErrorCode> OpenSslRsaPssVerifyHandler::FinalizeVerify(
    score::cpp::span<const std::uint8_t> signature)
{
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
    {
        return make_unexpected(checked.error());
    }
    if (m_prehashed)
    {
        if (m_digest_size == 0U || m_buffer.size() != m_digest_size)
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: prehashed input has " << m_buffer.size()
                                       << " bytes; expected " << m_digest_size;
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
        const bool configured = pctx != nullptr && EVP_PKEY_verify_init(pctx) == 1 &&
                                signature::ConfigureRsaPssPkeyContext(pctx, digest, RSA_PSS_SALTLEN_AUTO) &&
                                EVP_PKEY_CTX_set_signature_md(pctx, digest) == 1;
        const int verify_result =
            configured ? EVP_PKEY_verify(pctx, signature.data(), signature.size(), m_buffer.data(), m_buffer.size())
                       : -1;
        if (pctx != nullptr)
        {
            EVP_PKEY_CTX_free(pctx);
        }
        m_state = StreamOperationState::IDLE;
        m_buffer.clear();
        if (verify_result == 1)
        {
            return true;
        }
        if (verify_result == 0)
        {
            return false;
        }
        if (!configured)
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: failed to configure prehashed RSA-PSS "
                                       << "verification for " << m_algorithm;
        }
        else
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: EVP_PKEY_verify failed for " << m_algorithm;
        }
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    const int result = EVP_DigestVerifyFinal(m_stream.Context(), signature.data(), signature.size());
    m_state = StreamOperationState::IDLE;
    m_buffer.clear();
    if (result == 1)
    {
        return true;
    }
    if (result == 0)
    {
        return false;
    }
    score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: OpenSSL verification failed for " << m_algorithm;
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}

Expected<bool, DaemonErrorCode> OpenSslRsaPssVerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
    {
        return make_unexpected(checked.error());
    }
    auto initialized = InitializeVerifyContext();
    if (!initialized.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: verification initialization failed";
        return make_unexpected(initialized.error());
    }
    if (m_prehashed)
    {
        if (m_digest_size == 0U || data.size() != m_digest_size)
        {
            score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: prehashed input has " << data.size()
                                       << " bytes; expected " << m_digest_size;
            m_state = StreamOperationState::IDLE;
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        m_buffer.assign(data.begin(), data.end());
        return FinalizeVerify(signature);
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
    score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: EVP_DigestVerify failed for " << m_algorithm;
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
