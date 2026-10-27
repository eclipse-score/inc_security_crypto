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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/verify/openssl_rsa_pss_ed25519_verify_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/mw/log/logging.h"
#include <openssl/evp.h>
#include <string>
#include <utility>
namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{
constexpr std::string_view kLogPrefix{"[OPENSSL_RSA_ED25519_VERIFY_HANDLER] "};
}

namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;
OpenSslRsaPssEd25519VerifyHandler::OpenSslRsaPssEd25519VerifyHandler(
    std::unique_ptr<operations::verify::VerifyExecutor> executor,
    const common::AlgorithmId& algorithm)
    : ScoreVerifyHandler{std::move(executor), algorithm}
{
}
OpenSslRsaPssEd25519VerifyHandler::~OpenSslRsaPssEd25519VerifyHandler() = default;
bool OpenSslRsaPssEd25519VerifyHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           (algo::IsRsaPssAlgorithm(value) || algo::IsEd25519Algorithm(value));
}
bool OpenSslRsaPssEd25519VerifyHandler::IsEd25519() const noexcept
{
    return algo::IsEd25519Algorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    auto base = ScoreVerifyHandler::InitializeContext(params);
    if (!base.has_value())
        return base;

    const auto input_mode = signature::ParseInputMode(params);
    if (!input_mode.has_value())
        return make_unexpected(input_mode.error());
    m_prehashed = input_mode.value() == ::score::crypto::SignatureInputMode::kPrehashed;

    if (m_prehashed && IsEd25519())
    {
        score::mw::log::LogError() << kLogPrefix << "InitializeContext: prehashed mode is unsupported for Ed25519";
        return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
    }
    auto bound = m_stream.BindAny(params, m_algorithm);
    if (!bound.has_value())
        return bound;
    m_buffer.clear();
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}
std::size_t OpenSslRsaPssEd25519VerifyHandler::GetSignatureSize() const noexcept
{
    if (IsEd25519())
        return algo::kEd25519SignatureSize;
    const auto key =
        algo::LookupRsaKeyInfoForSignatureAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return key.has_value() ? key->modulus_size : 0U;
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::InitVerify()
{
    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "InitVerify: failed to restart verification stream";
        return restarted;
    }
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "InitVerify: no bound key";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    const auto digest = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    std::string digest_name = digest.has_value() ? std::string{digest.value()} : std::string{};
    const char* digest_ptr = IsEd25519() ? nullptr : digest_name.c_str();
    if (m_prehashed)
    {
        m_buffer.clear();
        return std::monostate{};
    }
    if (EVP_DigestVerifyInit_ex(m_stream.Context(), nullptr, digest_ptr, nullptr, nullptr, key, nullptr) != 1)
    {
        score::mw::log::LogError() << kLogPrefix << "InitVerify: EVP_DigestVerifyInit_ex failed for " << m_algorithm;
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    m_buffer.clear();
    if (!IsEd25519())
    {
        // AUTO accepts any legal salt length recovered from the signature, instead of
        // requiring it to match this provider's own (fixed) signing default.
        auto configured = ::score::crypto::daemon::provider::openssl::detail::ConfigureRsaPssContext(
            m_stream.Context(), std::string_view{m_algorithm.data(), m_algorithm.size()}, RSA_PSS_SALTLEN_AUTO);
        if (!configured.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "InitVerify: RSA-PSS context configuration failed for "
                                       << m_algorithm;
            return configured;
        }
    }
    return std::monostate{};
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
    {
        score::mw::log::LogError() << kLogPrefix << "UpdateVerify: verification stream is not initialized";
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || m_buffer.size() > expected_digest_size.value() ||
            data.size() > expected_digest_size.value() - m_buffer.size())
        {
            score::mw::log::LogError() << kLogPrefix << "UpdateVerify: prehashed input exceeds digest size for "
                                       << m_algorithm << "; buffered=" << m_buffer.size() << ", chunk=" << data.size();
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        m_buffer.insert(m_buffer.end(), data.begin(), data.end());
        return std::monostate{};
    }
    if (IsEd25519())
    {
        if (m_buffer.size() > algo::kMaxEd25519MessageSize ||
            data.size() > algo::kMaxEd25519MessageSize - m_buffer.size())
        {
            score::mw::log::LogError() << kLogPrefix << "UpdateVerify: Ed25519 message exceeds configured limit"
                                       << "; buffered=" << m_buffer.size() << ", chunk=" << data.size()
                                       << ", limit=" << algo::kMaxEd25519MessageSize;
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
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::CheckSignature(
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
Expected<bool, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::FinalizeVerify(
    score::cpp::span<const std::uint8_t> signature)
{
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
        return make_unexpected(checked.error());
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || m_buffer.size() != expected_digest_size.value())
        {
            score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: prehashed input has " << m_buffer.size()
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
        const bool configured = pctx != nullptr && EVP_PKEY_verify_init(pctx) == 1 &&
                                ::score::crypto::daemon::provider::openssl::detail::ConfigureRsaPssPkeyContext(
                                    pctx, digest, RSA_PSS_SALTLEN_AUTO) &&
                                EVP_PKEY_CTX_set_signature_md(pctx, digest) == 1;
        const int verify_result =
            configured ? EVP_PKEY_verify(pctx, signature.data(), signature.size(), m_buffer.data(), m_buffer.size())
                       : -1;
        if (pctx != nullptr)
            EVP_PKEY_CTX_free(pctx);
        m_state = StreamOperationState::IDLE;
        m_buffer.clear();
        if (verify_result == 1)
            return true;
        if (verify_result == 0)
            return false;
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
    const int result =
        IsEd25519()
            ? EVP_DigestVerify(m_stream.Context(), signature.data(), signature.size(), m_buffer.data(), m_buffer.size())
            : EVP_DigestVerifyFinal(m_stream.Context(), signature.data(), signature.size());
    m_state = StreamOperationState::IDLE;
    m_buffer.clear();
    if (result == 1)
        return true;
    if (result == 0)
        return false;
    score::mw::log::LogError() << kLogPrefix << "FinalizeVerify: OpenSSL verification failed for " << m_algorithm;
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}
Expected<bool, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    if (IsEd25519() && data.size() > algo::kMaxEd25519MessageSize)
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: Ed25519 message size " << data.size()
                                   << " exceeds configured limit " << algo::kMaxEd25519MessageSize;
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
        return make_unexpected(checked.error());
    auto initialized = InitVerify();
    if (!initialized.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: verification initialization failed";
        return make_unexpected(initialized.error());
    }
    if (m_prehashed)
    {
        const auto expected_digest_size =
            algo::LookupSignatureDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
        if (!expected_digest_size.has_value() || data.size() != expected_digest_size.value())
        {
            score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: prehashed input has " << data.size()
                                       << " bytes; expected "
                                       << (expected_digest_size.has_value() ? expected_digest_size.value() : 0U);
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
        return true;
    if (result == 0)
        return false;
    score::mw::log::LogError() << kLogPrefix << "SingleShotVerify: EVP_DigestVerify failed for " << m_algorithm;
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
