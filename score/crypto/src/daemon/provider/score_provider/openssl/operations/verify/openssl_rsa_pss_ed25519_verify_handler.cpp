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
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string>
#include <utility>
namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
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
    m_prehashed = ecdsa::IsPrehashed(params);
    if (m_prehashed && IsEd25519())
        return make_unexpected(DaemonErrorCode::kUnsupportedOperation);
    auto bound = m_stream.BindAny(params);
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
        return 64U;
    const auto key = algo::LookupRsaKeyForSignatureAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return key.has_value() ? key->modulus_size : 0U;
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::ConfigureRsaPss()
{
    if (IsEd25519())
        return std::monostate{};
    EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(m_stream.Context());
    const auto digest = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    const EVP_MD* md = digest.has_value()
                           ? ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(digest.value())
                           : nullptr;
    if (pctx == nullptr || md == nullptr || EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) != 1)
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    return std::monostate{};
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::InitVerify()
{
    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
        return restarted;
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
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
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    m_buffer.clear();
    return ConfigureRsaPss();
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::UpdateVerify(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    if (IsEd25519() || m_prehashed)
    {
        m_buffer.insert(m_buffer.end(), data.begin(), data.end());
        return std::monostate{};
    }
    if (EVP_DigestVerifyUpdate(m_stream.Context(), data.data(), data.size()) != 1)
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    return std::monostate{};
}
Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::CheckSignature(
    score::cpp::span<const std::uint8_t> signature) const
{
    if (signature.size() != GetSignatureSize())
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    return std::monostate{};
}
Expected<bool, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::FinalizeVerify(
    score::cpp::span<const std::uint8_t> signature)
{
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
        return make_unexpected(checked.error());
    const int result =
        m_prehashed ? ([&]() {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(m_stream.Key(), nullptr);
            const auto digest_name =
                algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
            const EVP_MD* digest =
                digest_name.has_value()
                    ? ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(digest_name.value())
                    : nullptr;
            const bool configured = pctx != nullptr && digest != nullptr && EVP_PKEY_verify_init(pctx) == 1 &&
                                    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                                    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1 &&
                                    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, digest) == 1 &&
                                    EVP_PKEY_CTX_set_signature_md(pctx, digest) == 1;
            const int verify_result =
                configured ? EVP_PKEY_verify(pctx, signature.data(), signature.size(), m_buffer.data(), m_buffer.size())
                           : -1;
            if (pctx != nullptr)
                EVP_PKEY_CTX_free(pctx);
            return verify_result;
        })()
        : IsEd25519()
            ? EVP_DigestVerify(m_stream.Context(), signature.data(), signature.size(), m_buffer.data(), m_buffer.size())
            : EVP_DigestVerifyFinal(m_stream.Context(), signature.data(), signature.size());
    m_state = StreamOperationState::IDLE;
    m_buffer.clear();
    if (result == 1)
        return true;
    if (result == 0)
        return false;
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}
Expected<bool, DaemonErrorCode> OpenSslRsaPssEd25519VerifyHandler::SingleShotVerify(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<const std::uint8_t> signature)
{
    auto checked = CheckSignature(signature);
    if (!checked.has_value())
        return make_unexpected(checked.error());
    auto initialized = InitVerify();
    if (!initialized.has_value())
        return make_unexpected(initialized.error());
    if (m_prehashed)
    {
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
    return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
}
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
