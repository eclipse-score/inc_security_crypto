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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/sign/openssl_rsa_pss_ed25519_sign_handler.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/mw/log/logging.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace algo = ::score::crypto::daemon::common;
using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::common::StreamOperationState;

OpenSslRsaPssEd25519SignHandler::OpenSslRsaPssEd25519SignHandler(
    std::unique_ptr<operations::sign::SignExecutor> executor,
    const common::AlgorithmId& algorithm)
    : ScoreSignHandler{std::move(executor), algorithm}
{
}
OpenSslRsaPssEd25519SignHandler::~OpenSslRsaPssEd25519SignHandler() = default;

bool OpenSslRsaPssEd25519SignHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view value{algorithm.data(), algorithm.size()};
    return ::score::crypto::daemon::provider::openssl::detail::IsSignatureAlgorithmSupported(value) &&
           (algo::IsRsaPssAlgorithm(value) || algo::IsEd25519Algorithm(value));
}

bool OpenSslRsaPssEd25519SignHandler::IsEd25519() const noexcept
{
    return algo::IsEd25519Algorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    auto base = ScoreSignHandler::InitializeContext(params);
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

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::Reset()
{
    return InitializeContext(m_stream.InitParams());
}

std::size_t OpenSslRsaPssEd25519SignHandler::GetSignatureSize() const noexcept
{
    if (IsEd25519())
        return 64U;
    const auto key = algo::LookupRsaKeyForSignatureAlgorithm(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return key.has_value() ? key->modulus_size : 0U;
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::ConfigureRsaPss()
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
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::InitSign()
{
    auto restarted = m_stream.Restart();
    if (!restarted.has_value())
        return restarted;
    EVP_PKEY* key = m_stream.Key();
    if (key == nullptr)
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    const auto digest = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
    const std::string digest_name_storage = digest.has_value() ? std::string{digest.value()} : std::string{};
    const char* digest_name = IsEd25519() ? nullptr : digest_name_storage.c_str();
    if (m_prehashed)
    {
        m_buffer.clear();
        return std::monostate{};
    }
    if (EVP_DigestSignInit_ex(m_stream.Context(), nullptr, digest_name, nullptr, nullptr, key, nullptr) != 1)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    m_buffer.clear();
    return ConfigureRsaPss();
}

Expected<std::monostate, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::UpdateSign(
    score::cpp::span<const std::uint8_t> data)
{
    if (m_stream.Context() == nullptr)
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    if (IsEd25519() || m_prehashed)
    {
        m_buffer.insert(m_buffer.end(), data.begin(), data.end());
        return std::monostate{};
    }
    if (EVP_DigestSignUpdate(m_stream.Context(), data.data(), data.size()) != 1)
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    return std::monostate{};
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::ResolveBuffer(
    score::cpp::span<std::uint8_t> output) const
{
    const auto size = GetSignatureSize();
    if (size == 0U)
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    if (output.size() < size)
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    return size;
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::FinalizeSign(
    score::cpp::span<std::uint8_t> output)
{
    auto size = ResolveBuffer(output);
    if (!size.has_value())
        return make_unexpected(size.error());
    std::size_t written = size.value();
    int ok = 0;
    if (m_prehashed)
    {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(m_stream.Key(), nullptr);
        const auto digest_name = algo::LookupSignatureDigest(std::string_view{m_algorithm.data(), m_algorithm.size()});
        const EVP_MD* digest =
            digest_name.has_value()
                ? ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(digest_name.value())
                : nullptr;
        const bool configured = pctx != nullptr && digest != nullptr && EVP_PKEY_sign_init(pctx) == 1 &&
                                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                                EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1 &&
                                EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, digest) == 1 &&
                                EVP_PKEY_CTX_set_signature_md(pctx, digest) == 1;
        std::size_t written = output.size();
        const int ok = configured ? EVP_PKEY_sign(pctx, output.data(), &written, m_buffer.data(), m_buffer.size()) : 0;
        if (pctx != nullptr)
            EVP_PKEY_CTX_free(pctx);
        m_state = StreamOperationState::IDLE;
        m_buffer.clear();
        return ok == 1 ? Expected<std::size_t, DaemonErrorCode>{written}
                       : Expected<std::size_t, DaemonErrorCode>{
                             make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
    }
    if (IsEd25519())
    {
        ok = EVP_DigestSign(m_stream.Context(), output.data(), &written, m_buffer.data(), m_buffer.size());
    }
    else
    {
        ok = EVP_DigestSignFinal(m_stream.Context(), output.data(), &written);
    }
    m_state = StreamOperationState::IDLE;
    m_buffer.clear();
    return ok == 1
               ? Expected<std::size_t, DaemonErrorCode>{written}
               : Expected<std::size_t, DaemonErrorCode>{make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
}

Expected<std::size_t, DaemonErrorCode> OpenSslRsaPssEd25519SignHandler::SingleShotSign(
    score::cpp::span<const std::uint8_t> data,
    score::cpp::span<std::uint8_t> output)
{
    auto size = ResolveBuffer(output);
    if (!size.has_value())
        return make_unexpected(size.error());
    auto initialized = InitSign();
    if (!initialized.has_value())
        return make_unexpected(initialized.error());
    if (m_prehashed)
    {
        m_buffer.assign(data.begin(), data.end());
        return FinalizeSign(output);
    }
    std::size_t written = size.value();
    const int ok = EVP_DigestSign(m_stream.Context(), output.data(), &written, data.data(), data.size());
    m_state = StreamOperationState::IDLE;
    return ok == 1
               ? Expected<std::size_t, DaemonErrorCode>{written}
               : Expected<std::size_t, DaemonErrorCode>{make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed)};
}
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
