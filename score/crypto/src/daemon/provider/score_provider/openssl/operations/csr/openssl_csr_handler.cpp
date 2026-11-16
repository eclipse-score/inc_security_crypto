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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/openssl_csr_handler.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/csr_der.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/csr/csr_processing.hpp"

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
namespace
{
using common::DaemonErrorCode;
namespace csr = ::score::crypto::daemon::provider::handler::csr_handler_operations;
namespace utils = ::score::crypto::daemon::provider::handler::handler_utils;
namespace detail = ::score::crypto::daemon::provider::openssl::detail;

// Source count validation adapted to accept the optional output span.
Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ValidateParameterCount(
    const common::RequestParameters& parameters,
    const std::size_t minimum_count,
    const std::size_t maximum_count) noexcept
{
    if (parameters.size() < minimum_count)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }
    if (parameters.size() > maximum_count)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }
    return std::monostate{};
}
}  // namespace

OpenSslCsrHandler::OpenSslCsrHandler(const AlgorithmDescriptor& algorithm) : m_algorithm{algorithm} {}

bool OpenSslCsrHandler::IsAlgorithmSupported(const AlgorithmDescriptor& algorithm) noexcept
{
    return detail::IsSignatureSupported(algorithm);
}

Expected<std::monostate, DaemonErrorCode> OpenSslCsrHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& params)
{
    m_initialized = false;
    if (!IsAlgorithmSupported(m_algorithm))
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }
    // Defense in depth for direct provider callers; the mediator enforces this
    // same permission before binding the handle to the context.
    if (params.bound_key_handler == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    if (!score::crypto::HasPermission(params.bound_key_handler->GetHandle().permissions,
                                      score::crypto::KeyOperationPermission::kSign))
    {
        return make_unexpected(DaemonErrorCode::kKeyOperationNotPermitted);
    }
    if (params.context_creation_params.size() > common::kSignatureInputModeParamIndex &&
        !std::holds_alternative<common::NoParam>(params.context_creation_params[common::kSignatureInputModeParamIndex]))
    {
        const auto mode = common::ParseInputMode(params.context_creation_params);
        if (!mode.has_value() || mode.value() != score::crypto::SignatureInputMode::kMessage)
        {
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
    }
    // Do not retain borrowed CTX_CREATE string/span parameters. Stream only
    // needs the bound key and numeric identifiers after initialization.
    auto binding = params;
    binding.context_creation_params.clear();
    auto bound = m_stream.Bind(binding, m_algorithm);
    m_initialized = bound.has_value();
    return bound;
}

Expected<std::monostate, DaemonErrorCode> OpenSslCsrHandler::Reset()
{
    return m_initialized
               ? m_stream.Restart()
               : Expected<std::monostate, DaemonErrorCode>{make_unexpected(DaemonErrorCode::kInvalidArgument)};
}

Expected<common::ResponseParameters, DaemonErrorCode> OpenSslCsrHandler::Execute(
    const common::OperationIdentifier& operation,
    common::RequestParameters& request)
{
    if (operation.operationActor != common::actors::OP_ACTOR_CSR_HANDLER ||
        (operation.operationAction != csr::CSR_GENERATE && operation.operationAction != csr::CSR_PUBLIC_KEY_INFO &&
         operation.operationAction != csr::CSR_GENERATE_NATIVE))
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }
    if (operation.operationAction == csr::CSR_PUBLIC_KEY_INFO)
    {
        const auto count = ValidateParameterCount(request, 0U, 1U);
        if (!count.has_value())
        {
            return make_unexpected(count.error());
        }
        score::cpp::span<std::uint8_t> output{};
        const bool has_output = request.size() == 1U;
        if (has_output)
        {
            const auto span = utils::CheckAndGetSpan<std::uint8_t>(request[0]);
            if (!span.has_value())
            {
                return make_unexpected(span.error());
            }
            output = span.value();
        }
        if (!m_initialized || m_stream.Key() == nullptr)
        {
            return make_unexpected(DaemonErrorCode::kInvalidArgument);
        }
        // SubjectPublicKeyInfo only: never encode private material or rebind
        // the key from this sign-authorized context.
        const int size = i2d_PUBKEY(m_stream.Key(), nullptr);
        if (size <= 0)
        {
            return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
        }
        if (static_cast<std::size_t>(size) > csr::kMaxDerBytes ||
            (has_output && static_cast<std::size_t>(size) > output.size()))
        {
            return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
        }
        common::OwnedBuffer der(static_cast<std::size_t>(size));
        auto* cursor = der.data();
        if (i2d_PUBKEY(m_stream.Key(), &cursor) != size || cursor != der.data() + der.size())
        {
            return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
        }
        common::ResponseParameters response;
        if (has_output)
        {
            // Finish response allocation before touching the caller's buffer.
            response.emplace_back(static_cast<std::uint64_t>(der.size()));
            std::copy(der.begin(), der.end(), output.begin());
        }
        else
        {
            response.emplace_back(std::move(der));
        }
        return response;
    }
    // Optional output SHM is resolved to a writable span before dispatch.
    // Direct callers may omit it, but both forms accept only DER parameters.
    const auto count = ValidateParameterCount(request, 1U, 2U);
    if (!count.has_value())
    {
        return make_unexpected(count.error());
    }
    const auto input = utils::CheckAndGetSpan<const std::uint8_t>(request[0]);
    if (!input.has_value())
    {
        return make_unexpected(input.error());
    }
    score::cpp::span<std::uint8_t> output{};
    const bool has_output = request.size() == 2U;
    if (has_output)
    {
        const auto span = utils::CheckAndGetSpan<std::uint8_t>(request[1]);
        if (!span.has_value())
        {
            return make_unexpected(span.error());
        }
        output = span.value();
    }
    const bool native = operation.operationAction == csr::CSR_GENERATE_NATIVE;
    if (input->size() > (native ? score::crypto::csr::wire::kMaxWireBytes : csr::kMaxInputDerBytes))
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    if (!m_initialized || m_stream.Key() == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidArgument);
    }
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{X509_REQ_new(), X509_REQ_free};
    if (!req)
    {
        return make_unexpected(DaemonErrorCode::kAllocationFailed);
    }
    if (X509_REQ_set_version(req.get(), 0L) != 1 || X509_REQ_set_pubkey(req.get(), m_stream.Key()) != 1)
    {
        return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
    }
    const auto populate = [&]() -> score::Result<std::monostate> {
        if (!native)
        {
            return score::crypto::csr::der::PopulateRequest(req.get(), input.value());
        }
        auto document = score::crypto::csr::wire::Decode(input.value());
        if (!document.has_value())
        {
            return score::Unexpected{document.error()};
        }
        auto request = NativeCsrProcessing::GenerationRequest(document.value());
        if (!request.has_value())
        {
            return score::Unexpected{request.error()};
        }
        // Reuse the tested encoder/decoder and all raw-octet semantics. Public
        // context is derived ONLY from the already authorized bound key; it
        // never crosses IPC and cannot be supplied by this wire operation.
        const int size = i2d_PUBKEY(m_stream.Key(), nullptr);
        if (size <= 0 || static_cast<std::size_t>(size) > csr::kMaxInputDerBytes)
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid bound CSR public key")};
        }
        std::vector<uint8_t> spki(static_cast<std::size_t>(size));
        auto* cursor = spki.data();
        if (i2d_PUBKEY(m_stream.Key(), &cursor) != size || cursor != spki.data() + spki.size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid bound CSR public key")};
        }
        auto parameters = NativeCsrProcessing::ToDer(request.value(), spki);
        if (!parameters.has_value())
        {
            return score::Unexpected{parameters.error()};
        }
        return score::crypto::csr::der::PopulateRequest(req.get(), parameters.value());
    };
    const auto populated = populate();
    if (!populated.has_value())
    {
        const auto error = *populated.error();
        return make_unexpected(
            error == static_cast<score::result::ErrorCode>(score::crypto::CryptoErrorCode::kAllocationFailed)
                ? DaemonErrorCode::kAllocationFailed
                : DaemonErrorCode::kInvalidArgument);
    }
    const auto restarted = m_stream.Restart();
    if (!restarted.has_value())
    {
        return make_unexpected(restarted.error());
    }
    const auto* digest = detail::ToEvpMd(m_algorithm.hash);
    const auto* digest_name = digest == nullptr ? nullptr : EVP_MD_get0_name(digest);
    if (EVP_DigestSignInit_ex(m_stream.Context(), nullptr, digest_name, nullptr, nullptr, m_stream.Key(), nullptr) != 1)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    if (m_algorithm.key_type == KeyType::kRsa)
    {
        const auto configured =
            signature::ConfigureRsaPssContext(m_stream.Context(), m_algorithm, RSA_PSS_SALTLEN_DIGEST);
        if (!configured.has_value())
        {
            return make_unexpected(configured.error());
        }
    }
    // X509_REQ_sign_ctx writes the correct AlgorithmIdentifier, including PSS
    // parameters and DER ECDSA signatures (not the raw P1363 sign API format).
    if (X509_REQ_sign_ctx(req.get(), m_stream.Context()) <= 0 ||
        X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())) != 1)
    {
        return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
    }
    const int size = i2d_X509_REQ(req.get(), nullptr);
    if (size <= 0)
    {
        return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
    }
    if (static_cast<std::size_t>(size) > csr::kMaxDerBytes ||
        (has_output && static_cast<std::size_t>(size) > output.size()))
    {
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }
    common::OwnedBuffer der(static_cast<std::size_t>(size));
    auto* cursor = der.data();
    if (i2d_X509_REQ(req.get(), &cursor) != size)
    {
        return make_unexpected(DaemonErrorCode::kCsrGenerationFailed);
    }
    common::ResponseParameters response;
    if (has_output)
    {
        response.emplace_back(static_cast<std::uint64_t>(der.size()));
        std::copy(der.begin(), der.end(), output.begin());
    }
    else
    {
        response.emplace_back(std::move(der));
    }
    return response;
}
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
