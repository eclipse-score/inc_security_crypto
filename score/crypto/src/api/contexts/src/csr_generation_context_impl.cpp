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

#include "score/crypto/src/api/contexts/src/csr_generation_context_impl.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"

#include <algorithm>
#include <utility>

namespace score::crypto
{
namespace
{
namespace proto = daemon::control_plane::protocol;
namespace csr_operations = daemon::provider::handler::csr_handler_operations;
const daemon::common::OperationIdentifier kGenerate{daemon::common::actors::OP_ACTOR_CSR_HANDLER,
                                                    csr_operations::CSR_GENERATE_NATIVE};

class CsrExport final : public ICsrExport
{
  public:
    CsrExport(std::vector<uint8_t> der, std::string url) : der_{std::move(der)}, url_{std::move(url)} {}
    std::size_t GetEncodedCsrLength() const noexcept override
    {
        return der_.size();
    }
    score::Result<std::size_t> GetEncodedCsr(score::cpp::span<uint8_t> output) const override
    {
        if (output.size() < der_.size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kInsufficientBufferSize, "CSR buffer too small")};
        }
        std::copy(der_.begin(), der_.end(), output.begin());
        return der_.size();
    }
    std::string_view GetSubmissionUrl() const noexcept override
    {
        return url_;
    }

  private:
    std::vector<uint8_t> der_;
    std::string url_;
};
}  // namespace

CsrGenerationContextImpl::CsrGenerationContextImpl(std::shared_ptr<api::control_plane::IConnection> connection,
                                                   uint64_t context_id,
                                                   const CsrGenerationContextConfig& config,
                                                   std::shared_ptr<IBufferTranscoder> transcoder)
    : connection_{std::move(connection)},
      context_id_{context_id},
      config_{config},
      transcoder_{std::move(transcoder)},
      processing_{connection_, transcoder_}
{
}

CsrGenerationContextImpl::~CsrGenerationContextImpl()
{
    if (connection_ && context_id_ != 0U)
    {
        auto close = proto::ControlRequestBuilder()
                         .forDataNodeId(context_id_)
                         .operation(daemon::mediator::operations::CloseContext())
                         .build();
        if (close.has_value())
        {
            static_cast<void>(connection_->SendRequest(close.value()));
        }
    }
}

score::Result<std::monostate> CsrGenerationContextImpl::Commit(CsrRequest candidate)
{
    // Validate setters before a subject is supplied without committing a dummy subject.
    auto validation = candidate;
    if (validation.subject.Attributes().empty())
    {
        auto added = validation.subject.Add(processing_, CsrOid::kCommonName, "validation");
        if (!added.has_value())
        {
            return score::Unexpected{added.error()};
        }
    }
    auto valid = validation.Validate(processing_);
    if (!valid.has_value())
    {
        return score::Unexpected{valid.error()};
    }
    request_ = std::move(candidate);
    return std::monostate{};
}

score::Result<std::monostate> CsrGenerationContextImpl::SetSubject(const CsrSubject& subject)
{
    if (subject.Attributes().empty())
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "CSR subject is empty")};
    }
    auto candidate = request_;
    candidate.subject = subject;
    return Commit(std::move(candidate));
}

score::Result<std::monostate> CsrGenerationContextImpl::SetSubjectDn(std::string_view dn)
{
    auto subject = CsrSubject::FromDn(processing_, dn);
    if (!subject.has_value())
    {
        return score::Unexpected{subject.error()};
    }
    return SetSubject(subject.value());
}

score::Result<std::monostate> CsrGenerationContextImpl::AddExtension(const CsrExtension& extension)
{
    auto candidate = request_;
    candidate.extensions.push_back(extension);
    return Commit(std::move(candidate));
}

score::Result<std::monostate> CsrGenerationContextImpl::AddSubjectAltName(std::string_view san)
{
    auto names = sans_;
    names.emplace_back(san);
    score::crypto::csr::wire::Document input;
    input.action = score::crypto::csr::wire::Action::SanText;
    for (const auto& name : names)
    {
        auto entry = std::make_unique<score::crypto::csr::wire::fb::EntryT>();
        entry->value = name;
        input.names.push_back(std::move(entry));
    }
    auto response = processing_.Process(input);
    if (!response.has_value())
    {
        return score::Unexpected{response.error()};
    }
    const auto& value = *response->extensions.front();
    const CsrExtension extension{value.oid, value.critical, value.value};
    auto candidate = request_;
    if (!sans_.empty())
    {
        for (auto& existing : candidate.extensions)
        {
            if (existing.oid == extension.oid)
            {
                existing = extension;
            }
        }
    }
    else
    {
        candidate.extensions.push_back(extension);
    }
    auto committed = Commit(std::move(candidate));
    if (committed.has_value())
    {
        sans_ = std::move(names);
    }
    return committed;
}

score::Result<std::monostate> CsrGenerationContextImpl::SetChallengePassword(std::string_view password)
{
    auto candidate = request_;
    candidate.challenge_password = password;
    return Commit(std::move(candidate));
}

score::Result<std::monostate> CsrGenerationContextImpl::SetSubjectKey(const CryptoResourceId& key)
{
    if (key != config_.key)
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kInvalidOperation, "CSR key is bound at creation")};
    }
    return std::monostate{};
}

score::Result<std::monostate> CsrGenerationContextImpl::SetSignatureAlgorithm(const AlgorithmId& algorithm)
{
    if (algorithm.truncated() || algorithm != config_.algorithm)
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kInvalidOperation, "CSR algorithm is bound at creation")};
    }
    return std::monostate{};
}

score::Result<ICsrExport::Uptr> CsrGenerationContextImpl::Generate()
{
    if (!connection_ || !transcoder_ || context_id_ == 0U)
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kInvalidOperation, "CSR context unavailable")};
    }
    if (request_.subject.Attributes().empty())
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "CSR subject is empty")};
    }
    // No DN/OID/UTF-8/ASN.1 processing and no SPKI retry occurs here. The
    // immutable keyed daemon context receives neutral, versioned input.
    auto encoded = score::crypto::csr::wire::Encode(
        score::crypto::csr::wire::Request(score::crypto::csr::wire::Action::Generate, request_));
    if (!encoded.has_value())
    {
        return score::Unexpected{encoded.error()};
    }
    auto input = transcoder_->AcquireInputShm(encoded.value());
    if (!input.has_value())
    {
        return score::Unexpected{input.error()};
    }
    // Reserve output before sending: DER travels through the data plane, while
    // the control response carries only the written byte count. Keep both
    // tokens alive until output extraction completes.
    std::vector<uint8_t> der(csr_operations::kMaxDerBytes);
    auto output = transcoder_->Acquire(der, /*is_output=*/true);
    if (!output.has_value())
    {
        return score::Unexpected{output.error()};
    }
    proto::OperationRequestBuilder builder;
    builder.operation(kGenerate);
    transcoder_->AppendInputBuffer(builder, input.value());
    transcoder_->AppendOutputBuffer(builder, output.value());
    auto operation = builder.build();
    if (!operation.has_value())
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "Cannot build CSR request")};
    }
    proto::ControlRequest control{};
    control.data_node_id = context_id_;
    control.operation = std::move(operation.value());
    auto response = connection_->SendRequest(control);
    if (!response.has_value())
    {
        return score::Unexpected{MakeError(response.error(), "CSR transport failed")};
    }
    auto validator = proto::ControlResponseValidator::FromResult(response);
    validator.expectOperation(kGenerate).expectSuccess();
    if (!validator.isValid())
    {
        return score::Unexpected{MakeError(validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed),
                                           "CSR daemon response invalid")};
    }
    if (response->operation.operations.size() != 1U || response->operation.operations[0].parameters.size() != 1U)
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "CSR response shape invalid")};
    }
    if (output->kind() != TranscoderSpan::Kind::kInBand)
    {
        // Bound the wire count before size_t conversion or any SHM-to-caller
        // copy, including on platforms where size_t is narrower than uint64_t.
        const auto count = validator.getParameterAt<uint64_t>(0U, 0U);
        if (!count.has_value() || count.value() == 0U || count.value() > der.size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "CSR byte count invalid")};
        }
    }
    else
    {
        const auto data = validator.getParameterAt<daemon::common::OwnedBuffer>(0U, 0U);
        if (!data.has_value() || data->empty() || data->size() > der.size())
        {
            return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "CSR inline response size invalid")};
        }
    }
    auto written = transcoder_->ExtractOutputBuffer(output.value(), validator);
    if (!written.has_value())
    {
        return score::Unexpected{written.error()};
    }
    if (written.value() == 0U || written.value() > der.size())
    {
        return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "CSR DER response invalid")};
    }
    der.resize(written.value());
    return std::make_unique<CsrExport>(std::move(der), config_.submission_url);
}
}  // namespace score::crypto
