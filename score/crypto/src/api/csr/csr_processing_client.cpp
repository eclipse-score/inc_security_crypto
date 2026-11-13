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

#include "score/crypto/src/api/csr/csr_processing_client.hpp"

#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"

namespace score::crypto
{
score::Result<csr::wire::Document> CsrProcessingClient::Process(const csr::wire::Document& input)
{
    namespace proto = daemon::control_plane::protocol;
    const auto failed = [] {
        return score::Unexpected{MakeError(CryptoErrorCode::kOperationFailed, "Invalid CSR processing response")};
    };
    if (!connection_ || !transcoder_ || connection_->GetConnectionNodeId() == 0U ||
        input.action == csr::wire::Action::Generate)
    {
        return score::Unexpected{
            MakeError(CryptoErrorCode::kInvalidOperation, "CSR processing connection unavailable")};
    }
    auto encoded = csr::wire::Encode(input);
    if (!encoded.has_value())
    {
        return score::Unexpected{encoded.error()};
    }
    auto source = transcoder_->AcquireInputShm(encoded.value());
    if (!source.has_value())
    {
        return score::Unexpected{source.error()};
    }
    std::vector<uint8_t> bytes(csr::wire::kMaxWireBytes);
    auto output = transcoder_->Acquire(bytes, true);
    if (!output.has_value())
    {
        return score::Unexpected{output.error()};
    }
    const auto operation_id = daemon::mediator::operations::ProcessCsr();
    proto::OperationRequestBuilder builder;
    builder.operation(operation_id);
    transcoder_->AppendInputBuffer(builder, source.value());
    transcoder_->AppendOutputBuffer(builder, output.value());
    auto operation = builder.build();
    if (!operation.has_value())
    {
        return failed();
    }
    proto::ControlRequest control{};
    control.data_node_id = connection_->GetConnectionNodeId();
    control.operation = std::move(operation.value());
    auto response = connection_->SendRequest(control);
    if (!response.has_value())
    {
        return score::Unexpected{MakeError(response.error(), "CSR processing transport failed")};
    }
    auto validator = proto::ControlResponseValidator::FromResult(response);
    validator.expectOperation(operation_id).expectSuccess();
    if (!validator.isValid())
    {
        return score::Unexpected{MakeError(validator.getOperationError().value_or(CryptoErrorCode::kOperationFailed),
                                           "CSR processing daemon failure")};
    }
    if (response->operation.operations.size() != 1U || response->operation.operations[0].parameters.size() != 1U)
    {
        return failed();
    }
    if (output->kind() != TranscoderSpan::Kind::kInBand)
    {
        const auto count = validator.getParameterAt<uint64_t>(0U, 0U);
        if (!count.has_value() || count.value() == 0U || count.value() > bytes.size())
        {
            return failed();
        }
    }
    else
    {
        const auto data = validator.getParameterAt<daemon::common::OwnedBuffer>(0U, 0U);
        if (!data.has_value() || data->empty() || data->size() > bytes.size())
        {
            return failed();
        }
    }
    auto written = transcoder_->ExtractOutputBuffer(output.value(), validator);
    if (!written.has_value())
    {
        return score::Unexpected{written.error()};
    }
    if (written.value() == 0U || written.value() > bytes.size())
    {
        return failed();
    }
    bytes.resize(written.value());
    auto result = csr::wire::Decode(bytes);
    if (!result.has_value() || result->action != input.action || !csr::wire::ResponseShape(result.value()))
    {
        return failed();
    }
    if (input.action == csr::wire::Action::Add && result->subject.size() != input.subject.size() + 1U)
    {
        return failed();
    }
    return result;
}
}  // namespace score::crypto
