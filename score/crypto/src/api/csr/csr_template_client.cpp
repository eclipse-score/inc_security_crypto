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

#include "score/crypto/src/api/contexts/i_csr_generation_context.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"

namespace score::crypto
{
namespace wire = csr::wire;
score::Result<CsrTemplate> DerCsrTemplateStorage::Load(std::string_view id) const
{
    wire::Document input;
    input.action = wire::Action::Load;
    input.id = id;
    input.bytes = document_;
    auto result = processing_.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return wire::ReadTemplate(result.value());
}
score::Result<std::vector<uint8_t>> DerCsrTemplateStorage::Save(ICsrProcessingService& processing,
                                                                const CsrTemplate& value)
{
    auto result = processing.Process(wire::Template(wire::Action::Save, value));
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return std::move(result->bytes);
}
score::Result<PreparedCsrTemplate> CsrTemplateProcessor::Prepare(ICsrProcessingService& processing,
                                                                 const CsrTemplate& value,
                                                                 const CsrRuntimeValues& runtime,
                                                                 const CsrAttributeRequirements& requirements)
{
    auto input = wire::Template(wire::Action::Prepare, value);
    for (const auto& item : runtime)
    {
        auto entry = std::make_unique<wire::fb::EntryT>();
        entry->oid = item.first;
        entry->value = item.second;
        input.runtime.push_back(std::move(entry));
    }
    input.required_subject = requirements.subject_oids;
    input.required_issuer = requirements.issuer_oids;
    auto result = processing.Process(input);
    if (!result.has_value())
    {
        return score::Unexpected{result.error()};
    }
    return wire::ReadPrepared(result.value());
}
score::Result<CsrTemplateOutput> CsrTemplateProcessor::Generate(ICsrProcessingService& processing,
                                                                const PreparedCsrTemplate& value,
                                                                ICryptoContext& crypto,
                                                                ICsrKeyResolver& keys)
{
    // Remote validation precedes key resolution, including caller-built
    // prepared values. The key resolver remains application-owned and ordered.
    auto valid = processing.Process(wire::Prepared(wire::Action::ValidatePrepared, value));
    if (!valid.has_value())
    {
        return score::Unexpected{valid.error()};
    }
    auto key = keys.ResolveSigningKey(value.key_resource);
    if (!key.has_value())
    {
        return score::Unexpected{key.error()};
    }
    CsrGenerationContextConfig config;
    config.SetKey(key.value()).SetAlgorithm(value.algorithm).SetSubmissionUrl(value.submission_url);
    auto context = crypto.CreateCsrGenerationContext(config);
    if (!context.has_value())
    {
        return score::Unexpected{context.error()};
    }
    auto configured = context.value()->SetSubject(value.request.subject);
    if (!configured.has_value())
    {
        return score::Unexpected{configured.error()};
    }
    for (const auto& extension : value.request.extensions)
    {
        configured = context.value()->AddExtension(extension);
        if (!configured.has_value())
        {
            return score::Unexpected{configured.error()};
        }
    }
    configured = context.value()->SetChallengePassword(value.request.challenge_password);
    if (!configured.has_value())
    {
        return score::Unexpected{configured.error()};
    }
    auto csr = context.value()->Generate();
    if (!csr.has_value())
    {
        return score::Unexpected{csr.error()};
    }
    return CsrTemplateOutput{value.id, value.issuer, std::move(csr.value())};
}
std::vector<score::Result<CsrTemplateOutput>> CsrTemplateProcessor::GenerateBatch(
    ICsrProcessingService& processing,
    const std::vector<PreparedCsrTemplate>& values,
    ICryptoContext& crypto,
    ICsrKeyResolver& keys)
{
    std::vector<score::Result<CsrTemplateOutput>> output;
    output.reserve(values.size());
    for (const auto& value : values)
    {
        output.push_back(Generate(processing, value, crypto, keys));
    }
    return output;
}
}  // namespace score::crypto
