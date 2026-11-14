/*****************************************************************************
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
 *****************************************************************************/

#include "score/crypto/src/daemon/mediator/src/context_creation_decoder.hpp"

#include "score/crypto/src/daemon/common/context/context_types.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string_view>
#include <utility>

namespace score::crypto::daemon::mediator
{
namespace
{

using CryptoError = score::crypto::CryptoErrorCode;
using common::CryptoProviderType;

control_plane::protocol::SingleOperationRequest MakeOperation(common::RequestParameters parameters)
{
    control_plane::protocol::SingleOperationRequest operation{};
    operation.parameters = std::move(parameters);
    return operation;
}

// Wire contract, see mediator_operations.hpp CTX_PARAM_*:
//   [0] context type, [1] algorithm, [2] provider preference, [3] key node id.

TEST(ContextCreationDecoderTest, RejectsFewerThanTwoParameters)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects fewer than two parameters.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{std::string_view{"HASH"}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kInvalidArgument);
}

TEST(ContextCreationDecoderTest, RejectsNonStringContextType)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects non string context type.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation =
        MakeOperation(common::RequestParameters{std::uint8_t{1U}, std::string_view{"ECDSA-P256-SHA384"}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kInvalidArgument);
}

TEST(ContextCreationDecoderTest, RejectsUnknownAlgorithmForAlgorithmBoundContext)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects unknown algorithm for algorithm bound context.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation =
        MakeOperation(common::RequestParameters{std::string_view{"HASH"}, std::string_view{"NOT_AN_ALGORITHM"}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kUnsupportedAlgorithm);
}

TEST(ContextCreationDecoderTest, RejectsUnknownProviderPreferenceValue)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects unknown provider preference value.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kKeyManagement}, std::string_view{""}, std::uint8_t{0xEEU}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kInvalidArgument);
}

TEST(ContextCreationDecoderTest, RejectsZeroKeyNodeId)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects zero key node id.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kRandom}, std::string_view{""}, std::uint8_t{0U}, std::uint64_t{0U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kInvalidArgument);
}

TEST(ContextCreationDecoderTest, RejectsKeyedContextWithoutKeyBeforeCheckingAlgorithm)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Rejects keyed context without key before checking algorithm.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    // The missing key is reported even though the algorithm name is also unresolvable,
    // which pins the check order: key requirement before algorithm resolution.
    const auto operation =
        MakeOperation(common::RequestParameters{std::string_view{common::context_types::kSign}, std::string_view{""}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error(), CryptoError::kInvalidArgument);
}

TEST(ContextCreationDecoderTest, KeyManagementContextTakesNoAlgorithmDescriptor)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Key management context takes no algorithm descriptor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kKeyManagement}, std::string_view{""}, std::uint8_t{0U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().context_type, common::context_types::kKeyManagement);
    EXPECT_FALSE(decoded.value().algorithm_descriptor.has_value());
    EXPECT_FALSE(decoded.value().key_node_id.has_value());
}

TEST(ContextCreationDecoderTest, CertificateManagementContextTakesNoAlgorithmDescriptor)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Certificate management context takes no algorithm descriptor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kCertManagement}, std::string_view{""}, std::uint8_t{0U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().context_type, common::context_types::kCertManagement);
    EXPECT_FALSE(decoded.value().algorithm_descriptor.has_value());
    EXPECT_FALSE(decoded.value().key_node_id.has_value());
}

TEST(ContextCreationDecoderTest, TrustStoreContextTakesNoAlgorithmDescriptor)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Trust store management context takes no algorithm descriptor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kCertTrustStore}, std::string_view{""}, std::uint8_t{0U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().context_type, common::context_types::kCertTrustStore);
    EXPECT_FALSE(decoded.value().algorithm_descriptor.has_value());
    EXPECT_FALSE(decoded.value().key_node_id.has_value());
}

TEST(ContextCreationDecoderTest, VerificationContextTakesNoAlgorithmDescriptor)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Certificate verification context takes no algorithm descriptor.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kCertVerification}, std::string_view{""}, std::uint8_t{0U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().context_type, common::context_types::kCertVerification);
    EXPECT_FALSE(decoded.value().algorithm_descriptor.has_value());
    EXPECT_FALSE(decoded.value().key_node_id.has_value());
}

TEST(ContextCreationDecoderTest, DecodesProviderPreferenceWithFallback)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Decodes provider preference with fallback.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kKeyManagement}, std::string_view{""}, std::uint8_t{3U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().provider_type_preference.primary, CryptoProviderType::HARDWARE);
    ASSERT_TRUE(decoded.value().provider_type_preference.fallback.has_value());
    EXPECT_EQ(decoded.value().provider_type_preference.fallback.value(), CryptoProviderType::SOFTWARE);
}

TEST(ContextCreationDecoderTest, AbsentProviderPreferenceDefaultsToDefaultWithoutFallback)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Absent provider preference defaults to default without fallback.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(
        common::RequestParameters{std::string_view{common::context_types::kKeyManagement}, std::string_view{""}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().provider_type_preference.primary, CryptoProviderType::DEFAULT);
    EXPECT_FALSE(decoded.value().provider_type_preference.fallback.has_value());
}

TEST(ContextCreationDecoderTest, CarriesKeyNodeIdThroughUnchanged)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Carries key node id through unchanged.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(common::RequestParameters{
        std::string_view{common::context_types::kRandom}, std::string_view{""}, std::uint8_t{0U}, std::uint64_t{7U}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(decoded.value().key_node_id.has_value());
    EXPECT_EQ(decoded.value().key_node_id.value(), 7U);
}

TEST(ContextCreationDecoderTest, RandomWithEmptyAlgorithmResolvesToDefaultGenerator)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Random with empty algorithm resolves to default generator.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto operation = MakeOperation(
        common::RequestParameters{std::string_view{common::context_types::kRandom}, std::string_view{""}});

    const auto decoded = DecodeContextCreationRequest(operation);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded.value().algorithm_descriptor.has_value());
    EXPECT_EQ(decoded.value().context_type, common::context_types::kRandom);
}

using ProviderType = common::CryptoProviderType;

TEST(ProviderTypePreferenceDecodeTest, DecodesExactProviderTypesWithoutFallback)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Decodes exact provider types without fallback.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto hardware = DecodeProviderTypePreference(1U);
    ASSERT_TRUE(hardware.has_value());
    EXPECT_EQ(hardware->primary, ProviderType::HARDWARE);
    EXPECT_FALSE(hardware->fallback.has_value());

    const auto software = DecodeProviderTypePreference(2U);
    ASSERT_TRUE(software.has_value());
    EXPECT_EQ(software->primary, ProviderType::SOFTWARE);
    EXPECT_FALSE(software->fallback.has_value());
}

TEST(ProviderTypePreferenceDecodeTest, PreservesPreferredProviderFallbackOrder)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Preserves preferred provider fallback order.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto hardware_preferred = DecodeProviderTypePreference(3U);
    ASSERT_TRUE(hardware_preferred.has_value());
    EXPECT_EQ(hardware_preferred->primary, ProviderType::HARDWARE);
    ASSERT_TRUE(hardware_preferred->fallback.has_value());
    EXPECT_EQ(hardware_preferred->fallback.value(), ProviderType::SOFTWARE);

    const auto software_preferred = DecodeProviderTypePreference(4U);
    ASSERT_TRUE(software_preferred.has_value());
    EXPECT_EQ(software_preferred->primary, ProviderType::SOFTWARE);
    ASSERT_TRUE(software_preferred->fallback.has_value());
    EXPECT_EQ(software_preferred->fallback.value(), ProviderType::HARDWARE);
}

TEST(ProviderTypePreferenceDecodeTest, DecodesDefaultAndRejectsUnknownValues)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__decode_validate");
    RecordProperty("Description", "Decodes default and rejects unknown values.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto default_provider = DecodeProviderTypePreference(0U);
    ASSERT_TRUE(default_provider.has_value());
    EXPECT_EQ(default_provider->primary, ProviderType::DEFAULT);
    EXPECT_FALSE(default_provider->fallback.has_value());

    EXPECT_FALSE(DecodeProviderTypePreference(5U).has_value());
    EXPECT_FALSE(DecodeProviderTypePreference(255U).has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
