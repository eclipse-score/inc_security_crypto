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

#include "score/crypto/src/daemon/mediator/src/provider_arbiter.hpp"

#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/mediator/context_algorithm.hpp"
#include "score/crypto/src/daemon/mediator/src/mediator_test_doubles.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>

namespace score::crypto::daemon::mediator
{
namespace
{

using common::CryptoProviderType;
using common::ProviderCapability;
using test_doubles::StubProvider;
using CryptoError = score::crypto::CryptoErrorCode;

constexpr std::uint64_t kClient = 7U;

class ProviderArbiterTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Keep provider lookup real; only the providers and their handler factories are stubs.
        m_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
    }

    std::shared_ptr<StubProvider> Register(const std::string& name,
                                           const CryptoProviderType type,
                                           const ProviderCapability capabilities)
    {
        // The manager assigns the stub's provider id when initialized in MakeArbiter().
        auto stub = std::make_shared<StubProvider>(name, capabilities);
        EXPECT_TRUE(m_manager->RegisterProvider(name, stub, type));
        return stub;
    }

    ProviderArbiter MakeArbiter()
    {
        // Initialize only after registration so all stubs receive ids before selection begins.
        m_manager->Initialize();
        return ProviderArbiter{m_manager, nullptr};
    }

    static ProviderSelectionRequest Request(const common::ProviderTypePreference preference,
                                            const ProviderCapability required = ProviderCapability::kNone,
                                            const std::string_view context_type = "HASH")
    {
        ProviderSelectionRequest request{};
        request.client_id = kClient;
        request.context_type = context_type;
        // Supplying an algorithm exercises CreateHandler rather than the key-management factory path.
        request.algorithm = operations::ResolveContextAlgorithm(common::context_types::kHash, "SHA256");
        request.provider = preference;
        request.required_capability = required;
        return request;
    }

    provider::ProviderManager::Sptr m_manager;
};

TEST_F(ProviderArbiterTest, ExplicitProviderTypeSelectsProviderOfThatType)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__arbitration");
    RecordProperty("Description", "An explicit provider type selects the provider registered for that type.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto hardware = Register("HW", CryptoProviderType::HARDWARE, ProviderCapability::kCrypto);
    const auto arbiter = MakeArbiter();

    const auto selected = arbiter.Select(Request({CryptoProviderType::HARDWARE, std::nullopt}));

    ASSERT_TRUE(selected.has_value());
    EXPECT_EQ(selected->provider->GetProviderId(), hardware->GetProviderId());
    EXPECT_FALSE(selected->used_fallback);
    // Factory counters show that only the selected stub provider was asked to create a handler.
    EXPECT_EQ(hardware->Factory()->CreateCalls(), 1);
    EXPECT_EQ(software->Factory()->CreateCalls(), 0);
}

TEST_F(ProviderArbiterTest, DefaultPreferenceSelectsByCapabilityAndPrefersSoftwareForCertificates)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__arbitration");
    RecordProperty("Description",
                   "With the DEFAULT preference a required capability selects the provider by capability, "
                   "software first for certificate management.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto hardware = Register("HW", CryptoProviderType::HARDWARE, ProviderCapability::kCertManagement);
    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCertManagement);
    const auto arbiter = MakeArbiter();

    const auto selected = arbiter.Select(
        Request({CryptoProviderType::DEFAULT, std::nullopt}, ProviderCapability::kCertManagement, "CERT:VERIFICATION"));

    ASSERT_TRUE(selected.has_value());
    EXPECT_EQ(selected->provider->GetProviderId(), software->GetProviderId());
    EXPECT_EQ(hardware->Factory()->CreateCalls(), 0);
}

TEST_F(ProviderArbiterTest, ExplicitProviderTypeIsStillCheckedAgainstTheRequiredCapability)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__arbitration");
    RecordProperty("Description",
                   "An explicit provider type that lacks the required capability is refused as unsupported.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto arbiter = MakeArbiter();

    const auto selected = arbiter.Select(Request(
        {CryptoProviderType::SOFTWARE, std::nullopt}, ProviderCapability::kCertManagement, "CERT:VERIFICATION"));

    ASSERT_FALSE(selected.has_value());
    EXPECT_EQ(selected.error(), CryptoError::kUnsupportedOperation);
    EXPECT_EQ(software->Factory()->CreateCalls(), 0);
}

TEST_F(ProviderArbiterTest, UnregisteredProviderTypeIsNotAvailable)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__arbitration");
    RecordProperty("Description", "A provider type with no registered provider is reported as not available.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto arbiter = MakeArbiter();

    const auto selected = arbiter.Select(Request({CryptoProviderType::HARDWARE, std::nullopt}));

    ASSERT_FALSE(selected.has_value());
    EXPECT_EQ(selected.error(), CryptoError::kProviderNotAvailable);
}

TEST_F(ProviderArbiterTest, FallbackProviderServesTheRequestWhenThePrimaryCannotCreateTheHandler)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__fallback");
    RecordProperty("Description",
                   "A fallback eligible failure of the primary provider moves the request to the fallback provider.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto hardware = Register("HW", CryptoProviderType::HARDWARE, ProviderCapability::kCrypto);
    hardware->Factory()->FailWith(CryptoError::kUnsupportedAlgorithm);
    const auto arbiter = MakeArbiter();

    // The primary stub's factory injects a fallback-eligible error, so arbitration tries software next.
    const auto selected = arbiter.Select(Request({CryptoProviderType::HARDWARE, CryptoProviderType::SOFTWARE}));

    ASSERT_TRUE(selected.has_value());
    EXPECT_EQ(selected->provider->GetProviderId(), software->GetProviderId());
    EXPECT_TRUE(selected->used_fallback);
    EXPECT_EQ(hardware->Factory()->CreateCalls(), 1);
}

TEST_F(ProviderArbiterTest, RequestWithoutFallbackReportsThePrimaryFailure)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__fallback");
    RecordProperty("Description", "A request that names one provider type does not fall back.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto hardware = Register("HW", CryptoProviderType::HARDWARE, ProviderCapability::kCrypto);
    hardware->Factory()->FailWith(CryptoError::kUnsupportedAlgorithm);
    const auto arbiter = MakeArbiter();

    // With no fallback configured, the stub factory's error is returned unchanged.
    const auto selected = arbiter.Select(Request({CryptoProviderType::HARDWARE, std::nullopt}));

    ASSERT_FALSE(selected.has_value());
    EXPECT_EQ(selected.error(), CryptoError::kUnsupportedAlgorithm);
    EXPECT_EQ(software->Factory()->CreateCalls(), 0);
}

TEST_F(ProviderArbiterTest, FailureThatIsNotFallbackEligibleEndsArbitration)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__fallback");
    RecordProperty("Description", "A primary failure that is not fallback eligible does not reach the fallback.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto software = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    const auto hardware = Register("HW", CryptoProviderType::HARDWARE, ProviderCapability::kCrypto);
    hardware->Factory()->FailWith(CryptoError::kInternalError);
    const auto arbiter = MakeArbiter();

    // InternalError is not fallback-eligible, so the software stub's factory must not be called.
    const auto selected = arbiter.Select(Request({CryptoProviderType::HARDWARE, CryptoProviderType::SOFTWARE}));

    ASSERT_FALSE(selected.has_value());
    EXPECT_EQ(selected.error(), CryptoError::kInternalError);
    EXPECT_EQ(software->Factory()->CreateCalls(), 0);
}

TEST_F(ProviderArbiterTest, SameProviderIsNotTriedTwice)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_mediator__fallback");
    RecordProperty("Description", "A fallback that resolves to the provider already tried is skipped.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto only = Register("SW", CryptoProviderType::SOFTWARE, ProviderCapability::kCrypto);
    only->Factory()->FailWith(CryptoError::kUnsupportedAlgorithm);
    const auto arbiter = MakeArbiter();

    // Both preference entries resolve to the same stub; the arbiter must not call its factory twice.
    const auto selected = arbiter.Select(Request({CryptoProviderType::SOFTWARE, CryptoProviderType::SOFTWARE}));

    ASSERT_FALSE(selected.has_value());
    EXPECT_EQ(selected.error(), CryptoError::kUnsupportedAlgorithm);
    EXPECT_EQ(only->Factory()->CreateCalls(), 1);
}

}  // namespace
}  // namespace score::crypto::daemon::mediator
