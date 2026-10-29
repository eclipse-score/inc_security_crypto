/*******************************************************************************
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
 *******************************************************************************/
//
// Unit tests for cert_management/query/cert_object_response_builder.
//
// Tests verify the IPC wire format produced by each response-builder function:
//   - Parameter count and order
//   - Parameter variant type (OwnedString, OwnedBuffer, uint64, uint8)
//   - Parameter values for known synthetic inputs
//
// These tests do NOT require OpenSSL.  CertObject is constructed synthetically
// from a known CertChainMetadata.  ICertSlotHandler is stubbed inline and
// wrapped inside a minimal CertSlotManager so the response builder's
// access-policy path is exercised without a real storage backend.
//
// BuildTrustStoreMemberIdListResponse and BuildTrustStoreMemberObjectResponse
// both require a live CertManagementService for slot resolution and are
// therefore covered by test_cert_management_service.cpp (service-level
// integration tests) rather than here.

#include "score/crypto/src/daemon/cert_management/query/cert_object_response_builder.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/provider_manager.hpp"
#include "score/span.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace query = cert::query;
namespace common = score::crypto::daemon::common;
namespace config = score::crypto::daemon::config;
namespace provider = score::crypto::daemon::provider;

// ---------------------------------------------------------------------------
// Helpers — extract typed value from ResponseParameter variant
// ---------------------------------------------------------------------------

template <typename T>
const T* ParamAt(const score::crypto::daemon::common::ResponseParameters& params, std::size_t idx)
{
    if (idx >= params.size())
        return nullptr;
    return std::get_if<T>(&params[idx]);
}

// ---------------------------------------------------------------------------
// Synthetic CertObject factory — no OpenSSL dependency
// ---------------------------------------------------------------------------

struct CertObjectResponseCase
{
    const char* name;
    bool is_ca;
    std::vector<std::uint8_t> skid;
    std::vector<std::uint8_t> akid;
    std::optional<score::crypto::CrlMetadata> crl_metadata;
};

cert::CertObject MakeSyntheticCert(const CertObjectResponseCase& test_case)
{
    cert::CertChainMetadata meta;
    meta.subject_canonical = "CN=Test CA,O=SCORE,C=DE";
    meta.issuer_canonical = "CN=Root CA,O=SCORE,C=DE";
    meta.serial_number_hex = "01ABCDEF";
    // Epoch values chosen to fit in int64 and uint64 without sign issues.
    meta.not_before_epoch_s = 1700000000LL;
    meta.not_after_epoch_s = 1730000000LL;
    meta.is_ca = test_case.is_ca;
    meta.skid = test_case.skid;
    meta.akid = test_case.akid;
    meta.fingerprint.fill(0x5AU);

    // Raw bytes not exercised by serializer — single placeholder byte is sufficient.
    return cert::CertObject{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
}

common::ResponseParameters ExpectedCertObjectResponse(const CertObjectResponseCase& test_case)
{
    const auto crl = test_case.crl_metadata.value_or(score::crypto::CrlMetadata{});
    return {
        common::OwnedString{"CN=Test CA,O=SCORE,C=DE"},
        common::OwnedString{"CN=Root CA,O=SCORE,C=DE"},
        std::uint64_t{1700000000ULL},
        std::uint64_t{1730000000ULL},
        static_cast<std::uint8_t>(test_case.is_ca ? 1U : 0U),
        common::OwnedBuffer{test_case.skid},
        common::OwnedBuffer{test_case.akid},
        common::OwnedString{"01ABCDEF"},
        common::OwnedBuffer(32U, 0x5AU),
        static_cast<std::uint8_t>(test_case.crl_metadata.has_value() ? 1U : 0U),
        common::OwnedBuffer{crl.fingerprint.begin(), crl.fingerprint.end()},
        common::OwnedBuffer{crl.issuer_fingerprint.begin(), crl.issuer_fingerprint.end()},
        static_cast<std::uint64_t>(crl.this_update),
        static_cast<std::uint64_t>(crl.next_update),
        static_cast<std::uint64_t>(crl.crl_number),
    };
}

bool ResponseParameterEquals(const common::ResponseParameter& actual, const common::ResponseParameter& expected)
{
    return std::visit(
        [&actual](const auto& expected_value) {
            using Value = std::decay_t<decltype(expected_value)>;
            const auto* actual_value = std::get_if<Value>(&actual);
            if (actual_value == nullptr)
                return false;
            if constexpr (std::is_same_v<Value, common::NoParam>)
            {
                return true;
            }
            else if constexpr (std::is_same_v<Value, score::cpp::span<const std::uint8_t>>)
            {
                return actual_value->size() == expected_value.size() &&
                       std::equal(actual_value->begin(), actual_value->end(), expected_value.begin());
            }
            else
            {
                return *actual_value == expected_value;
            }
        },
        expected);
}

void ExpectResponseParametersEqual(const common::ResponseParameters& actual, const common::ResponseParameters& expected)
{
    ASSERT_EQ(actual.size(), expected.size());
    for (std::size_t index = 0U; index < expected.size(); ++index)
    {
        EXPECT_TRUE(ResponseParameterEquals(actual[index], expected[index])) << "parameter index " << index;
    }
}

// ---------------------------------------------------------------------------
// ICertSlotHandler stub — configurable slot state and CRL metadata
// ---------------------------------------------------------------------------

struct SlotHandlerStub : public cert::ICertSlotHandler
{
    SlotHandlerStub() : cert::ICertSlotHandler{cert::CertSlotConfig{}} {}

    mutable score::crypto::Expected<score::crypto::CertificateSlotInfo, score::crypto::daemon::common::DaemonErrorCode>
        slot_info_result{score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kOccupied}};

    score::crypto::Expected<cert::CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode> LoadCertificate()
        override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> StoreCertificate(
        const cert::CertObject&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ClearSlot() override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CertificateSlotState, score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState() override
    {
        return score::crypto::CertificateSlotState::kEmpty;
    }

    score::crypto::Expected<score::crypto::CertificateSlotInfo, score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo() override
    {
        return slot_info_result;
    }

    score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> HasCrl() override
    {
        return slot_info_result.has_value() && slot_info_result->has_crl;
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> StoreCrl(
        const cert::CrlData&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ClearCrl() override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }
};

// ===========================================================================
// BuildCertObjectResponse
// ===========================================================================

class BuildCertObjectResponseTest : public ::testing::TestWithParam<CertObjectResponseCase>
{
};

TEST_P(BuildCertObjectResponseTest, MatchesEveryExpectedParameter)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__parse");
    RecordProperty("Description",
                   "Verifies CertObject chain metadata is encoded in the daemon IPC response parameters.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const auto& test_case = GetParam();
    const auto cert = MakeSyntheticCert(test_case);
    const auto result = query::BuildCertObjectResponse(cert, test_case.crl_metadata);
    ASSERT_TRUE(result.has_value());
    ExpectResponseParametersEqual(result.value(), ExpectedCertObjectResponse(test_case));
}

score::crypto::CrlMetadata MakeSyntheticCrlMetadata()
{
    score::crypto::CrlMetadata metadata;
    metadata.fingerprint.fill(0xA1U);
    metadata.issuer_fingerprint.fill(0xB2U);
    metadata.this_update = 1700000000LL;
    metadata.next_update = 1730000000LL;
    metadata.crl_number = 7U;
    return metadata;
}

INSTANTIATE_TEST_SUITE_P(
    CertificateVariants,
    BuildCertObjectResponseTest,
    ::testing::Values(
        CertObjectResponseCase{"CertificateWithoutCrl", true, {0x11U, 0x22U, 0x33U}, {0xAAU, 0xBBU}, std::nullopt},
        CertObjectResponseCase{"NonCaWithCrlMetadata",
                               false,
                               {0x11U, 0x22U, 0x33U},
                               {0xAAU, 0xBBU},
                               MakeSyntheticCrlMetadata()},
        CertObjectResponseCase{"EmptyKeyIdentifiers", true, {}, {}, std::nullopt}),
    [](const ::testing::TestParamInfo<CertObjectResponseCase>& info) {
        return info.param.name;
    });

TEST(BuildCertObjectResponse, PreEpochTimesEncodeAsTwosComplementBits)
{
    cert::CertChainMetadata meta;
    meta.subject_canonical = "CN=Pre-Epoch CA,O=SCORE,C=DE";
    meta.issuer_canonical = "CN=Pre-Epoch CA,O=SCORE,C=DE";
    meta.not_before_epoch_s = -631152000LL;  // 1950-01-01T00:00:00Z
    meta.not_after_epoch_s = -1LL;           // 1969-12-31T23:59:59Z
    const auto cert = cert::CertObject{std::move(meta), {0x30}, score::crypto::FormatType::kDer};

    score::crypto::CrlMetadata crl = MakeSyntheticCrlMetadata();
    crl.this_update = -86400LL;
    const auto result = query::BuildCertObjectResponse(cert, crl);
    ASSERT_TRUE(result.has_value());
    const auto& params = result.value();
    ASSERT_EQ(params.size(), 15U);

    const auto* not_before = ParamAt<std::uint64_t>(params, 2U);
    const auto* not_after = ParamAt<std::uint64_t>(params, 3U);
    const auto* this_update = ParamAt<std::uint64_t>(params, 12U);
    ASSERT_NE(not_before, nullptr);
    ASSERT_NE(not_after, nullptr);
    ASSERT_NE(this_update, nullptr);
    EXPECT_EQ(static_cast<std::int64_t>(*not_before), -631152000LL);
    EXPECT_EQ(static_cast<std::int64_t>(*not_after), -1LL);
    EXPECT_EQ(static_cast<std::int64_t>(*this_update), -86400LL);
}

TEST(BuildCertObjectResponse, OversizedDnsReturnResponseTooLarge)
{
    cert::CertChainMetadata meta;
    // Each DN alone fits comfortably under the budget; the combined total of
    // two such DNs does not, so this exercises the budget check rather than
    // any single-field limit.
    meta.subject_canonical = std::string(900U, 'A');
    meta.issuer_canonical = std::string(900U, 'B');
    meta.fingerprint.fill(0x00U);

    cert::CertObject oversized{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
    const auto result = query::BuildCertObjectResponse(oversized);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kResponseTooLarge);
}

// ===========================================================================
// BuildCertSlotInfoResponse
//
// CertSlotManager uses the real SlotHandlerFactory; a registered test provider
// returns the SlotHandlerStub. CheckSlotAccess is permissive for reads, so no UID
// configuration is required.
// ===========================================================================

class QueryTestParser final : public provider::cert_management::ICertParser
{
  public:
    score::crypto::Expected<cert::CertObject::Sptr, common::DaemonErrorCode>
    ParseCertificate(const std::uint8_t*, std::size_t, score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::vector<cert::CertObject::Sptr>, common::DaemonErrorCode>
    ParseCertificates(const std::uint8_t*, std::size_t, score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::vector<std::uint8_t>, common::DaemonErrorCode> EncodeCertificate(
        const cert::CertObject&,
        score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CrlMetadata, common::DaemonErrorCode>
    ValidateCrl(const cert::CrlData&, const std::uint8_t*, std::size_t, score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }
};

class QueryTestProvider final : public provider::IProvider
{
  public:
    QueryTestProvider(provider::cert_management::ICertParser::Sptr parser, cert::ICertSlotHandler::Sptr handler)
        : m_parser{std::move(parser)}, m_handler{std::move(handler)}
    {
    }

    bool Initialize(const provider::ProviderInitContext& context) override
    {
        m_provider_id = context.numeric_id;
        m_provider_name = context.name;
        m_initialized = true;
        return true;
    }

    void Shutdown() override
    {
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const override
    {
        return m_initialized;
    }

    common::ProviderId GetProviderId() const override
    {
        return m_provider_id;
    }

    const common::ProviderName& GetProviderName() const override
    {
        return m_provider_name;
    }

    provider::cert_management::ICertParser::Sptr GetCertParser() override
    {
        return m_parser;
    }

    std::shared_ptr<cert::ICertSlotHandler> GetCertSlotHandler(const cert::CertSlotConfig&,
                                                               provider::cert_management::ICertParser::Sptr) override
    {
        return m_handler;
    }

    [[nodiscard]] common::ProviderCapability GetProviderCapabilities() override
    {
        return common::ProviderCapability::kCertManagement;
    }

  private:
    provider::cert_management::ICertParser::Sptr m_parser;
    cert::ICertSlotHandler::Sptr m_handler;
    common::ProviderId m_provider_id{common::kInvalidProviderId};
    common::ProviderName m_provider_name;
    bool m_initialized{false};
};

class BuildCertSlotInfoResponseTest : public ::testing::Test
{
  protected:
    static constexpr score::crypto::daemon::data_manager::ClientId kClientId = 42U;

    void SetUp() override
    {
        auto registry = std::make_shared<cert::CertSlotRegistry>();
        cert::CertSlotConfig cfg;
        cfg.slot_name = "test/serializer-slot";
        cfg.storage_backend = "QUERY_TEST_PROVIDER";
        slot_handle_ = registry->RegisterSlot(cfg);

        stub_ = std::make_shared<SlotHandlerStub>();
        auto provider_manager = std::make_shared<provider::ProviderManager>(config::ProviderInitConfig{});
        auto test_provider = std::make_shared<QueryTestProvider>(std::make_shared<QueryTestParser>(), stub_);
        ASSERT_TRUE(provider_manager->RegisterProvider(
            "QUERY_TEST_PROVIDER", test_provider, common::CryptoProviderType::SOFTWARE));
        ASSERT_TRUE(provider_manager->Initialize());
        auto factory = std::make_shared<cert::SlotHandlerFactory>(std::move(provider_manager));
        mgr_ = std::make_unique<cert::CertSlotManager>(std::move(registry), std::move(factory));
    }

    cert::CertSlotHandle slot_handle_{};
    std::shared_ptr<SlotHandlerStub> stub_;
    std::unique_ptr<cert::CertSlotManager> mgr_;
};

TEST_F(BuildCertSlotInfoResponseTest, ProducesTwoParameters)
{
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), 2U);
}

struct SlotInfoCase
{
    score::crypto::CertificateSlotState state;
    bool has_crl;
};

class BuildCertSlotInfoEncodingTest : public BuildCertSlotInfoResponseTest,
                                      public ::testing::WithParamInterface<SlotInfoCase>
{
};

TEST_P(BuildCertSlotInfoEncodingTest, EncodesStateAndCrlFlagAsBytes)
{
    const auto [state, has_crl] = GetParam();
    stub_->slot_info_result = score::crypto::CertificateSlotInfo{state};
    stub_->slot_info_result->has_crl = has_crl;

    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());
    const auto* state_val = ParamAt<std::uint8_t>(result.value(), 0U);
    const auto* crl_val = ParamAt<std::uint8_t>(result.value(), 1U);
    ASSERT_NE(state_val, nullptr);
    ASSERT_NE(crl_val, nullptr);
    EXPECT_EQ(*state_val, static_cast<std::uint8_t>(state));
    EXPECT_EQ(*crl_val, has_crl ? 1U : 0U);
}

INSTANTIATE_TEST_SUITE_P(StateAndCrl,
                         BuildCertSlotInfoEncodingTest,
                         ::testing::Values(SlotInfoCase{score::crypto::CertificateSlotState::kEmpty, false},
                                           SlotInfoCase{score::crypto::CertificateSlotState::kEmpty, true},
                                           SlotInfoCase{score::crypto::CertificateSlotState::kOccupied, false},
                                           SlotInfoCase{score::crypto::CertificateSlotState::kOccupied, true}));

TEST_F(BuildCertSlotInfoResponseTest, GetSlotInfoError_PropagatesError)
{
    stub_->slot_info_result =
        score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInternalError);
}

}  // namespace
