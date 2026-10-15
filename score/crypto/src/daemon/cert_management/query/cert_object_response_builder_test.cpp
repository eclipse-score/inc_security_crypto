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
#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace query = cert::query;
namespace common = score::crypto::daemon::common;

// ---------------------------------------------------------------------------
// Helpers — extract typed value from ResponseParameter variant
// ---------------------------------------------------------------------------

template <typename T>
const T* GetParam(const score::crypto::daemon::common::ResponseParameters& params, std::size_t idx)
{
    if (idx >= params.size())
        return nullptr;
    return std::get_if<T>(&params[idx]);
}

// ---------------------------------------------------------------------------
// Synthetic CertObject factory — no OpenSSL dependency
// ---------------------------------------------------------------------------

cert::CertObject MakeSyntheticCert(bool is_ca = true)
{
    cert::CertChainMetadata meta;
    meta.subject_canonical = "CN=Test CA,O=SCORE,C=DE";
    meta.issuer_canonical = "CN=Root CA,O=SCORE,C=DE";
    meta.serial_number_hex = "01ABCDEF";
    // Epoch values chosen to fit in int64 and uint64 without sign issues.
    meta.not_before_epoch_s = 1700000000LL;
    meta.not_after_epoch_s = 1730000000LL;
    meta.is_ca = is_ca;
    meta.skid = {0x11, 0x22, 0x33};
    meta.akid = {0xAA, 0xBB};
    meta.fingerprint.assign(32U, 0x5A);

    // Raw bytes not exercised by serializer — single placeholder byte is sufficient.
    return cert::CertObject{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
}

// ---------------------------------------------------------------------------
// ICertSlotHandler stub — configurable slot state and CRL metadata
// ---------------------------------------------------------------------------

struct SlotHandlerStub : public cert::ICertSlotHandler
{
    mutable score::crypto::Expected<score::crypto::CertificateSlotInfo, score::crypto::daemon::common::DaemonErrorCode>
        slot_info_result{score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kOccupied}};

    mutable std::optional<int64_t> crl_next_update_value{std::nullopt};

    score::crypto::Expected<cert::CertObject::Sptr, score::crypto::daemon::common::DaemonErrorCode> LoadCertificate(
        const cert::CertSlotConfig&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> StoreCertificate(
        const cert::CertSlotConfig&,
        const cert::CertObject&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ClearSlot(
        const cert::CertSlotConfig&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CertificateSlotState, score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const cert::CertSlotConfig&) override
    {
        return score::crypto::CertificateSlotState::kEmpty;
    }

    score::crypto::Expected<score::crypto::CertificateSlotInfo, score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const cert::CertSlotConfig&) override
    {
        return slot_info_result;
    }

    score::crypto::Expected<bool, score::crypto::daemon::common::DaemonErrorCode> HasCrl(
        const cert::CertSlotConfig&) override
    {
        return slot_info_result.has_value() && slot_info_result->has_crl;
    }

    score::crypto::Expected<std::vector<uint8_t>, score::crypto::daemon::common::DaemonErrorCode> LoadCrl(
        const cert::CertSlotConfig&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> StoreCrl(
        const cert::CertSlotConfig&,
        score::crypto::span<const uint8_t>,
        score::crypto::FormatType,
        std::optional<score::crypto::CrlMetadata>) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ClearCrl(
        const cert::CertSlotConfig&) override
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    score::crypto::Expected<int64_t, score::crypto::daemon::common::DaemonErrorCode> GetCrlNextUpdate(
        const cert::CertSlotConfig&) override
    {
        if (!crl_next_update_value.has_value())
            return score::crypto::make_unexpected(
                score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
        return *crl_next_update_value;
    }

    score::crypto::FormatType GetCrlFormat(const cert::CertSlotConfig&) override
    {
        return score::crypto::FormatType::kDer;
    }
};

// ===========================================================================
// BuildCertObjectResponse
// ===========================================================================

TEST(BuildCertObjectResponse, ProducesFifteenParameters)
{
    const auto cert = MakeSyntheticCert();
    EXPECT_EQ(query::BuildCertObjectResponse(cert).value().size(), 15U);
}

TEST(BuildCertObjectResponse, Param0_SubjectString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "CN=Test CA,O=SCORE,C=DE");
}

TEST(BuildCertObjectResponse, Param1_IssuerString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 1U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "CN=Root CA,O=SCORE,C=DE");
}

TEST(BuildCertObjectResponse, Param2_NotBeforeEpochUint64)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<std::uint64_t>(params, 2U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint64_t>(1700000000ULL));
}

TEST(BuildCertObjectResponse, Param3_NotAfterEpochUint64)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<std::uint64_t>(params, 3U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint64_t>(1730000000ULL));
}

TEST(BuildCertObjectResponse, Param4_IsCaTrue_EncodesAs1)
{
    const auto cert = MakeSyntheticCert(/*is_ca=*/true);
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<std::uint8_t>(params, 4U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, 1U);
}

TEST(BuildCertObjectResponse, Param4_IsCaFalse_EncodesAs0)
{
    const auto cert = MakeSyntheticCert(/*is_ca=*/false);
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<std::uint8_t>(params, 4U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, 0U);
}

TEST(BuildCertObjectResponse, Param5_SkidBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 5U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 3U);
    EXPECT_EQ((*val)[0], 0x11U);
    EXPECT_EQ((*val)[1], 0x22U);
    EXPECT_EQ((*val)[2], 0x33U);
}

TEST(BuildCertObjectResponse, Param6_AkidBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 6U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 2U);
    EXPECT_EQ((*val)[0], 0xAAU);
    EXPECT_EQ((*val)[1], 0xBBU);
}

TEST(BuildCertObjectResponse, Param7_SerialNumberString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 7U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "01ABCDEF");
}

TEST(BuildCertObjectResponse, Param8_Fingerprint32ByteBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::BuildCertObjectResponse(cert).value();
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 8U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 32U);
    for (const auto byte : *val)
        EXPECT_EQ(byte, 0x5AU);
}

TEST(BuildCertObjectResponse, CrlMetadataUsesTypedTail)
{
    const auto cert = MakeSyntheticCert();
    score::crypto::CrlMetadata metadata;
    metadata.fingerprint.fill(0xA1U);
    metadata.issuer_fingerprint.fill(0xB2U);
    metadata.this_update = 1700000000LL;
    metadata.next_update = 1730000000LL;
    metadata.crl_number = 7U;

    const auto params = query::BuildCertObjectResponse(cert, metadata).value();
    const auto* has_crl = GetParam<std::uint8_t>(params, 9U);
    const auto* crl_fp = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 10U);
    const auto* issuer_fp = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 11U);
    const auto* this_update = GetParam<std::uint64_t>(params, 12U);
    const auto* next_update = GetParam<std::uint64_t>(params, 13U);
    const auto* crl_number = GetParam<std::uint64_t>(params, 14U);
    ASSERT_NE(has_crl, nullptr);
    ASSERT_NE(crl_fp, nullptr);
    ASSERT_NE(issuer_fp, nullptr);
    ASSERT_NE(this_update, nullptr);
    ASSERT_NE(next_update, nullptr);
    ASSERT_NE(crl_number, nullptr);
    EXPECT_EQ(*has_crl, 1U);
    EXPECT_EQ(crl_fp->size(), 32U);
    EXPECT_EQ(issuer_fp->size(), 32U);
    EXPECT_EQ(*this_update, static_cast<std::uint64_t>(metadata.this_update));
    EXPECT_EQ(*next_update, static_cast<std::uint64_t>(metadata.next_update));
    EXPECT_EQ(*crl_number, metadata.crl_number);
}

TEST(BuildCertObjectResponse, EmptySkidAndAkidEncodeAsEmptyBuffers)
{
    cert::CertChainMetadata meta;
    meta.subject_canonical = "CN=Leaf";
    meta.issuer_canonical = "CN=CA";
    meta.fingerprint.assign(32U, 0x00);
    // skid and akid left default (empty vectors)

    cert::CertObject leaf{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
    const auto params = query::BuildCertObjectResponse(leaf).value();
    const auto* skid = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 5U);
    const auto* akid = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 6U);
    ASSERT_NE(skid, nullptr);
    ASSERT_NE(akid, nullptr);
    EXPECT_TRUE(skid->empty());
    EXPECT_TRUE(akid->empty());
}

TEST(BuildCertObjectResponse, OversizedDnsReturnResponseTooLarge)
{
    cert::CertChainMetadata meta;
    // Each DN alone fits comfortably under the budget; the combined total of
    // two such DNs does not, so this exercises the budget check rather than
    // any single-field limit.
    meta.subject_canonical = std::string(900U, 'A');
    meta.issuer_canonical = std::string(900U, 'B');
    meta.fingerprint.assign(32U, 0x00);

    cert::CertObject oversized{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
    const auto result = query::BuildCertObjectResponse(oversized);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kResponseTooLarge);
}

// ===========================================================================
// BuildCertSlotInfoResponse
//
// CertSlotManager is constructed with a minimal CertSlotRegistry and a factory
// that returns a SlotHandlerStub.  CheckSlotAccess is unconditionally permissive
// for reads, so no UID configuration is required.
// ===========================================================================

class BuildCertSlotInfoResponseTest : public ::testing::Test
{
  protected:
    static constexpr score::crypto::daemon::data_manager::ClientId kClientId = 42U;

    void SetUp() override
    {
        auto registry = std::make_shared<cert::CertSlotRegistry>();
        cert::CertSlotConfig cfg;
        cfg.slot_name = "test/serializer-slot";
        slot_handle_ = registry->RegisterSlot(cfg);

        stub_ = std::make_shared<SlotHandlerStub>();
        auto stub_ptr = stub_;
        mgr_ = std::make_unique<cert::CertSlotManager>(std::move(registry), [stub_ptr](const cert::CertSlotConfig&) {
            return stub_ptr;
        });
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

TEST_F(BuildCertSlotInfoResponseTest, Param0_SlotStateUint8_Occupied)
{
    stub_->slot_info_result = score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kOccupied};
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());
    const auto* val = GetParam<std::uint8_t>(result.value(), 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint8_t>(score::crypto::CertificateSlotState::kOccupied));
}

TEST_F(BuildCertSlotInfoResponseTest, Param0_SlotStateUint8_Empty)
{
    stub_->slot_info_result = score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kEmpty};
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());
    const auto* val = GetParam<std::uint8_t>(result.value(), 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint8_t>(score::crypto::CertificateSlotState::kEmpty));
}

TEST_F(BuildCertSlotInfoResponseTest, NoCrl_Param1IsZero)
{
    stub_->slot_info_result->has_crl = false;
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());

    const auto* has_crl = GetParam<std::uint8_t>(result.value(), 1U);
    ASSERT_NE(has_crl, nullptr);
    EXPECT_EQ(*has_crl, 0U);
}

TEST_F(BuildCertSlotInfoResponseTest, CrlPresent_Param1IsOne)
{
    stub_->slot_info_result->has_crl = true;
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_TRUE(result.has_value());

    const auto* has_crl = GetParam<std::uint8_t>(result.value(), 1U);
    ASSERT_NE(has_crl, nullptr);
    EXPECT_EQ(*has_crl, 1U);
}

TEST_F(BuildCertSlotInfoResponseTest, GetSlotInfoError_PropagatesError)
{
    stub_->slot_info_result =
        score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    const auto result = query::BuildCertSlotInfoResponse(*mgr_, slot_handle_, kClientId);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInternalError);
}

}  // namespace
