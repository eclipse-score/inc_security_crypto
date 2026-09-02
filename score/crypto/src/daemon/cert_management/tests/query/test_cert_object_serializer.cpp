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
// Unit tests for cert_management/query/cert_object_serializer.
//
// Tests verify the IPC wire format produced by each serializer function:
//   - Parameter count and order
//   - Parameter variant type (OwnedString, OwnedBuffer, uint64, uint8)
//   - Parameter values for known synthetic inputs
//
// These tests do NOT require OpenSSL.  CertObject is constructed synthetically
// from a known CertChainMetadata.  ICertSlotHandler is stubbed inline.
//
// SerializeTrustStoreMembers requires a live CertManagementService for slot
// resolution and is therefore covered by test_cert_management_service.cpp
// (service-level integration tests) rather than here.

#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/query/cert_object_serializer.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
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
// ICertSlotHandler stub — configurable inline
// ---------------------------------------------------------------------------

struct SlotHandlerStub : public cert::ICertSlotHandler
{
    // Mutable so the stub can be used from const methods.
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

    bool HasCrl(const cert::CertSlotConfig&) override
    {
        return slot_info_result->has_crl;
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
        std::int64_t) override
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
// SerializeCertObject
// ===========================================================================

TEST(SerializeCertObject, ProducesNineParameters)
{
    const auto cert = MakeSyntheticCert();
    EXPECT_EQ(query::SerializeCertObject(cert).size(), 9U);
}

TEST(SerializeCertObject, Param0_SubjectString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "CN=Test CA,O=SCORE,C=DE");
}

TEST(SerializeCertObject, Param1_IssuerString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 1U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "CN=Root CA,O=SCORE,C=DE");
}

TEST(SerializeCertObject, Param2_NotBeforeEpochUint64)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<std::uint64_t>(params, 2U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint64_t>(1700000000ULL));
}

TEST(SerializeCertObject, Param3_NotAfterEpochUint64)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<std::uint64_t>(params, 3U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint64_t>(1730000000ULL));
}

TEST(SerializeCertObject, Param4_IsCaTrue_EncodesAs1)
{
    const auto cert = MakeSyntheticCert(/*is_ca=*/true);
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<std::uint8_t>(params, 4U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, 1U);
}

TEST(SerializeCertObject, Param4_IsCaFalse_EncodesAs0)
{
    const auto cert = MakeSyntheticCert(/*is_ca=*/false);
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<std::uint8_t>(params, 4U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, 0U);
}

TEST(SerializeCertObject, Param5_SkidBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 5U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 3U);
    EXPECT_EQ((*val)[0], 0x11U);
    EXPECT_EQ((*val)[1], 0x22U);
    EXPECT_EQ((*val)[2], 0x33U);
}

TEST(SerializeCertObject, Param6_AkidBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 6U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 2U);
    EXPECT_EQ((*val)[0], 0xAAU);
    EXPECT_EQ((*val)[1], 0xBBU);
}

TEST(SerializeCertObject, Param7_SerialNumberString)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedString>(params, 7U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, "01ABCDEF");
}

TEST(SerializeCertObject, Param8_Fingerprint32ByteBuffer)
{
    const auto cert = MakeSyntheticCert();
    const auto params = query::SerializeCertObject(cert);
    const auto* val = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 8U);
    ASSERT_NE(val, nullptr);
    ASSERT_EQ(val->size(), 32U);
    for (const auto byte : *val)
        EXPECT_EQ(byte, 0x5AU);
}

TEST(SerializeCertObject, EmptySkidAndAkidEncodeAsEmptyBuffers)
{
    cert::CertChainMetadata meta;
    meta.subject_canonical = "CN=Leaf";
    meta.issuer_canonical = "CN=CA";
    meta.fingerprint.assign(32U, 0x00);
    // skid and akid left default (empty vectors)

    cert::CertObject leaf{std::move(meta), {0x30}, score::crypto::FormatType::kDer};
    const auto params = query::SerializeCertObject(leaf);
    const auto* skid = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 5U);
    const auto* akid = GetParam<score::crypto::daemon::common::OwnedBuffer>(params, 6U);
    ASSERT_NE(skid, nullptr);
    ASSERT_NE(akid, nullptr);
    EXPECT_TRUE(skid->empty());
    EXPECT_TRUE(akid->empty());
}

// ===========================================================================
// SerializeCertSlotInfo
// ===========================================================================

TEST(SerializeCertSlotInfo, ProducesThreeParameters)
{
    SlotHandlerStub stub;
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), 3U);
}

TEST(SerializeCertSlotInfo, Param0_SlotStateUint8_Occupied)
{
    SlotHandlerStub stub;
    stub.slot_info_result = score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kOccupied};
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());
    const auto* val = GetParam<std::uint8_t>(result.value(), 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint8_t>(score::crypto::CertificateSlotState::kOccupied));
}

TEST(SerializeCertSlotInfo, Param0_SlotStateUint8_Empty)
{
    SlotHandlerStub stub;
    stub.slot_info_result = score::crypto::CertificateSlotInfo{score::crypto::CertificateSlotState::kEmpty};
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());
    const auto* val = GetParam<std::uint8_t>(result.value(), 0U);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, static_cast<std::uint8_t>(score::crypto::CertificateSlotState::kEmpty));
}

TEST(SerializeCertSlotInfo, NoCrl_Param1IsZero_Param2IsZero)
{
    SlotHandlerStub stub;
    stub.slot_info_result->has_crl = false;
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());

    const auto* has_crl = GetParam<std::uint8_t>(result.value(), 1U);
    const auto* crl_next = GetParam<std::uint64_t>(result.value(), 2U);
    ASSERT_NE(has_crl, nullptr);
    ASSERT_NE(crl_next, nullptr);
    EXPECT_EQ(*has_crl, 0U);
    EXPECT_EQ(*crl_next, 0U);
}

TEST(SerializeCertSlotInfo, CrlPresent_Param1IsOne_Param2IsEpoch)
{
    SlotHandlerStub stub;
    stub.slot_info_result->has_crl = true;
    stub.crl_next_update_value = 1700000000LL;
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());

    const auto* has_crl = GetParam<std::uint8_t>(result.value(), 1U);
    const auto* crl_next = GetParam<std::uint64_t>(result.value(), 2U);
    ASSERT_NE(has_crl, nullptr);
    ASSERT_NE(crl_next, nullptr);
    EXPECT_EQ(*has_crl, 1U);
    EXPECT_EQ(*crl_next, static_cast<std::uint64_t>(1700000000ULL));
}

TEST(SerializeCertSlotInfo, CrlPresent_GetCrlNextUpdateFails_Param2IsZero)
{
    // HasCrl() returns true but GetCrlNextUpdate() is unavailable.
    // The serializer should encode has_crl=1 and crl_next=0 (not an error).
    SlotHandlerStub stub;
    stub.slot_info_result->has_crl = true;
    stub.crl_next_update_value = std::nullopt;  // causes GetCrlNextUpdate to return error
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_TRUE(result.has_value());

    const auto* has_crl = GetParam<std::uint8_t>(result.value(), 1U);
    const auto* crl_next = GetParam<std::uint64_t>(result.value(), 2U);
    ASSERT_NE(has_crl, nullptr);
    ASSERT_NE(crl_next, nullptr);
    EXPECT_EQ(*has_crl, 1U);
    EXPECT_EQ(*crl_next, 0U);
}

TEST(SerializeCertSlotInfo, GetSlotInfoError_PropagatesError)
{
    SlotHandlerStub stub;
    stub.slot_info_result =
        score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInternalError);
    cert::CertSlotConfig config{};
    const auto result = query::SerializeCertSlotInfo(stub, config);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), score::crypto::daemon::common::DaemonErrorCode::kInternalError);
}

}  // namespace
