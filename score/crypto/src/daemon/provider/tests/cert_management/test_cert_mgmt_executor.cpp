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

#include "score/crypto/src/daemon/cert_management/core/cert_management_service.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/data_manager/data_manager.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"
#include "score/crypto/src/daemon/provider/executors/cert_mgmt_executor.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::provider::crypto_executor
{
namespace
{
namespace cert = ::score::crypto::daemon::cert_management;
namespace ops = provider::cert_management;
using Error = common::DaemonErrorCode;

// A rejecting parser proves validation occurs before provider calls, without any OpenSSL dependency.
class RejectingCertParser final : public ops::ICertParser
{
  public:
    Expected<cert::CertObject::Sptr, Error> ParseCertificate(const std::uint8_t* /*bytes*/,
                                                             std::size_t /*size*/,
                                                             FormatType /*format*/) override
    {
        ++single_calls;
        return make_unexpected(Error::kCertificateParsingFailed);
    }

    Expected<std::vector<cert::CertObject::Sptr>, Error> ParseCertificates(const std::uint8_t* /*bytes*/,
                                                                           std::size_t /*size*/,
                                                                           FormatType /*format*/) override
    {
        ++bundle_calls;
        return make_unexpected(Error::kCertificateParsingFailed);
    }

    Expected<std::vector<std::uint8_t>, Error> EncodeCertificate(const cert::CertObject& /*certificate*/,
                                                                 FormatType /*format*/) override
    {
        return make_unexpected(Error::kUnsupportedOperation);
    }

    Expected<CrlMetadata, Error> ValidateCrl(const std::uint8_t* /*crl_data*/,
                                             std::size_t /*crl_size*/,
                                             FormatType /*crl_format*/,
                                             const std::uint8_t* /*issuer_data*/,
                                             std::size_t /*issuer_size*/,
                                             FormatType /*issuer_format*/) override
    {
        return make_unexpected(Error::kUnsupportedOperation);
    }

    unsigned single_calls{0U};
    unsigned bundle_calls{0U};
};

class CertManagementExecutorParseTest : public ::testing::Test
{
  protected:
    auto Parse(span<const std::uint8_t> bytes, FormatType format, common::OperationAction action = ops::CERT_PARSE)
    {
        common::RequestParameters request{static_cast<std::uint8_t>(format), bytes};
        return executor.Execute(context, {common::actors::OP_ACTOR_CERT_MANAGEMENT, action}, request);
    }

    std::shared_ptr<RejectingCertParser> parser = std::make_shared<RejectingCertParser>();
    CertManagementExecutor executor{parser, nullptr};
    CertMgmtExecutionContext context{};
};

TEST_F(CertManagementExecutorParseTest, InvalidSingleInputNeverReachesProvider)
{
    const std::vector<std::uint8_t> invalid{0x30U, 0x01U, 0x00U};
    const std::vector<std::uint8_t> oversized(ops::kMaxCertificateInputBytes + 1U, 0x30U);
    const auto empty = Parse({}, FormatType::kDer);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error(), Error::kInvalidArgument);
    const auto nonnull_empty = Parse({invalid.data(), 0U}, FormatType::kPem);
    ASSERT_FALSE(nonnull_empty.has_value());
    EXPECT_EQ(nonnull_empty.error(), Error::kInvalidArgument);
    for (const auto format : {FormatType::kRaw, static_cast<FormatType>(0xFFU)})
    {
        const auto result = Parse({invalid.data(), invalid.size()}, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInvalidArgument);
    }
    for (const auto format : {FormatType::kDer, FormatType::kPem})
    {
        const auto result = Parse({oversized.data(), oversized.size()}, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kInvalidArgument);
    }
    EXPECT_EQ(parser->single_calls, 0U);
}

TEST_F(CertManagementExecutorParseTest, SourceSingleBudgetBoundaryStillReachesProvider)
{
    static_assert(ops::kMaxCertificateInputBytes == 8192U);
    const std::vector<std::uint8_t> bytes(ops::kMaxCertificateInputBytes, 0x30U);
    for (const auto format : {FormatType::kDer, FormatType::kPem})
    {
        const auto result = Parse({bytes.data(), bytes.size()}, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kCertificateParsingFailed);
    }
    EXPECT_EQ(parser->single_calls, 2U);
}

TEST_F(CertManagementExecutorParseTest, BundleInputIsNotCappedAtSingleCertificateBudget)
{
    const std::vector<std::uint8_t> bytes(ops::kMaxCertificateInputBytes + 1U, 0x30U);
    for (const auto format : {FormatType::kDer, FormatType::kPem})
    {
        const auto result = Parse({bytes.data(), bytes.size()}, format, ops::CERT_PARSE_CHAIN);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), Error::kCertificateParsingFailed);
    }
    EXPECT_EQ(parser->bundle_calls, 2U);
    EXPECT_EQ(parser->single_calls, 0U);
}

TEST(CertManagementExecutorSaveTest, EveryConfiguredMemberIsDeniedBeforeSourceResolutionEvenWhenDisabled)
{
    // Real registry/manager/service wiring follows the source certificate-management integration fixture.
    constexpr data_manager::ClientId client = 1U;  // UID 0, PID 1.
    auto data = std::make_shared<data_manager::DataManager>();
    auto registry = std::make_shared<cert::CertSlotRegistry>();
    cert::CertSlotConfig slot_config;
    slot_config.slot_name = "protected-member";
    slot_config.access_policy.allowed_write_uids = {0U};
    const auto slot = registry->RegisterSlot(slot_config);
    auto manager = std::make_shared<cert::TrustStoreManager>();
    auto service = std::make_shared<cert::CertManagementService>(data, registry, manager);
    CertManagementExecutor executor{nullptr, service};
    const CertMgmtExecutionContext context{common::ProviderId{1U}, client, 42U};
    const auto slot_node = service->ResolveCertSlot(slot, client);
    ASSERT_TRUE(slot_node.has_value());

    for (const auto kind : {cert::TrustStoreMemberKind::kSharedStatic,
                            cert::TrustStoreMemberKind::kExclusiveMutable,
                            cert::TrustStoreMemberKind::kConditionalExternal})
    {
        SCOPED_TRACE(static_cast<unsigned>(kind));
        cert::TrustStoreConfig store;
        store.store_name = "protected-store";
        store.members.push_back({slot_config.slot_name, kind});
        store.access_policy.allowed_write_uids = {0U};
        manager->Load({store}, registry);
        ASSERT_FALSE(manager->GetMembershipsForSlot(slot).empty());

        for (const bool disabled : {false, true})
        {
            SCOPED_TRACE(disabled);
            if (disabled)
                ASSERT_TRUE(manager->DisableMember(cert::TrustStoreHandle{0U}, slot, client).has_value());
            for (const bool with_crl : {false, true})
            {
                // Nonexistent source must not hide membership denial. No slot backend or cert bytes are needed.
                common::RequestParameters request{static_cast<std::uint64_t>(*slot_node), std::uint64_t{0U}};
                if (with_crl)
                    request.push_back(std::uint8_t{1U});
                const auto result =
                    executor.Execute(context, {common::actors::OP_ACTOR_CERT_MANAGEMENT, ops::CERT_SAVE}, request);
                ASSERT_FALSE(result.has_value());
                EXPECT_EQ(result.error(), Error::kAccessDenied);
            }
        }
    }
    EXPECT_TRUE(data->deleteClientNodes(client).has_value());
}

}  // namespace
}  // namespace score::crypto::daemon::provider::crypto_executor
