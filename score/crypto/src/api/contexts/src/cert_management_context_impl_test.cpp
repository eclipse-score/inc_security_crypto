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

#include "score/crypto/src/api/contexts/src/cert_management_context_impl.hpp"
#include "score/crypto/src/daemon/provider/cert_management/cert_management_operations.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto
{
namespace
{
namespace proto = daemon::control_plane::protocol;
namespace ops = daemon::provider::cert_management;

// Mirrors the source transport fake: context-close requests are independent of parse requests.
class ParseConnection final : public api::control_plane::IConnection
{
  public:
    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        ++requests;
        proto::ControlResponse response;
        for (const auto& operation : request.operation.operations)
        {
            response.operation.operations.push_back(
                proto::SingleOperationResponse{operation.operationId, proto::OPERATION_RESULT_SUCCESS, {}});
        }
        return response;
    }

    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 1U;
    }

    unsigned requests{0U};
};

// Stop at acquisition so a failed assertion cannot accidentally create a daemon resource.
class RejectingTranscoder final : public IBufferTranscoder
{
  public:
    Expected<TranscoderSpan, score::result::Error> Acquire(score::cpp::span<const uint8_t> /*data*/,
                                                           bool /*is_output*/) override
    {
        ++acquisitions;
        return make_unexpected(MakeError(CryptoErrorCode::kOperationFailed, "Test acquisition failure"));
    }

    void AppendInputBuffer(proto::OperationRequestBuilder& /*builder*/, TranscoderSpan& /*span*/) override {}
    void AppendOutputBuffer(proto::OperationRequestBuilder& /*builder*/, TranscoderSpan& /*span*/) override {}

    score::Result<std::size_t> ExtractOutputBuffer(TranscoderSpan& /*span*/,
                                                   proto::ControlResponseValidator& /*validator*/,
                                                   std::size_t /*param_idx*/) override
    {
        return std::size_t{0U};
    }

    unsigned acquisitions{0U};
};

class CertManagementContextParseTest : public ::testing::Test
{
  protected:
    std::shared_ptr<ParseConnection> connection = std::make_shared<ParseConnection>();
    std::shared_ptr<RejectingTranscoder> transcoder = std::make_shared<RejectingTranscoder>();
};

TEST_F(CertManagementContextParseTest, InvalidInputNeverAcquiresOrSends)
{
    CertManagementContextImpl context{connection, 42U, transcoder};
    const std::vector<std::uint8_t> invalid{0x30U, 0x01U, 0x00U};
    const std::vector<std::uint8_t> oversized(ops::kMaxCertificateInputBytes + 1U, 0x30U);
    const score::cpp::span<const std::uint8_t> bytes{invalid.data(), invalid.size()};

    const auto empty = context.ParseCertificate({}, FormatType::kDer);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(*empty.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    const auto nonnull_empty = context.ParseCertificate({invalid.data(), 0U}, FormatType::kPem);
    ASSERT_FALSE(nonnull_empty.has_value());
    EXPECT_EQ(*nonnull_empty.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    for (const auto format : {FormatType::kRaw, static_cast<FormatType>(0xFFU)})
    {
        const auto result = context.ParseCertificate(bytes, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    }
    for (const auto format : {FormatType::kDer, FormatType::kPem})
    {
        const auto result = context.ParseCertificate({oversized.data(), oversized.size()}, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidArgument));
    }
    EXPECT_EQ(transcoder->acquisitions, 0U);
    EXPECT_EQ(connection->requests, 0U);
}

TEST_F(CertManagementContextParseTest, SourceBudgetBoundaryReachesTranscoder)
{
    static_assert(ops::kMaxCertificateInputBytes == 8192U);
    CertManagementContextImpl context{connection, 42U, transcoder};
    const std::vector<std::uint8_t> bytes(ops::kMaxCertificateInputBytes, 0x30U);
    for (const auto format : {FormatType::kDer, FormatType::kPem})
    {
        const auto result = context.ParseCertificate({bytes.data(), bytes.size()}, format);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
    }
    EXPECT_EQ(transcoder->acquisitions, 2U);
    EXPECT_EQ(connection->requests, 0U);
}

TEST_F(CertManagementContextParseTest, MissingConnectionTranscoderOrContextNeverDereferencesThem)
{
    const std::vector<std::uint8_t> bytes{0x30U, 0x01U, 0x00U};
    const score::cpp::span<const std::uint8_t> input{bytes.data(), bytes.size()};
    CertManagementContextImpl no_connection{nullptr, 42U, transcoder};
    CertManagementContextImpl no_transcoder{connection, 42U, nullptr};
    CertManagementContextImpl no_context{connection, 0U, transcoder};
    for (auto* context : {&no_connection, &no_transcoder, &no_context})
    {
        const auto result = context->ParseCertificate(input, FormatType::kDer);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidOperation));
    }
    EXPECT_EQ(transcoder->acquisitions, 0U);
    EXPECT_EQ(connection->requests, 0U);
}

}  // namespace
}  // namespace score::crypto
