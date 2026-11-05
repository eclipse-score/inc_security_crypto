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

/// @file context_operation_error_code_test.cpp
/// @brief Every context operation that sends a request to the daemon returns
///        the daemon's error code, and its fallback code only when there is no
///        daemon verdict.

#include "score/crypto/src/api/contexts/src/cipher_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/hash_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/key_management_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/mac_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/random_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/sign_context_impl.hpp"
#include "score/crypto/src/api/contexts/src/verify_signature_context_impl.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace score::crypto
{
namespace
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;

constexpr std::uint64_t kContextId = 42U;

/// Answers each request with the next queued reply, echoing the request's
/// operation id so the response passes the client's operation check.
class FakeConnection final : public api::control_plane::IConnection
{
  public:
    struct Reply
    {
        std::optional<CryptoErrorCode> transport_error;  ///< no response at all
        proto::OperationResult result{proto::OPERATION_RESULT_SUCCESS};
        ::score::crypto::daemon::common::ResponseParameters parameters{};
    };

    Expected<proto::ControlResponse, CryptoErrorCode> SendRequest(const proto::ControlRequest& request) override
    {
        Reply reply = default_reply;
        if (!replies.empty())
        {
            reply = replies.front();
            replies.pop_front();
        }
        if (reply.transport_error.has_value())
        {
            return make_unexpected(reply.transport_error.value());
        }

        proto::ControlResponse response{};
        if (!request.operation.operations.empty())
        {
            response.operation.operations.push_back(proto::SingleOperationResponse{
                request.operation.operations.front().operationId, reply.result, reply.parameters});
        }
        return response;
    }

    proto::DataNodeId GetConnectionNodeId() const override
    {
        return 0U;
    }

    std::deque<Reply> replies;
    Reply default_reply{};
};

/// Passes data in-band without a shared-memory pool; output buffers are never
/// read because every reply under test is an error.
class InBandTranscoder final : public IBufferTranscoder
{
  public:
    score::crypto::Expected<TranscoderSpan, score::result::Error> Acquire(score::cpp::span<const uint8_t> /*data*/,
                                                                          bool /*is_output*/) override
    {
        return TranscoderSpan{};
    }

    void AppendInputBuffer(proto::OperationRequestBuilder& /*builder*/, TranscoderSpan& /*tspan*/) override {}

    void AppendOutputBuffer(proto::OperationRequestBuilder& /*builder*/, TranscoderSpan& /*tspan*/) override {}

    score::Result<std::size_t> ExtractOutputBuffer(TranscoderSpan& /*tspan*/,
                                                   proto::ControlResponseValidator& /*validator*/,
                                                   std::size_t /*param_idx*/) override
    {
        return std::size_t{0U};
    }
};

/// One context operation: how to call it, and the code it reports when the
/// daemon gave no verdict.
struct OperationCase
{
    std::string name;
    CryptoErrorCode fallback;
    std::function<std::optional<score::result::ErrorCode>(const std::shared_ptr<FakeConnection>&,
                                                          const std::shared_ptr<IBufferTranscoder>&)>
        call;
};

void PrintTo(const OperationCase& operation, std::ostream* os)
{
    *os << operation.name;
}

template <typename T>
std::optional<score::result::ErrorCode> ErrorOf(const score::Result<T>& result)
{
    if (result.has_value())
    {
        return std::nullopt;
    }
    return *result.error();
}

std::array<std::uint8_t, 16> g_input{};
std::array<std::uint8_t, 128> g_output{};

template <typename Context, typename Op>
OperationCase Case(std::string name,
                   Op op,
                   std::string algorithm,
                   CryptoErrorCode fallback = CryptoErrorCode::kOperationFailed)
{
    return OperationCase{std::move(name),
                         fallback,
                         [op, algorithm](const std::shared_ptr<FakeConnection>& connection,
                                         const std::shared_ptr<IBufferTranscoder>& transcoder) {
                             Context context{connection, kContextId, algorithm, transcoder};
                             return op(context);
                         }};
}

std::vector<OperationCase> AllOperations()
{
    const score::cpp::span<const std::uint8_t> in{g_input.data(), g_input.size()};
    const score::cpp::span<std::uint8_t> out{g_output.data(), g_output.size()};

    return {
        Case<HashContextImpl>(
            "Hash_Init",
            [](auto& c) {
                return ErrorOf(c.Init(std::nullopt));
            },
            "SHA256"),
        Case<HashContextImpl>(
            "Hash_Update",
            [in](auto& c) {
                return ErrorOf(c.Update(in));
            },
            "SHA256"),
        Case<HashContextImpl>(
            "Hash_Finalize",
            [out](auto& c) {
                return ErrorOf(c.Finalize(out));
            },
            "SHA256"),
        Case<HashContextImpl>(
            "Hash_SingleShot",
            [in, out](auto& c) {
                return ErrorOf(c.SingleShot(in, out));
            },
            "SHA256"),
        Case<HashContextImpl>(
            "Hash_Reset",
            [](auto& c) {
                return ErrorOf(c.Reset());
            },
            "SHA256"),

        Case<SignContextImpl>(
            "Sign_Init",
            [](auto& c) {
                return ErrorOf(c.Init(std::nullopt));
            },
            "ECDSA-P256-SHA256"),
        Case<SignContextImpl>(
            "Sign_Update",
            [in](auto& c) {
                return ErrorOf(c.Update(in));
            },
            "ECDSA-P256-SHA256"),
        Case<SignContextImpl>(
            "Sign_SignFinalize",
            [out](auto& c) {
                return ErrorOf(c.SignFinalize(out));
            },
            "ECDSA-P256-SHA256"),
        Case<SignContextImpl>(
            "Sign_SingleShot",
            [in, out](auto& c) {
                return ErrorOf(c.SingleShot(in, out));
            },
            "ECDSA-P256-SHA256"),
        Case<SignContextImpl>(
            "Sign_Reset",
            [](auto& c) {
                return ErrorOf(c.Reset());
            },
            "ECDSA-P256-SHA256"),

        Case<VerifySignatureContextImpl>(
            "Verify_Init",
            [](auto& c) {
                return ErrorOf(c.Init(std::nullopt));
            },
            "ECDSA-P256-SHA256"),
        Case<VerifySignatureContextImpl>(
            "Verify_Update",
            [in](auto& c) {
                return ErrorOf(c.Update(in));
            },
            "ECDSA-P256-SHA256"),
        Case<VerifySignatureContextImpl>(
            "Verify_VerifyFinalize",
            [in](auto& c) {
                return ErrorOf(c.VerifyFinalize(in));
            },
            "ECDSA-P256-SHA256"),
        Case<VerifySignatureContextImpl>(
            "Verify_SingleShot",
            [in](auto& c) {
                return ErrorOf(c.SingleShot(in, in));
            },
            "ECDSA-P256-SHA256"),
        Case<VerifySignatureContextImpl>(
            "Verify_Reset",
            [](auto& c) {
                return ErrorOf(c.Reset());
            },
            "ECDSA-P256-SHA256"),

        Case<CipherContextImpl>(
            "Cipher_Init",
            [in](auto& c) {
                return ErrorOf(c.Init(in));
            },
            "AES-256-CBC"),
        Case<CipherContextImpl>(
            "Cipher_Update",
            [in, out](auto& c) {
                return ErrorOf(c.Update(in, out));
            },
            "AES-256-CBC"),
        Case<CipherContextImpl>(
            "Cipher_Finalize",
            [out](auto& c) {
                return ErrorOf(c.Finalize(out));
            },
            "AES-256-CBC"),
        Case<CipherContextImpl>(
            "Cipher_SingleShot",
            [in, out](auto& c) {
                return ErrorOf(c.SingleShot(in, in, out));
            },
            "AES-256-CBC"),
        Case<CipherContextImpl>(
            "Cipher_Reset",
            [](auto& c) {
                return ErrorOf(c.Reset());
            },
            "AES-256-CBC"),
        Case<CipherContextImpl>(
            "Cipher_GetMaximumOutputSize",
            [](auto& c) {
                return ErrorOf(c.GetMaximumOutputSize(5U));
            },
            "AES-256-CBC"),

        Case<MacContextImpl>(
            "Mac_Init",
            [](auto& c) {
                return ErrorOf(c.Init(std::nullopt));
            },
            "HMAC-SHA256"),
        Case<MacContextImpl>(
            "Mac_Update",
            [in](auto& c) {
                return ErrorOf(c.Update(in));
            },
            "HMAC-SHA256"),
        Case<MacContextImpl>(
            "Mac_Finalize",
            [out](auto& c) {
                return ErrorOf(c.Finalize(out));
            },
            "HMAC-SHA256"),
        Case<MacContextImpl>(
            "Mac_Verify",
            [in](auto& c) {
                return ErrorOf(c.Verify(in));
            },
            "HMAC-SHA256"),
        Case<MacContextImpl>(
            "Mac_Reset",
            [](auto& c) {
                return ErrorOf(c.Reset());
            },
            "HMAC-SHA256"),

        Case<RandomContextImpl>(
            "Random_Generate",
            [out](auto& c) {
                return ErrorOf(c.Generate(out));
            },
            "CTR-DRBG"),
        Case<RandomContextImpl>(
            "Random_Seed",
            [in](auto& c) {
                return ErrorOf(c.Seed(in));
            },
            "CTR-DRBG"),

        OperationCase{"KeyManagement_GenerateKey",
                      CryptoErrorCode::kKeyGenerationFailed,
                      [](const auto& connection, const auto& transcoder) {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          return ErrorOf(key_mgmt.GenerateKey(GenerateKeyParams{}.SetAlgorithm("AES-256")));
                      }},
        OperationCase{"KeyManagement_LoadKey",
                      CryptoErrorCode::kInternalError,
                      [](const auto& connection, const auto& transcoder) {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          CryptoResourceId slot{};
                          slot.type = ResourceType::kKeySlot;
                          return ErrorOf(key_mgmt.LoadKey(slot));
                      }},
        OperationCase{"KeyManagement_ImportKey",
                      CryptoErrorCode::kOperationFailed,
                      [in](const auto& connection, const auto& transcoder) {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          ImportKeyParams params{};
                          params.key_data = in;
                          params.algorithm = "ECDSA-P256";
                          return ErrorOf(key_mgmt.ImportKey(params));
                      }},
        OperationCase{"KeyManagement_ExportKey",
                      CryptoErrorCode::kOperationFailed,
                      [out](const auto& connection, const auto& transcoder) {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          CryptoResourceId key{};
                          key.type = ResourceType::kKey;
                          return ErrorOf(key_mgmt.ExportKey(key, out, FormatType::kDer));
                      }},
        OperationCase{"KeyManagement_GetExportKeySize",
                      CryptoErrorCode::kOperationFailed,
                      [](const auto& connection, const auto& transcoder) {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          CryptoResourceId key{};
                          key.type = ResourceType::kKey;
                          return ErrorOf(key_mgmt.GetExportKeySize(key, FormatType::kDer));
                      }},
        // Release goes through the guard of a key the daemon generated first.
        OperationCase{"KeyManagement_Release",
                      CryptoErrorCode::kOperationFailed,
                      [](const auto& connection, const auto& transcoder) -> std::optional<score::result::ErrorCode> {
                          KeyManagementContextImpl key_mgmt{connection, kContextId, transcoder};
                          connection->replies.push_back(FakeConnection::Reply{
                              std::nullopt, proto::OPERATION_RESULT_SUCCESS, {std::uint64_t{7U}, std::uint16_t{1U}}});
                          auto key = key_mgmt.GenerateKey(GenerateKeyParams{}.SetAlgorithm("AES-256"));
                          EXPECT_TRUE(key.has_value()) << "GenerateKey precondition failed";
                          if (!key.has_value())
                          {
                              return std::nullopt;
                          }
                          return ErrorOf(key.value().Release());
                      }},
    };
}

class ContextErrorForwardingTest : public ::testing::TestWithParam<OperationCase>
{
  protected:
    std::shared_ptr<FakeConnection> connection_{std::make_shared<FakeConnection>()};
    std::shared_ptr<IBufferTranscoder> transcoder_{std::make_shared<InBandTranscoder>()};
};

TEST_P(ContextErrorForwardingTest, ReturnsTheDaemonsErrorCode)
{
    for (const auto code :
         {CryptoErrorCode::kInvalidArgument, CryptoErrorCode::kAccessDenied, CryptoErrorCode::kIncompatibleKeyType})
    {
        SCOPED_TRACE(static_cast<score::result::ErrorCode>(code));
        connection_->default_reply = FakeConnection::Reply{std::nullopt, static_cast<proto::OperationResult>(code), {}};

        const auto error = GetParam().call(connection_, transcoder_);

        ASSERT_TRUE(error.has_value()) << "operation succeeded on a daemon error";
        EXPECT_EQ(error.value(), static_cast<score::result::ErrorCode>(code));
    }
}

TEST_P(ContextErrorForwardingTest, ReturnsItsFallbackWithoutADaemonVerdict)
{
    connection_->default_reply = FakeConnection::Reply{CryptoErrorCode::kConnectionFailed};

    const auto error = GetParam().call(connection_, transcoder_);

    ASSERT_TRUE(error.has_value()) << "operation succeeded without a response";
    EXPECT_EQ(error.value(), static_cast<score::result::ErrorCode>(GetParam().fallback));
}

INSTANTIATE_TEST_SUITE_P(AllContexts,
                         ContextErrorForwardingTest,
                         ::testing::ValuesIn(AllOperations()),
                         [](const ::testing::TestParamInfo<OperationCase>& info) {
                             return info.param.name;
                         });

}  // namespace
}  // namespace score::crypto
