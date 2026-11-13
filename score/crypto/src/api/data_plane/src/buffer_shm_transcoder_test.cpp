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

#include "score/crypto/src/api/data_plane/src/buffer_shm_transcoder.hpp"
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"
#include <gtest/gtest.h>
#include <array>

namespace score::crypto
{
namespace
{
namespace proto = daemon::control_plane::protocol;

TEST(BufferShmTranscoderTest, RequiredInputShmNeverFallsBackToInlineForSmallDer)
{
    BufferShmTranscoder transcoder{nullptr, nullptr};
    const std::array<uint8_t, 2> data{0x30U, 0U};
    auto ordinary = transcoder.Acquire(data);
    ASSERT_TRUE(ordinary.has_value());
    EXPECT_EQ(ordinary->kind(), TranscoderSpan::Kind::kInBand);
    auto required = transcoder.AcquireInputShm(data);
    ASSERT_FALSE(required.has_value());
    EXPECT_EQ(*required.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kOperationFailed));
    // Other operations retain the existing small-input routing policy.
    EXPECT_TRUE(transcoder.Acquire(data).has_value());
}

TEST(BufferShmTranscoderTest, RequiredInputReservationIsAttachedAsReadOnlyShm)
{
    BufferShmTranscoder transcoder{nullptr, nullptr};
    std::array<uint8_t, 2> data{0x30U, 0U};
    TranscoderSpan token;
    token.set_kind(TranscoderSpan::Kind::kBulk);
    token.set_caller_span(data);
    token.obj_node_offset() = {23U, 4U};
    proto::OperationRequestBuilder builder;
    builder.operation({daemon::common::actors::OP_ACTOR_CSR_HANDLER,
                       daemon::provider::handler::csr_handler_operations::CSR_GENERATE});
    transcoder.AppendInputBuffer(builder, token);
    auto operation = builder.build();
    ASSERT_TRUE(operation.has_value());
    ASSERT_EQ(operation->operations.size(), 1U);
    ASSERT_EQ(operation->operations[0].parameters.size(), 1U);
    const auto* descriptor = std::get_if<daemon::common::DataShm>(&operation->operations[0].parameters[0]);
    ASSERT_NE(descriptor, nullptr);
    EXPECT_EQ(descriptor->node_id, 23U);
    EXPECT_EQ(descriptor->offset, 4U);
    EXPECT_EQ(descriptor->size, data.size());
    EXPECT_EQ(descriptor->direction, daemon::common::ShmDirection::In);
}
}  // namespace
}  // namespace score::crypto
