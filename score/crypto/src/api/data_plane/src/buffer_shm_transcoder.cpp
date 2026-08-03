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

#include "score/crypto/src/api/common/error_domain.hpp"

#include "score/crypto/src/daemon/common/types.hpp"

#include <cstring>

namespace score
{

namespace crypto
{

namespace proto = ::score::crypto::daemon::control_plane::protocol;

// ---------------------------------------------------------------------------
// TranscoderSpan destructor — RAII cleanup
// ---------------------------------------------------------------------------
TranscoderSpan::~TranscoderSpan() noexcept
{
    if (kind() == TranscoderSpan::Kind::kPool && !pool_span().empty())
    {
        if (auto allocator = pool_allocator_weak().lock())
        {
            allocator->Deallocate(pool_span());
        }
        // If allocator is already destroyed, no cleanup needed (safe no-op)
    }
}

// ---------------------------------------------------------------------------
// BufferShmTranscoder implementation
// ---------------------------------------------------------------------------

BufferShmTranscoder::BufferShmTranscoder(std::shared_ptr<IPoolAllocator> pool_allocator,
                                         std::shared_ptr<IShmRegionRegistry> registry)
    : m_pool_allocator(std::move(pool_allocator)), m_registry(std::move(registry))
{
}

score::crypto::Expected<TranscoderSpan, CryptoErrorCode> BufferShmTranscoder::Acquire(
    score::cpp::span<const uint8_t> data,
    bool is_output)
{
    const auto make_span = [](score::cpp::span<const uint8_t> s) {
        return score::cpp::span<uint8_t>{const_cast<uint8_t*>(s.data()), s.size()};
    };

    const auto make_inband_span = [&make_span](score::cpp::span<const uint8_t> s) {
        TranscoderSpan tspan;
        tspan.set_kind(TranscoderSpan::Kind::kInBand);
        tspan.set_caller_span(make_span(s));
        return tspan;
    };

    // Small input buffers can always use in-band transport. Output buffers and
    // inputs larger than the threshold must use SHM and are handled below.
    if (!is_output && data.size() <= kInBandThreshold)
    {
        return make_inband_span(data);
    }

    // From here on SHM is required: either an output buffer or an input larger than the threshold.
    if (m_registry == nullptr)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kOperationFailed);
    }

    // BULK SHM: Check if data is in a registered bulk region (but not in pool).
    {
        const std::uint64_t node_id = m_registry->IdentifyNode(data);
        if ((node_id != 0) && ((m_pool_allocator == nullptr) || (node_id != m_pool_allocator->GetNodeId())))
        {
            const auto offset = m_registry->GetOffset(data);
            if (!offset.has_value())
            {
                return score::crypto::make_unexpected(CryptoErrorCode::kInternalError);
            }
            TranscoderSpan tspan;
            tspan.set_kind(TranscoderSpan::Kind::kBulk);
            tspan.set_caller_span(make_span(data));
            tspan.obj_node_offset().node_id = node_id;
            tspan.obj_node_offset().offset = offset.value();
            return tspan;
        }
    }

    // POOL SHM: Try pool allocation.
    if (m_pool_allocator == nullptr)
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kOperationFailed);
    }

    auto pool_span = m_pool_allocator->Allocate(data.size());
    if (!pool_span.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kInsufficientBufferSize);
    }

    // Pool path: obtain node_id and offset directly from pool allocator (no registry lookup needed).
    const std::uint64_t node_id = m_pool_allocator->GetNodeId();
    if (node_id == 0)
    {
        m_pool_allocator->Deallocate(pool_span.value());
        return score::crypto::make_unexpected(CryptoErrorCode::kOperationFailed);
    }

    const auto offset_result = m_pool_allocator->GetOffset(pool_span.value());
    if (!offset_result.has_value())
    {
        return score::crypto::make_unexpected(CryptoErrorCode::kInternalError);
    }
    const std::size_t offset = offset_result.value();

    TranscoderSpan tspan;
    tspan.set_kind(TranscoderSpan::Kind::kPool);
    tspan.set_caller_span(make_span(data));
    tspan.set_pool_span(pool_span.value());
    tspan.obj_node_offset().node_id = node_id;
    tspan.obj_node_offset().offset = offset;
    tspan.set_pool_allocator_weak(m_pool_allocator);  // Enable RAII cleanup
    return tspan;
}

void BufferShmTranscoder::AppendInputBuffer(proto::OperationRequestBuilder& builder, TranscoderSpan& tspan)
{
    using ShmDirection = score::crypto::daemon::common::ShmDirection;

    switch (tspan.kind())
    {
        case TranscoderSpan::Kind::kPool:
        {
            const std::size_t copy_size = std::min(tspan.caller_span().size(), tspan.pool_span().size());
            std::memcpy(tspan.pool_span().data(), tspan.caller_span().data(), copy_size);
            builder.with_shm(tspan.obj_node_offset().node_id,
                             tspan.obj_node_offset().offset,
                             tspan.caller_span().size(),
                             ShmDirection::In);
            break;
        }
        case TranscoderSpan::Kind::kBulk:
            builder.with_shm(tspan.obj_node_offset().node_id,
                             tspan.obj_node_offset().offset,
                             tspan.caller_span().size(),
                             ShmDirection::In);
            break;
        case TranscoderSpan::Kind::kInBand:
            builder.with_in_data_buffer(
                score::cpp::span<const uint8_t>{tspan.caller_span().data(), tspan.caller_span().size()});
            break;
    }
}

void BufferShmTranscoder::AppendOutputBuffer(proto::OperationRequestBuilder& builder, TranscoderSpan& tspan)
{
    using ShmDirection = score::crypto::daemon::common::ShmDirection;

    switch (tspan.kind())
    {
        case TranscoderSpan::Kind::kBulk:
        case TranscoderSpan::Kind::kPool:
            builder.with_shm(tspan.obj_node_offset().node_id,
                             tspan.obj_node_offset().offset,
                             tspan.caller_span().size(),
                             ShmDirection::InOut);
            break;
        case TranscoderSpan::Kind::kInBand:
            break;  // in-band: daemon returns result in response
    }
}

score::Result<std::size_t> BufferShmTranscoder::ExtractOutputBuffer(TranscoderSpan& tspan,
                                                                    proto::ControlResponseValidator& validator,
                                                                    std::size_t param_idx)
{
    switch (tspan.kind())
    {
        case TranscoderSpan::Kind::kBulk:
        {
            // BULK SHM: Daemon writes to caller's SHM buffer and returns written byte count.
            auto result = validator.getParameterAt<uint64_t>(0, param_idx);
            if (!result.has_value())
            {
                return score::Result<std::size_t>{
                    score::unexpect,
                    MakeError(CryptoErrorCode::kOperationFailed, "response has invalid parameter type")};
            }
            const std::size_t actual_size = static_cast<std::size_t>(result.value());
            if (actual_size > tspan.caller_span().size())
            {
                return score::Result<std::size_t>{
                    score::unexpect, MakeError(CryptoErrorCode::kInsufficientBufferSize, "Output buffer too small")};
            }
            return actual_size;
        }

        case TranscoderSpan::Kind::kPool:
        {
            // POOL SHM: Daemon writes to pool buffer and returns written byte count.
            auto result = validator.getParameterAt<uint64_t>(0, param_idx);
            if (!result.has_value())
            {
                return score::Result<std::size_t>{
                    score::unexpect,
                    MakeError(CryptoErrorCode::kOperationFailed, "response has invalid parameter type")};
            }
            const std::size_t actual_size = static_cast<std::size_t>(result.value());
            if (actual_size > tspan.caller_span().size())
            {
                return score::Result<std::size_t>{
                    score::unexpect, MakeError(CryptoErrorCode::kInsufficientBufferSize, "Output buffer too small")};
            }
            std::memcpy(tspan.caller_span().data(), tspan.pool_span().data(), actual_size);
            return actual_size;
        }

        case TranscoderSpan::Kind::kInBand:
        {
            auto result = validator.getParameterAt<proto::DataBufferReturn>(0, param_idx);
            if (!result.has_value())
            {
                return score::Result<std::size_t>{
                    score::unexpect,
                    MakeError(CryptoErrorCode::kOperationFailed, "response has invalid parameter type")};
            }
            const auto& data = result.value();
            if (data.size() > tspan.caller_span().size())
            {
                return score::Result<std::size_t>{
                    score::unexpect, MakeError(CryptoErrorCode::kInsufficientBufferSize, "Output buffer too small")};
            }
            std::memcpy(tspan.caller_span().data(), data.data(), data.size());
            return data.size();
        }
    }

    // Unreachable — suppress compiler warning.
    return score::Result<std::size_t>{score::unexpect,
                                      MakeError(CryptoErrorCode::kOperationFailed, "unknown transcoder kind")};
}

}  // namespace crypto

}  // namespace score
