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

#ifndef SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_PROTOCOL_H
#define SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_PROTOCOL_H

#include "score/mw/log/logging.h"
#include <cstddef>
#include <cstdint>
#include <functional>

#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/data_manager/i_data_manager.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"

namespace score::crypto::daemon::control_plane::protocol
{

// ============================================================================
// Protocol Types
// ============================================================================
// TODO(error-unification phase-3): OperationResult now uses CryptoErrorCode's underlying type,
// so IPC wire values are 0x01CCxxxx (API-defined ranges), not the old 0x000x daemon ranges.
// If cross-version wire stability ever becomes a requirement (rolling daemon/client upgrades),
// introduce a dedicated serialization enum here and translate at the boundary so CryptoErrorCode
// can evolve independently of the on-wire representation.
using OperationResult = std::underlying_type<score::mw::crypto::CryptoErrorCode>::type;
static constexpr OperationResult OPERATION_RESULT_SUCCESS = 0;

// ============================================================================
// Convenience type aliased to bring them to into the namespace
// ============================================================================

using OperationIdentifier = common::OperationIdentifier;
using NoParam = daemon::common::NoParam;
using DataNodeId = daemon::data_manager::DataNodeId;
using OwnedString = common::OwnedString;
using OwnedBuffer = common::OwnedBuffer;
using DataBufferReturn = common::OwnedBuffer;

// ============================================================================
// Request and Response Classes
// ============================================================================

struct SingleOperationRequest
{
    OperationIdentifier operationId;
    common::RequestParameters parameters;

    template <typename T>
    Expected<T, score::mw::crypto::CryptoErrorCode> getParameter(std::size_t idx) const
    {
        if (idx >= parameters.size())
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(parameters[idx]))
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::get<T>(parameters[idx]);
    }
};

struct SingleOperationResponse
{
    OperationIdentifier operationId;
    OperationResult result{static_cast<OperationResult>(score::mw::crypto::CryptoErrorCode::kInternalError)};
    common::ResponseParameters parameters;

    template <typename T>
    Expected<T, score::mw::crypto::CryptoErrorCode> getParameter(std::size_t idx) const
    {
        if (idx >= parameters.size())
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(parameters[idx]))
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::get<T>(parameters[idx]);
    }
};

// ============================================================================
// Batching of multiple Operation per Request & Response
// ============================================================================

struct OperationRequest
{
    std::vector<SingleOperationRequest> operations;
};

struct OperationResponse
{
    std::vector<SingleOperationResponse> operations;
};

// ============================================================================
// ControlRequest & ControlResponse
// ============================================================================

using RequestId = std::uint64_t;

/// Request for control operation
struct ControlRequest
{
    RequestId request_id;
    // TODO: This is not really nice, since we duplicate the union definition
    // But we avoid confusion about the order / portability
    // BUT, we should get rid of this in general
    // There are currently THREE copies either change none or all
    union
    {
        data_manager::ClientId client_id;
        struct
        {
            uint32_t pid;
            uint32_t uid;
        };
    };
    union
    {
        data_manager::DataNodeId data_node_id;
        // TODO: Unclear if this depends on endianess or other factors
        // Is there a clear statemenet about the order of these elements in the C / C++ spec?
        // It may be better to define a named struct within data_manager
        struct
        {
            uint64_t node_id_value : data_manager::DATA_NODE_ID_VALUE_BITS;
            uint64_t node_tag_value : data_manager::DATA_NODE_ID_RESERVED_BITS;
        };
    };
    protocol::OperationRequest operation;
};

static_assert(sizeof(pid_t) == sizeof(decltype(ControlRequest::pid)),
              "Error: The size of pid_t is not the expected size.");
static_assert(sizeof(uid_t) == sizeof(decltype(ControlRequest::uid)),
              "Error: The size of uid_t is not the expected size.");
static_assert(sizeof(data_manager::ClientId) ==
                  sizeof(decltype(ControlRequest::pid)) + sizeof(decltype(ControlRequest::uid)),
              "Error: The size of data_manager::ClientId and its components do not match.");

/// Response from control operation
struct ControlResponse
{
    RequestId request_id;
    protocol::OperationResponse operation;
};

/// Extract the process ID (pid) from a ClientId
inline uint32_t GetPidFromClientId(data_manager::ClientId client_id)
{
    // TODO: This is not really nice, since we duplicate the union definition
    // But we avoid confusion about the order / portability
    // BUT, we should get rid of this in general
    // There are currently THREE copies either change none or all
    union
    {
        data_manager::ClientId id;
        struct
        {
            uint32_t pid;
            uint32_t uid;
        };
    } decomposed{client_id};
    return decomposed.pid;
}

/// Extract the user ID (uid) from a ClientId
inline uint32_t GetUidFromClientId(data_manager::ClientId client_id)
{
    // TODO: This is not really nice, since we duplicate the union definition
    // But we avoid confusion about the order / portability
    // BUT, we should get rid of this in general
    // There are currently THREE copies either change none or all
    union
    {
        data_manager::ClientId id;
        struct
        {
            uint32_t pid;
            uint32_t uid;
        };
    } decomposed{client_id};
    return decomposed.uid;
}

// ============================================================================
// Builders
// ============================================================================

class OperationRequestBuilder
{
  public:
    OperationRequestBuilder& operation(const OperationIdentifier& opId)
    {
        operationRequest.operations.push_back(SingleOperationRequest{opId, {}});

        return *this;
    }

    OperationRequestBuilder& with_no_param()
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(NoParam{});
        }
        return *this;
    };

    OperationRequestBuilder& with_in_string(std::string_view string)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(string);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_data_buffer(span<const uint8_t> data)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(
                common::VirtualMemoryBufferConst{data.data(), data.size()});
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_bool(bool val)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint8(uint8_t val)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint16(uint16_t val)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint32(uint32_t val)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint64(uint64_t val)
    {
        if (validateOperationExists())
        {
            operationRequest.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    Expected<OperationRequest, score::mw::crypto::CryptoErrorCode> build()
    {
        if (error)
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_REQ_BUILDER] ERROR - Cannot build OperationRequest due to previous errors in "
                   "building process";

            error = false;
            operationRequest.operations.clear();

            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
        }

        OperationRequest ret{
            std::move(operationRequest.operations),
        };
        return ret;
    }

  private:
    bool error = false;

    OperationRequest operationRequest;

    bool validateOperationExists()
    {
        if (operationRequest.operations.empty())
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_REQ_BUILDER] ERROR - Trying to add parameter without an operation";
            error = true;
            return false;
        }
        return true;
    }
};

class OperationResponseBuilder
{
  public:
    OperationResponseBuilder& operation(const OperationIdentifier& opId)
    {
        operationResponse.operations.push_back(SingleOperationResponse{opId, {}});

        return *this;
    }

    OperationResponseBuilder& return_success()
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().result = OPERATION_RESULT_SUCCESS;
        }
        return *this;
    };

    OperationResponseBuilder& return_error(score::mw::crypto::CryptoErrorCode error)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().result = static_cast<OperationResult>(error);
        }
        return *this;
    };

    /// @brief Daemon-internal overload: translates DaemonErrorCode to the wire
    /// CryptoErrorCode value at the IPC boundary. Daemon code should prefer this
    /// overload so handler/executor files never reference CryptoErrorCode directly.
    OperationResponseBuilder& return_error(score::crypto::daemon::common::DaemonErrorCode error)
    {
        return return_error(score::crypto::daemon::common::ToCryptoErrorCode(error));
    };

    OperationResponseBuilder& return_value_bool(bool val)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint8(uint8_t val)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint16(uint16_t val)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint32(uint32_t val)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint64(uint64_t val)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_data_buffer_out(std::vector<std::uint8_t>&& data)
    {
        if (validateOperationExists())
        {
            operationResponse.operations.back().parameters.push_back(OwnedBuffer{std::move(data)});
        }
        return *this;
    };

    OperationResponseBuilder& return_crypto_operation_response(const OperationIdentifier& opId,
                                                               OperationResult res,
                                                               common::ResponseParameters&& response)
    {
        operation(opId);
        if (res == OPERATION_RESULT_SUCCESS)
        {
            return_success();
        }
        else
        {
            return_error(static_cast<score::mw::crypto::CryptoErrorCode>(res));
        }
        operationResponse.operations.back().parameters = std::move(response);
        return *this;
    };

    Expected<OperationResponse, score::mw::crypto::CryptoErrorCode> build()
    {
        if (error)
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_RESP_BUILDER] ERROR - Cannot build OperationResponse due to previous errors in "
                   "building process";

            error = false;
            operationResponse.operations.clear();

            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
        }

        return OperationResponse{
            std::move(operationResponse.operations),
        };
    }

  private:
    bool error = false;

    OperationResponse operationResponse;

    bool validateOperationExists()
    {
        if (operationResponse.operations.empty())
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_RESP_BUILDER] ERROR - Trying to add parameter without an operation";
            error = true;
            return false;
        }
        return true;
    }
};

// ============================================================================
// Response Validator (Fluent Builder Pattern)
// ============================================================================

class ControlResponseValidator
{
  public:
    explicit ControlResponseValidator(const OperationResponse& response, bool logErrors = false)
        : m_response(response),
          m_currentOpIndex(std::numeric_limits<size_t>::max()),
          m_errorMsg(""),
          m_logErrors(logErrors)
    {
    }

    /// Create a validator from a Result/Expected type, validating has_value() first
    /// Works with any type T where has_value() and value() are available
    /// Automatically extracts .operation from ControlResponse if present
    template <typename T>
    static ControlResponseValidator FromResult(const T& result, bool logErrors = false)
    {
        if (!result.has_value())
        {
            ControlResponseValidator validator(OperationResponse{}, logErrors);
            validator.m_isValid = false;
            validator.m_errorMsg = "Operation response is not available (has_value() returned false)";
            return validator;
        }

        // Extract .operation from ControlResponse
        ControlResponseValidator validator(result.value().operation, logErrors);
        return validator;
    }

    // ========================================================================
    // Operation Switching
    // ========================================================================

    /// Start validating a new operation (implicit index increment)
    ControlResponseValidator& expectOperation(const OperationIdentifier& opId)
    {
        if (!m_isValid)
            return *this;

        // Increment to next operation
        if (m_currentOpIndex == std::numeric_limits<size_t>::max())
        {
            m_currentOpIndex = 0;
        }
        else
        {
            m_currentOpIndex++;
        }

        // Validate we have enough operations
        if (m_currentOpIndex >= m_response.get().operations.size())
        {
            m_isValid = false;
            m_errorMsg = "Expected operation at index " + std::to_string(m_currentOpIndex) + " but response has only " +
                         std::to_string(m_response.get().operations.size()) + " operations";
            return *this;
        }

        // Validate operation ID
        const auto& op = m_response.get().operations[m_currentOpIndex];
        if (op.operationId.operationActor != opId.operationActor ||
            op.operationId.operationAction != opId.operationAction)
        {
            m_isValid = false;
            m_errorMsg = "Operation at index " + std::to_string(m_currentOpIndex) +
                         " ID mismatch. Expected actor=" + std::to_string(opId.operationActor) +
                         " action=" + std::to_string(opId.operationAction) +
                         " but got actor=" + std::to_string(op.operationId.operationActor) +
                         " action=" + std::to_string(op.operationId.operationAction);
            return *this;
        }

        return *this;
    }

    // ========================================================================
    // Result Validation (applies to current operation)
    // ========================================================================

    /// Validate current operation succeeded (result code = 0)
    ControlResponseValidator& expectSuccess()
    {
        if (!m_isValid)
            return *this;

        const auto& op = m_response.get().operations[m_currentOpIndex];
        if (op.result != OPERATION_RESULT_SUCCESS)
        {
            auto errorCode = static_cast<score::mw::crypto::CryptoErrorCode>(op.result);

            m_isValid = false;
            m_errorMsg = "Operation at index " + std::to_string(m_currentOpIndex) + " failed with error code " +
                         std::string(score::mw::crypto::kCryptoErrorDomain.MessageFor(
                             static_cast<score::result::ErrorCode>(errorCode)));
        }

        return *this;
    }

    // ========================================================================
    // Parameter Verification & Extraction (applies to specific operation)
    // ========================================================================

    /// Query if parameter at specified operation and parameter index is of requested type
    template <typename T>
    Expected<bool, score::mw::crypto::CryptoErrorCode> isParameterOfType(size_t opIndex, size_t paramIdx)
    {
        if (!m_isValid)
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
        }

        if (opIndex >= m_response.get().operations.size())
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        const auto& op = m_response.get().operations[opIndex];

        if (paramIdx >= op.parameters.size())
        {
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::holds_alternative<T>(op.parameters[paramIdx]);
    }

    /// Extract parameter at specified operation and parameter index with type checking
    template <typename T>
    Expected<T, score::mw::crypto::CryptoErrorCode> getParameterAt(size_t opIndex, size_t paramIdx)
    {
        if (!m_isValid)
        {
            logError();
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInternalError);
        }

        if (opIndex >= m_response.get().operations.size())
        {
            m_isValid = false;
            m_errorMsg = "Operation index " + std::to_string(opIndex) + " out of bounds";
            logError();
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        const auto& op = m_response.get().operations[opIndex];

        if (paramIdx >= op.parameters.size())
        {
            m_isValid = false;
            m_errorMsg = "Parameter index " + std::to_string(paramIdx) + " out of bounds";
            logError();
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(op.parameters[paramIdx]))
        {
            m_isValid = false;
            m_errorMsg = "Parameter type mismatch at operation " + std::to_string(opIndex) + " parameter " +
                         std::to_string(paramIdx);
            logError();
            return make_unexpected(score::mw::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::get<T>(op.parameters[paramIdx]);
    }

    // ========================================================================
    // Status Query
    // ========================================================================

    bool isValid() const
    {
        return m_isValid;
    }
    const std::string& getError() const
    {
        return m_errorMsg;
    }

  private:
    std::reference_wrapper<const OperationResponse> m_response;
    size_t m_currentOpIndex;
    bool m_isValid = true;
    std::string m_errorMsg;
    bool m_logErrors = false;

    void logError()
    {
        if (m_logErrors)
        {
            score::mw::log::LogError() << "[ControlResponseValidator] ERROR - " << m_errorMsg;
        }
    }
};

// ============================================================================
// ControlRequest Builder (Fluent API)
// ============================================================================

/**
 * @class ControlRequestBuilder
 * @brief Fluent builder for constructing ControlRequest objects.
 *
 * Provides a convenient fluent API for building ControlRequest objects with
 * automatic operation and parameter configuration. Delegates to an internal
 * OperationRequestBuilder for operation handling.
 *
 * Usage:
 *   auto request = ControlRequestBuilder()
 *       .forDataNodeId(node_id)
 *       .operation(my_operation)
 *       .with_in_string("param")
 *       .build();
 */
class ControlRequestBuilder
{
  public:
    ControlRequestBuilder() : m_request{}
    {
        // Filled in by the IPC during transmission
        m_request.request_id = 0;
        m_request.pid = 0;
        m_request.uid = 0;

        // Default value, in case not provided
        m_request.data_node_id = 0;
    }

    /**
     * @brief Set the data node ID for this control request.
     *
     * @param data_node_id The data node ID to associate with this request.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& forDataNodeId(daemon::data_manager::DataNodeId data_node_id)
    {
        m_request.data_node_id = data_node_id;
        return *this;
    }

    /**
     * @brief Start a new operation in the request.
     *
     * Delegates to the internal OperationRequestBuilder.
     *
     * @param opId The operation identifier.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& operation(const protocol::OperationIdentifier& opId)
    {
        m_op_builder.operation(opId);
        return *this;
    }

    /**
     * @brief Add a no-parameter operation parameter.
     *
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_no_param()
    {
        m_op_builder.with_no_param();
        return *this;
    }

    /**
     * @brief Add a string input parameter.
     *
     * @param string The string parameter value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_string(std::string_view string)
    {
        m_op_builder.with_in_string(string);
        return *this;
    }

    /**
     * @brief Add a data buffer input parameter.
     *
     * @param data The buffer data.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_data_buffer(span<const uint8_t> data)
    {
        m_op_builder.with_in_data_buffer(data);
        return *this;
    }

    /**
     * @brief Add a bool value input parameter.
     *
     * @param val The bool value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_val_bool(bool val)
    {
        m_op_builder.with_in_val_bool(val);
        return *this;
    }

    /**
     * @brief Add an uint8 value input parameter.
     *
     * @param val The uint8 value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_val_uint8(uint8_t val)
    {
        m_op_builder.with_in_val_uint8(val);
        return *this;
    }

    /**
     * @brief Add an uint16 value input parameter.
     *
     * @param val The uint16 value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_val_uint16(uint16_t val)
    {
        m_op_builder.with_in_val_uint16(val);
        return *this;
    }

    /**
     * @brief Add an uint32 value input parameter.
     *
     * @param val The uint32 value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_val_uint32(uint32_t val)
    {
        m_op_builder.with_in_val_uint32(val);
        return *this;
    }

    /**
     * @brief Add an uint64 value input parameter.
     *
     * @param val The uint64 value.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& with_in_val_uint64(uint64_t val)
    {
        m_op_builder.with_in_val_uint64(val);
        return *this;
    }

    /**
     * @brief Build the ControlRequest.
     *
     * Finalizes the internal OperationRequestBuilder and constructs the
     * ControlRequest with all accumulated settings.
     *
     * @return Expected<ControlRequest, score::mw::crypto::CryptoErrorCode>
     *         or an error if the operation builder encountered issues.
     */
    Expected<ControlRequest, score::mw::crypto::CryptoErrorCode> build()
    {
        auto op_result = m_op_builder.build();
        if (!op_result.has_value())
        {
            return make_unexpected(op_result.error());
        }

        m_request.operation = op_result.value();
        return m_request;
    }

  private:
    ControlRequest m_request;
    protocol::OperationRequestBuilder m_op_builder;
};

}  // namespace score::crypto::daemon::control_plane::protocol

#endif  // SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_PROTOCOL_H
