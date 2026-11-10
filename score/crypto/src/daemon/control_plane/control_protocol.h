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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>

#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

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
using OperationResult = common::OperationResult;
using common::OPERATION_RESULT_SUCCESS;
using DataNodeId = common::DataNodeId;
using ClientId = common::ClientId;
using common::DATA_NODE_ID_RESERVED_BITS;
using common::DATA_NODE_ID_VALUE_BITS;
using RequestId = common::RequestId;

using OperationIdentifier = common::OperationIdentifier;
using common::GetUidFromClientId;
using common::IsEnvelopeErrorOperation;
using common::kEnvelopeErrorOperationIdentifier;

using NoParam = daemon::common::NoParam;
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
    Expected<T, score::crypto::CryptoErrorCode> getParameter(std::size_t idx) const
    {
        if (idx >= parameters.size())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(parameters[idx]))
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::get<T>(parameters[idx]);
    }
};

struct SingleOperationResponse
{
    OperationIdentifier operationId;
    OperationResult result{static_cast<OperationResult>(score::crypto::CryptoErrorCode::kInternalError)};
    common::ResponseParameters parameters;

    template <typename T>
    Expected<T, score::crypto::CryptoErrorCode> getParameter(std::size_t idx) const
    {
        if (idx >= parameters.size())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(parameters[idx]))
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::get<T>(parameters[idx]);
    }
};

// ============================================================================
// ControlRequest & ControlResponse
// ============================================================================

struct ExecutionPolicy
{
};

/// Request for control operation
struct ControlRequest
{
    RequestId request_id;
    ClientId client_id{0U};
    ExecutionPolicy execution_policy;
    union
    {
        DataNodeId data_node_id;
        // TODO: Unclear if this depends on endianess or other factors
        // Is there a clear statemenet about the order of these elements in the C / C++ spec?
        // It may be better to define a named struct within data_manager
        struct
        {
            uint64_t node_id_value : DATA_NODE_ID_VALUE_BITS;
            uint64_t node_tag_value : DATA_NODE_ID_RESERVED_BITS;
        };
    };
    std::chrono::steady_clock::time_point deadline{};
    std::vector<SingleOperationRequest> operations;
};

/// Response from control operation
struct ControlResponse
{
    RequestId request_id;
    std::vector<SingleOperationResponse> operations;
};

inline bool IsEnvelopeErrorResponse(const ControlResponse& response) noexcept
{
    return (response.operations.size() == 1U) && IsEnvelopeErrorOperation(response.operations.front().operationId);
}

// ============================================================================
// Builders
// ============================================================================

class OperationRequestBuilder
{
  public:
    OperationRequestBuilder& operation(const OperationIdentifier& opId)
    {
        operations.push_back(SingleOperationRequest{opId, {}});

        return *this;
    }

    OperationRequestBuilder& with_no_param()
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(NoParam{});
        }
        return *this;
    };

    OperationRequestBuilder& with_in_string(std::string_view string)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(string);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_data_buffer(span<const uint8_t> data)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(data);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_bool(bool val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint8(uint8_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint16(uint16_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint32(uint32_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_in_val_uint64(uint64_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationRequestBuilder& with_shm(std::uint64_t node_id,
                                      std::size_t offset,
                                      std::size_t size,
                                      common::ShmDirection direction = common::ShmDirection::In)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(common::DataShm{node_id, offset, size, direction});
        }
        return *this;
    };

    Expected<std::vector<SingleOperationRequest>, score::crypto::CryptoErrorCode> build()
    {
        if (error)
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_REQ_BUILDER] ERROR - Cannot build OperationRequest due to previous errors in "
                   "building process";

            error = false;
            operations.clear();

            return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
        }

        return std::move(operations);
    }

  private:
    bool error = false;

    std::vector<SingleOperationRequest> operations;

    bool validateOperationExists()
    {
        if (operations.empty())
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
        operations.push_back(SingleOperationResponse{opId, {}});

        return *this;
    }

    OperationResponseBuilder& return_success()
    {
        if (validateOperationExists())
        {
            operations.back().result = OPERATION_RESULT_SUCCESS;
        }
        return *this;
    };

    OperationResponseBuilder& return_error(score::crypto::CryptoErrorCode error)
    {
        if (validateOperationExists())
        {
            operations.back().result = static_cast<OperationResult>(error);
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
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint8(uint8_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint16(uint16_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint32(uint32_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_uint64(uint64_t val)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(val);
        }
        return *this;
    };

    OperationResponseBuilder& return_value_data_buffer_out(std::vector<std::uint8_t>&& data)
    {
        if (validateOperationExists())
        {
            operations.back().parameters.push_back(OwnedBuffer{std::move(data)});
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
            return_error(static_cast<score::crypto::CryptoErrorCode>(res));
        }
        operations.back().parameters = std::move(response);
        return *this;
    };

    Expected<std::vector<SingleOperationResponse>, score::crypto::CryptoErrorCode> build()
    {
        if (error)
        {
            score::mw::log::LogError()
                << "[CONTROL_OP_RESP_BUILDER] ERROR - Cannot build OperationResponse due to previous errors in "
                   "building process";

            error = false;
            operations.clear();

            return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
        }

        return std::move(operations);
    }

  private:
    bool error = false;

    std::vector<SingleOperationResponse> operations;

    bool validateOperationExists()
    {
        if (operations.empty())
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

/**
 * @brief Validates operation results and parameters in a control response.
 *
 * The validator does not own the operations it examines. The referenced operations response must
 * outlive the validator.
 */
class ControlResponseValidator
{
  public:
    /// @brief Constructs a validator over caller-owned response operations.
    /// @param response Operations to validate; the vector must outlive this validator.
    /// @param logErrors Whether validation failures should be logged.
    explicit ControlResponseValidator(const std::vector<SingleOperationResponse>& response, bool logErrors = false)
        : m_response(response),
          m_currentOpIndex(std::numeric_limits<size_t>::max()),
          m_errorMsg(""),
          m_logErrors(logErrors)
    {
    }

    /// @brief Creates a validator from a Result/Expected-like object.
    ///
    /// Checks has_value() and uses the contained ControlResponse's operations when present.
    /// The caller must keep the result alive for the lifetime of the returned validator.
    /// @param result Result-like object containing a ControlResponse.
    /// @param logErrors Whether validation failures should be logged.
    template <typename T>
    static ControlResponseValidator FromResult(const T& result, bool logErrors = false)
    {
        if (!result.has_value())
        {
            ControlResponseValidator validator(std::vector<SingleOperationResponse>{}, logErrors);
            validator.m_isValid = false;
            validator.m_errorMsg = "Operation response is not available (has_value() returned false)";
            return validator;
        }

        const auto& response = result.value();
        ControlResponseValidator validator(response.operations, logErrors);
        if (IsEnvelopeErrorResponse(response))
        {
            const auto operation_result = response.operations.front().result;
            if (operation_result == OPERATION_RESULT_SUCCESS)
            {
                validator.m_isValid = false;
                validator.m_errorMsg = "Request error envelope contains a success result";
                validator.m_operationError = score::crypto::CryptoErrorCode::kInternalError;
            }
            else
            {
                const auto error = static_cast<score::crypto::CryptoErrorCode>(operation_result);
                validator.m_isValid = false;
                validator.m_errorMsg = "Request failed: " + std::string(score::crypto::kCryptoErrorDomain.MessageFor(
                                                                static_cast<score::result::ErrorCode>(error)));
                validator.m_operationError = static_cast<score::crypto::CryptoErrorCode>(operation_result);
            }
        }
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
        if (m_currentOpIndex >= m_response.get().size())
        {
            m_isValid = false;
            m_errorMsg = "Expected operation at index " + std::to_string(m_currentOpIndex) + " but response has only " +
                         std::to_string(m_response.get().size()) + " operations";
            return *this;
        }

        // Validate operation ID
        const auto& op = m_response.get()[m_currentOpIndex];
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

        // Validate we have enough operations
        if (m_currentOpIndex >= m_response.get().size())
        {
            m_isValid = false;
            m_errorMsg = "Expected successful operation at index " + std::to_string(m_currentOpIndex) +
                         " but response has only " + std::to_string(m_response.get().size()) + " operations";
            return *this;
        }

        const auto& op = m_response.get()[m_currentOpIndex];
        if (op.result != OPERATION_RESULT_SUCCESS)
        {
            auto errorCode = static_cast<score::crypto::CryptoErrorCode>(op.result);

            m_isValid = false;
            m_operationError = errorCode;
            m_errorMsg = "Operation at index " + std::to_string(m_currentOpIndex) + " failed with error code " +
                         std::string(score::crypto::kCryptoErrorDomain.MessageFor(
                             static_cast<score::result::ErrorCode>(errorCode)));
        }

        return *this;
    }

    /// The error code the daemon reported, when the failure came from the daemon.
    ///
    /// expectSuccess() folds the code into a human-readable message for logging;
    /// this exposes the code itself so a caller can forward the daemon's verdict
    /// instead of collapsing every failure into one generic error. A client that
    /// asked for something the key policy forbids needs to see
    /// kKeyOperationNotPermitted, not "context creation failed".
    ///
    /// Returns std::nullopt when validation failed for a client-side reason —
    /// no response at all, wrong operation id, missing or mistyped parameter —
    /// because there is no daemon verdict to report in those cases.
    [[nodiscard]] std::optional<score::crypto::CryptoErrorCode> getOperationError() const
    {
        return m_operationError;
    }

    // ========================================================================
    // Parameter Verification & Extraction (applies to specific operation)
    // ========================================================================

    /// Query if parameter at specified operation and parameter index is of requested type
    template <typename T>
    Expected<bool, score::crypto::CryptoErrorCode> isParameterOfType(size_t opIndex, size_t paramIdx)
    {
        if (!m_isValid)
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
        }

        if (opIndex >= m_response.get().size())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        const auto& op = m_response.get()[opIndex];

        if (paramIdx >= op.parameters.size())
        {
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        return std::holds_alternative<T>(op.parameters[paramIdx]);
    }

    /// Extract parameter at specified operation and parameter index with type checking
    template <typename T>
    Expected<T, score::crypto::CryptoErrorCode> getParameterAt(size_t opIndex, size_t paramIdx)
    {
        if (!m_isValid)
        {
            logError();
            return make_unexpected(score::crypto::CryptoErrorCode::kInternalError);
        }

        if (opIndex >= m_response.get().size())
        {
            m_isValid = false;
            m_errorMsg = "Operation index " + std::to_string(opIndex) + " out of bounds";
            logError();
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        const auto& op = m_response.get()[opIndex];

        if (paramIdx >= op.parameters.size())
        {
            m_isValid = false;
            m_errorMsg = "Parameter index " + std::to_string(paramIdx) + " out of bounds";
            logError();
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
        }

        if (!std::holds_alternative<T>(op.parameters[paramIdx]))
        {
            m_isValid = false;
            m_errorMsg = "Parameter type mismatch at operation " + std::to_string(opIndex) + " parameter " +
                         std::to_string(paramIdx);
            logError();
            return make_unexpected(score::crypto::CryptoErrorCode::kInvalidArgument);
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
    std::reference_wrapper<const std::vector<SingleOperationResponse>> m_response;
    size_t m_currentOpIndex;
    bool m_isValid = true;
    std::string m_errorMsg;
    bool m_logErrors = false;

    /// Set only by expectSuccess(), so it stays empty for client-side
    /// validation failures where the daemon returned no verdict.
    std::optional<score::crypto::CryptoErrorCode> m_operationError;

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
        m_request.client_id = 0U;

        // Default value, in case not provided
        m_request.data_node_id = 0;
    }

    /**
     * @brief Set the data node ID for this control request.
     *
     * @param data_node_id The data node ID to associate with this request.
     * @return Reference to this builder for method chaining.
     */
    ControlRequestBuilder& forDataNodeId(DataNodeId data_node_id)
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
     * @return Expected<ControlRequest, score::crypto::CryptoErrorCode>
     *         or an error if the operation builder encountered issues.
     */
    Expected<ControlRequest, score::crypto::CryptoErrorCode> build()
    {
        auto op_result = m_op_builder.build();
        if (!op_result.has_value())
        {
            return make_unexpected(op_result.error());
        }

        m_request.operations = std::move(op_result).value();
        return m_request;
    }

  private:
    ControlRequest m_request;
    protocol::OperationRequestBuilder m_op_builder;
};

}  // namespace score::crypto::daemon::control_plane::protocol

#endif  // SCORE_CRYPTO_DAEMON_CONTROL_PLANE_CONTROL_PROTOCOL_H
