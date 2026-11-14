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

#ifndef SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP

#include "score/crypto/src/api/common/crypto_resource_guard.hpp"
#include "score/crypto/src/api/common/src/i_release_callback.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

namespace score
{

namespace crypto
{
/// @brief Concrete IKeyManagementContext implementation for communication with the crypto daemon.
///
/// Each instance is bound to a daemon-side key management context identified
/// by the context_id supplied to the constructor.
/// Returned CryptoResourceGuard instances manage resource lifetime through
/// an IReleaseCallback bound to the daemon connection.
///
/// Operation support depends on the selected provider's capabilities.
class KeyManagementContextImpl final : public IKeyManagementContext
{
  public:
    /// @brief Constructs a key management context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    /// @param transcoder Stack-shared buffer-routing abstraction for binary data.
    KeyManagementContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                             uint64_t context_id,
                             std::shared_ptr<IBufferTranscoder> transcoder = nullptr);

    ~KeyManagementContextImpl() override;

    // No copy, no move. Just handled via unique_ptr
    KeyManagementContextImpl(const KeyManagementContextImpl&) = delete;
    KeyManagementContextImpl& operator=(const KeyManagementContextImpl&) = delete;
    KeyManagementContextImpl(KeyManagementContextImpl&&) = delete;
    KeyManagementContextImpl& operator=(KeyManagementContextImpl&&) = delete;

    // -- Key Generation --
    score::Result<CryptoResourceGuard> GenerateKey(const GenerateKeyParams& params) override;
    score::Result<std::monostate> GenerateKey(const CryptoResourceId& target_slot,
                                              const std::optional<CryptoResourceId>& public_slot,
                                              const GenerateKeyParams& params) override;

    // -- KEM (all secret outputs are managed, non-exportable resources) --
    score::Result<std::size_t> GetEncapsulationCiphertextSize(const EncapsulateKeyParams& params) override;
    score::Result<EncapsulationResult> EncapsulateKey(const EncapsulateKeyParams& params,
                                                      score::cpp::span<uint8_t> ciphertext_out) override;
    score::Result<CryptoResourceGuard> DecapsulateKey(const DecapsulateKeyParams& params) override;

    // -- Key Derivation --
    score::Result<CryptoResourceGuard> DeriveKey(const DeriveKeyParams& params) override;
    score::Result<std::monostate> DeriveKey(const CryptoResourceId& target_slot,
                                            const DeriveKeyParams& params) override;

    // -- Key Agreement --
    score::Result<CryptoResourceGuard> AgreeKey(const AgreeKeyParams& params) override;
    score::Result<std::monostate> AgreeKey(const CryptoResourceId& target_slot, const AgreeKeyParams& params) override;

    // -- Persistence --
    score::Result<std::monostate> PersistKey(const CryptoResourceId& target_slot,
                                             const CryptoResourceId& ephemeral_key) override;

    // -- Key Unwrapping --
    score::Result<CryptoResourceGuard> UnwrapKey(const UnwrapKeyParams& params) override;
    score::Result<std::monostate> UnwrapKey(const CryptoResourceId& target_slot,
                                            const UnwrapKeyParams& params) override;

    // -- Key Import --
    score::Result<CryptoResourceGuard> ImportKey(const ImportKeyParams& params) override;
    score::Result<std::monostate> ImportKey(const CryptoResourceId& target_slot,
                                            const ImportKeyParams& params) override;

    // -- Key Loading --
    score::Result<CryptoResourceGuard> LoadKey(const CryptoResourceId& slot) override;

    // -- Key Wrapping --
    score::Result<std::size_t> WrapKey(const WrapKeyParams& params, score::cpp::span<uint8_t> output) override;
    score::Result<std::size_t> GetWrapKeySize(const WrapKeyParams& params) override;

    // -- Key Export --
    score::Result<std::size_t> ExportKey(const CryptoResourceId& key,
                                         score::cpp::span<uint8_t> output,
                                         FormatType format) override;
    score::Result<std::size_t> GetExportKeySize(const CryptoResourceId& key, FormatType format) override;

    // -- Key Clearing --
    score::Result<std::monostate> ClearKey(const CryptoResourceId& key) override;

    // -- Slot Queries --
    score::Result<KeySlotInfo> GetKeySlotInfo(const CryptoResourceId& slot) override;

  private:
    /// @brief Sends a key-management request and returns the unvalidated daemon response.
    /// @param request Built request, or the error encountered during request construction.
    /// @return Daemon response, or a request-construction, connection, or transport error.
    /// The caller validates its operation-specific response and maps errors as required.
    score::Result<daemon::control_plane::protocol::ControlResponse> SendKeyManagementRequest(
        const Expected<daemon::control_plane::protocol::ControlRequest, CryptoErrorCode>& request);

    /// @brief Sends a key-management request and validates its single-operation response.
    /// @param request Built request, or the error encountered during request construction.
    /// @param response_parameter_count Exact number of parameters required in the response.
    /// @return Successful response with matching actor, action, and parameter count, or an error.
    score::Result<daemon::control_plane::protocol::SingleOperationResponse> ExecuteKeyManagementRequest(
        const Expected<daemon::control_plane::protocol::ControlRequest, CryptoErrorCode>& request,
        std::size_t response_parameter_count);

    /// @brief Creates an ephemeral guard for returned key-management material.
    /// @param parameters Daemon response containing the resource id and provider id.
    /// @param offset Index of the resource id; the provider id follows immediately.
    /// @param type kKey for keys, or kSharedSecret for KEM output.
    /// @return Guard that releases the resource through KEY_RELEASE, or a response error.
    score::Result<CryptoResourceGuard> MakeResourceGuard(const daemon::common::ResponseParameters& parameters,
                                                       std::size_t offset,
                                                       ResourceType type);
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;
    std::shared_ptr<IBufferTranscoder> m_transcoder;

    /// @brief IReleaseCallback whose destructor sends CTX_CLOSE to the daemon.
    /// Held by the context *and* transitively by every CryptoResourceGuard (via
    /// ReleaseCallbackImpl).  CTX_CLOSE is therefore deferred until both the
    /// context and all outstanding guards have been destroyed.
    /// @hint: May look like never used, but used via shared_ptr lifetime handling to keep this context alive until all
    /// guards are released.
    class ContextReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_context_release_callback;

    /// @brief IReleaseCallback implementation for constructing CryptoResourceGuards.
    /// Sends KEY_RELEASE for individual keys and holds a shared_ptr to
    /// ContextReleaseCallbackImpl to keep the key management context alive.
    class ReleaseCallbackImpl;
    std::shared_ptr<IReleaseCallback> m_release_callback;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_CONTEXTS_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP
