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

#ifndef SCORE_MW_CRYPTO_API_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP
#define SCORE_MW_CRYPTO_API_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/common/src/i_release_callback.hpp"
#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/key_operation_params.hpp"
#include "score/mw/crypto/api/contexts/i_key_management_context.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>

namespace score
{
namespace mw
{
namespace crypto
{
/// @brief Concrete IKeyManagementContext implementation that delegates to the crypto daemon via IPC.
///
/// Each instance is bound to a daemon-side key management context (identified by
/// context_id) created during construction. Key-producing operations (GenerateKey,
/// etc.) return CryptoResourceGuard instances that auto-release through an
/// IReleaseCallback bound to the daemon connection.
///
/// Currently implements:
///   - GenerateKey (ephemeral overload) — returns CryptoResourceGuard
///   - Key release via CryptoResourceGuard RAII / explicit Release()
///
/// Other operations (DeriveKey, AgreeKey, etc.) return kUnsupportedOperation stubs.
class KeyManagementContextImpl final : public IKeyManagementContext
{
  public:
    /// @brief Constructs a key management context bound to an existing daemon-side context.
    /// @param connection Shared connection for IPC communication
    /// @param context_id Daemon-assigned context identifier (from CTX_CREATE response)
    KeyManagementContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                             uint64_t context_id);

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

    // -- Key Derivation (stubs) --
    score::Result<CryptoResourceGuard> DeriveKey(const DeriveKeyParams& params) override;
    score::Result<std::monostate> DeriveKey(const CryptoResourceId& target_slot,
                                            const DeriveKeyParams& params) override;

    // -- Key Agreement (stubs) --
    score::Result<CryptoResourceGuard> AgreeKey(const AgreeKeyParams& params) override;
    score::Result<std::monostate> AgreeKey(const CryptoResourceId& target_slot, const AgreeKeyParams& params) override;

    // -- Persistence (stub) --
    score::Result<std::monostate> PersistKey(const CryptoResourceId& target_slot,
                                             const CryptoResourceId& ephemeral_key) override;

    // -- Key Unwrapping (stubs) --
    score::Result<CryptoResourceGuard> UnwrapKey(const UnwrapKeyParams& params) override;
    score::Result<std::monostate> UnwrapKey(const CryptoResourceId& target_slot,
                                            const UnwrapKeyParams& params) override;

    // -- Key Import (stubs) --
    score::Result<CryptoResourceGuard> ImportKey(const ImportKeyParams& params) override;
    score::Result<std::monostate> ImportKey(const CryptoResourceId& target_slot,
                                            const ImportKeyParams& params) override;

    // -- Key Loading (stub) --
    score::Result<CryptoResourceGuard> LoadKey(const CryptoResourceId& slot) override;

    // -- Key Wrapping (stubs) --
    score::Result<std::size_t> WrapKey(const WrapKeyParams& params, score::cpp::span<uint8_t> output) override;
    score::Result<std::size_t> GetWrapKeySize(const WrapKeyParams& params) override;

    // -- Key Export (stubs) --
    score::Result<std::size_t> ExportKey(const CryptoResourceId& key,
                                         score::cpp::span<uint8_t> output,
                                         FormatType format) override;
    score::Result<std::size_t> GetExportKeySize(const CryptoResourceId& key, FormatType format) override;

    // -- Key Clearing (stub) --
    score::Result<std::monostate> ClearKey(const CryptoResourceId& key) override;

    // -- Slot Queries (stub) --
    score::Result<KeySlotInfo> GetKeySlotInfo(const CryptoResourceId& slot) override;

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    score::crypto::daemon::control_plane::protocol::DataNodeId m_context_id;

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
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_SRC_KEY_MANAGEMENT_CONTEXT_IMPL_HPP
