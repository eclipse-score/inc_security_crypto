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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <memory>

namespace score::crypto::daemon::key_management
{

/// Interface for provider-specific key slot operations.
///
/// A slot handler manages the storage backend for one provider category:
///   - FileBackedSlotHandler: file system (pure-SW provider, daemon manages I/O)
///   - Pkcs11KeySlotHandler:  PKCS#11 token (HW/SW HSM manages storage)
///   - TeeKeySlotHandler:     TEE/PSA (secure enclave manages storage)
///
/// LoadKey is the primary operation: it retrieves key material from the slot
/// and returns an IKeyHandler that owns the material for its lifetime.
///
/// The key management module depends only on this interface.
class IKeySlotHandler
{
  public:
    using Sptr = std::shared_ptr<IKeySlotHandler>;

    IKeySlotHandler() = default;

    virtual ~IKeySlotHandler() = default;

    IKeySlotHandler(const IKeySlotHandler&) = delete;
    IKeySlotHandler& operator=(const IKeySlotHandler&) = delete;
    IKeySlotHandler(IKeySlotHandler&&) = delete;
    IKeySlotHandler& operator=(IKeySlotHandler&&) = delete;

    /// Load key material from the slot and return a key handler that owns it.
    ///
    /// For file-backed slots: reads file bytes, delegates to provider ImportKey.
    /// For PKCS#11 slots: opens a session, finds the token object, wraps it.
    /// For TEE slots: calls psa_open_key() or equivalent.
    ///
    /// The returned IKeyHandler must be transferred to a KeyDataNode
    /// (via RegisterKeyMaterial) immediately; the caller must not hold bare references.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    LoadKey(const KeySlotConfig& slot) = 0;

    /// Query slot occupancy state (kEmpty or kOccupied).
    [[nodiscard]] virtual score::crypto::Expected<score::mw::crypto::KeySlotState,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotState(const KeySlotConfig& slot) = 0;

    /// Get slot metadata (state, algorithm, provider, permissions).
    [[nodiscard]] virtual score::crypto::Expected<score::mw::crypto::KeySlotInfo,
                                                  score::crypto::daemon::common::DaemonErrorCode>
    GetSlotInfo(const KeySlotConfig& slot) = 0;

    /// Store key material from an IKeyHandler into a persistent slot.
    ///
    /// Used by GenerateKeyToSlot (default compose path) and PersistKey.
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    StoreKey(const KeySlotConfig& slot, IKeyHandler& handler);

    /// Erase key material from a persistent slot.
    ///
    /// After this call GetSlotState() must return kEmpty.
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ClearSlot(const KeySlotConfig& slot);
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_SLOT_HANDLER_HPP
