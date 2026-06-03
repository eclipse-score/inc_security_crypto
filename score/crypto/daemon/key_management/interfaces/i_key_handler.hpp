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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"

#include <memory>
#include <variant>

namespace score::crypto::daemon::key_management
{

/// Per-key object that owns the lifetime of a single key material entry.
///
/// An IKeyHandler is created by IKeyFactory (for generated/imported keys) or
/// IKeySlotHandler (for slot-loaded keys). Its ownership is transferred to a
/// KeyDataNode in the per-provider KeyRegistry.
///
/// Thread safety: individual instances are not thread-safe. The DataNode
/// exclusiveAccess flag ensures mutual exclusion for the KeyDataNode path.
///
/// Lifecycle contract:
///   - Release() must be called exactly once before destruction.
///   - The destructor always calls Release() as a fallback, so callers that
///     simply destroy the IKeyHandler without calling Release() are safe.
///   - After Release() the object is spent; calling Release() again returns
///     true without repeating the zeroization (idempotent).

class IKeyHandler
{
  public:
    using Sptr = std::shared_ptr<IKeyHandler>;

    IKeyHandler() = default;

    virtual ~IKeyHandler() = default;

    IKeyHandler(const IKeyHandler&) = delete;
    IKeyHandler& operator=(const IKeyHandler&) = delete;
    IKeyHandler(IKeyHandler&&) = delete;
    IKeyHandler& operator=(IKeyHandler&&) = delete;

    /// Read provider metadata for this key (algorithm, size, exportability).
    ///
    /// The returned reference is valid for the lifetime of the IKeyHandler.
    [[nodiscard]] virtual const ProviderKeyHandle& GetHandle() const noexcept = 0;

    /// Returns the numeric ProviderId (uint16_t) that owns this key handler.
    ///
    /// Used by crypto operation handlers to verify the key comes from the
    /// expected provider before performing provider-specific operations.
    [[nodiscard]] virtual common::ProviderId GetProviderId() const noexcept = 0;

    /// Securely zeroize and release provider-held key material.
    ///
    /// After a successful call, the key material is gone. Idempotent: a second
    /// call returns true without attempting another zeroization.
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    Release() = 0;

    /// Export raw key material into a SecureKeyBytes buffer.
    ///
    /// Returns kNotPermitted for non-exportable keys or after Release() was called.
    [[nodiscard]] virtual score::crypto::Expected<SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode>
    Export() const = 0;
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_HANDLER_HPP
