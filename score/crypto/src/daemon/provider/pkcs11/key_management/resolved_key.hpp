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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_RESOLVED_KEY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_RESOLVED_KEY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <pkcs11.h>

#include <atomic>
#include <memory>

namespace score::crypto::daemon::provider::pkcs11
{

/// RAII borrow of a PKCS#11 key for use in a single crypto operation.
///
/// Obtained exclusively via the two factory methods:
///   - Acquire()  — for session-object keys (GenerateKey / ImportKey).
///                  Atomically sets the per-key in-use flag; returns
///                  kResourceBusy if the key is already held by another handler.
///   - ForToken() — for token-object keys (LoadKey).
///                  No exclusion flag; multiple handlers may hold the same
///                  token key concurrently.
///
/// Destruction (or move-assignment from an empty ResolvedKey) automatically
/// clears the in-use flag so the key becomes available to subsequent handlers.
///
/// Move-only: copying is deleted to prevent double-release of the flag.
class ResolvedKey
{
  public:
    /// Attempt to exclusively acquire a session-object key.
    ///
    /// Atomically sets `flag` from false to true (std::memory_order_acquire).
    /// Returns kResourceBusy without blocking if the flag is already set.
    [[nodiscard]] static score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode>
    Acquire(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, std::shared_ptr<std::atomic_flag> flag) noexcept;

    /// Wrap a token-object key that requires no exclusion flag.
    [[nodiscard]] static score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode> ForToken(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE object) noexcept;

    /// Constructs an empty (unbound) ResolvedKey — no session, no flag held.
    ResolvedKey() noexcept = default;

    /// Clears the in-use flag (if held) so the key becomes available.
    ~ResolvedKey() noexcept;

    ResolvedKey(const ResolvedKey&) = delete;
    ResolvedKey& operator=(const ResolvedKey&) = delete;

    ResolvedKey(ResolvedKey&& other) noexcept;
    ResolvedKey& operator=(ResolvedKey&& other) noexcept;

    [[nodiscard]] CK_SESSION_HANDLE session() const noexcept;

    [[nodiscard]] CK_OBJECT_HANDLE object() const noexcept;

  private:
    ResolvedKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, std::shared_ptr<std::atomic_flag> flag) noexcept;

    CK_SESSION_HANDLE m_session{CK_INVALID_HANDLE};
    CK_OBJECT_HANDLE m_object{CK_INVALID_HANDLE};
    std::shared_ptr<std::atomic_flag> m_flag;  ///< null for token objects
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_RESOLVED_KEY_HPP
