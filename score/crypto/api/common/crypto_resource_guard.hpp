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

#ifndef SCORE_MW_CRYPTO_API_COMMON_CRYPTO_RESOURCE_GUARD_HPP
#define SCORE_MW_CRYPTO_API_COMMON_CRYPTO_RESOURCE_GUARD_HPP

#include "score/mw/crypto/api/common/types.hpp"
#include "score/result/result.h"

#include <memory>
#include <utility>
#include <variant>

namespace score
{
namespace mw
{
namespace crypto
{

// Forward declaration enabling internal guard construction
class CryptoResourceGuardFactory;

/// @brief RAII guard for transient CryptoResourceId handles returned by resource-producing operations.
///
/// Returned by resource-producing methods (GenerateKey, DeriveKey, AgreeKey,
/// UnwrapKey, ImportKey, LoadKey, LoadCertificatePublicKey, ImportCrl). The guard owns
/// the ephemeral resource and releases it to the daemon when it goes out of
/// scope or when Release() is called.
///
/// **CryptoResourceGuard is move-only** — copying would alias ownership of
/// the same daemon resource, causing a double-release.
///
/// **Slot-direct path** (no guard needed):
/// @code
///   auto slot = ctx->ResolveResource("MyKey", ResourceType::kKeySlot).value();
///   CipherContextConfig config;
///   config.SetAlgorithm("AES-256-CBC").SetKey(slot).SetDirection(CipherDirection::kEncrypt);
///   auto cipher = ctx->CreateCipherContext(config).value();
///   // Context loads and releases key material internally.
/// @endcode
///
/// **Guard path** (for generated/derived/loaded/imported resources):
/// @code
///   auto guard = key_mgmt->GenerateKey(GenerateKeyParams{}.SetAlgorithm("AES-256")).value();
///   CipherContextConfig config;
///   config.SetAlgorithm("AES-256-GCM").SetKey(guard).SetDirection(CipherDirection::kEncrypt);
///   // guard must remain alive until CreateCipherContext() returns.
///   auto cipher = ctx->CreateCipherContext(config).value();
///   // Daemon has bound the key to the context — guard may now be destroyed.
///
///   // PersistKey copies the key to persistent storage.
///   // The guard remains active and releases the ephemeral copy independently.
///   key_mgmt->PersistKey(guard, slot).value();
///   // guard still active; ephemeral copy released when guard goes out of scope.
/// @endcode
///
/// For explicit synchronous release with error handling, call Release()
/// before the guard is destroyed. The destructor silently swallows errors
/// because destructors must not propagate exceptions.

class CryptoResourceGuard
{
  public:
    /// @brief Destructor. Releases the transient resource if still active.
    ~CryptoResourceGuard() noexcept;

    // Non-copyable — would create aliased ownership leading to double-release.
    CryptoResourceGuard(const CryptoResourceGuard&) = delete;
    CryptoResourceGuard& operator=(const CryptoResourceGuard&) = delete;

    /// @brief Move constructor. Transfers ownership; moved-from guard becomes inactive.
    CryptoResourceGuard(CryptoResourceGuard&& other) noexcept;

    /// @brief Move assignment. Releases current resource (if active), then transfers.
    CryptoResourceGuard& operator=(CryptoResourceGuard&& other) noexcept;

    /// @brief Returns a const reference to the underlying CryptoResourceId.
    /// @pre Guard must be active (IsActive() == true).
    const CryptoResourceId& Id() const noexcept;

    /// @brief Implicit conversion to const CryptoResourceId&.
    ///
    /// Enables passing a CryptoResourceGuard directly to any API that
    /// accepts `const CryptoResourceId&` (e.g., SetKey(), ExportKey(),
    /// PersistKey()) without requiring overloads or explicit .Id() calls.
    // NOLINTNEXTLINE(google-explicit-constructor)
    operator const CryptoResourceId&() const noexcept;

    /// @brief Explicitly releases the transient resource with synchronous error feedback.
    ///
    /// Use this when release must happen at a specific point or when errors must
    /// be handled. On success, the guard becomes inactive and the destructor is
    /// a no-op.
    ///
    /// @code
    ///   auto result = guard.Release();
    ///   if (!result.has_value()) {
    ///       // Release failed — e.g., daemon still has active contexts using this key.
    ///   }
    /// @endcode
    ///
    /// @return std::monostate on success; error if the guard is already inactive.
    score::Result<std::monostate> Release() noexcept;

    /// @brief Returns whether the guard still owns a resource.
    ///
    /// Returns false for moved-from guards and guards on which Release() succeeded.
    /// Useful for assertions: the guard must return true at Create*Context() time.
    bool IsActive() const noexcept;

  private:
    // CryptoResourceGuardFactory is the sole construction path for guards. It is an
    // internal implementation detail
    friend class CryptoResourceGuardFactory;

    /// @brief Private constructor — only callable by CryptoResourceGuardFactory.
    CryptoResourceGuard(std::shared_ptr<void> release_handle, CryptoResourceId id) noexcept;

    /// @brief Type-erased release handle. Internally holds a shared_ptr<IReleaseCallback>
    ///        constructed by the IPC layer. Not accessible from application code.
    std::shared_ptr<void> release_handle_;

    /// @brief The guarded resource handle.
    CryptoResourceId id_;

    /// @brief Whether this guard still owns the resource.
    bool active_;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_COMMON_CRYPTO_RESOURCE_GUARD_HPP
