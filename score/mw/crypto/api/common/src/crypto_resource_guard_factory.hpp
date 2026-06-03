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

#ifndef SCORE_MW_CRYPTO_API_COMMON_SRC_CRYPTO_RESOURCE_GUARD_FACTORY_HPP
#define SCORE_MW_CRYPTO_API_COMMON_SRC_CRYPTO_RESOURCE_GUARD_FACTORY_HPP

/// @file
/// @brief Internal factory for constructing CryptoResourceGuard instances.
///
/// **This is an internal header — never include it from application or public
/// interface code.** It belongs in `src/` alongside `i_release_callback.hpp`
/// and is only included by concrete IPC-layer implementations that produce
/// guards on behalf of key-producing context methods.
///
/// ## Design
///
/// `CryptoResourceGuard` has a private constructor to prevent arbitrary
/// construction in application code. `CryptoResourceGuardFactory` is declared
/// as a `friend` of `CryptoResourceGuard` so that it can call that private
/// constructor. Because this header lives only in `src/` (not under the public
/// include root), no application code can ever obtain or instantiate the
/// factory.
///
/// ## How the type erasure works
///
/// The release handle is stored as `std::shared_ptr<void>` inside the guard,
/// but is always constructed from a `std::shared_ptr<IReleaseCallback>`.
/// The implicit upcast (`shared_ptr<IReleaseCallback>` → `shared_ptr<void>`)
/// preserves the deleter, so the pointed-to object is correctly destroyed.
/// The destructor of `CryptoResourceGuard` recovers the concrete pointer via
/// `static_cast<IReleaseCallback*>`, which is safe because `release_handle_`
/// is always set through this factory and never any other way.
///
/// ## Usage in a concrete implementation
///
/// @code
///   #include "score/mw/crypto/api/common/src/crypto_resource_guard_factory.hpp"
///   #include "score/mw/crypto/api/common/src/i_release_callback.hpp"
///
///   class ConcreteKeyMgmt : public score::mw::crypto::IKeyManagementContext {
///   public:
///       score::Result<score::mw::crypto::CryptoResourceGuard>
///       GenerateKey(const score::mw::crypto::GenerateKeyParams& params) override
///       {
///           // 1. IPC: send GenerateKey to daemon, receive assigned resource id
///           score::mw::crypto::CryptoResourceId id = /* IPC result */;
///
///           // 2. ipc_release_cb_ is std::shared_ptr<IReleaseCallback>
///           //    Implicit conversion to shared_ptr<void> happens here.
///           return score::mw::crypto::CryptoResourceGuardFactory::Make(
///               ipc_release_cb_, id);
///       }
///
///   private:
///       std::shared_ptr<score::mw::crypto::IReleaseCallback> ipc_release_cb_;
///   };
/// @endcode

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Internal factory for CryptoResourceGuard construction.
///
/// Declared as a friend of `CryptoResourceGuard`. Concrete IPC-layer
/// implementations call `CryptoResourceGuardFactory::Make()` to produce guards.
/// Application code has no access to this class.
class CryptoResourceGuardFactory
{
  public:
    /// @brief Constructs a guard that owns a daemon-assigned transient resource.
    ///
    /// @param release_handle `shared_ptr<IReleaseCallback>` obtained from the
    ///        IPC layer, implicitly converted to `shared_ptr<void>` at the call
    ///        site. Must not be null.
    /// @param id The transient resource handle assigned by the daemon.
    /// @return An active CryptoResourceGuard; IsActive() == true.
    static CryptoResourceGuard Make(std::shared_ptr<void> release_handle, CryptoResourceId id) noexcept
    {
        return CryptoResourceGuard{std::move(release_handle), id};
    }

  private:
    CryptoResourceGuardFactory() = delete;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_COMMON_SRC_CRYPTO_RESOURCE_GUARD_FACTORY_HPP
