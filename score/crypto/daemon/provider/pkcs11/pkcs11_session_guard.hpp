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

#ifndef CRYPTO_DAEMON_PROVIDER_PKCS11_SESSION_GUARD_HPP
#define CRYPTO_DAEMON_PROVIDER_PKCS11_SESSION_GUARD_HPP

#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

namespace score::crypto::daemon::provider::pkcs11
{

/// @brief RAII guard for pool-level PKCS#11 session acquire/release.
///
/// Wraps `Pkcs11Provider::AcquireSession` / `ReleaseSession` to guarantee that
/// every acquired session is returned to the pool on all code paths (including
/// exceptions and early returns).  This eliminates the fragile manual
/// release-on-error pattern in key factories and handler constructors.
///
/// ### Usage
/// ```cpp
/// Pkcs11SessionGuard guard(provider, requirements);
/// if (!guard) { return make_unexpected(guard.error()); }
/// CK_SESSION_HANDLE session = guard.get();
/// // ... use session ...
/// // on scope exit, guard releases the session back to the pool
/// ```
///
/// ### Ownership transfer
/// Call `release()` to yield ownership of the session handle (e.g. when the
/// session must outlive the guard, such as storing it in a handler instance).
/// After `release()`, the guard no longer calls `ReleaseSession`.
class Pkcs11SessionGuard final
{
  public:
    /// @brief Acquire a session from the provider pool.
    Pkcs11SessionGuard(Pkcs11Provider& provider, const Pkcs11HandlerRequirements& requirements) noexcept
        : m_provider{&provider}, m_requirements{requirements}
    {
        auto result = provider.AcquireSession(requirements);
        if (result.has_value())
        {
            m_session = result.value();
        }
        else
        {
            m_error = result.error();
        }
    }

    ~Pkcs11SessionGuard()
    {
        if (m_session != CK_INVALID_HANDLE && m_provider != nullptr)
        {
            m_provider->ReleaseSession(m_session, m_requirements);
        }
    }

    Pkcs11SessionGuard(const Pkcs11SessionGuard&) = delete;
    Pkcs11SessionGuard& operator=(const Pkcs11SessionGuard&) = delete;

    Pkcs11SessionGuard(Pkcs11SessionGuard&& other) noexcept
        : m_provider{other.m_provider},
          m_session{other.m_session},
          m_requirements{other.m_requirements},
          m_error{other.m_error}
    {
        other.m_session = CK_INVALID_HANDLE;
        other.m_provider = nullptr;
    }

    Pkcs11SessionGuard& operator=(Pkcs11SessionGuard&& other) noexcept
    {
        if (this != &other)
        {
            if (m_session != CK_INVALID_HANDLE && m_provider != nullptr)
            {
                m_provider->ReleaseSession(m_session, m_requirements);
            }
            m_provider = other.m_provider;
            m_session = other.m_session;
            m_requirements = other.m_requirements;
            m_error = other.m_error;
            other.m_session = CK_INVALID_HANDLE;
            other.m_provider = nullptr;
        }
        return *this;
    }

    /// @brief Check if the session was acquired successfully.
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return m_session != CK_INVALID_HANDLE;
    }

    /// @brief Get the acquired session handle.
    [[nodiscard]] CK_SESSION_HANDLE get() const noexcept
    {
        return m_session;
    }

    /// @brief Get the acquisition error (valid only when `!guard`).
    [[nodiscard]] score::crypto::daemon::common::DaemonErrorCode error() const noexcept
    {
        return m_error;
    }

    /// @brief Yield ownership of the session handle.
    ///
    /// After this call the guard will NOT release the session on destruction.
    /// The caller assumes responsibility for calling `ReleaseSession`.
    [[nodiscard]] CK_SESSION_HANDLE release() noexcept
    {
        CK_SESSION_HANDLE h = m_session;
        m_session = CK_INVALID_HANDLE;
        m_provider = nullptr;
        return h;
    }

  private:
    Pkcs11Provider* m_provider{nullptr};
    CK_SESSION_HANDLE m_session{CK_INVALID_HANDLE};
    Pkcs11HandlerRequirements m_requirements{};
    score::crypto::daemon::common::DaemonErrorCode m_error{score::crypto::daemon::common::DaemonErrorCode::kUnknown};
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // CRYPTO_DAEMON_PROVIDER_PKCS11_SESSION_GUARD_HPP
