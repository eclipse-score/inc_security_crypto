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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/key_management/core/key_management_service.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/provider/i_provider.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/factory/pkcs11_handler_factory.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include <cryptoki.h>
#include <pkcs11.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declarations
class Pkcs11KeyStore;
class Pkcs11KeyFactory;
class Pkcs11KeyManagementHandler;

/// @brief PKCS#11 provider -- one instance per token/slot.
///
/// Supports crypto operations (hash, MAC via PKCS#11 C_Digest*/C_Sign*) and
/// key management (key generation, import, slot loading via PKCS#11
/// C_GenerateKey / C_CreateObject / C_FindObjects).
///
/// Owns a shared Pkcs11Module (library lifecycle), a token-wide TokenAuthGuard,
/// and two session pools:
///   - m_roPool: ReadOnly sessions for hash, verify, sign, encrypt, decrypt, MAC, AEAD
///   - m_rwPool: ReadWrite sessions for key generation, persistence, import, deletion
///
/// Sessions are acquired per-handler (one active PKCS#11 operation per session)
/// and returned to the pool on handler destruction.  Login/logout is deferred:
/// C_Login is called on the first User-state handler acquisition; C_Logout is called
/// when the last User-state handler is released.
class Pkcs11Provider final : public IProvider, public std::enable_shared_from_this<Pkcs11Provider>
{
  public:
    /// @brief Construct provider with an exclusive PKCS#11 module (single-provider path).
    explicit Pkcs11Provider(Pkcs11ProviderConfig config);

    /// @brief Construct provider with a shared, pre-initialized PKCS#11 module.
    ///
    /// Use this constructor when multiple token-bound providers share the same linked
    /// PKCS#11 library.  The caller (e.g. ProviderManager) must call sharedModule->Init()
    /// before constructing any provider with it.  C_Finalize is deferred until the last
    /// shared_ptr owner is destroyed -- guaranteeing all sessions are closed first.
    Pkcs11Provider(Pkcs11ProviderConfig config, std::shared_ptr<Pkcs11Module> sharedModule);

    ~Pkcs11Provider() override;

    Pkcs11Provider(const Pkcs11Provider&) = delete;
    Pkcs11Provider& operator=(const Pkcs11Provider&) = delete;
    Pkcs11Provider(Pkcs11Provider&&) = delete;
    Pkcs11Provider& operator=(Pkcs11Provider&&) = delete;

    // --- IProvider interface ---

    [[nodiscard]] bool Initialize(const ProviderInitContext& ctx) override;
    void Shutdown() override;
    [[nodiscard]] common::ProviderId GetProviderId() const override;
    [[nodiscard]] const common::ProviderName& GetProviderName() const override;

    // --- Crypto capability ---

    [[nodiscard]] std::shared_ptr<handler::ICryptoHandlerFactory> GetCryptoHandlerFactory() override;

    // --- Key management capability ---

    /// Return the PKCS#11 key factory.
    [[nodiscard]] std::shared_ptr<key_management::IKeyFactory> GetKeyFactory() override;

    /// @brief Inject the key management service for key DataNode lifecycle management.
    void SetKeyManagementService(std::shared_ptr<key_management::KeyManagementService> service) override
    {
        m_keyManagementService = std::move(service);
    }

    /// @brief Get the injected key management service (may be null if not yet injected).
    [[nodiscard]] std::shared_ptr<key_management::KeyManagementService> GetKeyManagementService() const
    {
        return m_keyManagementService;
    }

    /// @brief Return a key slot handler for the given slot configuration.
    ///
    /// Returns a new Pkcs11KeySlotHandler per call. The shared Pkcs11KeyHandler
    /// (key map + session pool) is retained via m_key_handler so PKCS#11 object
    /// handles remain valid across calls.
    [[nodiscard]] std::shared_ptr<key_management::IKeySlotHandler> GetKeySlotHandler(
        const key_management::KeySlotConfig& config) override;

    // --- Session pool API (called by handlers via factory) ---

    /// @brief Acquire a session for an operation handler.
    ///
    /// 1. If requiredAuth==User and token is Public -> lazy C_Login.
    /// 2. Reuse an idle session from the appropriate pool (RO or RW).
    /// 3. Open a new session if no idle slot and pool limit not reached.
    /// 4. Return ERROR_RESOURCE_EXHAUSTED if pool is at the hard limit.
    [[nodiscard]] Expected<CK_SESSION_HANDLE, score::crypto::daemon::common::DaemonErrorCode> AcquireSession(
        const Pkcs11HandlerRequirements& requirements) noexcept;

    /// @brief Return a session from a handler being destroyed.
    ///
    /// 1. Mark session slot idle in the appropriate pool.
    /// 2. If usedAuth==User -> decrement active-user-handler count.
    /// 3. If count reaches zero -> C_Logout (token reverts to Public).
    void ReleaseSession(CK_SESSION_HANDLE session, const Pkcs11HandlerRequirements& usedRequirements) noexcept;

    /// @brief Validate that a session handle is still usable.
    ///
    /// Calls C_GetSessionInfo to verify the session has not been closed or
    /// invalidated (e.g. after token removal or HSM error).
    /// @return true if the session is valid and open, false otherwise.
    [[nodiscard]] bool ValidateSession(CK_SESSION_HANDLE session) const noexcept;

  private:
    /// @brief A pooled session entry.
    struct PooledSession
    {
        std::unique_ptr<SessionGuard> guard;
        bool inUse{false};
    };

    /// @brief Try to acquire from pool; open new session if no idle entry and under limit.
    [[nodiscard]] Expected<CK_SESSION_HANDLE, score::crypto::daemon::common::DaemonErrorCode>
    AcquireFromPool(std::vector<PooledSession>& pool, Pkcs11SessionType sessionType, CK_ULONG hardLimit) noexcept;

    /// @brief Return any open session handle for token-wide operations (login/logout).
    /// Returns CK_INVALID_HANDLE if no session is open at all.
    [[nodiscard]] CK_SESSION_HANDLE AnyOpenSession() const noexcept;

    // --- Initialize helpers (called in order by Initialize()) ---

    /// @brief Ensure m_module is created and C_Initialize has been called.
    /// @return false and logs on failure.
    [[nodiscard]] bool InitialiseLibrary() noexcept;

    /// @brief Resolve the concrete slot ID when slotId == kSlotIdAutoDetect.
    /// @return false and logs on failure.
    [[nodiscard]] bool AutodiscoverSlot() noexcept;

    /// @brief Query C_GetTokenInfo and populate m_maxRoSessions / m_maxRwSessions.
    /// @return false and logs on failure.
    [[nodiscard]] bool QuerySessionLimits() noexcept;

    /// @brief Open the initial ReadOnly seed session and push it onto m_roPool.
    /// @return false and logs on failure.
    [[nodiscard]] bool SeedSessionPool() noexcept;

    Pkcs11ProviderConfig m_config;
    bool m_initialized{false};
    common::ProviderId m_numeric_id{common::kInvalidProviderId};
    common::ProviderName m_provider_name{};
    std::shared_ptr<Pkcs11Module> m_module;  ///< shared across all providers on the same library

    std::vector<PooledSession> m_roPool;  ///< ReadOnly sessions
    std::vector<PooledSession> m_rwPool;  ///< ReadWrite sessions
    CK_ULONG m_maxRoSessions{0U};         ///< from C_GetTokenInfo.ulMaxSessionCount
    CK_ULONG m_maxRwSessions{0U};         ///< from C_GetTokenInfo.ulMaxRwSessionCount

    mutable std::mutex m_poolMutex;  ///< Protects m_roPool, m_rwPool against concurrent access
    TokenAuthGuard m_authGuard;      ///< token-wide login state + User refcount
    handler::ICryptoHandlerFactory::Sptr m_handlerFactory;

    /// @brief Key store: opaque-id ↔ (session, object) translation table.
    std::shared_ptr<Pkcs11KeyStore> m_key_store;
    /// @brief Key factory: GenerateKey and ImportKey implementation.
    std::shared_ptr<Pkcs11KeyFactory> m_key_factory;
    key_management::KeyManagementService::Sptr m_keyManagementService;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_PROVIDER_HPP
