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

#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_factory.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_slot_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"

#include "score/mw/log/logging.h"

namespace score::crypto::daemon::provider::pkcs11
{

// ============================================================================
// Construction
// ============================================================================

Pkcs11Provider::Pkcs11Provider(Pkcs11ProviderConfig config)
    : m_config{std::move(config)},
      m_initialized{false},
      m_module{nullptr},
      m_roPool{},
      m_rwPool{},
      m_maxRoSessions{0U},
      m_maxRwSessions{0U},
      m_authGuard{m_config.userPin},
      m_handlerFactory{nullptr}
{
}

Pkcs11Provider::Pkcs11Provider(Pkcs11ProviderConfig config, std::shared_ptr<Pkcs11Module> sharedModule)
    : m_config{std::move(config)},
      m_initialized{false},
      m_module{std::move(sharedModule)},
      m_roPool{},
      m_rwPool{},
      m_maxRoSessions{0U},
      m_maxRwSessions{0U},
      m_authGuard{m_config.userPin},
      m_handlerFactory{nullptr}
{
}

Pkcs11Provider::~Pkcs11Provider()
{
    Shutdown();
}

// ============================================================================
// IProvider::Initialize
// ============================================================================

bool Pkcs11Provider::Initialize(const ProviderInitContext& ctx)
{
    if (m_initialized)
    {
        return true;
    }

    m_numeric_id = ctx.numeric_id;
    m_provider_name = ctx.name;

    if (!InitialiseLibrary() || !AutodiscoverSlot() || !QuerySessionLimits() || !SeedSessionPool())
    {
        return false;
    }

    // NOTE: m_handlerFactory is NOT created here anymore. It will be lazily created
    // in GetCryptoHandlerFactory() after SetKeyManagementService() has been called.
    // This avoids circular dependencies where the factory needs the service.

    m_initialized = true;
    score::mw::log::LogDebug() << "[PKCS#11] Provider (ID:" << m_numeric_id << ", Name:" << m_provider_name
                               << ") initialised successfully";
    return true;
}

// ============================================================================
// Initialize helpers
// ============================================================================

bool Pkcs11Provider::InitialiseLibrary() noexcept
{
    // Create an exclusive module instance when no shared one was injected.
    if (m_module == nullptr)
    {
        m_module = std::make_shared<Pkcs11Module>();
    }

    // Shared modules may already be initialised by the caller (e.g. ProviderManager).
    if (m_module->IsInitialized())
    {
        return true;
    }

    const auto result = m_module->Init(m_config.initArgs);
    if (!result.has_value())
    {
        score::mw::log::LogError() << "[PKCS#11] Error: Failed to initialise module (error "
                                   << static_cast<int>(result.error()) << ")";
        return false;
    }
    return true;
}

bool Pkcs11Provider::AutodiscoverSlot() noexcept
{
    if (m_config.slotId != kSlotIdAutoDetect)
    {
        return true;  // Slot already specified — nothing to do.
    }

    if (m_config.tokenLabel.empty())
    {
        score::mw::log::LogError() << "[PKCS#11] Error: slotId is kSlotIdAutoDetect but tokenLabel is empty";
        return false;
    }

    const auto result = Pkcs11Module::FindSlotByToken(*m_module, m_config.tokenLabel, m_config.tokenModel);
    if (!result.has_value())
    {
        score::mw::log::LogError() << "[PKCS#11] Error: Failed to find slot for token '" << m_config.tokenLabel
                                   << "' (error:" << static_cast<int>(result.error()) << ")";
        return false;
    }

    m_config.slotId = result.value();
    return true;
}

bool Pkcs11Provider::QuerySessionLimits() noexcept
{
    // Two values indicate "no hard limit" in the PKCS#11 spec and must be treated as unlimited:
    //   0x00000000  — PKCS#11 v2.40 CK_EFFECTIVELY_INFINITE (SoftHSM uses this)
    //   0xFFFFFFFF  — PKCS#11 v3.0  CK_UNAVAILABLE_INFORMATION
    // In both cases cap at a safe default so the pool has a finite upper bound.
    constexpr CK_ULONG kNoLimit{0xFFFFFFFFUL};
    constexpr CK_ULONG kEffectivelyInfinite{0U};
    constexpr CK_ULONG kDefaultMaxSessions{32UL};

    CK_TOKEN_INFO tokenInfo{};
    const CK_RV rv = m_module->GetFunctionList()->C_GetTokenInfo(m_config.slotId, &tokenInfo);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << "[PKCS#11] Error: C_GetTokenInfo failed on slot" << m_config.slotId
                                   << " (rv=" << static_cast<unsigned long>(rv) << ")";
        return false;
    }

    const auto resolveLimit = [&](CK_ULONG tokenVal, std::uint32_t override_) -> CK_ULONG {
        if (override_ != 0U)
        {
            return static_cast<CK_ULONG>(override_);
        }
        const bool unlimited = (tokenVal == kNoLimit) || (tokenVal == kEffectivelyInfinite);
        return unlimited ? kDefaultMaxSessions : tokenVal;
    };

    m_maxRoSessions = resolveLimit(tokenInfo.ulMaxSessionCount, m_config.maxRoSessionsOverride);
    m_maxRwSessions = resolveLimit(tokenInfo.ulMaxRwSessionCount, m_config.maxRwSessionsOverride);
    return true;
}

bool Pkcs11Provider::SeedSessionPool() noexcept
{
    // Open one initial ReadOnly session to validate slot accessibility and seed the pool.
    auto seedSession = std::make_unique<SessionGuard>();
    const auto result = seedSession->Open(*m_module, m_config.slotId, Pkcs11SessionType::ReadOnly);
    if (!result.has_value())
    {
        score::mw::log::LogError() << "[PKCS#11] Error: Failed to open initial session on slot" << m_config.slotId
                                   << " (error" << static_cast<int>(result.error()) << ")";
        return false;
    }
    m_roPool.push_back(PooledSession{std::move(seedSession), false});
    return true;
}

// ============================================================================
// IProvider::Shutdown
// ============================================================================

void Pkcs11Provider::Shutdown()
{
    if (!m_initialized)
    {
        return;
    }

    m_handlerFactory.reset();

    // Close all pooled sessions (RAII via SessionGuard destructors).
    m_roPool.clear();
    m_rwPool.clear();

    m_module.reset();  // decrement shared refcount; C_Finalize only when last owner
    m_initialized = false;
}

// ============================================================================
// Session pool helpers
// ============================================================================

CK_SESSION_HANDLE Pkcs11Provider::AnyOpenSession() const noexcept
{
    for (const auto& entry : m_roPool)
    {
        if (entry.guard && entry.guard->IsOpen())
        {
            return entry.guard->Get();
        }
    }
    for (const auto& entry : m_rwPool)
    {
        if (entry.guard && entry.guard->IsOpen())
        {
            return entry.guard->Get();
        }
    }
    return CK_INVALID_HANDLE;
}

Expected<CK_SESSION_HANDLE, score::crypto::daemon::common::DaemonErrorCode> Pkcs11Provider::AcquireFromPool(
    std::vector<PooledSession>& pool,
    const Pkcs11SessionType sessionType,
    const CK_ULONG hardLimit) noexcept
{
    // Try to reuse an idle session.
    for (auto& entry : pool)
    {
        if (!entry.inUse)
        {
            entry.inUse = true;
            return entry.guard->Get();
        }
    }

    // No idle session -- check hard limit.
    if (static_cast<CK_ULONG>(pool.size()) >= hardLimit)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded);
    }

    // Open a new session.
    auto newSession = std::make_unique<SessionGuard>();
    const auto openResult = newSession->Open(*m_module, m_config.slotId, sessionType);
    if (!openResult.has_value())
    {
        return make_unexpected(openResult.error());
    }

    const CK_SESSION_HANDLE handle = newSession->Get();
    pool.push_back(PooledSession{std::move(newSession), true});
    return handle;
}

// ============================================================================
// AcquireSession / ReleaseSession
// ============================================================================

Expected<CK_SESSION_HANDLE, score::crypto::daemon::common::DaemonErrorCode> Pkcs11Provider::AcquireSession(
    const Pkcs11HandlerRequirements& requirements) noexcept
{
    std::lock_guard<std::mutex> lock(m_poolMutex);
    auto& pool = (requirements.sessionType == Pkcs11SessionType::ReadWrite) ? m_rwPool : m_roPool;
    const CK_ULONG limit =
        (requirements.sessionType == Pkcs11SessionType::ReadWrite) ? m_maxRwSessions : m_maxRoSessions;

    auto sessionResult = AcquireFromPool(pool, requirements.sessionType, limit);
    if (!sessionResult.has_value())
    {
        return sessionResult;
    }

    // Lazy login: elevate to User state if required and not already logged in.
    if (requirements.requiredAuth == Pkcs11TokenAuthState::User)
    {
        const auto loginResult = m_authGuard.EnsureUserState(sessionResult.value(), *m_module);
        if (!loginResult.has_value())
        {
            // Return session to pool on login failure.
            for (auto& entry : pool)
            {
                if (entry.guard && entry.guard->Get() == sessionResult.value())
                {
                    entry.inUse = false;
                    break;
                }
            }
            return make_unexpected(loginResult.error());
        }
    }

    return sessionResult;
}

void Pkcs11Provider::ReleaseSession(const CK_SESSION_HANDLE session,
                                    const Pkcs11HandlerRequirements& usedRequirements) noexcept
{
    std::lock_guard<std::mutex> lock(m_poolMutex);
    auto& pool = (usedRequirements.sessionType == Pkcs11SessionType::ReadWrite) ? m_rwPool : m_roPool;

    auto it = pool.end();
    for (auto candidate = pool.begin(); candidate != pool.end(); ++candidate)
    {
        if (candidate->guard && (candidate->guard->Get() == session))
        {
            it = candidate;
            break;
        }
    }

    // Notify auth guard while session is still open — OnUserHandlerReleased may
    // call C_Logout, which requires a valid handle.
    if (usedRequirements.requiredAuth == Pkcs11TokenAuthState::User)
    {
        m_authGuard.OnUserHandlerReleased(session, *m_module);
    }

    if (it != pool.end())
    {
        if (m_config.cleanupStrategy == Pkcs11SessionCleanupStrategy::kHardCleanup)
        {
            // Erase the entry: unique_ptr<SessionGuard> destructor calls Close(),
            // which calls C_CloseSession.  No closed-but-idle slots are left in
            // the pool; AcquireFromPool opens a fresh session when next needed.
            pool.erase(it);
        }
        else
        {
            it->inUse = false;
        }
    }
}

// ============================================================================
// Session validation
// ============================================================================

bool Pkcs11Provider::ValidateSession(const CK_SESSION_HANDLE session) const noexcept
{
    if ((session == CK_INVALID_HANDLE) || (m_module == nullptr))
    {
        return false;
    }
    CK_FUNCTION_LIST* const fns = m_module->GetFunctionList();
    if (fns == nullptr)
    {
        return false;
    }
    CK_SESSION_INFO info{};
    const CK_RV rv = fns->C_GetSessionInfo(session, &info);
    return (rv == CKR_OK);
}

// ============================================================================
// IProvider -- other interface methods
// ============================================================================

common::ProviderId Pkcs11Provider::GetProviderId() const
{
    return m_numeric_id;
}

const common::ProviderName& Pkcs11Provider::GetProviderName() const
{
    return m_provider_name;
}

handler::ICryptoHandlerFactory::Sptr Pkcs11Provider::GetCryptoHandlerFactory()
{
    if (!m_handlerFactory)
    {
        // Lazy creation: by the time this is called, SetKeyManagementService() has been
        // called by KeyManagementModule::Create(), so the service is guaranteed to be available.
        m_handlerFactory = std::make_shared<Pkcs11HandlerFactory>(*m_module, *this);
    }
    return m_handlerFactory;
}

std::shared_ptr<key_management::IKeyFactory> Pkcs11Provider::GetKeyFactory()
{
    if (!m_key_factory)
    {
        // Lazy initialization: ensure key store exists first
        if (!m_key_store)
        {
            m_key_store = std::make_shared<Pkcs11KeyStore>(shared_from_this(), m_module);
        }
        m_key_factory = std::make_shared<Pkcs11KeyFactory>(shared_from_this(), m_module, m_key_store);
    }
    return m_key_factory;
}

std::shared_ptr<key_management::IKeySlotHandler> Pkcs11Provider::GetKeySlotHandler(
    const key_management::KeySlotConfig& /*config*/)
{
    // Transient: a new Pkcs11KeySlotHandler is created per call and destroyed after
    // the operation. The shared Pkcs11KeyStore (opaque-id table) is retained
    // via m_key_store so PKCS#11 object handles remain valid across calls.

    // Ensure key store exists
    if (!m_key_store)
    {
        m_key_store = std::make_shared<Pkcs11KeyStore>(shared_from_this(), m_module);
    }
    return std::make_shared<Pkcs11KeySlotHandler>(shared_from_this(), m_module, m_key_store);
}

}  // namespace score::crypto::daemon::provider::pkcs11
