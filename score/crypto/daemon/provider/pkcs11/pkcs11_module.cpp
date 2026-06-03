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

#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"

#include "score/crypto/common/types.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/mw/log/logging.h"
#include <cstring>

#include <mutex>
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

// ============================================================================
// TokenAuthGuard
// ============================================================================

TokenAuthGuard::TokenAuthGuard(std::string_view pin) noexcept : m_pin{pin} {}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> TokenAuthGuard::EnsureUserState(
    const CK_SESSION_HANDLE anySession,
    const Pkcs11Module& module) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    CK_FUNCTION_LIST* const functionList = module.GetFunctionList();
    if (m_state == Pkcs11TokenAuthState::User)
    {
        // Already logged in — token is in User state for all sessions.
        m_activeUserCount++;
        return std::monostate{};
    }

    // Attempt C_Login via the stored function list — never through direct C-linkage —
    // so that the call correctly targets the library that owns this session.
    //
    // An empty PIN is valid for some PKCS#11 implementations (e.g. certain
    // smart-card middleware).  Per PKCS#11 spec, pPin may be NULL_PTR when
    // ulPinLen is 0.  We pass nullptr explicitly for the empty case so that
    // implementations that dereference pPin unconditionally do not fault.
    // MISRA C++:2023 Rule 8.2.3 + Rule 8.2.4 deviation — PKCS#11 C_Login requires CK_UTF8CHAR_PTR
    // (non-const). reinterpret_cast is needed because CK_UTF8CHAR is unsigned char while
    // std::string stores char.  The token will not modify the PIN data.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast)
    auto* pinData = m_pin.empty() ? static_cast<CK_UTF8CHAR_PTR>(nullptr)
                                  : const_cast<CK_UTF8CHAR_PTR>(reinterpret_cast<const CK_UTF8CHAR*>(m_pin.data()));
    const auto pinLen = static_cast<CK_ULONG>(m_pin.size());

    const CK_RV rv = functionList->C_Login(anySession, CKU_USER, pinData, pinLen);
    if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN))
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }

    m_state = Pkcs11TokenAuthState::User;
    m_activeUserCount++;
    return std::monostate{};
}

void TokenAuthGuard::OnUserHandlerReleased(const CK_SESSION_HANDLE anySession, const Pkcs11Module& module) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    CK_FUNCTION_LIST* const functionList = module.GetFunctionList();
    if (m_activeUserCount == 0U)
    {
        return;  // should not happen; guard against underflow
    }

    m_activeUserCount--;

    if (m_activeUserCount == 0U)
    {
        m_state = Pkcs11TokenAuthState::Public;
        if (anySession != CK_INVALID_HANDLE)
        {
            static_cast<void>(functionList->C_Logout(anySession));
        }
    }
}

Pkcs11TokenAuthState TokenAuthGuard::GetCurrentState() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

std::uint32_t TokenAuthGuard::GetActiveUserHandlerCount() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeUserCount;
}

// ============================================================================
// ModuleGuard
// ============================================================================

ModuleGuard::ModuleGuard() noexcept : m_initialized{false} {}

ModuleGuard::~ModuleGuard()
{
    if (m_initialized)
    {
        static_cast<void>(C_Finalize(nullptr));
        m_initialized = false;
    }
}

ModuleGuard::ModuleGuard(ModuleGuard&& other) noexcept : m_initialized{other.m_initialized}
{
    other.m_initialized = false;
}

ModuleGuard& ModuleGuard::operator=(ModuleGuard&& other) noexcept
{
    if (this != &other)
    {
        if (m_initialized)
        {
            static_cast<void>(C_Finalize(nullptr));
        }
        m_initialized = other.m_initialized;
        other.m_initialized = false;
    }
    return *this;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ModuleGuard::Initialize(
    CK_C_INITIALIZE_ARGS* initArgs) noexcept
{
    if (m_initialized)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlreadyInitialized);
    }

    const CK_RV rv = C_Initialize(static_cast<CK_VOID_PTR>(initArgs));
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        // Library was already initialised by another Pkcs11Module instance in this process.
        // This guard must NOT claim ownership of C_Finalize — it would prematurely
        // tear down the library while other sessions are still open.
        // Solution: share a single Pkcs11Module (via shared_ptr) across all providers
        // that use the same linked PKCS#11 library.
        return std::monostate{};
    }
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }

    m_initialized = true;  // This guard exclusively owns C_Finalize.
    return std::monostate{};
}

bool ModuleGuard::IsInitialized() const noexcept
{
    return m_initialized;
}

// ============================================================================
// SessionGuard
// ============================================================================

SessionGuard::SessionGuard() noexcept : m_functionList{nullptr}, m_session{CK_INVALID_HANDLE}, m_open{false} {}

SessionGuard::~SessionGuard()
{
    Close();
}

SessionGuard::SessionGuard(SessionGuard&& other) noexcept
    : m_functionList{other.m_functionList}, m_session{other.m_session}, m_open{other.m_open}
{
    other.m_functionList = nullptr;
    other.m_session = CK_INVALID_HANDLE;
    other.m_open = false;
}

SessionGuard& SessionGuard::operator=(SessionGuard&& other) noexcept
{
    if (this != &other)
    {
        Close();
        m_functionList = other.m_functionList;
        m_session = other.m_session;
        m_open = other.m_open;
        other.m_functionList = nullptr;
        other.m_session = CK_INVALID_HANDLE;
        other.m_open = false;
    }
    return *this;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
SessionGuard::Open(const Pkcs11Module& module, const CK_SLOT_ID slotId, const Pkcs11SessionType sessionType) noexcept
{
    if (m_open)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlreadyInitialized);
    }

    CK_FLAGS flags = CKF_SERIAL_SESSION;
    if (sessionType == Pkcs11SessionType::ReadWrite)
    {
        flags |= CKF_RW_SESSION;
    }

    // Cache the raw pointer now — Close() may be called from the destructor after
    // the Pkcs11Module has been destroyed during shutdown, so we must not retain
    // a reference to the module itself.
    CK_FUNCTION_LIST* const fl = module.GetFunctionList();
    const CK_RV rv = fl->C_OpenSession(slotId, flags, nullptr, nullptr, &m_session);
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }

    m_functionList = fl;  // cached for Close()
    m_open = true;
    return std::monostate{};
}

CK_SESSION_HANDLE SessionGuard::Get() const noexcept
{
    return m_session;
}

bool SessionGuard::IsOpen() const noexcept
{
    return m_open;
}

void SessionGuard::Close() noexcept
{
    if (m_open)
    {
        static_cast<void>(m_functionList->C_CloseSession(m_session));
        m_functionList = nullptr;
        m_session = CK_INVALID_HANDLE;
        m_open = false;
    }
}

// ============================================================================
// Pkcs11Module
// ============================================================================

Pkcs11Module::Pkcs11Module() noexcept : m_functionList{nullptr}, m_moduleGuard{}, m_capabilities{} {}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11Module::Init(
    CK_C_INITIALIZE_ARGS* initArgs) noexcept
{
    // Obtain the function list from the linked library
    const CK_RV rv = C_GetFunctionList(&m_functionList);
    if (rv != CKR_OK)
    {
        return make_unexpected(MapErrorReturn(rv));
    }

    if (m_functionList == nullptr)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUninitializedStack);
    }

    // Initialize the PKCS#11 module with optional init args
    const auto initResult = m_moduleGuard.Initialize(initArgs);
    if (!initResult.has_value())
    {
        return initResult;
    }

    // Query library info for version and capabilities
    CK_INFO info{};
    const CK_RV infoRv = m_functionList->C_GetInfo(&info);
    if (infoRv == CKR_OK)
    {
        m_capabilities.versionMajor = info.cryptokiVersion.major;
        m_capabilities.versionMinor = info.cryptokiVersion.minor;

        // PKCS#11 v3.0+ supports C_MessageDigest* APIs
        constexpr std::uint8_t kPkcs11V3Major{3U};
        m_capabilities.supportsMessageDigest = (m_capabilities.versionMajor >= kPkcs11V3Major);
    }

    return std::monostate{};
}

CK_FUNCTION_LIST* Pkcs11Module::GetFunctionList() const noexcept
{
    return m_functionList;
}

bool Pkcs11Module::IsInitialized() const noexcept
{
    return m_functionList != nullptr;
}

const Pkcs11Capabilities& Pkcs11Module::GetCapabilities() const noexcept
{
    return m_capabilities;
}

score::crypto::daemon::common::DaemonErrorCode Pkcs11Module::MapErrorReturn(const CK_RV rv) noexcept
{
    switch (rv)
    {
        case CKR_OK:
            score::mw::log::LogError()
                << "[PKCS11_MODULE] ERROR: Trying to map a success code to an error. This should not happen";
            return score::crypto::daemon::common::DaemonErrorCode::kOperationFailed;

        // Session / state errors
        case CKR_SESSION_HANDLE_INVALID:  // fallthrough
        case CKR_SESSION_CLOSED:          // fallthrough
        case CKR_SESSION_READ_ONLY:
            return score::crypto::daemon::common::DaemonErrorCode::kInvalidState;

        // Initialisation errors
        case CKR_CRYPTOKI_NOT_INITIALIZED:
            return score::crypto::daemon::common::DaemonErrorCode::kUninitializedStack;
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            return score::crypto::daemon::common::DaemonErrorCode::kAlreadyInitialized;

        // Operation errors
        case CKR_OPERATION_NOT_INITIALIZED:
            return score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized;
        case CKR_OPERATION_ACTIVE:
            return score::crypto::daemon::common::DaemonErrorCode::kOperationInProgress;
        case CKR_FUNCTION_NOT_SUPPORTED:
            return score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation;

        // Parameter / data errors
        case CKR_ARGUMENTS_BAD:  // fallthrough
        case CKR_DATA_INVALID:   // fallthrough
        case CKR_DATA_LEN_RANGE:
            return score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument;

        // Mechanism / algorithm errors
        case CKR_MECHANISM_INVALID:  // fallthrough
        case CKR_MECHANISM_PARAM_INVALID:
            return score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm;

        // Buffer errors
        case CKR_BUFFER_TOO_SMALL:
            return score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize;

        // Resource errors
        case CKR_HOST_MEMORY:  // fallthrough
        case CKR_DEVICE_MEMORY:
            return score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed;
        case CKR_SESSION_COUNT:  // fallthrough
        case CKR_TOKEN_NOT_PRESENT:
            return score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded;

        // Authentication
        case CKR_PIN_INCORRECT:  // fallthrough
        case CKR_PIN_LOCKED:     // fallthrough
        case CKR_USER_NOT_LOGGED_IN:
            return score::crypto::daemon::common::DaemonErrorCode::kInvalidContext;

        // General / device failures
        case CKR_DEVICE_ERROR:          // fallthrough
        case CKR_DEVICE_REMOVED:        // fallthrough
        case CKR_TOKEN_NOT_RECOGNIZED:  // fallthrough
        case CKR_GENERAL_ERROR:         // fallthrough
        case CKR_FUNCTION_FAILED:       // fallthrough
        default:
            return score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed;
    }
}

// ============================================================================
// Pkcs11Module::FindSlotByToken
// ============================================================================

/// @brief Trim trailing spaces from a PKCS#11 padded label/model field.
static std::string TrimTrailingSpaces(const unsigned char* field, std::size_t len) noexcept
{
    // PKCS#11 pads label/model to fixed width with trailing spaces.
    while ((len > 0U) && (field[len - 1U] == ' '))
    {
        --len;
    }
    // MISRA C++:2023 Rule 8.2.4 deviation — PKCS#11 CK_UTF8CHAR (unsigned char) → char for std::string.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::string(reinterpret_cast<const char*>(field), len);
}

Expected<CK_SLOT_ID, score::crypto::daemon::common::DaemonErrorCode> Pkcs11Module::FindSlotByToken(
    const Pkcs11Module& module,
    const std::string_view tokenLabel,
    const std::string_view tokenModel) noexcept
{
    CK_FUNCTION_LIST* const functionList = module.GetFunctionList();

    // 1. Enumerate slots that have a token present.
    CK_ULONG slotCount{0U};
    CK_RV rv = functionList->C_GetSlotList(CK_TRUE, nullptr, &slotCount);
    if (rv != CKR_OK)
    {
        return make_unexpected(MapErrorReturn(rv));
    }

    if (slotCount == 0U)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded);
    }

    std::vector<CK_SLOT_ID> slots(slotCount);
    rv = functionList->C_GetSlotList(CK_TRUE, slots.data(), &slotCount);
    if (rv != CKR_OK)
    {
        return make_unexpected(MapErrorReturn(rv));
    }

    // 2. Iterate slots, match label (+ optional model), skip uninitialised tokens.
    for (CK_ULONG i = 0U; i < slotCount; ++i)
    {
        CK_TOKEN_INFO tokenInfo{};
        rv = functionList->C_GetTokenInfo(slots[i], &tokenInfo);
        if (rv != CKR_OK)
        {
            continue;  // slot disappeared or inaccessible — skip
        }

        // Skip tokens that have not been initialised (no label/keys yet).
        if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0U)
        {
            continue;
        }

        // Compare label (trimmed).
        const std::string slotLabel = TrimTrailingSpaces(tokenInfo.label, sizeof(tokenInfo.label));
        if (slotLabel != tokenLabel)
        {
            continue;
        }

        // Optionally compare model.
        if (!tokenModel.empty())
        {
            const std::string slotModel = TrimTrailingSpaces(tokenInfo.model, sizeof(tokenInfo.model));
            if (slotModel != tokenModel)
            {
                continue;
            }
        }

        return slots[i];  // match found
    }

    // 3. No match.
    return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kQuotaExceeded);
}

}  // namespace score::crypto::daemon::provider::pkcs11
