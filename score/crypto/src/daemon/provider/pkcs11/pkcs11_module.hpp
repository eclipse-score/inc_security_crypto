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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MODULE_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MODULE_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

/// @brief Capability flags queried once at module initialisation.
struct Pkcs11Capabilities
{
    std::uint8_t versionMajor{0U};
    std::uint8_t versionMinor{0U};
    bool supportsMessageDigest{false};  ///< true if PKCS#11 v3.0+ C_MessageDigest* is available
};

/// @brief Session access type.
///
/// ReadOnly: sufficient for digest, verify, sign, encrypt/decrypt, MAC, AEAD (reads keys, never creates).
/// ReadWrite: required for key generation, key import, persist, unwrap, delete — any write to token objects.
enum class Pkcs11SessionType : std::uint8_t
{
    ReadOnly = 0U,  ///< CKF_SERIAL_SESSION — sufficient for all read and cryptographic ops
    ReadWrite = 1U  ///< CKF_SERIAL_SESSION | CKF_RW_SESSION — required for key creation/deletion/persistence
};

/// @brief Token-wide authentication state.
///
/// PKCS#11 login is token-wide: C_Login on any session elevates ALL open sessions on the token.
/// SO is intentionally absent — the SCORE stack is always normal User.
enum class Pkcs11TokenAuthState : std::uint8_t
{
    Public = 0U,  ///< No login — digest, verify, RNG, public cert ops
    User = 1U     ///< C_Login(CKU_USER) — sign, encrypt, decrypt, MAC, AEAD, all key mgmt ops
};

/// @brief Static session + auth requirements declared by each handler type.
///
/// Used by Pkcs11HandlerFactory to call AcquireSession with correct parameters,
/// and by handlers to call ReleaseSession with correct accounting on destruction.
struct Pkcs11HandlerRequirements
{
    Pkcs11SessionType sessionType;      ///< ReadOnly or ReadWrite (fixed at C_OpenSession)
    Pkcs11TokenAuthState requiredAuth;  ///< Public or User (token-wide state)
};

// Forward declaration — full definition follows SessionGuard below.
class Pkcs11Module;

/// @brief Manages token-wide login state and reference-counts active User-authenticated handlers.
///
/// PKCS#11 invariant: C_Login elevates ALL sessions on the token simultaneously.
/// C_Logout also reverts ALL sessions.  This guard tracks how many handlers currently
/// require User state so logout is deferred until the last such handler is released.
///
/// The user PIN is provided once at construction.  An empty PIN is valid —
/// some PKCS#11 implementations (e.g. certain smart-card middleware) accept a
/// zero-length PIN for token login.
class TokenAuthGuard final
{
  public:
    /// @brief Construct with the user PIN for this token.
    /// @param pin  User PIN.  Empty string is valid (zero-length PIN login).
    explicit TokenAuthGuard(std::string_view pin) noexcept;

    /// @brief Default-construct with no PIN (Public-only operations).
    TokenAuthGuard() noexcept = default;
    ~TokenAuthGuard() = default;

    TokenAuthGuard(const TokenAuthGuard&) = delete;
    TokenAuthGuard& operator=(const TokenAuthGuard&) = delete;
    TokenAuthGuard(TokenAuthGuard&&) = delete;
    TokenAuthGuard& operator=(TokenAuthGuard&&) = delete;

    /// @brief Ensure token is in User state.  No-op if already logged in.
    /// @param anySession  Any currently-open session on this token (login is token-wide).
    /// @param module      The owning module; its function list is used for C_Login.
    /// @note  Uses the PIN supplied at construction.
    /// @note  Increments the active-user-handler reference count on success.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> EnsureUserState(
        CK_SESSION_HANDLE anySession,
        const Pkcs11Module& module) noexcept;

    /// @brief Notify that a handler which required User state has been destroyed.
    ///
    /// Always decrements the reference count and, when it reaches zero, reverts the
    /// token state to Public.  C_Logout is issued only when anySession is valid;
    /// passing CK_INVALID_HANDLE is safe — the PKCS#11 spec guarantees the token
    /// reverts to Public automatically when all its sessions are closed.
    /// @param anySession  Any currently-open session on this token, or CK_INVALID_HANDLE.
    /// @param module      The owning module; its function list is used for C_Logout.
    void OnUserHandlerReleased(CK_SESSION_HANDLE anySession, const Pkcs11Module& module) noexcept;

    /// @brief Current token-wide auth state.
    [[nodiscard]] Pkcs11TokenAuthState GetCurrentState() const noexcept;

    /// @brief Number of active handlers currently holding User-state sessions.
    [[nodiscard]] std::uint32_t GetActiveUserHandlerCount() const noexcept;

  private:
    mutable std::mutex m_mutex;  ///< Protects m_state and m_activeUserCount against concurrent access
    std::string m_pin;           ///< User PIN for C_Login (empty is valid for some implementations)
    Pkcs11TokenAuthState m_state{Pkcs11TokenAuthState::Public};
    std::uint32_t m_activeUserCount{0U};
};

/// @brief Session cleanup strategy after handler destruction.
///
/// Determines how thoroughly to clean session state when a handler is destroyed,
/// particularly important for interrupted/aborted streaming operations.
/// The correct choice depends on the PKCS#11 implementation's cleanup robustness.
enum class Pkcs11SessionCleanupStrategy : std::uint8_t
{
    /// Soft cleanup (default): Call C_DigestFinal (or equivalent) with dummy buffer.
    ///
    /// Complies with PKCS#11 spec v2.40+ — operation completes and session returns to IDLE.
    /// Works reliably with modern implementations (SoftHSM 2.6+, Thales Luna, YubiHSM).
    /// Internal session state varies by implementation but is functionally clean for next operation.
    /// Pros: Fast, efficient, spec-compliant, minimal overhead
    /// Cons: May leave residual data in implementations with incomplete cleanup
    /// Reference: PKCS#11 v3.0, C_DigestFinal, etc. complete operations atomically.
    kSoftCleanup = 0U,

    /// Hard cleanup: Close and reopen session with C_CloseSession + C_OpenSession.
    ///
    /// Guarantees complete session reset REGARDLESS of PKCS#11 implementation quality.
    /// Useful for: Security-critical deployments, untrusted/legacy PKCS#11 implementations,
    /// strict zero-state requirements, or hardware that exhibits cleanup bugs.
    /// Pros: Most thorough, guaranteed fresh state, avoids residual state issues
    /// Cons: Slower (two extra system calls), higher overhead, requires RW session to reopen
    /// Note: Applied only during soft-cleanup failure or when explicitly required.
    kHardCleanup = 1U
};

/// @brief Sentinel value for Pkcs11ProviderConfig::slotId indicating that the slot
/// should be auto-discovered by matching tokenLabel (and optionally tokenModel)
/// via C_GetSlotList + C_GetTokenInfo at Initialize() time.
inline constexpr CK_SLOT_ID kSlotIdAutoDetect{static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION)};

/// @brief Configuration for a PKCS#11 provider instance (one token = one config).
struct Pkcs11ProviderConfig
{
    /// @brief Slot ID of the target token.
    ///        Set to kSlotIdAutoDetect to auto-discover the slot by tokenLabel/tokenModel.
    CK_SLOT_ID slotId{kSlotIdAutoDetect};

    /// @brief Human-readable token label (padded to 32 chars by PKCS#11).
    ///        Used for slot auto-discovery when slotId == kSlotIdAutoDetect.
    std::string tokenLabel{};

    /// @brief Optional token model string for disambiguation when multiple tokens
    ///        share the same label.  Empty = match by label only.
    std::string tokenModel{};

    /// @brief User PIN for lazy C_Login on first User-state handler.
    ///        Empty string is valid — some PKCS#11 implementations accept zero-length PIN.
    ///        Leave empty if only Public operations are needed.
    std::string userPin{};

    std::string providerName{};
    std::uint32_t maxRoSessionsOverride{0U};  ///< 0 = read from C_GetTokenInfo.ulMaxSessionCount
    std::uint32_t maxRwSessionsOverride{0U};  ///< 0 = read from C_GetTokenInfo.ulMaxRwSessionCount
    Pkcs11SessionCleanupStrategy cleanupStrategy{Pkcs11SessionCleanupStrategy::kSoftCleanup};

    /// @brief Optional C_Initialize arguments (thread-safety flags, mutex callbacks).
    ///        Nullptr = library-default behaviour.
    CK_C_INITIALIZE_ARGS* initArgs{nullptr};

    // sessionType intentionally removed — session type is now per-handler via Pkcs11HandlerRequirements
    // soPin intentionally absent — SO role is never used in the SCORE stack
};

/// @brief RAII guard for C_Initialize / C_Finalize lifecycle.
///
/// Owns C_Finalize ONLY if it itself called C_Initialize successfully (rv == CKR_OK).
/// If C_Initialize returns CKR_CRYPTOKI_ALREADY_INITIALIZED the guard does NOT take
/// ownership — it will not call C_Finalize on destruction.  This prevents premature
/// library teardown when multiple Pkcs11Module instances exist.
/// For multi-provider deployments, share a single Pkcs11Module via std::shared_ptr.
class ModuleGuard final
{
  public:
    ModuleGuard() noexcept;
    ~ModuleGuard();

    ModuleGuard(const ModuleGuard&) = delete;
    ModuleGuard& operator=(const ModuleGuard&) = delete;
    ModuleGuard(ModuleGuard&& other) noexcept;
    ModuleGuard& operator=(ModuleGuard&& other) noexcept;

    /// @brief Calls C_Initialize with the given init args.
    /// @param initArgs  Optional CK_C_INITIALIZE_ARGS (thread-safety flags, mutex callbacks, etc.).
    ///                  Pass nullptr for library-default behaviour (single-threaded / OS locking).
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Initialize(
        CK_C_INITIALIZE_ARGS* initArgs = nullptr) noexcept;

    /// @brief Returns true if C_Initialize succeeded.
    [[nodiscard]] bool IsInitialized() const noexcept;

  private:
    bool m_initialized;
};

/// @brief RAII guard for C_OpenSession / C_CloseSession lifecycle.
class SessionGuard final
{
  public:
    SessionGuard() noexcept;
    ~SessionGuard();

    SessionGuard(const SessionGuard&) = delete;
    SessionGuard& operator=(const SessionGuard&) = delete;
    SessionGuard(SessionGuard&& other) noexcept;
    SessionGuard& operator=(SessionGuard&& other) noexcept;

    /// @brief Opens a session on the given slot.
    /// @param module      The owning module; its function list is cached for Close().
    /// @param slotId      The token slot to open a session on.
    /// @param sessionType ReadOnly (digest, verify) or ReadWrite (key gen, object creation).
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Open(
        const Pkcs11Module& module,
        CK_SLOT_ID slotId,
        Pkcs11SessionType sessionType = Pkcs11SessionType::ReadOnly) noexcept;

    /// @brief Returns the managed session handle. Only valid when open.
    [[nodiscard]] CK_SESSION_HANDLE Get() const noexcept;

    /// @brief Returns true if session is open.
    [[nodiscard]] bool IsOpen() const noexcept;

  private:
    void Close() noexcept;
    CK_FUNCTION_LIST*
        m_functionList;  ///< cached from module.GetFunctionList() at Open(); outlives module during shutdown
    CK_SESSION_HANDLE m_session;
    bool m_open;
};

/// @brief Thin RAII wrapper around a linked PKCS#11 library's CK_FUNCTION_LIST.
///
/// Obtained via C_GetFunctionList() from the already-linked library (no dlopen).
/// Queries CK_INFO.cryptokiVersion once at Init() to populate capability flags.
class Pkcs11Module final
{
  public:
    Pkcs11Module() noexcept;
    ~Pkcs11Module() = default;

    Pkcs11Module(const Pkcs11Module&) = delete;
    Pkcs11Module& operator=(const Pkcs11Module&) = delete;
    Pkcs11Module(Pkcs11Module&&) noexcept = default;
    Pkcs11Module& operator=(Pkcs11Module&&) noexcept = default;

    /// @brief Obtains CK_FUNCTION_LIST, calls C_Initialize, queries version info.
    /// @param initArgs  Optional CK_C_INITIALIZE_ARGS forwarded to ModuleGuard::Initialize.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Init(
        CK_C_INITIALIZE_ARGS* initArgs = nullptr) noexcept;

    /// @brief Auto-discover the slot ID for a token by label (and optionally model).
    ///
    /// Enumerates all slots with a token present via C_GetSlotList(CK_TRUE),
    /// calls C_GetTokenInfo on each, and returns the first slot whose label
    /// matches @p tokenLabel (space-trimmed comparison).  If @p tokenModel is
    /// non-empty, the model field must also match.
    ///
    /// Additionally verifies that CKF_TOKEN_INITIALIZED is set — uninitialised
    /// tokens are skipped.
    ///
    /// @param module      Initialised module whose function list is used for enumeration.
    /// @param tokenLabel  Required token label to match.
    /// @param tokenModel  Optional model string (empty = match label only).
    /// @return Slot ID on success, or error (ERROR_RESOURCE_EXHAUSTED if no match).
    [[nodiscard]] static Expected<CK_SLOT_ID, score::crypto::daemon::common::DaemonErrorCode>
    FindSlotByToken(const Pkcs11Module& module, std::string_view tokenLabel, std::string_view tokenModel = {}) noexcept;

    /// @brief Returns the function list pointer. Only valid after successful Init().
    [[nodiscard]] CK_FUNCTION_LIST* GetFunctionList() const noexcept;

    /// @brief Returns capability flags queried at init time.
    [[nodiscard]] const Pkcs11Capabilities& GetCapabilities() const noexcept;

    /// @brief Returns true if Init() has completed successfully.
    /// Use this to avoid calling Init() on a shared module that was already initialised.
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Exhaustive mapping from CK_RV to score::crypto::daemon::common::DaemonErrorCode.
    [[nodiscard]] static score::crypto::daemon::common::DaemonErrorCode MapErrorReturn(CK_RV rv) noexcept;

  private:
    CK_FUNCTION_LIST* m_functionList;
    ModuleGuard m_moduleGuard;
    Pkcs11Capabilities m_capabilities;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MODULE_HPP
