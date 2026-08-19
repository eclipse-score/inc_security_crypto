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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_STORE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_STORE_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/resolved_key.hpp"

#include <pkcs11.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "score/crypto/src/common/types.hpp"

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Provider;
class Pkcs11Module;

/// Attributes used to locate a token-object key via C_FindObjects.
///
/// Stored at registration time and used by ResolveObject() to find the key
/// on any handler session on demand.
struct SearchTemplate
{
    std::string label;                          ///< CKA_LABEL value (may be empty)
    std::vector<uint8_t> id;                    ///< CKA_ID bytes (may be empty)
    CK_OBJECT_CLASS obj_class{CKO_SECRET_KEY};  ///< CKA_CLASS
};

/// Runtime table mapping opaque key IDs to PKCS#11 session and object handles.
///
/// Pkcs11KeyStore owns the per-provider key state: each daemon-visible key ID
/// (uint64_t opaque_id) maps to a CK_OBJECT_HANDLE. Session objects additionally
/// carry the owning CK_SESSION_HANDLE (kept open to prevent underlying impl from
/// destroying the object). Token objects carry only a SearchTemplate so that
/// any number of handlers can independently resolve a session-local handle
/// via ResolveObject().
///
/// ### Key lifecycle — session objects (GenerateKey / ImportKey)
///   - Register:       opaque_id ← session + object handle (creating session kept open)
///   - ResolveObject:  returns the creating session + object handle; sets an atomic in-use
///                     flag that serializes concurrent access — only one handler may hold
///                     the creating session at a time.  Per PKCS#11 §4.10 a session
///                     object's handle is only valid in the session that created it.
///   - Release:        C_DestroyObject + return session to RW pool + erase entry
///
/// ### Key lifecycle — token objects (LoadKey)
///   - RegisterTokenObject: opaque_id ← SearchTemplate
///   - ResolveObject:  runs C_FindObjects on the caller's session → session-local handle;
///                     no lock is returned (token handles are session-independent)
///   - Release:        erase map entry only (HSM object remains on token)
///
/// ### Thread safety
///   All public methods protect m_keys with m_map_mutex (std::lock_guard).
class Pkcs11KeyStore
{
  public:
    /// Constructor.
    ///
    /// \param provider weak_ptr to the parent Pkcs11Provider (for session management)
    /// \param module   weak_ptr to the Pkcs11Module (for GetFunctionList access)
    Pkcs11KeyStore(std::weak_ptr<Pkcs11Provider> provider, std::weak_ptr<Pkcs11Module> module);

    ~Pkcs11KeyStore() = default;

    Pkcs11KeyStore(const Pkcs11KeyStore&) = delete;
    Pkcs11KeyStore& operator=(const Pkcs11KeyStore&) = delete;
    Pkcs11KeyStore(Pkcs11KeyStore&&) = delete;
    Pkcs11KeyStore& operator=(Pkcs11KeyStore&&) = delete;

    /// Register a session key (session + object for a newly generated or imported key).
    ///
    /// Called by Pkcs11KeyFactory::GenerateKey and Pkcs11KeyFactory::ImportKey.
    /// Assigns a new opaque_id and stores the session/object pair.
    [[nodiscard]] key_management::ProviderKeyHandle Register(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE object,
        const std::string& algorithm,
        std::size_t key_size,
        score::crypto::KeyOperationPermission permissions = score::crypto::KeyOperationPermission::kNone) noexcept;

    /// Register a persistent token object by storing its search template.
    ///
    /// Called by Pkcs11KeySlotHandler::LoadKey after C_FindObjects and
    /// C_GetAttributeValue succeed. No session is stored: the caller releases the
    /// find session back to the pool immediately. Future access uses ResolveObject()
    /// which re-runs C_FindObjects on the calling handler's session.
    [[nodiscard]] key_management::ProviderKeyHandle RegisterTokenObject(const SearchTemplate& search_template,
                                                                        const std::string& algorithm,
                                                                        std::size_t key_size) noexcept;

    /// Resolve a PKCS#11 key for use on a crypto handler session.
    ///
    /// For session-object keys (GenerateKey / ImportKey): atomically acquires the
    /// per-key in-use flag and returns a ResolvedKey that releases it on destruction.
    /// Returns kResourceBusy if the key is already held by another handler.
    ///
    /// For token-object keys (LoadKey): re-runs C_FindObjects on handler_session
    /// using the stored SearchTemplate.  Multiple handlers may hold the same token
    /// key concurrently (no exclusion flag).
    ///
    /// Error codes:
    ///   kInvalidResourceId — opaque_id not found in the key map
    ///   kResourceBusy      — session key already in use (session objects only)
    ///   kInvalidArgument   — handler_session is invalid (token objects only)
    ///   kInternalError     — module gone or C_FindObjects failure
    [[nodiscard]] score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode> ResolveObject(
        uint64_t opaque_id,
        CK_SESSION_HANDLE handler_session) noexcept;

    /// Look up the (session, object_handle) pair for a daemon-opaque key ID.
    ///
    /// For token objects the session field is CK_INVALID_HANDLE — use
    /// ResolveObject() when a live object handle is needed by a handler.
    [[nodiscard]] std::pair<CK_SESSION_HANDLE, CK_OBJECT_HANDLE> Lookup(uint64_t opaque_id) const noexcept;

    /// Destroy a PKCS#11 session key via C_DestroyObject and erase from map.
    ///
    /// Called by Pkcs11KeyHandler::Release. For persistent token objects only
    /// the map entry is erased; the HSM key object remains on the token.
    ///
    /// \param opaque_id The key ID to release
    /// \param key The ProviderKeyHandle from the dying key handler (unused for now,
    ///            kept for future extensibility)
    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Release(
        uint64_t opaque_id,
        const key_management::ProviderKeyHandle& key) noexcept;

  private:
    struct SessionKey
    {
        CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
        CK_OBJECT_HANDLE object{CK_INVALID_HANDLE};
        /// True for persistent token objects; Release does not call C_DestroyObject.
        bool is_token_object{false};
        /// Populated for token objects; used by ResolveObject() to locate
        /// the key via C_FindObjects on an arbitrary handler session.
        SearchTemplate token_search;
        /// Exclusive-use flag for session objects; acquired via test_and_set, cleared to release.
        /// Null for token objects. shared_ptr keeps the flag alive while ResolvedKey holds it.
        std::shared_ptr<std::atomic_flag> op_in_use;
    };

    std::weak_ptr<Pkcs11Provider> m_provider;
    std::weak_ptr<Pkcs11Module> m_module;  ///< for C_DestroyObject on release
    mutable std::mutex m_map_mutex;
    std::unordered_map<uint64_t, SessionKey> m_keys;  ///< opaque_id -> session+object
    uint64_t m_next_opaque_id{1U};
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_KEY_MANAGEMENT_PKCS11_KEY_STORE_HPP
