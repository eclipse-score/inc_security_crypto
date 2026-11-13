/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_TRUST_STORE_BINDING_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_TRUST_STORE_BINDING_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

#include <memory>
#include <optional>
#include <variant>

namespace score::crypto::daemon::cert_management
{

/// @brief One client's reference on a trust store, held for the lifetime of a verification session.
///
/// Bind() takes the new reference through TrustStoreManager::AddRef() before it drops the current one, so a failed bind
/// leaves the current binding in place and holds no reference of its own. Release() and the destructor drop the held
/// reference through TrustStoreManager::ReleaseRef(). The binding is neither copyable nor movable.
class TrustStoreBinding final
{
  public:
    /// @brief Construct an unbound binding.
    /// @param trust_store_manager Manager that owns the trust stores. Must be non-null.
    /// @param client_id Client on whose behalf the references are taken.
    TrustStoreBinding(TrustStoreManager::Sptr trust_store_manager, data_manager::ClientId client_id);

    /// @brief Drop the held reference, if any.
    ~TrustStoreBinding();

    TrustStoreBinding(const TrustStoreBinding&) = delete;
    TrustStoreBinding& operator=(const TrustStoreBinding&) = delete;
    TrustStoreBinding(TrustStoreBinding&&) = delete;
    TrustStoreBinding& operator=(TrustStoreBinding&&) = delete;

    /// @brief Bind the store identified by @p handle in place of the current binding.
    /// @param handle Trust store to bind.
    /// @return Success, or the error from AddRef(). On failure the current binding is unchanged.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> Bind(TrustStoreHandle handle);

    /// @brief Drop the held reference, if any, and leave the binding empty.
    void Release();

    /// @brief Return the bound store handle.
    /// @return The handle, or an empty optional when nothing is bound.
    [[nodiscard]] std::optional<TrustStoreHandle> Handle() const noexcept;

  private:
    TrustStoreManager::Sptr m_trust_store_manager;  ///< Owns the bound store and receives the release.
    data_manager::ClientId m_client_id;             ///< Client that holds the reference.
    std::optional<TrustStoreHandle> m_handle;       ///< Bound store; empty when unbound.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_TRUST_STORE_BINDING_HPP
