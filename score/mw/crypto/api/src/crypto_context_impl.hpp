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

#ifndef SCORE_MW_CRYPTO_API_SRC_CRYPTO_CONTEXT_IMPL_HPP
#define SCORE_MW_CRYPTO_API_SRC_CRYPTO_CONTEXT_IMPL_HPP

#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"
#include "score/crypto/daemon/control_plane/control_protocol.h"

#include "score/result/result.h"

#include <cstdint>
#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Concrete ICryptoContext implementation that delegates to the crypto daemon via IPC.
///
/// Factory methods to create CryptoContext (CreateHashContext, etc.)
/// send context-creation requests to the daemon and wrap the returned context_id
/// in the corresponding concrete context implementation.
class CryptoContextImpl final : public ICryptoContext
{
  public:
    /// @brief Constructs a crypto context with an established connection.
    /// @param connection Shared ownership of the connection (which contains the DataNodeId)
    CryptoContextImpl(std::shared_ptr<score::crypto::api::control_plane::IConnection> connection);

    ~CryptoContextImpl() override;

    // Deleted special members to prevent copying and moving
    CryptoContextImpl(const CryptoContextImpl&) = delete;
    CryptoContextImpl& operator=(const CryptoContextImpl&) = delete;
    CryptoContextImpl(CryptoContextImpl&&) = delete;
    CryptoContextImpl& operator=(CryptoContextImpl&&) = delete;

    // -- Resource Resolution --
    score::Result<CryptoResourceId> ResolveResource(const ResourceId& resource_id, ResourceType type) override;

    // -- Context Factory --
    score::Result<std::unique_ptr<IHashContext>> CreateHashContext(const HashContextConfig& config) override;
    score::Result<std::unique_ptr<IMacContext>> CreateMacContext(const MacContextConfig& config) override;
    score::Result<std::unique_ptr<IKeyManagementContext>> CreateKeyManagementContext(
        const KeyManagementContextConfig& config) override;

    // -- Queries --
    score::Result<AlgorithmCapabilities> QueryCapabilities(const AlgorithmId& algorithm) override;
    score::Result<SystemCapabilities> QueryCapabilities() override;
    score::Result<ProviderInfo> GetProviderInfo(uint16_t provider_id) override;
    score::Result<ProviderInfo> GetProviderInfo(const CryptoResourceId& resourceId) override;

    // -- Typed Object Access --
    score::Result<std::unique_ptr<IKeyObject>> GetKeyObject(const CryptoResourceId& id) override;
    score::Result<std::unique_ptr<IKeySlotObject>> GetKeySlotObject(const CryptoResourceId& id) override;

  private:
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_SRC_CRYPTO_CONTEXT_IMPL_HPP
