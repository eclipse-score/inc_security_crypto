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

#ifndef SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_PROVIDER_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_PROVIDER_DATA_NODE_HPP

#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"

namespace score::crypto::daemon::mediator
{

/// @brief DataNode for a provider resolved from an application-scoped resource name.
///
/// Created by ResolveResource(name, kProvider). The client receives only the
/// node's DataNodeId, so the provider id and name stay inside the daemon. The
/// DataManager scopes the id to the owning client.
class ProviderDataNode final : public data_manager::DataNode
{
  public:
    explicit ProviderDataNode(common::ProviderId provider_id) : DataNode(false), m_provider_id{provider_id} {}

    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kProvider;
    }

    [[nodiscard]] common::ProviderId GetProviderId() const noexcept
    {
        return m_provider_id;
    }

  private:
    common::ProviderId m_provider_id;
};

}  // namespace score::crypto::daemon::mediator

#endif  // SCORE_CRYPTO_SRC_DAEMON_MEDIATOR_SRC_PROVIDER_DATA_NODE_HPP
