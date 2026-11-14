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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_DATA_NODE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_DATA_NODE_HPP

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include <memory>
#include <optional>

namespace score::crypto::daemon::common
{

/**
 * @brief DataNode specialization for storing crypto operation context information
 *
 * Stores the handler and the resolved algorithm of a crypto context. A context bound to
 * no algorithm, such as key management, holds none.
 * Used by MediatorImpl to persist context across multiple operations.
 *
 * Key binding lifecycle: when a key is bound to a context, the mediator
 * creates a child KeyDataNode under this context in the data tree.
 * Cascade deletion of this context automatically releases the key binding.
 */
class ContextDataNode : public data_manager::DataNode
{
  public:
    ContextDataNode(std::shared_ptr<Handler> handler, std::optional<score::crypto::AlgorithmDescriptor> algorithm);

    ~ContextDataNode() override;

    [[nodiscard]] data_manager::DataNodeType GetNodeType() const noexcept override
    {
        return data_manager::DataNodeType::kContext;
    }

    std::shared_ptr<Handler> GetHandler() const;
    const std::optional<score::crypto::AlgorithmDescriptor>& GetAlgorithm() const;

  private:
    std::shared_ptr<Handler> m_handler;
    std::optional<score::crypto::AlgorithmDescriptor> m_algorithm;
};

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_CONTEXT_CONTEXT_DATA_NODE_HPP
