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

#include "score/crypto/src/daemon/common/context/context_data_node.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include <memory>
#include <optional>
#include <utility>

namespace score::crypto::daemon::provider::handler
{

ContextDataNode::ContextDataNode(std::shared_ptr<score::crypto::daemon::provider::handler::Handler> handler,
                                 std::optional<score::crypto::AlgorithmDescriptor> algorithm)
    : DataNode(true), m_handler(std::move(handler)), m_algorithm(algorithm)
{
}

ContextDataNode::~ContextDataNode() = default;

std::shared_ptr<score::crypto::daemon::provider::handler::Handler> ContextDataNode::GetHandler() const
{
    return m_handler;
}

const std::optional<score::crypto::AlgorithmDescriptor>& ContextDataNode::GetAlgorithm() const
{
    return m_algorithm;
}

}  // namespace score::crypto::daemon::provider::handler
