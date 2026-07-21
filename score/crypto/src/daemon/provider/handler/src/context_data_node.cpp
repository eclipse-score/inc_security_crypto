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

#include "score/crypto/daemon/provider/handler/context_data_node.hpp"
#include "score/crypto/daemon/data_manager/data_node.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <string>
#include <utility>

namespace score::crypto::daemon::provider::handler
{

ContextDataNode::ContextDataNode(std::shared_ptr<score::crypto::daemon::provider::handler::Handler> handler,
                                 const std::string& algorithm)
    : DataNode(true), m_handler(std::move(handler)), m_algorithm(algorithm)
{
}

ContextDataNode::~ContextDataNode() = default;

std::shared_ptr<score::crypto::daemon::provider::handler::Handler> ContextDataNode::GetHandler() const
{
    return m_handler;
}

const std::string& ContextDataNode::GetAlgorithm() const
{
    return m_algorithm;
}

}  // namespace score::crypto::daemon::provider::handler
