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

#ifndef CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_MANAGER_TOKEN_HPP_
#define CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_MANAGER_TOKEN_HPP_

namespace score::crypto::daemon::data_manager
{

class DataManager;  // forward-declare

/**
 * @brief Capability token restricting mutation of DataNode fields to the DataManager.
 *
 * All DataNode APIs that modify internal state (e.g. setNodeId(), setClientId(),
 * setParent(), addChild(), removeChild()) require a @c DataNodeManagerToken to be
 * passed by the caller.
 *
 * The constructor is private and only @c DataManager is declared as a friend,
 * so only the DataManager can create tokens.  This prevents arbitrary code from
 * directly mutating a node's identity or topology outside of the manager.
 */
class DataNodeManagerToken
{
  private:
    DataNodeManagerToken() = default;
    friend class DataManager;
};

}  // namespace score::crypto::daemon::data_manager

#endif  // CRYPTO_DAEMON_DATA_MANAGER_DATA_NODE_MANAGER_TOKEN_HPP_
