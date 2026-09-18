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

#ifndef CRYPTO_IPC_CONFIG_H
#define CRYPTO_IPC_CONFIG_H

#include <string_view>

namespace score::crypto::ipc
{

// QNX: /tmp is /dev/shmem and does not support Unix domain sockets; use /opt instead
#ifdef __QNXNTO__
constexpr std::string_view kControlSocket = "/opt/crypto_daemon.sock";
#else
constexpr std::string_view kControlSocket = "/tmp/crypto_daemon.sock";
#endif

}  // namespace score::crypto::ipc

#endif  // CRYPTO_IPC_CONFIG_H
