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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_CONTEXT_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_CONTEXT_HPP

#include "score/mw/crypto/api/common/types.hpp"  // OperationMode

#ifdef USE_RUST_PKCS11
    #include <pkcs11.h>
#else
    #include <cryptoki.h>
#endif

#include <cstddef>

namespace score::crypto::daemon::provider::pkcs11
{

/// Groups the stable per-context parameters for Pkcs11MacExecutor operations.
///
/// These values are established once during InitializeContext() and remain
/// constant for the lifetime of the handler context.  Passing them as a
/// struct reduces the executor's Execute() call from 9 parameters to 5,
/// improving readability and MISRA C++ Rule 8-0-1 compliance.
struct Pkcs11MacExecutionContext
{
    CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
    CK_MECHANISM mechanism{};
    CK_OBJECT_HANDLE key_object{CK_INVALID_HANDLE};
    std::size_t mac_size{0U};
    score::mw::crypto::OperationMode operation_mode{score::mw::crypto::OperationMode::kGenerate};
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_CONTEXT_HPP
