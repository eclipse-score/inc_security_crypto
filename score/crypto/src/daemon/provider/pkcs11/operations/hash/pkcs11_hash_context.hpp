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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_CONTEXT_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_CONTEXT_HPP

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstddef>

namespace score::crypto::daemon::provider::pkcs11
{

/// Groups the stable per-context parameters for Pkcs11HashExecutor operations.
///
/// These values are established once during handler construction / InitializeContext()
/// and remain constant for the lifetime of the handler context.  Passing them as a
/// struct reduces the executor's Execute() parameter count, improving readability
/// and MISRA C++ Rule 8-0-1 compliance.
struct Pkcs11HashExecutionContext
{
    CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
    CK_MECHANISM mechanism{};
    std::size_t digest_size{0U};
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_CONTEXT_HPP
