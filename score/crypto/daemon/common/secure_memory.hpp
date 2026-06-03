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

#ifndef SCORE_CRYPTO_DAEMON_COMMON_SECURE_MEMORY_HPP
#define SCORE_CRYPTO_DAEMON_COMMON_SECURE_MEMORY_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#if defined(__linux__)
#include <cstring>  // explicit_bzero
#elif defined(__QNX__)
#include <sys/neutrino.h>  // _NTO_VERSION
#if _NTO_VERSION >= 700
#include <string.h>  // memset_s
#endif
#endif

namespace score::crypto::daemon::common
{

/// @brief Securely zeroize memory. Guaranteed not to be optimized away.
///
/// Uses platform-specific primitives:
///   - Linux:   explicit_bzero
///   - QNX 7.0+: memset_s
///   - Fallback: manual loop with volatile ptr
///
/// No provider dependencies (no OpenSSL, PKCS#11, etc.).
inline void SecureZeroize(void* ptr, std::size_t len) noexcept
{
    if (ptr == nullptr || len == 0U)
    {
        return;
    }
#if defined(__linux__)
    explicit_bzero(ptr, len);
#elif defined(__QNX__) && (_NTO_VERSION >= 700)
    memset_s(ptr, len, 0, len);
#else
    // Volatile pointer prevents compiler from optimizing away the memset
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len-- > 0U)
    {
        *p++ = 0;
    }
#endif
}

/// @brief Securely zeroize a std::vector<uint8_t> and then clear it.
///
/// Zeroizes the buffer contents before clearing the vector, ensuring
/// sensitive data does not remain in freed heap memory.
inline void SecureZeroizeAndClear(std::vector<uint8_t>& v) noexcept
{
    if (!v.empty())
    {
        SecureZeroize(v.data(), v.size());
        v.clear();
    }
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_DAEMON_COMMON_SECURE_MEMORY_HPP
