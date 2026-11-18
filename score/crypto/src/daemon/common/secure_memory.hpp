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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_SECURE_MEMORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_SECURE_MEMORY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#if defined(__linux__)
#include <cstring>  // explicit_bzero
#elif defined(__QNX__)
#include <sys/neutrino.h>  // _NTO_VERSION
#if _NTO_VERSION >= 700
#include <string.h>  // memset_s
#else
#error "QNX versions lesser than 7.0 are not supported"
#endif
#else
#error "Unsupported platform: secure memory is supported only on Linux and QNX 7.0+"
#endif

namespace score::crypto::daemon::common
{

/// @brief Securely zeroize memory. Guaranteed not to be optimized away.
///
/// Uses platform-specific primitives:
///   - Linux:   explicit_bzero
///   - QNX 7.0+: memset_s
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

/// @brief Securely clear a byte buffer when leaving the current scope.
///
/// This guard is intended for buffers that temporarily contain credentials or
/// serialized secret configuration. Call Release() only after ownership of the
/// sensitive bytes has been intentionally transferred to another object.
class ScopedByteBufferZeroizer final
{
  public:
    explicit ScopedByteBufferZeroizer(std::vector<std::uint8_t>& buffer) noexcept : buffer_{buffer} {}

    ~ScopedByteBufferZeroizer()
    {
        if (armed_)
        {
            SecureZeroizeAndClear(buffer_);
        }
    }

    ScopedByteBufferZeroizer(const ScopedByteBufferZeroizer&) = delete;
    ScopedByteBufferZeroizer& operator=(const ScopedByteBufferZeroizer&) = delete;
    ScopedByteBufferZeroizer(ScopedByteBufferZeroizer&&) = delete;
    ScopedByteBufferZeroizer& operator=(ScopedByteBufferZeroizer&&) = delete;

    void Release() noexcept
    {
        armed_ = false;
    }

  private:
    std::vector<std::uint8_t>& buffer_;
    bool armed_{true};
};

/// @brief Securely zeroize a std::string and then clear it.
///
/// This overload is intended for short-lived credential copies. It clears the
/// currently active character range before resetting the string length.
inline void SecureZeroizeAndClear(std::string& value) noexcept
{
    if (!value.empty())
    {
        SecureZeroize(value.data(), value.size());
        value.clear();
    }
}

}  // namespace score::crypto::daemon::common

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_SECURE_MEMORY_HPP
