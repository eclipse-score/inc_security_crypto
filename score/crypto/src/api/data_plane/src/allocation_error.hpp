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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SRC_ALLOCATION_ERROR_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SRC_ALLOCATION_ERROR_HPP

#include <cstdint>

namespace score
{

namespace crypto
{

/// @brief Error codes for pool/bulk SHM allocation failures.
///
/// TODO : why not combine with error codes from the daemon?
enum class AllocationError : std::uint32_t
{
    kQuotaExhausted = 0x0001,
    kConcurrentLimitHit = 0x0002,
    kFragmentationError = 0x0003,
    kPoolNotInitialized = 0x0004,
    kActivationFailed = 0x0005,
    kInvalidArgument = 0x0007,
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SRC_ALLOCATION_ERROR_HPP
