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

/// @file memory_allocator_example.cpp
/// @brief Demonstrates the data-plane shared memory allocator and zero-copy path.
///
/// Shows default and provider-compatible memory allocation, quota management,
/// and how shared memory regions are used with operation contexts.

#include "score/mw/crypto/api/common/i_memory_allocator.hpp"
#include "score/mw/crypto/api/common/i_memory_region.hpp"
#include "score/mw/crypto/api/config/hash_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_hash_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>

using namespace score::mw::crypto;

int main()
{
    // 1. Create crypto stack
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///var/run/crypto-daemon.sock");

    auto stack = CreateCryptoStack(stack_config).value();

    // ──────────────────────────────────────────────────────────────────────
    // 2. Access the memory allocator (data plane, lifetime tied to stack)
    // ──────────────────────────────────────────────────────────────────────
    auto allocator_result = stack->GetMemoryAllocator();
    if (!allocator_result)
    {
        std::cerr << "Failed to access memory allocator: " << allocator_result.error().Message().data() << std::endl;
        return 1;
    }
    auto allocator = std::move(allocator_result).value();

    std::cout << "Memory allocator:" << std::endl;
    std::cout << "  Quota:         " << allocator->GetQuota() << " bytes" << std::endl;
    std::cout << "  Current usage: " << allocator->GetCurrentUsage() << " bytes" << std::endl;

    // ──────────────────────────────────────────────────────────────────────
    // 3. Allocate default shared memory
    // ──────────────────────────────────────────────────────────────────────
    constexpr std::size_t kDataSize = 1024;
    auto region = allocator->Allocate(kDataSize).value();

    std::cout << std::endl << "Allocated default region:" << std::endl;
    std::cout << "  Size: " << region->size() << " bytes" << std::endl;
    std::cout << "  Usage after alloc: " << allocator->GetCurrentUsage() << " bytes" << std::endl;

    // Write data into the shared memory region
    const char* message = "Data to hash via shared memory";
    const auto msg_len = std::strlen(message);
    auto writable = region->AsWritableSpan();
    std::memcpy(writable.data(), message, msg_len);

    std::cout << "  Wrote " << msg_len << " bytes into shared memory" << std::endl;

    // ──────────────────────────────────────────────────────────────────────
    // 4. Use the shared memory region with a hash context (zero-copy path)
    // ──────────────────────────────────────────────────────────────────────
    auto ctx = stack->CreateCryptoContext().value();

    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA-256");
    auto hash = ctx->CreateHashContext(hash_config).value();

    // Pass shared memory span directly to the hash context
    // When using default memory, the daemon copies internally.
    // When using provider-compatible memory, this is zero-copy.
    std::array<uint8_t, 32> digest{};

    auto bytes = hash->SingleShot(region->AsSpan().subspan(0, msg_len),  // read-only view of the region
                                  {digest.data(), digest.size()})
                     .value();

    std::cout << std::endl << "SHA-256 digest: ";
    for (std::size_t i = 0; i < bytes; ++i)
    {
        std::printf("%02x", digest[i]);
    }
    std::printf("\n");

    // ──────────────────────────────────────────────────────────────────────
    // 5. Provider-compatible allocation for true zero-copy
    // ──────────────────────────────────────────────────────────────────────
    // Resolve a provider handle
    auto provider = ctx->ResolveResource("HW_Provider", ResourceType::kProvider).value();

    // Allocate memory compatible with the specific provider (e.g., DMA-capable)
    auto hw_region = allocator->Allocate(kDataSize, MemoryType::kProviderCompatible, provider).value();

    std::cout << std::endl << "Allocated provider-compatible region:" << std::endl;
    std::cout << "  Size: " << hw_region->size() << " bytes" << std::endl;
    std::cout << "  Usage after alloc: " << allocator->GetCurrentUsage() << " bytes" << std::endl;

    // Write data and use with a context — this path is zero-copy end-to-end:
    //   Application → shared memory → daemon → provider device
    //   No copies at any boundary.
    auto hw_writable = hw_region->AsWritableSpan();
    std::memcpy(hw_writable.data(), message, msg_len);

    // ──────────────────────────────────────────────────────────────────────
    // 6. Region resizing
    // ──────────────────────────────────────────────────────────────────────
    auto resize_result = hw_region->Resize(2048);
    if (resize_result.has_value())
    {
        std::cout << std::endl << "Resized region to " << hw_region->size() << " bytes" << std::endl;
        // NOTE: Previously obtained pointers/spans may be invalidated!
    }

    // ──────────────────────────────────────────────────────────────────────
    // 7. Memory region destruction and quota tracking
    // ──────────────────────────────────────────────────────────────────────
    std::cout << std::endl
              << "Usage before region destruction: " << allocator->GetCurrentUsage() << " bytes" << std::endl;

    region.reset();     // Release default region
    hw_region.reset();  // Release provider-compatible region

    std::cout << "Usage after region destruction:  " << allocator->GetCurrentUsage() << " bytes" << std::endl;

    // Stack destruction releases any remaining regions automatically.
    return 0;
}
