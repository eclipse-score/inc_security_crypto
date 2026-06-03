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

// =============================================================================
//  HMAC MAC Slot & Provider Switching Demo
// =============================================================================
/// @file hmac_slot_provider_switching_demo.cpp
/// @brief Demonstrates HMAC-SHA256 using slot-loaded keys with multi-provider (OpenSSL & SoftHSM).
///        Same code runs on different providers. Only provider selection differs.
///
/// Key Insights:
///   1. Slot-based key loading (pre-deployed, deterministic)
///   2. Streaming MAC pattern: Init() -> Update() -> Finalize()
///   3. Provider switching via ProviderType - code path identical
///   4. RAII pattern ensures automatic key zeroization on cleanup

#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/key_management_context_config.hpp"
#include "score/mw/crypto/api/config/mac_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_key_management_context.hpp"
#include "score/mw/crypto/api/contexts/i_mac_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"
#include "tests/utility/test_utility.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

using namespace score::mw::crypto;
using tests::utility::Color;
using tests::utility::print_colored;
using tests::utility::print_error;
using tests::utility::print_hex;
using tests::utility::print_section;
using tests::utility::print_success;

namespace
{
const std::string kAlgHmacSha256 = "HMAC-SHA256";
const std::size_t kHmacSha256MacSize = 32;

// Slot names - these must be configured with daemon before running
// Both slots contain the same key material, but are associated
// with different providers.
const std::string kSlotOpenSSL = "HMAC_SHA256_IntegrationTestKey_OpenSSL";
const std::string kSlotSoftHSM = "HMAC_SHA256_IntegrationTestKey_SoftHSM";

// Test data
const std::string kTestDataPath = "/opt/crypto/tests/test_vectors/mac/input_hello_world.bin";
const std::string kExpectedMacPath = "/opt/crypto/tests/test_vectors/mac/hmac_sha256_hello_world.bin";

// =========================================================================
// Utility: Compute and display MAC
// =========================================================================

score::Result<std::vector<uint8_t>> ComputeMacWithProvider(const std::string& slot_name,
                                                           ProviderType provider,
                                                           const std::vector<uint8_t>& message,
                                                           const std::vector<uint8_t>& expected_mac)
{
    // =========================================================================
    // [Setup] Connect to daemon & establish context factory
    // =========================================================================
    print_colored("[Setup] Connecting to daemon");

    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");
    // Note: In the future a default endpoint will be configured, making an explicit
    // selection obsolete.
    auto stack_result = CreateCryptoStack(stack_config);
    if (!stack_result.has_value())
    {
        print_error("ERROR: Failed to create crypto stack");
        return score::Result<std::vector<uint8_t>>{score::unexpect, stack_result.error()};
    }
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    if (!ctx_result.has_value())
    {
        print_error("ERROR: Failed to create crypto context");
        return score::Result<std::vector<uint8_t>>{score::unexpect, ctx_result.error()};
    }
    auto& ctx = ctx_result.value();
    print_success("IPC connection established");

    // =========================================================================
    // [Phase 1] Resolve KeySlot
    // =========================================================================
    print_colored("[Phase 1] Resolve KeySlot Resource");

    auto slot_result = ctx->ResolveResource(slot_name, ResourceType::kKeySlot);
    if (!slot_result.has_value())
    {
        print_error("ERROR: Failed to resolve slot \"" + slot_name + "\"");
        return score::Result<std::vector<uint8_t>>{score::unexpect, slot_result.error()};
    }

    print_success("Resolved KeySlot resource: " + slot_name);

    // Note: If the key shall be used on multiple contexts it can be explicitly loaded
    // via the KeyManagementContext and shared across contexts to reduce overhead.

    // =========================================================================
    // [Phase 2] Configure MAC context with provider selection
    // =========================================================================
    print_colored("[Phase 2] Configure and Create MAC Context");
    print_colored("- Algorithm: HMAC-SHA256", Color::BrightCyan);
    print_colored("- With KeySlot: " + slot_name, Color::BrightCyan);
    print_colored("- With Provider: " +
                      std::string(provider == ProviderType::kSoftware ? "OpenSSL (Software)" : "SoftHSM (Hardware)"),
                  Color::BrightCyan);

    // No need to select provider again.
    // Provider is implicitly selected based on the key's origin (slot)
    MacContextConfig mac_config;
    mac_config.SetAlgorithm(kAlgHmacSha256).SetKey(slot_result.value());
    auto mac_result = ctx->CreateMacContext(mac_config);
    if (!mac_result.has_value())
    {
        print_error("ERROR: Failed to create MAC context");
        return score::Result<std::vector<uint8_t>>{score::unexpect, mac_result.error()};
    }
    auto& mac = mac_result.value();
    print_success("MAC context created");
    print_success("Key bound to context");

    // =========================================================================
    // [Phase 3] Compute MAC via streaming pattern
    // =========================================================================
    print_colored("[Phase 3] Streaming MAC computation");

    auto init_result = mac->Init();
    if (!init_result.has_value())
    {
        print_error("ERROR: MAC Init failed");
        return score::Result<std::vector<uint8_t>>{score::unexpect, init_result.error()};
    }

    print_success("Init");

    auto update_result = mac->Update(message);
    if (!update_result.has_value())
    {
        print_error("ERROR: MAC Update failed");
        return score::Result<std::vector<uint8_t>>{score::unexpect, update_result.error()};
    }

    print_success("Update");

    std::vector<uint8_t> mac_output(kHmacSha256MacSize, 0);
    auto finalize_result = mac->Finalize(mac_output);
    if (!finalize_result.has_value())
    {
        print_error("ERROR: MAC Finalize failed");
        return score::Result<std::vector<uint8_t>>{score::unexpect, finalize_result.error()};
    }

    print_success("Finalize");

    print_hex("- Computed MAC: ", mac_output, mac_output.size(), Color::BrightCyan);
    print_hex("- Expected MAC: ", expected_mac, expected_mac.size(), Color::BrightCyan);

    // Verify against expected (inline verification)
    if (mac_output == expected_mac)
    {
        print_success("Computed MAC matches expected test vector");
    }
    else
    {
        print_error("ERROR: MAC does NOT match expected test vector");
        return score::Result<std::vector<uint8_t>>{score::unexpect, CryptoErrorCode::kInternalError};
    }

    return mac_output;

    // Notes: RAII-based cleanup of resources (contexts, keys).
    // Secure handling of resources e.g. keys are automatically zeroized when not used anymore.
    // No need for explicit cleanup steps.
}

}  // namespace

int main()
{
    print_section("Demo: HMAC-SHA256 with slot-based keys on multiple provider");

    // Read test data
    print_colored("[Setup] Reading test data and expected MAC");
    auto test_data = tests::utility::read_bin(kTestDataPath);
    if (test_data.empty())
    {
        print_error("Failed to read test data from: " + kTestDataPath);
        return 1;
    }

    auto expected_mac = tests::utility::read_bin(kExpectedMacPath);
    if (expected_mac.empty())
    {
        print_error("Failed to read expected MAC from: " + kExpectedMacPath);
        return 1;
    }

    print_hex("- ", test_data, test_data.size(), Color::BrightCyan);
    print_success("Read test data: " + std::to_string(test_data.size()) + " bytes");

    // =========================================================================
    // Demo: Provider 1 - OpenSSL (Software)
    // =========================================================================
    print_section("PROVIDER 1: OpenSSL (Software)");

    auto result_openssl = ComputeMacWithProvider(kSlotOpenSSL, ProviderType::kSoftware, test_data, expected_mac);
    if (!result_openssl.has_value())
    {
        print_error("OpenSSL computation failed");
        return 1;
    }

    // =========================================================================
    // Demo: Provider 2 - SoftHSM (Hardware)
    // =========================================================================
    print_section("PROVIDER 2: SoftHSM (Hardware)");

    auto result_softhsm = ComputeMacWithProvider(kSlotSoftHSM, ProviderType::kHardware, test_data, expected_mac);
    if (!result_softhsm.has_value())
    {
        print_error("Hardware provider (SoftHSM) unavailable or verification failed");
        return 1;
    }

    // =========================================================================
    // Comparison: Show both MACs are identical (provider transparency)
    // =========================================================================
    print_section("Verification: Provider Transparency");

    print_colored("Computed MAC (OpenSSL):");
    print_hex("", result_openssl.value(), result_openssl.value().size(), Color::BrightCyan);
    print_colored("Computed MAC (SoftHSM):");
    print_hex("", result_softhsm.value(), result_softhsm.value().size(), Color::BrightCyan);

    if (result_openssl.value() == result_softhsm.value())
    {
        print_success("OpenSSL and SoftHSM MACs are IDENTICAL");
    }
    else
    {
        print_error("ERROR: MACs differ between providers");
        return 1;
    }

    return 0;
}
