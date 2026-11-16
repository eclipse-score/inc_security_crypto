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

// Source: fea_um_crypto_1, 1f4b0daa5919e9d354b53a565e7febbd28a34546,
// score/tests/integration_tests/csr_enrollment_transport_test.cpp (Client,
// direct-to-slot generation, LoadKey, CSR configuration and bounded DER export).
// The same patterns are present in source ancestor
// 23e93337c70df8d92cd12bcc397f93195784bb6a.
// The offline oracle's parsing, signature, subject and public-key equality checks
// follow score_api_csr_test.cpp (ported from ancestor 5e8664e37).
// Adaptation: split provisioning/reuse into independent process invocations,
// never clear/overwrite a slot, and save only a public CSR as restart evidence.
// The source's structural ExtractP256PublicPoint scanner is deliberately unused.
//
// The external runner must invoke each exact GTEST_FILTER separately:
//   KeyPersistenceIntegration.GenerateAndPersistDeviceKey
//   [restart the daemon / power-cycle, preserving slot files and reference CSR]
//   KeyPersistenceIntegration.ReloadPersistedDeviceKeyAndSignCsr
// Running both tests against one daemon is NOT evidence of restart persistence.
// Each invocation exits, destroying all client contexts and in-memory handles.
// No PersistKey call is needed: the source persists by GenerateKey(target_slot,
// std::nullopt, params). No private-key export or backend internals are used.
#include "score/crypto/src/api/config/csr_generation_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/contexts/i_csr_generation_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/tests/integration_tests/csr_der_test_helper.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{
using namespace score::crypto;

// Fixed algorithm/subject expectations are test data, not deployment policy.
constexpr const char* kSignatureAlgorithm = "ECDSA-P256-SHA256";
constexpr const char* kKeyAlgorithm = "ECDSA-P256";
constexpr std::size_t kMaxDerBytes = test::kMaxCsrDerBytes;
constexpr auto kOperationTimeout = std::chrono::seconds{5};

const char* FixtureValue(const char* variable, const char* fallback)
{
    const auto* value = std::getenv(variable);
    return value != nullptr && *value != '\0' ? value : fallback;
}

const char* DeviceResource()
{
    return FixtureValue("CSR_TEST_DEVICE_RESOURCE", "csr/device-key");
}

const char* ReferenceCsrPath()
{
    return FixtureValue("CSR_TEST_REFERENCE_CSR", "/opt/crypto/etc/csr-slots/reference.csr.der");
}

class Client
{
  public:
    void Open()
    {
        CryptoStackConfig config;
        config.SetConnectionEndpoint(FixtureValue("CSR_TEST_ENDPOINT", "unix:///tmp/crypto_daemon.sock"))
            .SetDefaultOperationTimeout(kOperationTimeout);
        auto created = CreateCryptoStack(config);
        ASSERT_TRUE(created.has_value());
        stack = std::move(created.value());
        auto context_result = stack->CreateCryptoContext();
        ASSERT_TRUE(context_result.has_value());
        context = std::move(context_result.value());
        KeyManagementContextConfig key_config;
        key_config.SetProviderType(ProviderType::kSoftware);
        auto keys_result = context->CreateKeyManagementContext(key_config);
        ASSERT_TRUE(keys_result.has_value());
        keys = std::move(keys_result.value());
    }

    score::Result<ICsrGenerationContext::Uptr> Csr(const CryptoResourceId& key)
    {
        CsrGenerationContextConfig config;
        config.SetKey(key).SetAlgorithm(kSignatureAlgorithm).SetProviderType(ProviderType::kSoftware);
        return context->CreateCsrGenerationContext(config);
    }

    ICryptoStack::Uptr stack;
    ICryptoContext::Uptr context;
    IKeyManagementContext::Uptr keys;
};

std::vector<std::uint8_t> ReadCsr(const ICsrExport& exported)
{
    const auto size = exported.GetEncodedCsrLength();
    if (size == 0U || size > kMaxDerBytes)
    {
        ADD_FAILURE() << "Invalid CSR DER length: " << size;
        return {};
    }
    std::vector<std::uint8_t> der(size);
    auto written = exported.GetEncodedCsr(der);
    if (!written.has_value() || written.value() != der.size())
    {
        ADD_FAILURE() << "Incomplete CSR DER export";
        return {};
    }
    return der;
}

void SaveReferenceCsr(const std::vector<std::uint8_t>& der)
{
    ASSERT_FALSE(der.empty());
    ASSERT_LE(der.size(), kMaxDerBytes);
    // The parent directory is supplied by the runner. This file contains only
    // the signed public CSR, never serialized private-key material or handles.
    std::ofstream output{ReferenceCsrPath(), std::ios::binary | std::ios::trunc};
    ASSERT_TRUE(output.is_open()) << "Cannot write reference CSR: " << ReferenceCsrPath();
    output.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
    output.close();
    ASSERT_TRUE(output.good()) << "Incomplete reference CSR write: " << ReferenceCsrPath();
}

std::vector<std::uint8_t> ReadReferenceCsr()
{
    std::ifstream input{ReferenceCsrPath(), std::ios::binary};
    if (!input.is_open())
    {
        ADD_FAILURE() << "Existing phase-1 reference CSR required: " << ReferenceCsrPath();
        return {};
    }
    // Read at most the allowed size plus one byte, even for an oversized file.
    std::vector<std::uint8_t> der(kMaxDerBytes + 1U);
    input.read(reinterpret_cast<char*>(der.data()), static_cast<std::streamsize>(der.size()));
    const auto size = input.gcount();
    if (input.bad() || !input.eof() || size <= 0 || size > static_cast<std::streamsize>(kMaxDerBytes))
    {
        ADD_FAILURE() << "Unreadable, empty or oversized reference CSR: " << ReferenceCsrPath();
        return {};
    }
    der.resize(static_cast<std::size_t>(size));
    return der;
}

TEST(KeyPersistenceIntegration, GenerateAndPersistDeviceKey)
{
    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    auto slot = client.context->ResolveResource(DeviceResource(), ResourceType::kKeySlot);
    ASSERT_TRUE(slot.has_value()) << "Cannot resolve device slot: " << DeviceResource();
    auto initial_info = client.keys->GetKeySlotInfo(slot.value());
    ASSERT_TRUE(initial_info.has_value());
    ASSERT_EQ(initial_info.value().state, KeySlotState::kEmpty)
        << "Phase 1 requires an initially empty slot; no key is cleared or overwritten";

    GenerateKeyParams params;
    params.SetAlgorithm(kKeyAlgorithm).SetPermissions(KeyOperationPermission::kSign);
    ASSERT_TRUE(client.keys->GenerateKey(slot.value(), std::nullopt, params).has_value());
    auto stored_info = client.keys->GetKeySlotInfo(slot.value());
    ASSERT_TRUE(stored_info.has_value());
    ASSERT_EQ(stored_info.value().state, KeySlotState::kOccupied);
    auto key = client.keys->LoadKey(slot.value());
    ASSERT_TRUE(key.has_value());
    auto context = client.Csr(key.value());
    ASSERT_TRUE(context.has_value());
    ASSERT_TRUE(context.value()->SetSubjectDn("CN=first-enrollment,O=SCORE,C=DE").has_value());
    auto exported = context.value()->Generate();
    ASSERT_TRUE(exported.has_value());
    const auto der = ReadCsr(*exported.value());
    ASSERT_FALSE(der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("p256", der, {}, "first-enrollment"));
    ASSERT_NO_FATAL_FAILURE(SaveReferenceCsr(der));
    EXPECT_FALSE(client.keys->GenerateKey(slot.value(), std::nullopt, params).has_value())
        << "An occupied slot must not be silently overwritten";
    // Normal scope/process exit releases handles, not the persisted slot key.
}

TEST(KeyPersistenceIntegration, ReloadPersistedDeviceKeyAndSignCsr)
{
    // Fail without provisioning if phase 1 did not leave its public evidence.
    const auto reference_der = ReadReferenceCsr();
    ASSERT_FALSE(reference_der.empty());
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("p256", reference_der, {}, "first-enrollment"));

    Client client;
    ASSERT_NO_FATAL_FAILURE(client.Open());
    auto slot = client.context->ResolveResource(DeviceResource(), ResourceType::kKeySlot);
    ASSERT_TRUE(slot.has_value()) << "Cannot resolve persisted device slot: " << DeviceResource();
    auto info = client.keys->GetKeySlotInfo(slot.value());
    ASSERT_TRUE(info.has_value());
    ASSERT_EQ(info.value().state, KeySlotState::kOccupied)
        << "Phase 2 requires the persisted slot; it never generates or clears a key";
    auto key = client.keys->LoadKey(slot.value());
    ASSERT_TRUE(key.has_value());
    auto context = client.Csr(key.value());
    ASSERT_TRUE(context.has_value());
    ASSERT_TRUE(context.value()->SetSubjectDn("CN=renewed-enrollment,O=SCORE,C=DE").has_value());
    auto exported = context.value()->Generate();
    ASSERT_TRUE(exported.has_value());
    const auto der = ReadCsr(*exported.value());
    ASSERT_FALSE(der.empty());

    // Cryptographic identity, not resource IDs, DER equality or a byte scanner:
    // the fresh CSR must be signed by the very same key as before the restart.
    ASSERT_NO_FATAL_FAILURE(test::VerifyCsrDer("persistence", reference_der, der));
}
}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
