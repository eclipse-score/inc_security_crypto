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

/// @file score_api_key_import_export_test.cpp
/// @brief End-to-end integration tests for raw EC public-key import and export.
///
/// These drive the public client API against a running crypto_daemon, so each
/// case exercises the whole path that was wired for the feature:
///
///   client KeyManagementContext  →  control-plane IPC  →  daemon executor
///     →  key-management service   →  OpenSSL key factory  →  and back.
///
/// The factory already has unit coverage for the raw EC encoding itself; what
/// these tests add is confidence that the three new operations survive the IPC
/// round-trip with their parameters and buffers intact:
///
///   - KEY_IMPORT          (IKeyManagementContext::ImportKey)
///   - KEY_GET_EXPORT_SIZE (IKeyManagementContext::GetExportKeySize)
///   - KEY_EXPORT          (IKeyManagementContext::ExportKey)
///
/// The known-answer points are the published NIST curve points from RFC 6979
/// Appendix A.2, so a correct round-trip reproduces exactly the documented
/// 0x04||X||Y uncompressed encoding.

#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/result/result.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace score::crypto;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

// =========================================================================
// NIST RFC 6979 curve points (Appendix A.2)
// =========================================================================

// A.2.5 — P-256 public key U.
constexpr std::string_view kP256Ux = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
constexpr std::string_view kP256Uy = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

// A.2.6 — P-384 public key U.
constexpr std::string_view kP384Ux = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13";
constexpr std::string_view kP384Uy = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";

// =========================================================================
// Helpers
// =========================================================================

std::vector<std::uint8_t> HexToBytes(std::string_view hex)
{
    const auto nibble = [](char c) -> int {
        if ((c >= '0') && (c <= '9'))
        {
            return c - '0';
        }
        if ((c >= 'a') && (c <= 'f'))
        {
            return (c - 'a') + 10;
        }
        if ((c >= 'A') && (c <= 'F'))
        {
            return (c - 'A') + 10;
        }
        return 0;
    };

    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; (i + 1U) < hex.size(); i += 2U)
    {
        out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1U])));
    }
    return out;
}

/// Builds the uncompressed 0x04||X||Y encoding of an EC point.
std::vector<std::uint8_t> RawPoint(std::string_view x_hex, std::string_view y_hex)
{
    const auto x = HexToBytes(x_hex);
    const auto y = HexToBytes(y_hex);

    std::vector<std::uint8_t> point;
    point.reserve(1U + x.size() + y.size());
    point.push_back(0x04U);
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());
    return point;
}

// =========================================================================
// Fixture: a fresh stack, crypto context and key-management context per test
// =========================================================================

class KeyImportExportTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        stack_ = std::move(stack_result.value());

        auto ctx_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        ctx_ = std::move(ctx_result.value());

        KeyManagementContextConfig key_mgmt_config;
        // Raw EC public-key import/export and ephemeral EC key generation are
        // implemented only by the OpenSSL software provider. Binding the
        // provider explicitly is required because the daemon's default
        // provider preference is HARDWARE → SOFTWARE: on a deployment where a
        // hardware provider (e.g. SoftHSM on the QNX/QEMU target) is active,
        // leaving this unset resolves to that provider, which rejects raw EC
        // import ("Invalid argument") and ephemeral EC generate ("Operation
        // failed"). A software-only host silently falls back to OpenSSL, which
        // is why that gap only surfaces where a hardware provider is present.
        key_mgmt_config.SetProviderType(ProviderType::kSoftware);
        auto key_mgmt_result = ctx_->CreateKeyManagementContext(key_mgmt_config);
        ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
        key_mgmt_ = std::move(key_mgmt_result.value());
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr ctx_;
    std::unique_ptr<IKeyManagementContext> key_mgmt_;
};

// =========================================================================
// Test 1: import a known raw point, then size-then-export reproduces it
// =========================================================================

TEST_F(KeyImportExportTest, ImportThenExport_P384_ReproducesInputPoint)
{
    const auto point = RawPoint(kP384Ux, kP384Uy);
    ASSERT_EQ(point.size(), 97U) << "An uncompressed P-384 point is 1 + 2*48 bytes";

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value()) << "Importing a valid uncompressed point must succeed";
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive()) << "The returned guard must own the imported resource";

    // The two-call size-then-data contract: the reported size must match what
    // the export actually produces.
    auto size_result = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
    ASSERT_TRUE(size_result.has_value()) << "GetExportKeySize must succeed for an exportable key";
    EXPECT_EQ(size_result.value(), point.size());

    std::vector<std::uint8_t> exported(size_result.value(), 0U);
    auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
    ASSERT_TRUE(written.has_value()) << "ExportKey must succeed for an exportable key";
    ASSERT_EQ(written.value(), point.size());

    EXPECT_EQ(exported, point) << "Export must reproduce the imported 0x04||X||Y point verbatim";
}

// =========================================================================
// Test 2: the same contract on P-256
// =========================================================================

TEST_F(KeyImportExportTest, ImportThenExport_P256_ReproducesInputPoint)
{
    const auto point = RawPoint(kP256Ux, kP256Uy);
    ASSERT_EQ(point.size(), 65U) << "An uncompressed P-256 point is 1 + 2*32 bytes";

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value());
    auto key = std::move(key_result.value());

    auto size_result = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
    ASSERT_TRUE(size_result.has_value());
    EXPECT_EQ(size_result.value(), point.size());

    std::vector<std::uint8_t> exported(size_result.value(), 0U);
    auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(written.value(), point.size());
    EXPECT_EQ(exported, point);
}

// =========================================================================
// Test 3: generate → export → re-import → re-export round-trips per curve
// =========================================================================
//
// Generating a fresh key avoids needing a published point for every curve
// while still proving, end to end, that a public key exported from the daemon
// can be imported back and re-exported to the identical bytes.

struct RoundTripCurve
{
    std::string algorithm;
    std::size_t point_size;
};

class KeyImportExportRoundTripTest : public KeyImportExportTest,
                                     public ::testing::WithParamInterface<RoundTripCurve>
{
};

TEST_P(KeyImportExportRoundTripTest, GenerateExportImportReExport)
{
    const auto& curve = GetParam();

    GenerateKeyParams gen_params;
    gen_params.SetAlgorithm(curve.algorithm)
        .SetPermissions(KeyOperationPermission::kSign)
        .SetPublicKeyPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto generated = key_mgmt_->GenerateKey(gen_params);
    ASSERT_TRUE(generated.has_value()) << "Generation failed for " << curve.algorithm;
    auto gen_key = std::move(generated.value());

    auto gen_size = key_mgmt_->GetExportKeySize(gen_key, FormatType::kRaw);
    ASSERT_TRUE(gen_size.has_value());
    ASSERT_EQ(gen_size.value(), curve.point_size);

    std::vector<std::uint8_t> exported(gen_size.value(), 0U);
    auto written = key_mgmt_->ExportKey(gen_key, {exported.data(), exported.size()}, FormatType::kRaw);
    ASSERT_TRUE(written.has_value()) << "Export failed for " << curve.algorithm;
    ASSERT_EQ(written.value(), curve.point_size);
    EXPECT_EQ(exported.front(), 0x04U) << "Export must be an uncompressed point";

    ImportKeyParams import_params;
    import_params.SetKeyData(exported.data(), exported.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm(curve.algorithm)
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto reimported = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(reimported.has_value()) << "Re-import failed for " << curve.algorithm;
    auto reimported_key = std::move(reimported.value());

    std::vector<std::uint8_t> reexported(curve.point_size, 0U);
    auto rewritten = key_mgmt_->ExportKey(reimported_key, {reexported.data(), reexported.size()}, FormatType::kRaw);
    ASSERT_TRUE(rewritten.has_value());
    ASSERT_EQ(rewritten.value(), curve.point_size);
    EXPECT_EQ(reexported, exported) << "Raw export/import must round-trip for " << curve.algorithm;
}

INSTANTIATE_TEST_SUITE_P(AllThreePrimeCurves,
                         KeyImportExportRoundTripTest,
                         ::testing::Values(RoundTripCurve{"ECDSA-P256-SHA256", 65U},
                                           RoundTripCurve{"ECDSA-P384-SHA512", 97U},
                                           RoundTripCurve{"ECDSA-P521-SHA512", 133U}),
                         [](const ::testing::TestParamInfo<RoundTripCurve>& info) {
                             return std::to_string(info.param.point_size) + "BytesPoint";
                         });

// =========================================================================
// Test 4: a key imported without kExport must not be exportable
// =========================================================================

TEST_F(KeyImportExportTest, ExportWithoutPermission_IsRejected)
{
    const auto point = RawPoint(kP256Ux, kP256Uy);

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify);  // deliberately no kExport

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value()) << "A verify-only import is still a legitimate import";
    auto key = std::move(key_result.value());

    EXPECT_FALSE(key_mgmt_->GetExportKeySize(key, FormatType::kRaw).has_value())
        << "Querying the export size of a non-exportable key must fail";

    std::vector<std::uint8_t> buffer(point.size(), 0U);
    EXPECT_FALSE(key_mgmt_->ExportKey(key, {buffer.data(), buffer.size()}, FormatType::kRaw).has_value())
        << "Exporting a key that lacks kExport must fail";
}

// =========================================================================
// Test 5: a malformed raw point is rejected at import
// =========================================================================

TEST_F(KeyImportExportTest, ImportMalformedRawPoint_IsRejected)
{
    // Correct lead byte but a truncated body: 49 bytes is the length of a
    // compressed P-384 point, not the 97-byte uncompressed form the API expects.
    auto point = RawPoint(kP384Ux, kP384Uy);
    point.resize(49U);
    point[0] = 0x03U;

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify);

    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value())
        << "A malformed raw point must be rejected by the daemon";
}

// =========================================================================
// Test 6: an empty key buffer is rejected before any IPC round-trip
// =========================================================================

TEST_F(KeyImportExportTest, ImportEmptyKeyData_IsRejected)
{
    ImportKeyParams import_params;
    import_params.SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify);  // key_data left empty

    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value())
        << "Importing empty key material must fail";
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
