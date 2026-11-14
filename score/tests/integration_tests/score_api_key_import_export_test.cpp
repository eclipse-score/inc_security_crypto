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
/// @brief End-to-end integration tests for raw and DER EC public-key import and export.

#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/api/types/key.hpp"
#include "score/result/result.h"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace score::crypto;
using tests::utility::read_bin;

namespace
{

std::string GetTestVectorPath(const std::string_view relative_path)
{
    const char* dir = std::getenv("TEST_VECTORS_DIR");
    return std::string{dir != nullptr ? dir : "/opt/crypto/share/test_vectors"} + std::string{relative_path};
}

enum class EcCurve
{
    kP256,
    kP384
};

enum class PublicKeyFormat
{
    kRaw,
    kDer
};

/// Reads a public-key test vector.
/// For kRaw, constructs SEC 1 uncompressed encoding: 0x04 || X || Y.
/// For kDer, returns the complete SubjectPublicKeyInfo DER bytes.
std::vector<std::uint8_t> ReadPublicKey(const EcCurve curve, const PublicKeyFormat format)
{
    std::string curve_directory;
    std::string file_prefix;
    std::size_t coordinate_size{0U};

    switch (curve)
    {
        case EcCurve::kP256:
            curve_directory = "/ecdsa/P256/";
            file_prefix = "p256";
            coordinate_size = 32U;
            break;
        case EcCurve::kP384:
            curve_directory = "/ecdsa/P384/";
            file_prefix = "p384";
            coordinate_size = 48U;
            break;
        default:
            ADD_FAILURE() << "Unsupported EC curve";
            return {};
    }

    if (format == PublicKeyFormat::kDer)
    {
        return read_bin(GetTestVectorPath(curve_directory + file_prefix + "_public_key.der"));
    }

    const auto x = read_bin(GetTestVectorPath(curve_directory + file_prefix + "_ux.bin"));
    const auto y = read_bin(GetTestVectorPath(curve_directory + file_prefix + "_uy.bin"));

    if ((x.size() != coordinate_size) || (y.size() != coordinate_size))
    {
        ADD_FAILURE() << "Unexpected EC coordinate size. Expected " << coordinate_size << " bytes, got X=" << x.size()
                      << " and Y=" << y.size();
        return {};
    }

    std::vector<std::uint8_t> public_key;
    public_key.reserve(1U + x.size() + y.size());
    public_key.push_back(0x04U);
    public_key.insert(public_key.end(), x.begin(), x.end());
    public_key.insert(public_key.end(), y.begin(), y.end());
    return public_key;
}

class KeyImportExportTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto stack_result = CreateCryptoStack();
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        stack_ = std::move(stack_result.value());

        auto ctx_result = stack_->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        ctx_ = std::move(ctx_result.value());

        KeyManagementContextConfig key_mgmt_config;
        key_mgmt_config.SetProviderType(ProviderType::kSoftware);
        auto key_mgmt_result = ctx_->CreateKeyManagementContext(key_mgmt_config);
        ASSERT_TRUE(key_mgmt_result.has_value()) << "Failed to create key management context";
        key_mgmt_ = std::move(key_mgmt_result.value());
    }

    ICryptoStack::Uptr stack_;
    ICryptoContext::Uptr ctx_;
    std::unique_ptr<IKeyManagementContext> key_mgmt_;
};

TEST_F(KeyImportExportTest, ImportThenExport_P384_ReproducesInputPoint)
{
    const auto point = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kRaw);
    ASSERT_EQ(point.size(), 97U);

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value());
    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive());

    auto size_result = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
    ASSERT_TRUE(size_result.has_value());
    EXPECT_EQ(size_result.value(), point.size());

    std::vector<std::uint8_t> exported(size_result.value(), 0U);
    auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
    ASSERT_TRUE(written.has_value());
    ASSERT_EQ(written.value(), point.size());
    EXPECT_EQ(exported, point);
}

TEST_F(KeyImportExportTest, ImportThenExport_P256_ReproducesInputPoint)
{
    const auto point = ReadPublicKey(EcCurve::kP256, PublicKeyFormat::kRaw);
    ASSERT_EQ(point.size(), 65U);

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

struct RoundTripCurve
{
    std::string algorithm;
    std::size_t point_size;
};

class KeyImportExportRoundTripTest : public KeyImportExportTest, public ::testing::WithParamInterface<RoundTripCurve>
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
    ASSERT_TRUE(written.has_value());
    ASSERT_EQ(written.value(), curve.point_size);
    EXPECT_EQ(exported.front(), 0x04U);

    ImportKeyParams import_params;
    import_params.SetKeyData(exported.data(), exported.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm(curve.algorithm)
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto reimported = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(reimported.has_value());
    auto reimported_key = std::move(reimported.value());

    std::vector<std::uint8_t> reexported(curve.point_size, 0U);
    auto rewritten = key_mgmt_->ExportKey(reimported_key, {reexported.data(), reexported.size()}, FormatType::kRaw);
    ASSERT_TRUE(rewritten.has_value());
    ASSERT_EQ(rewritten.value(), curve.point_size);
    EXPECT_EQ(reexported, exported);
}

INSTANTIATE_TEST_SUITE_P(AllThreePrimeCurves,
                         KeyImportExportRoundTripTest,
                         ::testing::Values(RoundTripCurve{"ECDSA-P256-SHA256", 65U},
                                           RoundTripCurve{"ECDSA-P384-SHA512", 97U},
                                           RoundTripCurve{"ECDSA-P521-SHA512", 133U}),
                         [](const ::testing::TestParamInfo<RoundTripCurve>& info) {
                             return std::to_string(info.param.point_size) + "BytesPoint";
                         });

TEST_F(KeyImportExportTest, ExportWithoutPermission_IsRejected)
{
    const auto point = ReadPublicKey(EcCurve::kP256, PublicKeyFormat::kRaw);

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value());
    auto key = std::move(key_result.value());

    EXPECT_FALSE(key_mgmt_->GetExportKeySize(key, FormatType::kRaw).has_value());

    std::vector<std::uint8_t> buffer(point.size(), 0U);
    EXPECT_FALSE(key_mgmt_->ExportKey(key, {buffer.data(), buffer.size()}, FormatType::kRaw).has_value());
}

TEST_F(KeyImportExportTest, ImportMalformedRawPoint_IsRejected)
{
    auto point = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kRaw);
    point.resize(49U);
    point[0] = 0x03U;

    ImportKeyParams import_params;
    import_params.SetKeyData(point.data(), point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify);

    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value());
}

TEST_F(KeyImportExportTest, ImportEmptyKeyData_IsRejected)
{
    ImportKeyParams import_params;
    import_params.SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify);

    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value());
}

TEST_F(KeyImportExportTest, ImportDerP384WithMatchingAlgorithm_Succeeds)
{
    const auto der_key = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kDer);

    ASSERT_FALSE(der_key.empty());
    ASSERT_EQ(der_key.size(), 120U);

    ImportKeyParams import_params;
    import_params.SetKeyData(der_key.data(), der_key.size())
        .SetFormat(FormatType::kDer)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value()) << "Importing a valid P-384 SubjectPublicKeyInfo DER key must succeed";

    auto key = std::move(key_result.value());
    EXPECT_TRUE(key.IsActive());
}

TEST_F(KeyImportExportTest, ImportDerP384WithP256Algorithm_IsRejected)
{
    const auto der_key = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kDer);

    ASSERT_FALSE(der_key.empty());
    ASSERT_EQ(der_key.size(), 120U);

    ImportKeyParams import_params;
    import_params.SetKeyData(der_key.data(), der_key.size())
        .SetFormat(FormatType::kDer)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    const auto result = key_mgmt_->ImportKey(import_params);
    EXPECT_FALSE(result.has_value());
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
