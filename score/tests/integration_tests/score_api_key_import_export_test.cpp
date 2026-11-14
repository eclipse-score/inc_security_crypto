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
/// @brief End-to-end integration tests for raw, DER and PEM EC public-key import and
/// export, and for symmetric key import validation.

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
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace score::crypto;
using tests::utility::read_bin;

namespace
{

#ifdef __QNXNTO__
constexpr auto kControlSocketEndpoint = "unix:///opt/crypto_daemon.sock";
#else
constexpr auto kControlSocketEndpoint = "unix:///tmp/crypto_daemon.sock";
#endif

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
    kDer,
    kPem
};

/// Reads a public-key test vector.
/// For kRaw, constructs SEC 1 uncompressed encoding: 0x04 || X || Y.
/// For kDer, returns the complete SubjectPublicKeyInfo DER bytes.
/// For kPem, returns the same SubjectPublicKeyInfo in PEM armour.
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
    if (format == PublicKeyFormat::kPem)
    {
        return read_bin(GetTestVectorPath(curve_directory + file_prefix + "_public_key.pem"));
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
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint(kControlSocketEndpoint);

        auto stack_result = CreateCryptoStack(stack_config);
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

    const auto expected = static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyNotExportable);
    auto size = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(*size.error(), expected);

    std::vector<std::uint8_t> buffer(point.size(), 0U);
    auto written = key_mgmt_->ExportKey(key, {buffer.data(), buffer.size()}, FormatType::kRaw);
    ASSERT_FALSE(written.has_value());
    EXPECT_EQ(*written.error(), expected);
}

TEST_F(KeyImportExportTest, GenerateP256_ExportDer_ImportDer_RawExportsMatch)
{
    GenerateKeyParams gen_params;
    gen_params.SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kSign)
        .SetPublicKeyPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);
    auto generated = key_mgmt_->GenerateKey(gen_params);
    ASSERT_TRUE(generated.has_value());
    auto gen_key = std::move(generated.value());

    std::vector<std::uint8_t> raw(65U, 0U);
    auto raw_written = key_mgmt_->ExportKey(gen_key, {raw.data(), raw.size()}, FormatType::kRaw);
    ASSERT_TRUE(raw_written.has_value());
    ASSERT_EQ(raw_written.value(), raw.size());

    auto der_size = key_mgmt_->GetExportKeySize(gen_key, FormatType::kDer);
    ASSERT_TRUE(der_size.has_value());
    EXPECT_EQ(der_size.value(), 91U) << "P-256 SubjectPublicKeyInfo with an uncompressed point is 91 bytes";

    std::vector<std::uint8_t> der(der_size.value(), 0U);
    auto der_written = key_mgmt_->ExportKey(gen_key, {der.data(), der.size()}, FormatType::kDer);
    ASSERT_TRUE(der_written.has_value());
    ASSERT_EQ(der_written.value(), der.size());

    ImportKeyParams import_params;
    import_params.SetKeyData(der.data(), der.size())
        .SetFormat(FormatType::kDer)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);
    auto reimported = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(reimported.has_value()) << "an exported SPKI must import back";
    auto reimported_key = std::move(reimported.value());

    std::vector<std::uint8_t> reraw(65U, 0U);
    auto reraw_written = key_mgmt_->ExportKey(reimported_key, {reraw.data(), reraw.size()}, FormatType::kRaw);
    ASSERT_TRUE(reraw_written.has_value());
    EXPECT_EQ(reraw, raw);
}

TEST_F(KeyImportExportTest, ExportPem_SizeThenData)
{
    GenerateKeyParams gen_params;
    gen_params.SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kSign)
        .SetPublicKeyPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);
    auto generated = key_mgmt_->GenerateKey(gen_params);
    ASSERT_TRUE(generated.has_value());
    auto key = std::move(generated.value());

    auto pem_size = key_mgmt_->GetExportKeySize(key, FormatType::kPem);
    ASSERT_TRUE(pem_size.has_value());

    std::vector<std::uint8_t> pem(pem_size.value(), 0U);
    auto written = key_mgmt_->ExportKey(key, {pem.data(), pem.size()}, FormatType::kPem);
    ASSERT_TRUE(written.has_value());
    ASSERT_EQ(written.value(), pem.size());

    const std::string text(pem.begin(), pem.end());
    EXPECT_EQ(text.rfind("-----BEGIN PUBLIC KEY-----\n", 0), 0U) << text;
    EXPECT_NE(text.find("-----END PUBLIC KEY-----\n"), std::string::npos) << text;
}

TEST_F(KeyImportExportTest, ExportWithoutFormat_IsDerSubjectPublicKeyInfo)
{
    GenerateKeyParams gen_params;
    gen_params.SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kSign)
        .SetPublicKeyPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);
    auto generated = key_mgmt_->GenerateKey(gen_params);
    ASSERT_TRUE(generated.has_value());
    auto key = std::move(generated.value());

    auto native_size = key_mgmt_->GetExportKeySize(key);
    ASSERT_TRUE(native_size.has_value());
    std::vector<std::uint8_t> native(native_size.value(), 0U);
    auto native_written = key_mgmt_->ExportKey(key, {native.data(), native.size()});
    ASSERT_TRUE(native_written.has_value());
    ASSERT_EQ(native_written.value(), native.size());

    std::vector<std::uint8_t> der(native.size(), 0U);
    auto der_written = key_mgmt_->ExportKey(key, {der.data(), der.size()}, FormatType::kDer);
    ASSERT_TRUE(der_written.has_value());
    EXPECT_EQ(native, der) << "the native export of a public key is DER SubjectPublicKeyInfo";
}

/// Secret keys never leave in plaintext, even with kExport, on any provider.
class SecretKeyExportTest : public KeyImportExportTest, public ::testing::WithParamInterface<ProviderType>
{
};

TEST_P(SecretKeyExportTest, ExportSecretKey_IsNotExportable)
{
    KeyManagementContextConfig config;
    config.SetProviderType(GetParam());
    auto ctx_result = ctx_->CreateKeyManagementContext(config);
    ASSERT_TRUE(ctx_result.has_value());
    auto key_mgmt = std::move(ctx_result.value());

    GenerateKeyParams gen_params;
    gen_params.SetAlgorithm("HMAC-SHA256")
        .SetPermissions(KeyOperationPermission::kMac | KeyOperationPermission::kExport);
    auto generated = key_mgmt->GenerateKey(gen_params);
    ASSERT_TRUE(generated.has_value());
    auto key = std::move(generated.value());

    const auto expected = static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyNotExportable);
    const std::optional<FormatType> formats[] = {std::nullopt, FormatType::kRaw, FormatType::kDer};
    for (const auto& format : formats)
    {
        auto size = key_mgmt->GetExportKeySize(key, format);
        ASSERT_FALSE(size.has_value());
        EXPECT_EQ(*size.error(), expected);

        std::vector<std::uint8_t> buffer(64U, 0U);
        auto written = key_mgmt->ExportKey(key, {buffer.data(), buffer.size()}, format);
        ASSERT_FALSE(written.has_value());
        EXPECT_EQ(*written.error(), expected);
    }
}

INSTANTIATE_TEST_SUITE_P(AllProviders,
                         SecretKeyExportTest,
                         ::testing::Values(ProviderType::kSoftware
#ifdef SCORE_CRYPTO_HARDWARE_BACKEND_ENABLED
                                           ,
                                           ProviderType::kHardware
#endif
                                           ),
                         [](const ::testing::TestParamInfo<ProviderType>& info) {
                             return info.param == ProviderType::kHardware ? std::string{"Hardware"}
                                                                          : std::string{"Software"};
                         });

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

TEST_F(KeyImportExportTest, ImportPemP384_ExportsSamePointAsRawVector)
{
    const auto pem_key = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kPem);
    const auto point = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kRaw);
    ASSERT_FALSE(pem_key.empty());
    ASSERT_EQ(point.size(), 97U);

    ImportKeyParams import_params;
    import_params.SetKeyData(pem_key.data(), pem_key.size())
        .SetFormat(FormatType::kPem)
        .SetAlgorithm("ECDSA-P384-SHA512")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value()) << "Importing a valid P-384 SubjectPublicKeyInfo PEM key must succeed";
    auto key = std::move(key_result.value());

    std::vector<std::uint8_t> exported(point.size(), 0U);
    auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
    ASSERT_TRUE(written.has_value());
    ASSERT_EQ(written.value(), point.size());
    EXPECT_EQ(exported, point);
}

TEST_F(KeyImportExportTest, ImportPublicKeyWithoutFormat_DetectsPemDerAndRawPoint)
{
    const auto point = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kRaw);
    ASSERT_EQ(point.size(), 97U);

    for (const auto format : {PublicKeyFormat::kPem, PublicKeyFormat::kDer, PublicKeyFormat::kRaw})
    {
        const auto data = ReadPublicKey(EcCurve::kP384, format);
        ASSERT_FALSE(data.empty());

        ImportKeyParams import_params;
        import_params.SetKeyData(data.data(), data.size())
            .SetAlgorithm("ECDSA-P384-SHA512")
            .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

        auto key_result = key_mgmt_->ImportKey(import_params);
        ASSERT_TRUE(key_result.has_value()) << "Native import failed for format " << static_cast<int>(format);
        auto key = std::move(key_result.value());

        std::vector<std::uint8_t> exported(point.size(), 0U);
        auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
        ASSERT_TRUE(written.has_value());
        EXPECT_EQ(exported, point) << "format " << static_cast<int>(format);
    }
}

TEST_F(KeyImportExportTest, ImportPemP384WithP256Algorithm_IsRejected)
{
    const auto pem_key = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kPem);
    ASSERT_FALSE(pem_key.empty());

    ImportKeyParams import_params;
    import_params.SetKeyData(pem_key.data(), pem_key.size())
        .SetFormat(FormatType::kPem)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify);

    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value());
}

TEST_F(KeyImportExportTest, ImportAes256_NativeOrRawFormatAndExactLength)
{
    const std::vector<std::uint8_t> key_32(32U, 0x5AU);
    const std::vector<std::uint8_t> key_31(31U, 0x5AU);

    ImportKeyParams native_params;
    native_params.SetAlgorithm("AES-256").SetPermissions(KeyOperationPermission::kEncrypt);
    native_params.SetKeyData(key_32.data(), key_32.size());
    auto native_result = key_mgmt_->ImportKey(native_params);
    ASSERT_TRUE(native_result.has_value()) << "AES-256 key without a format must be read as raw bytes";
    EXPECT_TRUE(native_result.value().IsActive());

    native_params.SetKeyData(key_31.data(), key_31.size());
    EXPECT_FALSE(key_mgmt_->ImportKey(native_params).has_value()) << "31-byte AES-256 key must be rejected";

    ImportKeyParams import_params;
    import_params.SetAlgorithm("AES-256").SetPermissions(KeyOperationPermission::kEncrypt);

    import_params.SetKeyData(key_31.data(), key_31.size()).SetFormat(FormatType::kRaw);
    EXPECT_FALSE(key_mgmt_->ImportKey(import_params).has_value()) << "31-byte AES-256 key must be rejected";

    import_params.SetKeyData(key_32.data(), key_32.size()).SetFormat(FormatType::kDer);
    auto der_result = key_mgmt_->ImportKey(import_params);
    ASSERT_FALSE(der_result.has_value()) << "AES key labelled DER must be rejected";
    EXPECT_EQ(*der_result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kInvalidFormat));

    import_params.SetFormat(FormatType::kRaw);
    auto key_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(key_result.has_value()) << "32-byte raw AES-256 key must be accepted";
    EXPECT_TRUE(key_result.value().IsActive());
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
