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
/// @brief End-to-end EC key import/export, private DER signing and corrupt-key rejection tests.

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
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
        ADD_FAILURE() << "Unexpected EC coordinate size. Expected " << coordinate_size
                      << " bytes, got X=" << x.size() << " and Y=" << y.size();
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

    void ExpectRawExportMatches(const CryptoResourceId& key, const std::vector<std::uint8_t>& expected)
    {
        auto size_result = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
        ASSERT_TRUE(size_result.has_value());
        ASSERT_EQ(size_result.value(), expected.size());

        std::vector<std::uint8_t> exported(size_result.value(), 0U);
        auto written = key_mgmt_->ExportKey(key, {exported.data(), exported.size()}, FormatType::kRaw);
        ASSERT_TRUE(written.has_value());
        ASSERT_EQ(written.value(), expected.size());
        EXPECT_EQ(exported, expected);
    }

    void ExpectCorruptDerRejectedAndContextRecovers(const std::vector<std::uint8_t>& der_key,
                                                    const std::string& algorithm,
                                                    const std::size_t point_size)
    {
        ASSERT_GT(der_key.size(), 1U);
        ASSERT_EQ(der_key.front(), 0x30U) << "The valid fixture must start with an ASN.1 SEQUENCE";

        ImportKeyParams import_params;
        import_params.SetKeyData(der_key.data(), der_key.size())
            .SetFormat(FormatType::kDer)
            .SetAlgorithm(algorithm)
            .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

        auto original_result = key_mgmt_->ImportKey(import_params);
        ASSERT_TRUE(original_result.has_value()) << "The unmodified fixture must import before testing corruption";
        auto original = std::move(original_result.value());
        ASSERT_TRUE(original.IsActive());
        auto size_result = key_mgmt_->GetExportKeySize(original, FormatType::kRaw);
        ASSERT_TRUE(size_result.has_value());
        ASSERT_EQ(size_result.value(), point_size);
        std::vector<std::uint8_t> expected(point_size, 0U);
        auto written = key_mgmt_->ExportKey(original, {expected.data(), expected.size()}, FormatType::kRaw);
        ASSERT_TRUE(written.has_value());
        ASSERT_EQ(written.value(), point_size);
        ASSERT_EQ(expected.front(), 0x04U);

        // Corrupt copies in memory; never overwrite the packaged valid fixtures.
        auto invalid_tag = der_key;
        invalid_tag.front() = 0x31U;  // SET instead of the required SEQUENCE, with the original length.
        auto truncated = der_key;
        truncated.pop_back();  // Keep ASN.1 lengths unchanged so the encoded key is incomplete.
        auto trailing_data = der_key;
        trailing_data.push_back(0x00U);  // Valid DER followed by data the parser must not ignore.

        const std::vector<std::pair<std::string, std::vector<std::uint8_t>>> corrupt_keys{
            {"invalid ASN.1 tag", std::move(invalid_tag)},
            {"truncated DER", std::move(truncated)},
            {"trailing data", std::move(trailing_data)}};

        for (const auto& corrupt_key : corrupt_keys)
        {
            SCOPED_TRACE(corrupt_key.first);
            import_params.SetKeyData(corrupt_key.second.data(), corrupt_key.second.size());
            auto rejected = key_mgmt_->ImportKey(import_params);
            ASSERT_FALSE(rejected.has_value()) << "A corrupt key must not produce a usable resource guard";
            EXPECT_EQ(rejected.error(), MakeError(CryptoErrorCode::kInvalidFormat));

            // Exercise both an existing key and a fresh valid import on the same
            // context after every rejection: an IPC/daemon failure must not pass
            // merely because it also returned an error for the corrupt input.
            ASSERT_NO_FATAL_FAILURE(ExpectRawExportMatches(original, expected));
            import_params.SetKeyData(der_key.data(), der_key.size());
            auto recovered_result = key_mgmt_->ImportKey(import_params);
            ASSERT_TRUE(recovered_result.has_value()) << "Valid import must still work after corrupt DER";
            auto recovered = std::move(recovered_result.value());
            ASSERT_TRUE(recovered.IsActive());
            ASSERT_NO_FATAL_FAILURE(ExpectRawExportMatches(recovered, expected));
        }
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

TEST_F(KeyImportExportTest, ImportOffCurveRawPoint_IsRejectedAndContextRecovers)
{
    const auto valid_point = ReadPublicKey(EcCurve::kP256, PublicKeyFormat::kRaw);
    ASSERT_EQ(valid_point.size(), 65U);

    // This has the correct size and uncompressed tag, but (0, 0) is not
    // on P-256. Unlike a random bit flip, it is deterministically invalid.
    std::vector<std::uint8_t> corrupt_point(valid_point.size(), 0U);
    corrupt_point.front() = 0x04U;

    ImportKeyParams import_params;
    import_params.SetKeyData(corrupt_point.data(), corrupt_point.size())
        .SetFormat(FormatType::kRaw)
        .SetAlgorithm("ECDSA-P256-SHA256")
        .SetPermissions(KeyOperationPermission::kVerify | KeyOperationPermission::kExport);

    auto rejected = key_mgmt_->ImportKey(import_params);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(), MakeError(CryptoErrorCode::kInvalidFormat));

    import_params.SetKeyData(valid_point.data(), valid_point.size());
    auto recovered_result = key_mgmt_->ImportKey(import_params);
    ASSERT_TRUE(recovered_result.has_value());
    auto recovered = std::move(recovered_result.value());
    ASSERT_TRUE(recovered.IsActive());
    ASSERT_NO_FATAL_FAILURE(ExpectRawExportMatches(recovered, valid_point));
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
    ASSERT_TRUE(key_result.has_value())
        << "Importing a valid P-384 SubjectPublicKeyInfo DER key must succeed";

    auto key = std::move(key_result.value());
    ASSERT_TRUE(key.IsActive());

    const auto expected_point = ReadPublicKey(EcCurve::kP384, PublicKeyFormat::kRaw);
    ASSERT_EQ(expected_point.size(), 97U);
    ASSERT_NO_FATAL_FAILURE(ExpectRawExportMatches(key, expected_point));
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

struct DerCurve
{
    std::string algorithm;
    std::string vector_directory;
    std::size_t point_size;
};

class KeyImportExportDerTest : public KeyImportExportTest,
                              public ::testing::WithParamInterface<DerCurve>
{
};

TEST_P(KeyImportExportDerTest, ImportPrivateDer_CanSignAndPublicDerCanVerify)
{
    const auto& curve = GetParam();
    const auto directory = GetTestVectorPath("/ecdsa/" + curve.vector_directory + "/");
    const auto private_der = read_bin(directory + "siggen_private_key.der");
    const auto public_der = read_bin(directory + "siggen_public_key.der");
    const auto message = read_bin(directory + "siggen_message.bin");
    ASSERT_FALSE(private_der.empty());
    ASSERT_FALSE(public_der.empty());
    ASSERT_FALSE(message.empty());

    ImportKeyParams private_params;
    private_params.SetKeyData(private_der.data(), private_der.size())
        .SetFormat(FormatType::kDer)
        .SetAlgorithm(curve.algorithm)
        .SetPermissions(KeyOperationPermission::kSign);  // No client private-key export grant.
    auto private_result = key_mgmt_->ImportKey(private_params);
    ASSERT_TRUE(private_result.has_value());
    auto private_key = std::move(private_result.value());
    ASSERT_TRUE(private_key.IsActive());

    ImportKeyParams public_params;
    public_params.SetKeyData(public_der.data(), public_der.size())
        .SetFormat(FormatType::kDer)
        .SetAlgorithm(curve.algorithm)
        .SetPermissions(KeyOperationPermission::kVerify);
    auto public_result = key_mgmt_->ImportKey(public_params);
    ASSERT_TRUE(public_result.has_value());
    auto public_key = std::move(public_result.value());
    ASSERT_TRUE(public_key.IsActive());

    // Reuse the source ECDSA integration test's sign/verify SingleShot flow,
    // binding imported DER keys instead of generated keys or configured slots.
    SignContextConfig sign_config;
    sign_config.SetAlgorithm(curve.algorithm).SetKey(private_key).SetProviderType(ProviderType::kSoftware);
    auto sign_result = ctx_->CreateSignContext(sign_config);
    ASSERT_TRUE(sign_result.has_value());
    auto sign = std::move(sign_result.value());

    VerifySignatureContextConfig verify_config;
    verify_config.SetAlgorithm(curve.algorithm).SetKey(public_key).SetProviderType(ProviderType::kSoftware);
    auto verify_result = ctx_->CreateVerifySignatureContext(verify_config);
    ASSERT_TRUE(verify_result.has_value());
    auto verify = std::move(verify_result.value());

    // IEEE P1363 r || s has twice the coordinate size, without the SEC1 tag.
    const auto signature_size = curve.point_size - 1U;
    ASSERT_EQ(sign->GetSignatureSize(), signature_size);
    ASSERT_TRUE(sign->Reset().has_value());
    std::vector<std::uint8_t> signature(signature_size, 0U);
    auto written = sign->SingleShot({message.data(), message.size()}, {signature.data(), signature.size()});
    ASSERT_TRUE(written.has_value());
    ASSERT_EQ(written.value(), signature_size);

    ASSERT_TRUE(verify->Reset().has_value());
    auto verified = verify->SingleShot({message.data(), message.size()}, {signature.data(), signature.size()});
    ASSERT_TRUE(verified.has_value());
    EXPECT_TRUE(verified.value());

    auto tampered_message = message;
    tampered_message.front() ^= 0x01U;
    ASSERT_TRUE(verify->Reset().has_value());
    auto rejected = verify->SingleShot({tampered_message.data(), tampered_message.size()},
                                       {signature.data(), signature.size()});
    ASSERT_TRUE(rejected.has_value());
    EXPECT_FALSE(rejected.value()) << "Verification must not unconditionally accept imported keys";
}

TEST_P(KeyImportExportDerTest, ExportDer_IsRejectedWithoutAffectingRawExport)
{
    const auto& curve = GetParam();
    const auto directory = GetTestVectorPath("/ecdsa/" + curve.vector_directory + "/");

    for (const auto* filename : {"siggen_public_key.der", "siggen_private_key.der"})
    {
        SCOPED_TRACE(filename);
        const auto der_key = read_bin(directory + filename);
        ASSERT_FALSE(der_key.empty());
        ImportKeyParams import_params;
        import_params.SetKeyData(der_key.data(), der_key.size())
            .SetFormat(FormatType::kDer)
            .SetAlgorithm(curve.algorithm)
            .SetPermissions(KeyOperationPermission::kSign | KeyOperationPermission::kVerify |
                            KeyOperationPermission::kExport);
        auto key_result = key_mgmt_->ImportKey(import_params);
        ASSERT_TRUE(key_result.has_value());
        auto key = std::move(key_result.value());
        ASSERT_TRUE(key.IsActive());

        auto raw_size = key_mgmt_->GetExportKeySize(key, FormatType::kRaw);
        ASSERT_TRUE(raw_size.has_value());
        ASSERT_EQ(raw_size.value(), curve.point_size);
        std::vector<std::uint8_t> expected(curve.point_size, 0U);
        auto written = key_mgmt_->ExportKey(key, {expected.data(), expected.size()}, FormatType::kRaw);
        ASSERT_TRUE(written.has_value());
        ASSERT_EQ(written.value(), curve.point_size);
        ASSERT_EQ(expected.front(), 0x04U);

        auto der_size = key_mgmt_->GetExportKeySize(key, FormatType::kDer);
        ASSERT_FALSE(der_size.has_value());
        EXPECT_EQ(der_size.error(), MakeError(CryptoErrorCode::kUnsupportedOperation));

        std::vector<std::uint8_t> buffer(der_key.size(), 0U);
        auto exported_der = key_mgmt_->ExportKey(key, {buffer.data(), buffer.size()}, FormatType::kDer);
        ASSERT_FALSE(exported_der.has_value());
        EXPECT_EQ(exported_der.error(), MakeError(CryptoErrorCode::kUnsupportedOperation));

        ASSERT_NO_FATAL_FAILURE(ExpectRawExportMatches(key, expected));
    }
}

TEST_P(KeyImportExportDerTest, ImportCorruptPublicDer_IsRejectedAndContextRecovers)
{
    const auto& curve = GetParam();
    const auto der_key = read_bin(GetTestVectorPath("/ecdsa/" + curve.vector_directory + "/siggen_public_key.der"));
    ASSERT_NO_FATAL_FAILURE(ExpectCorruptDerRejectedAndContextRecovers(der_key, curve.algorithm, curve.point_size));
}

TEST_P(KeyImportExportDerTest, ImportCorruptPrivateDer_IsRejectedAndContextRecovers)
{
    const auto& curve = GetParam();
    const auto der_key = read_bin(GetTestVectorPath("/ecdsa/" + curve.vector_directory + "/siggen_private_key.der"));
    ASSERT_NO_FATAL_FAILURE(ExpectCorruptDerRejectedAndContextRecovers(der_key, curve.algorithm, curve.point_size));
}

INSTANTIATE_TEST_SUITE_P(AllThreePrimeCurves,
                         KeyImportExportDerTest,
                         ::testing::Values(DerCurve{"ECDSA-P256-SHA256", "P256-SHA256", 65U},
                                           DerCurve{"ECDSA-P384-SHA384", "P384-SHA384", 97U},
                                           DerCurve{"ECDSA-P521-SHA512", "P521-SHA512", 133U}),
                         [](const ::testing::TestParamInfo<DerCurve>& info) {
                             return std::to_string(info.param.point_size) + "BytesPoint";
                         });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
