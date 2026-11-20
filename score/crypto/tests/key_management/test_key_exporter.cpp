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

#include "score/crypto/src/daemon/provider/exports/key_exporter.hpp"

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_factory.hpp"

#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace
{
namespace km = score::crypto::daemon::key_management;
namespace provider = score::crypto::daemon::provider;
namespace openssl = score::crypto::daemon::provider::openssl;
using Error = score::crypto::daemon::common::DaemonErrorCode;
using Format = score::crypto::FormatType;
using Permission = score::crypto::KeyOperationPermission;

class ExportTestKey final : public km::IKeyHandler
{
  public:
    const km::ProviderKeyHandle& GetHandle() const noexcept override
    {
        return handle;
    }

    score::crypto::daemon::common::ProviderId GetProviderId() const noexcept override
    {
        return handle.provider_id;
    }

    score::crypto::Expected<std::monostate, Error> Release() override
    {
        return std::monostate{};
    }

    score::crypto::Expected<km::SecureKeyBytes, Error> Export() const override
    {
        ++export_calls;
        if (export_error.has_value())
        {
            return score::crypto::make_unexpected(*export_error);
        }
        km::SecureKeyBytes result;
        result.bytes = raw_bytes;
        return result;
    }

    km::ProviderKeyHandle handle{};
    const std::vector<std::uint8_t> raw_bytes{0x01U, 0x02U, 0x03U};
    std::optional<Error> export_error;
    mutable std::size_t export_calls{0U};
};

class ExportTestFactory final : public km::IKeyFactory
{
  public:
    score::crypto::Expected<km::SecureKeyBytes, Error> ExportKey(const km::ProviderKeyHandle& handle,
                                                                 Format format) override
    {
        ++export_calls;
        last_handle = &handle;
        last_format = format;
        if (export_error.has_value())
        {
            return score::crypto::make_unexpected(*export_error);
        }
        km::SecureKeyBytes result;
        result.bytes = encoded_bytes;
        return result;
    }

    score::crypto::Expected<std::size_t, Error> GetExportKeySize(const km::ProviderKeyHandle& handle,
                                                                 Format format) override
    {
        ++size_calls;
        last_handle = &handle;
        last_format = format;
        if (size_error.has_value())
        {
            return score::crypto::make_unexpected(*size_error);
        }
        return encoded_bytes.size();
    }

    const std::vector<std::uint8_t> encoded_bytes{0x30U, 0x03U, 0x04U, 0x01U, 0xA5U};
    std::optional<Error> export_error{Error::kUnsupportedOperation};
    std::optional<Error> size_error{Error::kUnsupportedOperation};
    std::size_t export_calls{0U};
    std::size_t size_calls{0U};
    const km::ProviderKeyHandle* last_handle{nullptr};
    Format last_format{Format::kRaw};
};

TEST(KeyExporterTest, RawHandlerSuccessDoesNotCallFormattedFactory)
{
    ExportTestKey key;
    auto factory = std::make_shared<ExportTestFactory>();
    provider::KeyExporter exporter{factory};

    auto exported = exporter.ExportKey(key, Format::kRaw);
    auto size = exporter.GetExportKeySize(key, Format::kRaw);

    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported.value().bytes, key.raw_bytes);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), key.raw_bytes.size());
    EXPECT_EQ(key.export_calls, 2U);
    EXPECT_EQ(factory->export_calls, 0U);
    EXPECT_EQ(factory->size_calls, 0U);
}

TEST(KeyExporterTest, NonRawFormatsUseExistingFactoryWithoutExportingRawMaterial)
{
    for (const auto format : {Format::kDer, Format::kPem})
    {
        ExportTestKey key;
        auto factory = std::make_shared<ExportTestFactory>();
        factory->export_error.reset();
        factory->size_error.reset();
        provider::KeyExporter exporter{factory};

        auto exported = exporter.ExportKey(key, format);
        auto size = exporter.GetExportKeySize(key, format);

        ASSERT_TRUE(exported.has_value());
        EXPECT_EQ(exported.value().bytes, factory->encoded_bytes);
        ASSERT_TRUE(size.has_value());
        EXPECT_EQ(size.value(), factory->encoded_bytes.size());
        EXPECT_EQ(factory->last_handle, &key.handle);
        EXPECT_EQ(factory->last_format, format);
        EXPECT_EQ(key.export_calls, 0U);
    }
}

TEST(KeyExporterTest, UnavailableRawMaterialUsesExistingFactoryAndSizeInterface)
{
    ExportTestKey key;
    key.export_error = Error::kKeyNotExportable;
    auto factory = std::make_shared<ExportTestFactory>();
    factory->export_error.reset();
    factory->size_error.reset();
    provider::KeyExporter exporter{factory};

    auto exported = exporter.ExportKey(key, Format::kRaw);
    auto size = exporter.GetExportKeySize(key, Format::kRaw);

    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported.value().bytes, factory->encoded_bytes);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), factory->encoded_bytes.size());
    EXPECT_EQ(factory->last_handle, &key.handle);
    EXPECT_EQ(factory->export_calls, 1U);
    EXPECT_EQ(factory->size_calls, 1U);
}

TEST(KeyExporterTest, UnsupportedFactoryPreservesRawPermissionError)
{
    ExportTestKey key;
    key.export_error = Error::kKeyOperationNotPermitted;
    provider::KeyExporter exporter{std::make_shared<km::IKeyFactory>()};

    auto exported = exporter.ExportKey(key, Format::kRaw);
    ASSERT_FALSE(exported.has_value());
    EXPECT_EQ(exported.error(), Error::kKeyOperationNotPermitted);

    auto size = exporter.GetExportKeySize(key, Format::kRaw);
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), Error::kKeyOperationNotPermitted);
}

TEST(KeyExporterTest, FormattedFactoryErrorsArePreserved)
{
    ExportTestKey key;
    key.export_error = Error::kKeyNotExportable;
    auto factory = std::make_shared<ExportTestFactory>();
    factory->export_error = Error::kInvalidFormat;
    factory->size_error = Error::kInvalidArgument;
    provider::KeyExporter exporter{factory};

    auto exported = exporter.ExportKey(key, Format::kRaw);
    ASSERT_FALSE(exported.has_value());
    EXPECT_EQ(exported.error(), Error::kInvalidFormat);

    auto size = exporter.GetExportKeySize(key, Format::kRaw);
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), Error::kInvalidArgument);
}

TEST(KeyExporterTest, TerminalRawFailureDoesNotCallFormattedFactory)
{
    for (const auto error : {Error::kInternalError, Error::kOperationFailed})
    {
        ExportTestKey key;
        key.export_error = error;
        auto factory = std::make_shared<ExportTestFactory>();
        factory->export_error.reset();
        factory->size_error.reset();
        provider::KeyExporter exporter{factory};

        auto exported = exporter.ExportKey(key, Format::kRaw);
        ASSERT_FALSE(exported.has_value());
        EXPECT_EQ(exported.error(), error);

        auto size = exporter.GetExportKeySize(key, Format::kRaw);
        ASSERT_FALSE(size.has_value());
        EXPECT_EQ(size.error(), error);
        EXPECT_EQ(factory->export_calls, 0U);
        EXPECT_EQ(factory->size_calls, 0U);
    }
}

TEST(KeyExporterTest, UnsupportedNonRawFormatsDoNotFallBackToRawBytes)
{
    ExportTestKey key;
    provider::KeyExporter exporter{std::make_shared<km::IKeyFactory>()};

    for (const auto format : {Format::kDer, Format::kPem})
    {
        auto exported = exporter.ExportKey(key, format);
        ASSERT_FALSE(exported.has_value());
        EXPECT_EQ(exported.error(), Error::kUnsupportedOperation);

        auto size = exporter.GetExportKeySize(key, format);
        ASSERT_FALSE(size.has_value());
        EXPECT_EQ(size.error(), Error::kUnsupportedOperation);
    }
    EXPECT_EQ(key.export_calls, 0U);
}

TEST(KeyExporterTest, ExistingOpenSslSymmetricHandlerReproducesImportedBytes)
{
    const std::vector<std::uint8_t> key_bytes(32U, 0xA5U);
    for (const char* name : {"HMAC-SHA256", "AES-256"})
    {
        auto factory = std::make_shared<openssl::OpenSslKeyFactory>(7U);
        provider::KeyExporter exporter{factory};
        const auto algorithm = score::crypto::GetAlgorithmDescriptor(name);
        ASSERT_TRUE(algorithm.has_value());
        km::KeyImportRequest request{};
        request.algorithm = *algorithm;
        request.key_data = key_bytes.data();
        request.key_data_size = key_bytes.size();
        request.format = Format::kRaw;
        request.permissions = Permission::kExport;
        auto key = factory->ImportKey(request);
        ASSERT_TRUE(key.has_value()) << name;

        auto exported = exporter.ExportKey(*key.value(), Format::kRaw);
        auto size = exporter.GetExportKeySize(*key.value(), Format::kRaw);

        ASSERT_TRUE(exported.has_value()) << name;
        EXPECT_EQ(exported.value().bytes, key_bytes) << name;
        ASSERT_TRUE(size.has_value()) << name;
        EXPECT_EQ(size.value(), key_bytes.size()) << name;
        EXPECT_TRUE(key.value()->Release().has_value());
    }
}

TEST(KeyExporterTest, ExistingOpenSslEcExportUsesPublicPermissions)
{
    auto factory = std::make_shared<openssl::OpenSslKeyFactory>(7U);
    provider::KeyExporter exporter{factory};
    const auto algorithm = score::crypto::GetAlgorithmDescriptor("ECDSA-P256");
    ASSERT_TRUE(algorithm.has_value());
    km::KeyGenerationRequest request{};
    request.algorithm = *algorithm;
    request.permissions = Permission::kSign;
    request.public_key_permissions = Permission::kExport;
    auto key = factory->GenerateKey(request);
    ASSERT_TRUE(key.has_value());

    auto exported = exporter.ExportKey(*key.value(), Format::kRaw);
    auto size = exporter.GetExportKeySize(*key.value(), Format::kRaw);

    ASSERT_TRUE(exported.has_value());
    ASSERT_EQ(exported.value().bytes.size(), 65U);
    EXPECT_EQ(exported.value().bytes.front(), 0x04U);
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(size.value(), exported.value().bytes.size());
    EXPECT_TRUE(key.value()->Release().has_value());
}

TEST(KeyExporterTest, ExistingOpenSslEcExportStillRejectsMissingPublicPermission)
{
    auto factory = std::make_shared<openssl::OpenSslKeyFactory>(7U);
    provider::KeyExporter exporter{factory};
    const auto algorithm = score::crypto::GetAlgorithmDescriptor("ECDSA-P256");
    ASSERT_TRUE(algorithm.has_value());
    km::KeyGenerationRequest request{};
    request.algorithm = *algorithm;
    request.permissions = Permission::kExport;
    request.public_key_permissions = Permission::kNone;
    auto key = factory->GenerateKey(request);
    ASSERT_TRUE(key.has_value());

    auto exported = exporter.ExportKey(*key.value(), Format::kRaw);
    ASSERT_FALSE(exported.has_value());
    EXPECT_EQ(exported.error(), Error::kKeyNotExportable);

    auto size = exporter.GetExportKeySize(*key.value(), Format::kRaw);
    ASSERT_FALSE(size.has_value());
    EXPECT_EQ(size.error(), Error::kKeyNotExportable);
    EXPECT_TRUE(key.value()->Release().has_value());
}

TEST(KeyExporterTest, ExistingOpenSslNonEcAsymmetricRawExportRemainsNotExportable)
{
    for (const char* name : {"Ed25519", "RSA-2048"})
    {
        auto factory = std::make_shared<openssl::OpenSslKeyFactory>(7U);
        provider::KeyExporter exporter{factory};
        const auto algorithm = score::crypto::GetAlgorithmDescriptor(name);
        ASSERT_TRUE(algorithm.has_value());
        km::KeyGenerationRequest request{};
        request.algorithm = *algorithm;
        request.permissions = Permission::kExport;
        auto key = factory->GenerateKey(request);
        ASSERT_TRUE(key.has_value()) << name;

        auto exported = exporter.ExportKey(*key.value(), Format::kRaw);
        ASSERT_FALSE(exported.has_value()) << name;
        EXPECT_EQ(exported.error(), Error::kKeyNotExportable) << name;

        auto size = exporter.GetExportKeySize(*key.value(), Format::kRaw);
        ASSERT_FALSE(size.has_value()) << name;
        EXPECT_EQ(size.error(), Error::kKeyNotExportable) << name;
        EXPECT_TRUE(key.value()->Release().has_value());
    }
}
}  // namespace
