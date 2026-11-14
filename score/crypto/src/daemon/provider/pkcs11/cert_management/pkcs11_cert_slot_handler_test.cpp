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

#include "score/crypto/src/daemon/provider/pkcs11/cert_management/pkcs11_cert_slot_handler.hpp"

#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"
#include "score/crypto/tests/softhsm/softhsm_test_fixture.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>
#include <pkcs11.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace cert = score::crypto::daemon::cert_management;
namespace common = score::crypto::daemon::common;
namespace storage = score::crypto::daemon::common::storage;
namespace pkcs11_ns = score::crypto::daemon::provider::pkcs11;
namespace provider_cert = score::crypto::daemon::provider::cert_management;
namespace openssl_ns = score::crypto::daemon::provider::score_provider::openssl;

constexpr char kLeafDerPath[] = "score/tests/test_vectors/certificate/basic/certificate_leaf.der";
constexpr char kCaPemPath[] = "score/tests/test_vectors/certificate/basic/certificate.pem";
constexpr char kUpdatedPemPath[] = "score/tests/test_vectors/certificate/basic/certificate_updated.pem";
constexpr char kCrlDerPath[] = "score/tests/test_vectors/certificate/basic/certificate.crl.der";
constexpr char kLabel[] = "score-cert-slot-test";
constexpr char kObjectIdHex[] = "0a0b0c0d";
constexpr std::uint8_t kObjectIdBytes[] = {0x0a, 0x0b, 0x0c, 0x0d};
constexpr char kUserPin[] = "1234";
constexpr char kTokenLabel[] = "Test Token";

std::vector<std::uint8_t> ReadBytes(const std::filesystem::path& path)
{
    std::ifstream in{path, std::ios::binary};
    const std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size());
    for (const char c : text)
    {
        bytes.push_back(static_cast<std::uint8_t>(c));
    }
    return bytes;
}

bool SameFingerprint(const cert::CertObject& first, const cert::CertObject& second)
{
    const auto a = first.GetFingerprint();
    const auto b = second.GetFingerprint();
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}

class Pkcs11CertSlotHandlerTest : public tests::softhsm::SofthsmTestFixture
{
  protected:
    void SetUp() override
    {
        ASSERT_NO_FATAL_FAILURE(tests::softhsm::SofthsmTestFixture::SetUp());

        m_dir = ::tests::utility::TempDirectory("pkcs11_cert_slot");
        std::filesystem::remove_all(m_dir);
        std::filesystem::create_directories(m_dir);
        const std::filesystem::path descriptor_path = m_dir / "slot.kv";
        ASSERT_NO_FATAL_FAILURE(WriteIdentityDescriptor(descriptor_path, ""));

        m_slot.slot_name = "pkcs11_cert_slot_test";
        m_slot.deployment_path = descriptor_path.string();
        m_slot.deployment_format = "kv";

        m_module = std::make_shared<pkcs11_ns::Pkcs11Module>();
        ASSERT_TRUE(m_module->Init().has_value());

        pkcs11_ns::Pkcs11ProviderConfig config{};
        config.tokenLabel = kTokenLabel;
        config.userPin = kUserPin;
        m_provider = std::make_shared<pkcs11_ns::Pkcs11Provider>(std::move(config), m_module);
        ASSERT_TRUE(m_provider->Initialize(score::crypto::daemon::provider::ProviderInitContext{1, "SOFTHSM_TEST"}));

        m_parser = std::make_shared<openssl_ns::OpenSslCertParser>(common::ProviderId{1U});
        m_handler = std::make_unique<pkcs11_ns::Pkcs11CertSlotHandler>(m_slot, m_provider, m_module, m_parser);
    }

    void TearDown() override
    {
        // Handler and provider must release their sessions before the fixture finalizes the library.
        m_handler.reset();
        m_provider.reset();
        m_module.reset();
        tests::softhsm::SofthsmTestFixture::TearDown();
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    /// Writes a slot descriptor that identifies the token object, with an optional CRL path.
    void WriteIdentityDescriptor(const std::filesystem::path& path, const std::string& crl_path)
    {
        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "pkcs11.label", kLabel);
        descriptor.Set("certificate", "pkcs11.object_id", kObjectIdHex);
        if (!crl_path.empty())
        {
            descriptor.Set("crl", "crl_path", crl_path);
        }
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(path.string(), descriptor).has_value());
    }

    std::shared_ptr<cert::CertObject> ParseFixture(const std::filesystem::path& path, score::crypto::FormatType format)
    {
        const auto bytes = ReadBytes(path);
        auto parsed = m_parser->ParseCertificate(bytes.data(), bytes.size(), format);
        if (!parsed.has_value())
        {
            return nullptr;
        }
        return *parsed;
    }

    /// Parses DER bytes as a certificate.
    std::shared_ptr<cert::CertObject> ParseDer(const std::vector<std::uint8_t>& der)
    {
        auto parsed = m_parser->ParseCertificate(der.data(), der.size(), score::crypto::FormatType::kDer);
        if (!parsed.has_value())
        {
            return nullptr;
        }
        return *parsed;
    }

    /// DER encoding of a PEM certificate file; empty on failure.
    std::vector<std::uint8_t> EncodeDerFromPem(const std::filesystem::path& path)
    {
        const auto parsed = ParseFixture(path, score::crypto::FormatType::kPem);
        if (parsed == nullptr)
        {
            ADD_FAILURE() << "could not parse " << path;
            return {};
        }
        auto der = m_parser->EncodeCertificate(*parsed, score::crypto::FormatType::kDer);
        if (!der.has_value())
        {
            ADD_FAILURE() << "could not encode " << path << " as DER";
            return {};
        }
        return *der;
    }

    /// Handles of every certificate object carrying the test label.
    std::vector<CK_OBJECT_HANDLE> FindTokenCertificates()
    {
        CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
        std::string label{kLabel};
        std::array<CK_ATTRIBUTE, 2U> attributes{
            CK_ATTRIBUTE{CKA_CLASS, &object_class, sizeof(object_class)},
            CK_ATTRIBUTE{CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())}};

        std::vector<CK_OBJECT_HANDLE> found;
        EXPECT_EQ(function_list->C_FindObjectsInit(session, attributes.data(), 2U), CKR_OK);
        std::array<CK_OBJECT_HANDLE, 8U> handles{};
        CK_ULONG count = 0U;
        do
        {
            EXPECT_EQ(function_list->C_FindObjects(session, handles.data(), 8U, &count), CKR_OK);
            found.insert(found.end(), handles.begin(), handles.begin() + static_cast<std::ptrdiff_t>(count));
        } while (count == 8U);
        EXPECT_EQ(function_list->C_FindObjectsFinal(session), CKR_OK);
        return found;
    }

    std::size_t CountTokenCertificates()
    {
        return FindTokenCertificates().size();
    }

    /// Value of one attribute of a token object, read with the size-then-bytes two-call pattern.
    std::vector<CK_BYTE> ReadAttribute(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type)
    {
        CK_ATTRIBUTE size_query{type, nullptr, 0U};
        EXPECT_EQ(function_list->C_GetAttributeValue(session, object, &size_query, 1U), CKR_OK);
        if (size_query.ulValueLen == CK_UNAVAILABLE_INFORMATION)
        {
            return {};
        }
        std::vector<CK_BYTE> value(static_cast<std::size_t>(size_query.ulValueLen));
        CK_ATTRIBUTE value_query{type, value.data(), size_query.ulValueLen};
        EXPECT_EQ(function_list->C_GetAttributeValue(session, object, &value_query, 1U), CKR_OK);
        return value;
    }

    /// Creates a certificate object with the test label and ID directly on the token, bypassing the handler.
    void PlantTokenCertificate(const cert::CertObject& certificate)
    {
        const auto raw = certificate.GetRawBytes();
        const auto& metadata = certificate.GetChainMetadata();
        std::vector<CK_BYTE> der(raw.begin(), raw.end());
        std::vector<CK_BYTE> subject(metadata.subject_name_der.begin(), metadata.subject_name_der.end());
        std::vector<CK_BYTE> issuer(metadata.issuer_name_der.begin(), metadata.issuer_name_der.end());
        std::vector<CK_BYTE> serial(metadata.serial_number_der.begin(), metadata.serial_number_der.end());
        std::string label{kLabel};
        std::vector<CK_BYTE> id(std::begin(kObjectIdBytes), std::end(kObjectIdBytes));
        CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
        CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
        CK_BBOOL token = CK_TRUE;
        std::array<CK_ATTRIBUTE, 9U> attributes{
            CK_ATTRIBUTE{CKA_CLASS, &object_class, sizeof(object_class)},
            CK_ATTRIBUTE{CKA_CERTIFICATE_TYPE, &certificate_type, sizeof(certificate_type)},
            CK_ATTRIBUTE{CKA_TOKEN, &token, sizeof(token)},
            CK_ATTRIBUTE{CKA_VALUE, der.data(), der.size()},
            CK_ATTRIBUTE{CKA_SUBJECT, subject.data(), subject.size()},
            CK_ATTRIBUTE{CKA_ISSUER, issuer.data(), issuer.size()},
            CK_ATTRIBUTE{CKA_SERIAL_NUMBER, serial.data(), serial.size()},
            CK_ATTRIBUTE{CKA_LABEL, label.data(), static_cast<CK_ULONG>(label.size())},
            CK_ATTRIBUTE{CKA_ID, id.data(), id.size()}};
        CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
        EXPECT_EQ(function_list->C_CreateObject(
                      session, attributes.data(), static_cast<CK_ULONG>(attributes.size()), &handle),
                  CKR_OK);
    }

    /// CRL fixture. Its issuer is the certificate in kCaPemPath.
    cert::CrlData LoadCrl(std::optional<score::crypto::CrlMetadata> metadata = std::nullopt)
    {
        cert::CrlData crl;
        crl.bytes = ReadBytes(kCrlDerPath);
        crl.format = score::crypto::FormatType::kDer;
        crl.metadata = metadata;
        return crl;
    }

    std::filesystem::path m_dir;
    cert::CertSlotConfig m_slot{};
    std::shared_ptr<pkcs11_ns::Pkcs11Module> m_module;
    std::shared_ptr<pkcs11_ns::Pkcs11Provider> m_provider;
    provider_cert::ICertParser::Sptr m_parser;
    std::unique_ptr<pkcs11_ns::Pkcs11CertSlotHandler> m_handler;
};

TEST_F(Pkcs11CertSlotHandlerTest, SlotStateFollowsStoreAndClear)
{
    RecordProperty("Description",
                   "Slot state moves empty -> occupied -> empty across store and clear, and the token object is "
                   "removed on clear");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);

    const auto initial = m_handler->GetSlotState();
    ASSERT_TRUE(initial.has_value());
    EXPECT_EQ(*initial, score::crypto::CertificateSlotState::kEmpty);

    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    const auto occupied = m_handler->GetSlotState();
    ASSERT_TRUE(occupied.has_value());
    EXPECT_EQ(*occupied, score::crypto::CertificateSlotState::kOccupied);

    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    const auto cleared = m_handler->GetSlotState();
    ASSERT_TRUE(cleared.has_value());
    EXPECT_EQ(*cleared, score::crypto::CertificateSlotState::kEmpty);
    EXPECT_EQ(CountTokenCertificates(), 0U);
}

TEST_F(Pkcs11CertSlotHandlerTest, LoadCertificate_EmptySlot_ReturnsKeySlotEmpty)
{
    RecordProperty("Description", "Loading from a slot with no token object fails with kKeySlotEmpty");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto result = m_handler->LoadCertificate();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeySlotEmpty);
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreThenLoad_RoundTripsCertificate)
{
    RecordProperty("Description",
                   "Subject, issuer, CA flag and fingerprint survive a store and load through the token");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());

    const auto loaded = m_handler->LoadCertificate();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_NE(*loaded, nullptr);
    const cert::CertObject& actual = **loaded;

    EXPECT_EQ(actual.GetSubject(), leaf->GetSubject());
    EXPECT_EQ(actual.GetIssuer(), leaf->GetIssuer());
    EXPECT_EQ(actual.IsCA(), leaf->IsCA());
    EXPECT_TRUE(SameFingerprint(actual, *leaf));
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreTwice_LeavesSingleTokenObject)
{
    RecordProperty("Description",
                   "Storing into an occupied slot replaces the token object instead of adding a second one");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());

    EXPECT_EQ(CountTokenCertificates(), 1U);
    EXPECT_TRUE(m_handler->LoadCertificate().has_value());
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreCertificate_RejectsPemEncoding)
{
    RecordProperty("Description",
                   "PEM-encoded input is rejected with kUnsupportedOperation and nothing reaches the token");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto ca = ParseFixture(kCaPemPath, score::crypto::FormatType::kPem);
    ASSERT_NE(ca, nullptr);

    const auto stored = m_handler->StoreCertificate(*ca);
    ASSERT_FALSE(stored.has_value());
    EXPECT_EQ(stored.error(), common::DaemonErrorCode::kUnsupportedOperation);
    EXPECT_EQ(CountTokenCertificates(), 0U);
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreCertificate_WritesDerNameAndSerialAttributes)
{
    RecordProperty("Description",
                   "The token object carries the certificate DER and the DER subject, issuer and serial number");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());

    const auto objects = FindTokenCertificates();
    ASSERT_EQ(objects.size(), 1U);
    const auto raw = leaf->GetRawBytes();
    const auto& metadata = leaf->GetChainMetadata();
    ASSERT_FALSE(metadata.subject_name_der.empty());
    EXPECT_EQ(ReadAttribute(objects.front(), CKA_VALUE), std::vector<CK_BYTE>(raw.begin(), raw.end()));
    EXPECT_EQ(ReadAttribute(objects.front(), CKA_SUBJECT), metadata.subject_name_der);
    EXPECT_EQ(ReadAttribute(objects.front(), CKA_ISSUER), metadata.issuer_name_der);
    EXPECT_EQ(ReadAttribute(objects.front(), CKA_SERIAL_NUMBER), metadata.serial_number_der);
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreCertificate_ReplacesPreviousCertificate)
{
    RecordProperty("Description", "Storing a different certificate replaces the one on the token");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    const auto updated = ParseDer(EncodeDerFromPem(kUpdatedPemPath));
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(updated, nullptr);
    ASSERT_FALSE(SameFingerprint(*leaf, *updated));

    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    ASSERT_TRUE(m_handler->StoreCertificate(*updated).has_value());

    EXPECT_EQ(CountTokenCertificates(), 1U);
    const auto loaded = m_handler->LoadCertificate();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_NE(*loaded, nullptr);
    EXPECT_TRUE(SameFingerprint(**loaded, *updated));
}

TEST_F(Pkcs11CertSlotHandlerTest, DuplicateObjects_LoadIsRefused_StoreLeavesOne)
{
    RecordProperty("Description",
                   "Two token objects matching the identity make loading fail, the slot reads as occupied, and a "
                   "store removes every match");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    PlantTokenCertificate(*leaf);
    PlantTokenCertificate(*leaf);
    ASSERT_EQ(CountTokenCertificates(), 2U);

    const auto state = m_handler->GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, score::crypto::CertificateSlotState::kOccupied);

    const auto ambiguous = m_handler->LoadCertificate();
    ASSERT_FALSE(ambiguous.has_value());
    EXPECT_EQ(ambiguous.error(), common::DaemonErrorCode::kResourceNotAllocated);

    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    EXPECT_EQ(CountTokenCertificates(), 1U);
    EXPECT_TRUE(m_handler->LoadCertificate().has_value());
}

TEST_F(Pkcs11CertSlotHandlerTest, DuplicateObjects_ClearRemovesEveryMatch)
{
    RecordProperty("Description", "Clearing a slot removes every token object matching the identity");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    PlantTokenCertificate(*leaf);
    PlantTokenCertificate(*leaf);
    ASSERT_EQ(CountTokenCertificates(), 2U);

    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    EXPECT_EQ(CountTokenCertificates(), 0U);
    const auto state = m_handler->GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, score::crypto::CertificateSlotState::kEmpty);
}

TEST_F(Pkcs11CertSlotHandlerTest, SlotWithoutIdentity_IsEmptyAndRefusesStore)
{
    RecordProperty("Description",
                   "A descriptor with no pkcs11 identity reads as empty, refuses a store, and creates no token object");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    storage::DeploymentDescriptor descriptor;
    descriptor.Set("metadata", "description", "no token identity");
    const std::filesystem::path path = m_dir / "no_identity.kv";
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(path.string(), descriptor).has_value());

    cert::CertSlotConfig slot = m_slot;
    slot.deployment_path = path.string();
    pkcs11_ns::Pkcs11CertSlotHandler handler{slot, m_provider, m_module, m_parser};

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    const auto stored = handler.StoreCertificate(*leaf);
    ASSERT_FALSE(stored.has_value());
    EXPECT_EQ(stored.error(), common::DaemonErrorCode::kInvalidArgument);

    const auto loaded = handler.LoadCertificate();
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error(), common::DaemonErrorCode::kKeySlotEmpty);

    const auto state = handler.GetSlotState();
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(*state, score::crypto::CertificateSlotState::kEmpty);
    EXPECT_EQ(CountTokenCertificates(), 0U);
}

TEST_F(Pkcs11CertSlotHandlerTest, IntegrityRequired_IsRefusedByProvider)
{
    RecordProperty("Description",
                   "The provider creates no handler for a kRequired slot, because token-backed slots do not "
                   "enforce integrity; a kDisabled slot is served");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__slots");

    cert::CertSlotConfig required = m_slot;
    required.integrity_policy = cert::IntegrityPolicy::kRequired;
    EXPECT_EQ(m_provider->GetCertSlotHandler(required, m_parser), nullptr);

    cert::CertSlotConfig disabled = m_slot;
    disabled.integrity_policy = cert::IntegrityPolicy::kDisabled;
    EXPECT_NE(m_provider->GetCertSlotHandler(disabled, m_parser), nullptr);
}

TEST_F(Pkcs11CertSlotHandlerTest, CrlRoundTrip_StoresAndReportsCrl)
{
    RecordProperty("Description",
                   "A validated CRL stored on a token slot is reported by HasCrl, GetSlotInfo and GetCrlMetadata, "
                   "returned by LoadCrlData, and removed by ClearCrl");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");

    const auto ca_der = EncodeDerFromPem(kCaPemPath);
    ASSERT_FALSE(ca_der.empty());
    const auto validated =
        m_parser->ValidateCrl(LoadCrl(), ca_der.data(), ca_der.size(), score::crypto::FormatType::kDer);
    ASSERT_TRUE(validated.has_value());

    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl(*validated)).has_value());

    const auto has_crl = m_handler->HasCrl();
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_TRUE(*has_crl);

    const auto info = m_handler->GetSlotInfo();
    ASSERT_TRUE(info.has_value());
    EXPECT_TRUE(info->has_crl);

    const auto metadata = m_handler->GetCrlMetadata();
    ASSERT_TRUE(metadata.has_value());
    ASSERT_TRUE(metadata->has_value());
    EXPECT_EQ(metadata->value().next_update, validated->next_update);
    EXPECT_EQ(metadata->value().fingerprint, validated->fingerprint);

    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->bytes, ReadBytes(kCrlDerPath));
    EXPECT_TRUE((*loaded)->metadata.has_value());

    ASSERT_TRUE(m_handler->ClearCrl().has_value());
    const auto cleared = m_handler->HasCrl();
    ASSERT_TRUE(cleared.has_value());
    EXPECT_FALSE(*cleared);
    const auto after_clear = m_handler->LoadCrlData();
    ASSERT_TRUE(after_clear.has_value());
    EXPECT_FALSE(after_clear->has_value());
}

TEST_F(Pkcs11CertSlotHandlerTest, CrlWithoutCachedMetadata_IsDerivedFromTokenCertificate)
{
    RecordProperty("Description",
                   "A CRL with no cached metadata gets metadata from the token certificate that issued it, in both "
                   "GetCrlMetadata and LoadCrlData, as the file-backed handler does");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");

    const auto ca = ParseDer(EncodeDerFromPem(kCaPemPath));
    ASSERT_NE(ca, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*ca).has_value());
    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl()).has_value());

    const auto metadata = m_handler->GetCrlMetadata();
    ASSERT_TRUE(metadata.has_value());
    ASSERT_TRUE(metadata->has_value());
    EXPECT_NE(metadata->value().next_update, 0);

    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    ASSERT_TRUE((*loaded)->metadata.has_value());
    EXPECT_EQ((*loaded)->metadata->next_update, metadata->value().next_update);
    EXPECT_EQ((*loaded)->metadata->fingerprint, metadata->value().fingerprint);
}

TEST_F(Pkcs11CertSlotHandlerTest, CrlWithoutMatchingIssuer_HasNoDerivedMetadata)
{
    RecordProperty("Description",
                   "A CRL whose issuer is not the token certificate gets no derived metadata, and its bytes are still "
                   "returned");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl()).has_value());

    const auto metadata = m_handler->GetCrlMetadata();
    ASSERT_TRUE(metadata.has_value());
    EXPECT_FALSE(metadata->has_value());

    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->bytes, ReadBytes(kCrlDerPath));
    EXPECT_FALSE((*loaded)->metadata.has_value());
}

TEST_F(Pkcs11CertSlotHandlerTest, StoreCertificate_ClearsCrlAndKeepsItsPath)
{
    RecordProperty("Description",
                   "Storing a certificate removes the stale CRL file and keeps crl_path, so the next StoreCrl writes "
                   "to the same location");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");

    const std::filesystem::path custom_crl = m_dir / "custom.crl";
    ASSERT_NO_FATAL_FAILURE(WriteIdentityDescriptor(m_dir / "slot.kv", custom_crl.string()));

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);

    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl()).has_value());
    EXPECT_TRUE(std::filesystem::exists(custom_crl));

    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    const auto stale = m_handler->HasCrl();
    ASSERT_TRUE(stale.has_value());
    EXPECT_FALSE(*stale);
    EXPECT_FALSE(std::filesystem::exists(custom_crl));

    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl()).has_value());
    EXPECT_TRUE(std::filesystem::exists(custom_crl));
}

TEST_F(Pkcs11CertSlotHandlerTest, ClearSlot_RemovesCrl)
{
    RecordProperty("Description", "Clearing a slot removes its CRL along with the token certificate");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");

    const auto leaf = ParseFixture(kLeafDerPath, score::crypto::FormatType::kDer);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(m_handler->StoreCertificate(*leaf).has_value());
    ASSERT_TRUE(m_handler->StoreCrl(LoadCrl()).has_value());

    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    const auto has_crl = m_handler->HasCrl();
    ASSERT_TRUE(has_crl.has_value());
    EXPECT_FALSE(*has_crl);
    EXPECT_EQ(CountTokenCertificates(), 0U);
}

}  // namespace
