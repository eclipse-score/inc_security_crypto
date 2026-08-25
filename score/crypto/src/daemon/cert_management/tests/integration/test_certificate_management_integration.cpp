#include "score/crypto/src/daemon/cert_management/slot/config_driven_slot_catalog.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/config_driven_trust_store_catalog.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/cert_management/openssl_cert_parser.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <utility>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace config = score::crypto::daemon::config;
namespace storage = score::crypto::daemon::common::storage;
namespace openssl = score::crypto::daemon::provider::score_provider::openssl;

class CertificateManagementIntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = std::filesystem::temp_directory_path() / "score_cert_management_integration";
        std::filesystem::remove_all(m_directory);
        std::filesystem::create_directories(m_directory);
        m_descriptor_path = m_directory / "device_root.kv";
        m_certificate_path = m_directory / "device_root.pem";
        m_trust_store_path = m_directory / "tls_roots.kv";

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate.pem",
                                               m_certificate_path,
                                               std::filesystem::copy_options::overwrite_existing));
        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/certificate_updated.pem",
                                               m_directory / "certificate_updated.pem",
                                               std::filesystem::copy_options::overwrite_existing));

        storage::DeploymentDescriptor slot_desc;
        slot_desc.Set("certificate", "cert_path", m_certificate_path.string());
        slot_desc.Set("certificate", "cert_format", "pem");
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor_path.string(), slot_desc).has_value());

        ASSERT_TRUE(std::filesystem::copy_file("score/tests/test_vectors/certificate/trust_store.kv",
                                               m_trust_store_path,
                                               std::filesystem::copy_options::overwrite_existing));

        config::CertificateConfig::CertSlotEntry slot;
        slot.slot_name = "device/root-ca";
        slot.storage_backend = "DEFAULT";
        slot.deployment_path = m_descriptor_path.string();
        slot.deployment_format = "kv";
        slot.allowed_uids = {0U};
        slot.allowed_write_uids = {0U};
        m_config.AddSlotEntry(std::move(slot));

        config::CertificateConfig::TrustStoreEntry trust_store;
        trust_store.store_name = "tls-roots";
        trust_store.members.push_back(
            {"device/root-ca", config::CertificateConfig::TrustStoreMemberKind::kSharedStatic});
        trust_store.deployment_path = m_trust_store_path.string();
        trust_store.deployment_format = "kv";
        trust_store.allowed_uids = {0U};
        trust_store.allowed_write_uids = {0U};
        m_config.AddTrustStoreEntry(std::move(trust_store));
        m_config.AddAppCertSlotEntry({0U, "device_certificate", "device/root-ca"});
        m_config.AddAppTrustStoreEntry({0U, "tls_roots", "tls-roots"});

        m_parser = std::make_shared<openssl::OpenSslCertParser>(1U);
        m_slot_registry = std::make_shared<cert::CertSlotRegistry>();
        cert::ConfigDrivenSlotCatalog slot_catalog{m_config};
        slot_catalog.Load(*m_slot_registry);

        m_trust_store_manager = std::make_shared<cert::TrustStoreManager>();
        cert::ConfigDrivenTrustStoreCatalog trust_store_catalog{m_config};
        trust_store_catalog.Load(*m_trust_store_manager, m_slot_registry, [this](const cert::CertSlotConfig&) {
            return std::make_shared<cert::FileBackedSlotHandler>(m_parser);
        });
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_directory, error);
    }

    std::string ReadFile(const std::filesystem::path& path) const
    {
        std::ifstream input{path};
        return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    }

    std::filesystem::path m_directory;
    std::filesystem::path m_descriptor_path;
    std::filesystem::path m_certificate_path;
    std::filesystem::path m_trust_store_path;
    config::CertificateConfig m_config;
    std::shared_ptr<openssl::OpenSslCertParser> m_parser;
    cert::CertSlotRegistry::Sptr m_slot_registry;
    cert::TrustStoreManager::Sptr m_trust_store_manager;
};

TEST_F(CertificateManagementIntegrationTest, LoadsPersistsUpdatesAndInvalidatesTrustStoreAnchor)
{
    const auto slot = m_slot_registry->ResolveAppResource("device_certificate", 0U);
    ASSERT_TRUE(slot.has_value());
    const auto slot_config = m_slot_registry->GetConfig(*slot);
    ASSERT_TRUE(slot_config.has_value());

    auto slot_handler = std::make_shared<cert::FileBackedSlotHandler>(m_parser);
    const auto initial = slot_handler->LoadCertificate(**slot_config);
    ASSERT_TRUE(initial.has_value());
    EXPECT_EQ((*initial)->GetSubject(), "CN=cert-management-test,O=Eclipse");
    EXPECT_TRUE((*initial)->IsCA());

    auto trust_store_handle = m_trust_store_manager->ResolveAppResource("tls_roots", 0U);
    ASSERT_TRUE(trust_store_handle.has_value());
    auto trust_store = m_trust_store_manager->GetStore(trust_store_handle->index);
    ASSERT_NE(trust_store, nullptr);

    const auto initial_anchors = trust_store->GetAnchors();
    ASSERT_TRUE(initial_anchors.has_value());
    ASSERT_EQ(initial_anchors->size(), 1U);
    EXPECT_EQ((*initial_anchors)[0]->GetSubject(), "CN=cert-management-test,O=Eclipse");

    const auto updated_pem = ReadFile(m_directory / "certificate_updated.pem");
    ASSERT_FALSE(updated_pem.empty());
    const auto updated = m_parser->ParseCertificate(
        reinterpret_cast<const std::uint8_t*>(updated_pem.data()), updated_pem.size(), score::crypto::FormatType::kPem);
    ASSERT_TRUE(updated.has_value());
    ASSERT_TRUE(slot_handler->StoreCertificate(**slot_config, **updated).has_value());

    const auto descriptor = cert::DeploymentLoader::Load(m_descriptor_path.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_EQ(descriptor->Get("certificate_metadata", "subject"), "CN=cert-management-updated,O=Eclipse");
    EXPECT_EQ(descriptor->Get("certificate_metadata", "issuer"), "CN=cert-management-updated,O=Eclipse");
    EXPECT_EQ(descriptor->Get("certificate_metadata", "is_ca"), "true");

    m_trust_store_manager->NotifySlotChanged(trust_store_handle->index, *slot);
    const auto updated_anchors = trust_store->GetAnchors();
    ASSERT_TRUE(updated_anchors.has_value());
    ASSERT_EQ(updated_anchors->size(), 1U);
    EXPECT_EQ((*updated_anchors)[0]->GetSubject(), "CN=cert-management-updated,O=Eclipse");
    EXPECT_FALSE(std::equal((*updated_anchors)[0]->GetFingerprint().begin(),
                            (*updated_anchors)[0]->GetFingerprint().end(),
                            (*initial_anchors)[0]->GetFingerprint().begin(),
                            (*initial_anchors)[0]->GetFingerprint().end()));
}
}  // namespace
