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

#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_writer.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
namespace cert = score::crypto::daemon::cert_management;
namespace provider = score::crypto::daemon::provider::cert_management;
namespace storage = score::crypto::daemon::common::storage;
using Error = score::crypto::daemon::common::DaemonErrorCode;

TEST(DeploymentLoaderTest, RejectsUnsupportedFormatBeforeValidatingPath)
{
    const auto result = cert::DeploymentLoader::Load("../unsafe/slot", "json");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kUnsupportedOperation);
}

TEST(DeploymentWriterTest, RejectsUnsupportedFormatBeforeValidatingPath)
{
    const storage::DeploymentDescriptor descriptor;
    const auto result = cert::DeploymentWriter::Write("../unsafe/slot", "json", descriptor);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kUnsupportedOperation);
}

class FakeParser : public provider::ICertParser
{
  public:
    score::crypto::Expected<cert::CertObject::Sptr, Error> ParseCertificate(const std::uint8_t* bytes,
                                                                            std::size_t size,
                                                                            score::crypto::FormatType format) override
    {
        if (bytes == nullptr || size == 0U)
            return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
        cert::CertChainMetadata metadata;
        metadata.subject_canonical = "CN=file-test";
        metadata.issuer_canonical = "CN=file-test";
        metadata.fingerprint.fill(0x11U);
        return std::make_shared<cert::CertObject>(
            std::move(metadata), std::vector<std::uint8_t>{bytes, bytes + size}, format);
    }

    score::crypto::Expected<std::vector<cert::CertObject::Sptr>, Error>
    ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) override
    {
        auto parsed = ParseCertificate(bytes, size, format);
        if (!parsed)
            return score::crypto::make_unexpected(parsed.error());
        return std::vector<cert::CertObject::Sptr>{*parsed};
    }

    score::crypto::Expected<std::vector<std::uint8_t>, Error> EncodeCertificate(const cert::CertObject&,
                                                                                score::crypto::FormatType) override
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    score::crypto::Expected<score::crypto::CrlMetadata, Error> ValidateCrl(const cert::CrlData&,
                                                                           const std::uint8_t*,
                                                                           std::size_t,
                                                                           score::crypto::FormatType) override
    {
        return score::crypto::CrlMetadata{};
    }
};

/// Blocks the first parser call until the test releases it, and counts how many parser calls are in
/// progress at once. The concurrent-load test uses it to check that two loads of the same slot never
/// run the parser at the same time.
class ParseGate final
{
  public:
    /// @brief Called by each parse. Records the call and blocks the first call until ReleaseFirstCall().
    /// Calls after the first return at once.
    void EnterAndWait()
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        ++m_call_count;
        ++m_active_calls;
        if (m_active_calls > m_max_active_calls)
            m_max_active_calls = m_active_calls;
        m_condition.notify_all();
        if (m_call_count == 1U)
            m_condition.wait(lock, [this] {
                return m_release_first_call;
            });
        --m_active_calls;
    }

    /// @brief Waits until at least @p count calls have been recorded, or until @p timeout elapses.
    /// @return True if the count was reached within the timeout.
    bool WaitForCalls(std::size_t count, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        return m_condition.wait_for(lock, timeout, [this, count] {
            return m_call_count >= count;
        });
    }

    /// @brief Lets the blocked first call return. Later calls are not affected.
    void ReleaseFirstCall()
    {
        const std::lock_guard<std::mutex> lock{m_mutex};
        m_release_first_call = true;
        m_condition.notify_all();
    }

    /// @brief The largest number of calls that were in progress at the same time.
    std::size_t MaxActiveCalls()
    {
        const std::lock_guard<std::mutex> lock{m_mutex};
        return m_max_active_calls;
    }

  private:
    /// Guards the members below. Released while the first call waits, so other calls can still record.
    std::mutex m_mutex;
    /// Signalled when a call starts and when the first call is released.
    std::condition_variable m_condition;
    /// Calls that have entered EnterAndWait(), including the first.
    std::size_t m_call_count{0U};
    /// Calls currently between entry to and return from EnterAndWait().
    std::size_t m_active_calls{0U};
    /// Highest value reached by m_active_calls.
    std::size_t m_max_active_calls{0U};
    /// Set by ReleaseFirstCall(); the first call waits until it is true.
    bool m_release_first_call{false};
};

class BlockingParser final : public FakeParser
{
  public:
    explicit BlockingParser(ParseGate& gate) : m_gate{gate} {}

    score::crypto::Expected<cert::CertObject::Sptr, Error> ParseCertificate(const std::uint8_t* bytes,
                                                                            std::size_t size,
                                                                            score::crypto::FormatType format) override
    {
        m_gate.EnterAndWait();
        return FakeParser::ParseCertificate(bytes, size, format);
    }

  private:
    ParseGate& m_gate;
};

/// Scripts the failure of a write issued through an injected FileWriter.
/// Writes are numbered from 1 in the order the handler issues them.
struct WriteScript
{
    std::size_t fail_at{0U};  // 1-based write that fails before touching storage; 0 never fails
    std::size_t calls{0U};    // number of writes issued so far, including the failed one
};

/// Returns a writer that behaves like WriteFile, except for the write numbered script->fail_at.
/// That write returns kPersistFailed without touching storage, so the file and the descriptor keep
/// their previous contents. The script is shared because the writer is copied into the handler, and
/// the test keeps its own handle to read the call count.
storage::FileWriter MakeScriptedWriter(std::shared_ptr<WriteScript> script)
{
    return [script](const std::string& path,
                    score::crypto::span<const std::uint8_t> data) -> score::crypto::Expected<std::monostate, Error> {
        ++script->calls;
        if (script->calls != script->fail_at)
        {
            return storage::WriteFile(path, data);
        }
        return score::crypto::make_unexpected(Error::kPersistFailed);
    };
}

std::vector<std::uint8_t> ReadBytes(const std::filesystem::path& path)
{
    auto bytes = storage::ReadFile(path.string(), 1024U * 1024U);
    EXPECT_TRUE(bytes.has_value());
    return bytes.has_value() ? bytes.value() : std::vector<std::uint8_t>{};
}

std::shared_ptr<cert::CertObject> MakeCertificate(std::vector<std::uint8_t> bytes, score::crypto::FormatType format)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    return std::make_shared<cert::CertObject>(std::move(metadata), std::move(bytes), format);
}

class FileBackedSlotHandlerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        m_directory = ::tests::utility::TempDirectory("score_cert_management_test");
        std::filesystem::create_directories(m_directory);
        m_descriptor = m_directory / "slot.kv";
        m_certificate = m_directory / "certificate.pem";
        m_crl = m_directory / "certificate.crl";

        storage::DeploymentDescriptor descriptor;
        descriptor.Set("certificate", "cert_path", m_certificate.string());
        descriptor.Set("certificate", "cert_format", "pem");
        descriptor.Set("crl", "crl_path", m_crl.string());
        ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(m_descriptor.string(), descriptor).has_value());

        m_slot.deployment_path = m_descriptor.string();
        m_slot.deployment_format = "kv";
        m_handler = std::make_unique<cert::FileBackedSlotHandler>(m_slot, std::make_shared<FakeParser>());
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_directory, error);
    }

    /// Replace the handler with one whose writes go through a scripted writer.
    void UseScriptedWriter(std::shared_ptr<WriteScript> script)
    {
        m_handler = std::make_unique<cert::FileBackedSlotHandler>(
            m_slot, std::make_shared<FakeParser>(), MakeScriptedWriter(std::move(script)));
    }

    std::filesystem::path m_directory;
    std::filesystem::path m_descriptor;
    std::filesystem::path m_certificate;
    std::filesystem::path m_crl;
    cert::CertSlotConfig m_slot;
    std::unique_ptr<cert::FileBackedSlotHandler> m_handler;
};

TEST_F(FileBackedSlotHandlerTest, StoresLoadsAndClearsCertificate)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());
    ASSERT_TRUE(m_handler->LoadCertificate().has_value());
    EXPECT_EQ(m_handler->GetSlotState().value(), score::crypto::CertificateSlotState::kOccupied);
    EXPECT_EQ(m_handler->LoadCertificate().value()->GetRawBytes().size(), 3U);

    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    EXPECT_EQ(m_handler->GetSlotState().value(), score::crypto::CertificateSlotState::kEmpty);
}

/// Two loads of the same slot run on separate threads. The parser blocks the first call, so the second
/// load must wait for the handler's per-slot lock instead of entering the parser. The test checks three
/// things: the first call reaches the parser, the second call does not enter the parser while the first is
/// blocked, and at most one parser call is ever active. Both loads succeed once the first is released.
/// The 250 ms window is how long the test gives a broken lock a chance to let the second call in; the
/// active-call count is what detects an overlap.
TEST_F(FileBackedSlotHandlerTest, SerializesConcurrentLoadsForSameSlot)
{
    const std::vector<std::uint8_t> certificate_bytes{0x01U};
    ASSERT_TRUE(storage::WriteFile(m_certificate.string(), certificate_bytes).has_value());
    // Every parse blocks in the gate; the first call waits there until the test releases it.
    ParseGate gate;
    cert::FileBackedSlotHandler handler{m_slot, std::make_shared<BlockingParser>(gate)};

    // The promise only shows that the thread has started running. It does not show that the thread
    // has reached the parser, which is why the test waits on the gate below as well.
    std::promise<void> first_started_promise;
    auto first_started = first_started_promise.get_future();
    bool first_succeeded = false;
    std::thread first_thread{[&] {
        first_started_promise.set_value();
        first_succeeded = handler.LoadCertificate().has_value();
    }};
    first_started.wait();
    // True once the first call has reached the parser. Waits up to one second, then gives up.
    const bool first_entered_parser = gate.WaitForCalls(1U, std::chrono::seconds{1});

    std::promise<void> second_started_promise;
    auto second_started = second_started_promise.get_future();
    bool second_succeeded = false;
    std::thread second_thread{[&] {
        second_started_promise.set_value();
        second_succeeded = handler.LoadCertificate().has_value();
    }};
    second_started.wait();
    // True only if a second call reached the parser within 250 ms while the first is still blocked.
    // A correct lock keeps the second call out, so this waits the full 250 ms and returns false.
    const bool second_entered_while_first_blocked = gate.WaitForCalls(2U, std::chrono::milliseconds{250});

    // Release the first call so both loads can finish. The threads are joined only after the
    // release, otherwise the first load would block forever.
    gate.ReleaseFirstCall();
    first_thread.join();
    second_thread.join();

    EXPECT_TRUE(first_entered_parser);
    EXPECT_FALSE(second_entered_while_first_blocked);
    EXPECT_EQ(gate.MaxActiveCalls(), 1U);
    EXPECT_TRUE(first_succeeded);
    EXPECT_TRUE(second_succeeded);
}

TEST_F(FileBackedSlotHandlerTest, StoresLoadsAndClearsCrl)
{
    RecordProperty("PartiallyVerifies", "comp_req__crypto_cert_management__persistence");
    RecordProperty("Description", "Stores, reloads, and clears CRL bytes through the file-backed slot handler.");
    RecordProperty("TestType", "requirements-based");
    RecordProperty("DerivationTechnique", "requirements-analysis");

    const cert::CrlData crl{{4U, 5U, 6U}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_TRUE(m_handler->HasCrl().value());
    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->bytes, crl.bytes);

    ASSERT_TRUE(m_handler->ClearCrl().has_value());
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_FALSE(m_handler->HasCrl().value());
}

TEST_F(FileBackedSlotHandlerTest, StoresCrlBesideCertificateWhenDirectoryContainsDot)
{
    const auto certificate_directory = m_directory / "my.certs";
    std::filesystem::create_directories(certificate_directory);
    const auto certificate_path = certificate_directory / "leaf";
    const auto descriptor_path = m_directory / "fallback_slot.kv";

    storage::DeploymentDescriptor descriptor;
    descriptor.Set("certificate", "cert_path", certificate_path.string());
    descriptor.Set("certificate", "cert_format", "pem");
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(descriptor_path.string(), descriptor).has_value());

    auto slot = m_slot;
    slot.deployment_path = descriptor_path.string();
    const cert::CrlData crl{{0x01U}, score::crypto::FormatType::kDer};
    cert::FileBackedSlotHandler handler{slot, std::make_shared<FakeParser>()};
    ASSERT_TRUE(handler.StoreCrl(crl).has_value());

    EXPECT_TRUE(std::filesystem::exists(certificate_directory / "leaf.crl"));
    EXPECT_FALSE(std::filesystem::exists(m_directory / "my.crl"));
}

TEST_F(FileBackedSlotHandlerTest, DerivesMetadataForPreconfiguredCrlWithoutCachedMetadata)
{
    cert::CertChainMetadata certificate_metadata;
    certificate_metadata.subject_canonical = "CN=file-test";
    certificate_metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(certificate_metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);
    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());

    const cert::CrlData crl{{4U, 5U, 6U}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());

    const auto result = m_handler->GetCrlMetadata();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->this_update, 0);
    EXPECT_EQ((*result)->next_update, 0);
    EXPECT_EQ((*result)->crl_number, 0U);
}

// GetCrlMetadata on a fresh slot reports no metadata, not an error.
TEST_F(FileBackedSlotHandlerTest, GetCrlMetadata_NoCrl_ReturnsEmpty)
{
    const auto result = m_handler->GetCrlMetadata();
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

// GetCrlMetadata returns the metadata stored with the CRL.
TEST_F(FileBackedSlotHandlerTest, GetCrlMetadata_ReturnsStoredMetadata)
{
    score::crypto::CrlMetadata metadata;
    metadata.this_update = 100;
    metadata.next_update = 200;
    metadata.crl_number = 7U;
    const cert::CrlData crl{{0x01U, 0x02U}, score::crypto::FormatType::kPem, metadata};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());

    const auto result = m_handler->GetCrlMetadata();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->this_update, 100);
    EXPECT_EQ((*result)->next_update, 200);
    EXPECT_EQ((*result)->crl_number, 7U);
}

// LoadCrlData on a slot without a CRL reports no value rather than an error.
TEST_F(FileBackedSlotHandlerTest, LoadCrlData_NoCrl_ReturnsNullopt)
{
    const auto crl = m_handler->LoadCrlData();
    ASSERT_TRUE(crl.has_value());
    EXPECT_FALSE(crl->has_value());
}

// LoadCrlData returns bytes, format, and metadata of the stored CRL together.
TEST_F(FileBackedSlotHandlerTest, LoadCrlData_ReturnsBytesFormatAndMetadata)
{
    const std::vector<std::uint8_t> bytes{0x01U, 0x02U, 0x03U};
    score::crypto::CrlMetadata metadata;
    metadata.this_update = 100;
    metadata.next_update = 200;
    metadata.crl_number = 7U;
    const cert::CrlData crl_data{bytes, score::crypto::FormatType::kPem, metadata};
    ASSERT_TRUE(m_handler->StoreCrl(crl_data).has_value());

    const auto crl = m_handler->LoadCrlData();
    ASSERT_TRUE(crl.has_value());
    ASSERT_TRUE(crl->has_value());
    EXPECT_EQ((*crl)->bytes, bytes);
    EXPECT_EQ((*crl)->format, score::crypto::FormatType::kPem);
    ASSERT_TRUE((*crl)->metadata.has_value());
    EXPECT_EQ((*crl)->metadata->this_update, 100);
    EXPECT_EQ((*crl)->metadata->next_update, 200);
    EXPECT_EQ((*crl)->metadata->crl_number, 7U);
}

// LoadCrlData derives metadata the same way GetCrlMetadata() does when the descriptor
// has a CRL but no cached metadata fields.
TEST_F(FileBackedSlotHandlerTest, LoadCrlData_DerivesMetadataForCrlWithoutCachedMetadata)
{
    cert::CertChainMetadata certificate_metadata;
    certificate_metadata.subject_canonical = "CN=file-test";
    certificate_metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(certificate_metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);
    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());

    const std::vector<std::uint8_t> bytes{4U, 5U, 6U};
    const cert::CrlData crl_data{bytes, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl_data).has_value());

    const auto crl = m_handler->LoadCrlData();
    ASSERT_TRUE(crl.has_value());
    ASSERT_TRUE(crl->has_value());
    EXPECT_EQ((*crl)->bytes, bytes);
    ASSERT_TRUE((*crl)->metadata.has_value());
    EXPECT_EQ((*crl)->metadata->crl_number, 0U);
}

// Storing a new certificate must invalidate any existing CRL: the CRL was
// issued for the previous CA key and is meaningless for the new cert.
// After StoreCertificate, HasCrl() must return false even though a CRL was
// stored before the update.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_ClearsExistingCrl)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    // Store a CRL first so the slot has one.
    const cert::CrlData crl_bytes{{7U, 8U, 9U}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl_bytes).has_value());
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    ASSERT_TRUE(m_handler->HasCrl().value());

    // Storing a new cert must invalidate the stale CRL.
    // crl_path is preserved in the descriptor (for future StoreCrl re-use)
    // but the CRL file is removed, so HasCrl() must return false.
    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());

    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_FALSE(m_handler->HasCrl().value());
    EXPECT_FALSE(std::filesystem::exists(m_crl));

    // crl_path is preserved in the descriptor so a subsequent StoreCrl re-uses
    // the same on-disk location without having to recompute it.
    const cert::CrlData new_crl{{0xAAU, 0xBBU}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(new_crl).has_value());
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_TRUE(m_handler->HasCrl().value());
    EXPECT_TRUE(std::filesystem::exists(m_crl));
}

// A freshly-configured slot with no stored CRL must report HasCrl() == false
// without any prior store call.  This baseline is separate from the
// StoresLoadsAndClearsCrl flow so that a regression in the empty-state
// detection doesn't go unnoticed.
TEST_F(FileBackedSlotHandlerTest, HasCrl_FalseForFreshSlot)
{
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_FALSE(m_handler->HasCrl().value());
}

// GetSlotState on a fresh slot must report kEmpty without a prior store.
TEST_F(FileBackedSlotHandlerTest, GetSlotState_EmptyForFreshSlot)
{
    EXPECT_EQ(m_handler->GetSlotState().value(), score::crypto::CertificateSlotState::kEmpty);
}

// After storing a CRL with kPem format, LoadCrlData must report kPem. This
// verifies that StoreCrl writes the format to the descriptor and LoadCrlData
// reads it back correctly.
TEST_F(FileBackedSlotHandlerTest, LoadCrlData_ReadsFormatFromDescriptor)
{
    const cert::CrlData crl{{0x01U, 0x02U, 0x03U}, score::crypto::FormatType::kPem};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());
    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->format, score::crypto::FormatType::kPem);
}

// ClearSlot must be idempotent: calling it a second time on an already-cleared
// slot must return success rather than an error. The FileExists guard ensures
// RemoveFile is not called when the cert file is already absent.
TEST_F(FileBackedSlotHandlerTest, ClearSlot_IsIdempotent)
{
    cert::CertChainMetadata metadata;
    metadata.subject_canonical = "CN=file-test";
    metadata.issuer_canonical = "CN=file-test";
    auto certificate = std::make_shared<cert::CertObject>(
        std::move(metadata), std::vector<std::uint8_t>{1U, 2U, 3U}, score::crypto::FormatType::kDer);

    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());

    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    // Second call must succeed — slot is already empty.
    ASSERT_TRUE(m_handler->ClearSlot().has_value());
    EXPECT_EQ(m_handler->GetSlotState().value(), score::crypto::CertificateSlotState::kEmpty);
}

// ClearCrl must be idempotent: calling it a second time when no CRL file exists
// must return success. The FileExists guard prevents a spurious error from
// RemoveFile on an absent file.
TEST_F(FileBackedSlotHandlerTest, ClearCrl_IsIdempotent)
{
    const cert::CrlData crl{{0x0AU, 0x0BU}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());

    ASSERT_TRUE(m_handler->ClearCrl().has_value());
    // Second call must succeed — CRL file is already gone.
    ASSERT_TRUE(m_handler->ClearCrl().has_value());
    ASSERT_TRUE(m_handler->HasCrl().has_value());
    EXPECT_FALSE(m_handler->HasCrl().value());
}

// StoreCrl without metadata must not write a crl_next_update key to the descriptor.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_WithoutMetadata_DoesNotWriteNextUpdateKey)
{
    const cert::CrlData crl{{0x01U, 0x02U}, score::crypto::FormatType::kDer};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());

    const auto descriptor = cert::DeploymentLoader::Load(m_descriptor.string(), "kv");
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_TRUE(descriptor->Get("crl", "crl_next_update").empty());
}

// StoreCrl with validated metadata must persist nextUpdate and expose it
// through the metadata query.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_MetadataPersistsNextUpdate)
{
    constexpr std::int64_t kEpoch = 1800000000LL;
    score::crypto::CrlMetadata metadata;
    metadata.next_update = kEpoch;
    const cert::CrlData crl{{0x03U, 0x04U}, score::crypto::FormatType::kDer, metadata};
    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());

    const auto result = m_handler->GetCrlMetadata();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->next_update, kEpoch);
}

// A certificate write that fails before touching storage leaves the previous certificate file
// and the descriptor unchanged.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_CertWriteFails_KeepsPreviousCertificate)
{
    const auto previous = MakeCertificate({9U, 9U}, score::crypto::FormatType::kDer);
    ASSERT_TRUE(m_handler->StoreCertificate(*previous).has_value());
    const auto certificate_before = ReadBytes(m_certificate);
    const auto descriptor_before = ReadBytes(m_descriptor);

    auto script = std::make_shared<WriteScript>();
    script->fail_at = 1U;
    UseScriptedWriter(script);

    const auto next = MakeCertificate({1U, 2U, 3U}, score::crypto::FormatType::kDer);
    const auto result = m_handler->StoreCertificate(*next);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kPersistFailed);
    EXPECT_EQ(ReadBytes(m_certificate), certificate_before);
    EXPECT_EQ(ReadBytes(m_descriptor), descriptor_before);
    EXPECT_TRUE(cert::DeploymentLoader::Load(m_descriptor.string(), "kv").has_value());
    const auto loaded = m_handler->LoadCertificate();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded.value()->GetRawBytes().size(), 2U);
}

// A certificate over the size limit is refused before the certificate file or the descriptor is written.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_OversizedCertificate_IsRejectedWithoutWriting)
{
    const auto descriptor_before = ReadBytes(m_descriptor);
    const std::vector<std::uint8_t> bytes(cert::FileBackedSlotHandler::kMaxCertSize + 1U, 0x01U);
    const auto oversized = MakeCertificate(bytes, score::crypto::FormatType::kDer);

    const auto result = m_handler->StoreCertificate(*oversized);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(m_certificate));
    EXPECT_EQ(ReadBytes(m_descriptor), descriptor_before);
}

// A certificate of exactly the size limit is stored and loaded.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_MaxSizeCertificate_RoundTrips)
{
    const std::vector<std::uint8_t> bytes(cert::FileBackedSlotHandler::kMaxCertSize, 0x01U);
    const auto certificate = MakeCertificate(bytes, score::crypto::FormatType::kDer);

    ASSERT_TRUE(m_handler->StoreCertificate(*certificate).has_value());
    const auto loaded = m_handler->LoadCertificate();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded.value()->GetRawBytes().size(), cert::FileBackedSlotHandler::kMaxCertSize);
}

// A CRL over the size limit is refused before the CRL file or the descriptor is written.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_OversizedCrl_IsRejectedWithoutWriting)
{
    const auto descriptor_before = ReadBytes(m_descriptor);
    const std::vector<std::uint8_t> bytes(cert::FileBackedCrlStorage::kMaxCrlSize + 1U, 0x01U);
    const cert::CrlData crl{bytes, score::crypto::FormatType::kDer};

    const auto result = m_handler->StoreCrl(crl);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::kInvalidArgument);
    EXPECT_FALSE(std::filesystem::exists(m_crl));
    EXPECT_EQ(ReadBytes(m_descriptor), descriptor_before);
}

// A CRL of exactly the size limit is stored and loaded.
TEST_F(FileBackedSlotHandlerTest, StoreCrl_MaxSizeCrl_RoundTrips)
{
    const std::vector<std::uint8_t> bytes(cert::FileBackedCrlStorage::kMaxCrlSize, 0x01U);
    const cert::CrlData crl{bytes, score::crypto::FormatType::kDer};

    ASSERT_TRUE(m_handler->StoreCrl(crl).has_value());
    const auto loaded = m_handler->LoadCrlData();
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded.value().has_value());
    EXPECT_EQ(loaded.value().value().bytes.size(), cert::FileBackedCrlStorage::kMaxCrlSize);
}

// A slot whose descriptor names no certificate file gets the fallback path recorded on store, so
// later loads and state queries find the certificate.
TEST_F(FileBackedSlotHandlerTest, StoreCertificate_WithoutConfiguredPath_RecordsPathInDescriptor)
{
    const auto slot_descriptor = m_directory / "unbound_slot.kv";
    const storage::DeploymentDescriptor descriptor;
    ASSERT_TRUE(storage::KvDeploymentWriter{}.Write(slot_descriptor.string(), descriptor).has_value());

    auto slot = m_slot;
    slot.deployment_path = slot_descriptor.string();
    const auto certificate = MakeCertificate({1U, 2U, 3U}, score::crypto::FormatType::kDer);

    cert::FileBackedSlotHandler handler{slot, std::make_shared<FakeParser>()};
    ASSERT_TRUE(handler.StoreCertificate(*certificate).has_value());
    EXPECT_TRUE(std::filesystem::exists(slot_descriptor.string() + ".pem"));
    EXPECT_EQ(handler.GetSlotState().value(), score::crypto::CertificateSlotState::kOccupied);
    EXPECT_TRUE(handler.LoadCertificate().has_value());
}

}  // namespace
