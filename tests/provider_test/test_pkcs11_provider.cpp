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

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "score/crypto/daemon/common/actors.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/daemon/provider/i_provider.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "tests/utility/test_utility.hpp"

namespace common = score::crypto::daemon::common;
namespace provider = score::crypto::daemon::provider;
namespace pkcs11 = score::crypto::daemon::provider::pkcs11;
namespace handler = score::crypto::daemon::provider::handler;
namespace ops = score::crypto::daemon::provider::handler::hash_handler_operations;

namespace
{

/// Helper to build an OperationIdentifier for hash operations.
common::OperationIdentifier MakeHashOp(common::OperationAction action)
{
    common::OperationIdentifier id{};
    id.operationActor = common::actors::OP_ACTOR_HASH_HANDLER;
    id.operationAction = action;
    return id;
}

/// @brief Helper to extract the digest bytes from a OwnedBuffer or a VirtualMemoryBufferConst in the response's
/// parameters.
std::vector<std::uint8_t> ExtractDigest(const common::ResponseParameters& response)
{
    for (const auto& param : response)
    {
        if (const auto buf = std::get_if<common::OwnedBuffer>(&param))
        {
            return *buf;
        }
        if (const auto* buf = std::get_if<common::VirtualMemoryBufferConst>(&param))
        {
            return {buf->data, buf->data + buf->size};
        }
    }
    return {};
}

/// @brief Test fixture that initialises a SoftHSM token before each test.
///
/// The fixture mirrors the token-setup pattern from the existing SoftHSM block
/// cipher tests: it creates a temporary token directory, writes a minimal
/// softhsm2.conf, initialises the token, and sets the user PIN.  The
/// Pkcs11Provider is then constructed and initialised on top of that token.
class Pkcs11ProviderHashTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // TODO: Check if we can use SetupTestSuite for the SoftHSM environment setup, since it is shared across all
        // tests in this suite. If we do that, we can avoid repeating the setup for each test and potentially speed up
        // the test execution. However, we need to ensure that the token state is properly isolated between tests, which
        // may require additional cleanup logic in TearDownTestSuite.
        //  -- SoftHSM environment setup ----------------------------------------
        const char* tmpDir = std::getenv("TEST_TMPDIR");
        const std::string baseDir = (tmpDir != nullptr) ? tmpDir : "/tmp";

        // Create a unique token directory for each test to avoid state conflicts.
        // Use a random number to generate a unique directory for each test instance.
        static unsigned int testCounter = 0;
        const std::string testId = std::to_string(++testCounter);
        const std::string tokenDir = baseDir + "/softhsm_pkcs11_tokens_" + testId;
        // NOLINTNEXTLINE(cert-env33-c) -- test-only; safe in test sandbox
        system(("rm -rf " + tokenDir).c_str());  // Clean up any prior state
        system(("mkdir -p " + tokenDir).c_str());

        const std::string configPath = baseDir + "/softhsm2_pkcs11_" + testId + ".conf";
        {
            std::ofstream config(configPath);
            config << "directories.tokendir = " << tokenDir << "\n";
            config << "objectstore.backend = file\n";
            config << "log.level = INFO\n";
        }
        // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test-only
        setenv("SOFTHSM2_CONF", configPath.c_str(), 1);

        // -- Raw PKCS#11 bootstrap to create a token with a user PIN ----------
        CK_FUNCTION_LIST_PTR fl{nullptr};
        CK_RV rv = C_GetFunctionList(&fl);
        ASSERT_EQ(rv, CKR_OK);
        ASSERT_NE(fl, nullptr);

        rv = fl->C_Initialize(nullptr);
        // CKR_CRYPTOKI_ALREADY_INITIALIZED (3) is OK — library is already initialized from a prior test.
        // CKR_OK is fine too (first test or fresh process).
        ASSERT_TRUE((rv == CKR_OK) || (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED));

        // Get first available slot (without token).
        CK_ULONG slotCount{0U};
        rv = fl->C_GetSlotList(CK_FALSE, nullptr, &slotCount);
        ASSERT_EQ(rv, CKR_OK);
        ASSERT_GT(slotCount, 0U);

        std::vector<CK_SLOT_ID> slots(slotCount);
        rv = fl->C_GetSlotList(CK_FALSE, slots.data(), &slotCount);
        ASSERT_EQ(rv, CKR_OK);
        slotId_ = slots[0];

        // Init token (label must be padded to 32 chars for SoftHSM).
        std::string label = "SoftHSM";
        label.resize(32U, ' ');
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast) -- PKCS#11 C API
        auto* labelPtr = reinterpret_cast<CK_UTF8CHAR_PTR>(label.data());

        CK_UTF8CHAR soPin[] = "12345678";
        constexpr CK_ULONG kSoPinLen{8U};
        rv = fl->C_InitToken(slotId_, soPin, kSoPinLen, labelPtr);
        // Token should be initializable since tokenDir is fresh (cleaned up above).
        ASSERT_EQ(rv, CKR_OK) << "C_InitToken failed: " << rv;

        // Open a RW session, login as SO, and set the user PIN.
        CK_SESSION_HANDLE tmpSession{CK_INVALID_HANDLE};
        rv = fl->C_OpenSession(slotId_, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &tmpSession);
        ASSERT_EQ(rv, CKR_OK);

        rv = fl->C_Login(tmpSession, CKU_SO, soPin, kSoPinLen);
        ASSERT_EQ(rv, CKR_OK);

        CK_UTF8CHAR userPin[] = "1234";
        constexpr CK_ULONG kUserPinLen{4U};
        rv = fl->C_InitPIN(tmpSession, userPin, kUserPinLen);
        ASSERT_EQ(rv, CKR_OK);

        rv = fl->C_Logout(tmpSession);
        ASSERT_EQ(rv, CKR_OK);
        rv = fl->C_CloseSession(tmpSession);
        ASSERT_EQ(rv, CKR_OK);

        // NOTE: Do NOT call C_Finalize here — the provider manages module lifecycle.
        // The provider's Pkcs11Module will finalize when it's destroyed.

        // -- Construct and initialise the PKCS#11 provider under test ---------
        pkcs11::Pkcs11ProviderConfig cfg{};
        // Use kSlotIdAutoDetect — Initialize() resolves slot via FindSlotByToken.
        // cfg.slotId is kSlotIdAutoDetect by default.
        cfg.tokenLabel = "SoftHSM";
        cfg.userPin = "1234";
        cfg.providerName = "SOFTHSM";  // SOFTHSM provider name
        // Override session limits to allow concurrent handler creation.
        // SoftHSM may report very small limits; we ensure at least 32 sessions available.
        cfg.maxRoSessionsOverride = 32U;
        cfg.maxRwSessionsOverride = 16U;
        // Use hard cleanup strategy to ensure complete session reset between handlers.
        // This addresses SoftHSM's soft cleanup edge cases with concurrent operations.
        cfg.cleanupStrategy = pkcs11::Pkcs11SessionCleanupStrategy::kHardCleanup;
        // sessionType removed: session type is now per-handler via kRequirements

        provider_ = std::make_shared<pkcs11::Pkcs11Provider>(std::move(cfg));
        provider::ProviderInitContext ctx{1, "SOFTHSM"};  // ID 1, name "SOFTHSM"
        ASSERT_TRUE(provider_->Initialize(ctx));
    }

    void TearDown() override
    {
        if (provider_ != nullptr)
        {
            provider_->Shutdown();
            provider_.reset();
        }
    }

    CK_SLOT_ID slotId_{0U};
    std::shared_ptr<pkcs11::Pkcs11Provider> provider_;
};

// ---------------------------------------------------------------------------
// Single-shot hash tests
// ---------------------------------------------------------------------------

TEST_F(Pkcs11ProviderHashTest, SHA256SingleShotHash)
{
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    // Create handler.
    auto handlerResult = cryptoOps->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto handler = handlerResult.value();
    ASSERT_NE(handler, nullptr);

    // Initialise.
    auto initCtxResult = handler->InitializeContext(handler::InitializationParams{});
    ASSERT_TRUE(initCtxResult.has_value()) << "InitializeContext failed";

    // Prepare input from test vector file.
    auto inputBuffer = tests::utility::read_bin("tests/test_vectors/hash/input_hello_world.bin");
    ASSERT_FALSE(inputBuffer.empty());

    // Prepare output (SHA-256 → 32 bytes).
    constexpr std::size_t kSha256DigestLen{32U};
    std::vector<std::uint8_t> outputBuffer(kSha256DigestLen);

    // Execute single-shot.
    common::RequestParameters request{};
    request.push_back(common::VirtualMemoryBufferConst{inputBuffer.data(), inputBuffer.size()});
    request.push_back(common::VirtualMemoryBuffer{outputBuffer.data(), outputBuffer.size()});

    auto executeResult = handler->Execute(MakeHashOp(ops::HASH_SS), request);
    ASSERT_TRUE(executeResult.has_value()) << "Execute failed";

    // Extract digest from response parameters.
    const auto digest = ExtractDigest(executeResult.value());

    // Verify against reference test vector.
    const auto expectedHash = tests::utility::read_bin("tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expectedHash.size(), kSha256DigestLen);
    EXPECT_EQ(digest, expectedHash) << "Hash output does not match expected SHA-256 digest";
}

// ---------------------------------------------------------------------------
// Streaming hash tests
// ---------------------------------------------------------------------------

TEST_F(Pkcs11ProviderHashTest, SHA256StreamingHash)
{
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    auto handlerResult = cryptoOps->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto handler = handlerResult.value();
    ASSERT_NE(handler, nullptr);

    auto initCtxResult = handler->InitializeContext(handler::InitializationParams{});
    ASSERT_TRUE(initCtxResult.has_value()) << "InitializeContext failed";

    // HASH_INIT
    common::RequestParameters initOp{};
    auto initResult = handler->Execute(MakeHashOp(ops::HASH_INIT), initOp);
    ASSERT_TRUE(initResult.has_value()) << "HASH_INIT failed";

    // HASH_UPDATE — chunk 1: "Hello, "
    const std::string chunk1Str = "Hello, ";
    std::vector<std::uint8_t> chunk1Buf(chunk1Str.begin(), chunk1Str.end());

    common::RequestParameters updateOp1{};
    updateOp1.push_back(common::VirtualMemoryBufferConst{chunk1Buf.data(), chunk1Buf.size()});
    auto update1Result = handler->Execute(MakeHashOp(ops::HASH_UPDATE), updateOp1);
    ASSERT_TRUE(update1Result.has_value()) << "HASH_UPDATE chunk1 failed";

    // HASH_UPDATE — chunk 2: "World!"
    const std::string chunk2Str = "World!";
    std::vector<std::uint8_t> chunk2Buf(chunk2Str.begin(), chunk2Str.end());

    common::RequestParameters updateOp2{};
    updateOp2.push_back(common::VirtualMemoryBufferConst{chunk2Buf.data(), chunk2Buf.size()});
    auto update2Result = handler->Execute(MakeHashOp(ops::HASH_UPDATE), updateOp2);
    ASSERT_TRUE(update2Result.has_value()) << "HASH_UPDATE chunk2 failed";

    // HASH_FINALIZE
    constexpr std::size_t kSha256DigestLen{32U};
    std::vector<std::uint8_t> outputBuffer(kSha256DigestLen);

    common::RequestParameters finishOp{};
    finishOp.push_back(common::VirtualMemoryBuffer{outputBuffer.data(), outputBuffer.size()});
    auto finishResult = handler->Execute(MakeHashOp(ops::HASH_FINALIZE), finishOp);
    ASSERT_TRUE(finishResult.has_value()) << "HASH_FINALIZE failed";

    // Extract digest from response.
    const auto digest = ExtractDigest(finishResult.value());

    // Verify same digest as single-shot using reference test vector.
    const auto expectedHash = tests::utility::read_bin("tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expectedHash.size(), kSha256DigestLen);
    EXPECT_EQ(digest, expectedHash) << "Streaming hash does not match expected SHA-256 digest";
}

// ---------------------------------------------------------------------------
// Stream state violation test
// ---------------------------------------------------------------------------

TEST_F(Pkcs11ProviderHashTest, StreamStateViolation)
{
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    auto handlerResult = cryptoOps->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto handler = handlerResult.value();
    ASSERT_NE(handler, nullptr);

    auto initCtxResult = handler->InitializeContext(handler::InitializationParams{});
    ASSERT_TRUE(initCtxResult.has_value()) << "InitializeContext failed";

    // HASH_UPDATE without prior HASH_INIT should fail.
    const std::string data = "test";
    std::vector<std::uint8_t> dataBuf(data.begin(), data.end());

    common::RequestParameters updateOp{};
    updateOp.push_back(common::VirtualMemoryBufferConst{dataBuf.data(), dataBuf.size()});

    auto updateResult = handler->Execute(MakeHashOp(ops::HASH_UPDATE), updateOp);
    EXPECT_FALSE(updateResult.has_value()) << "HASH_UPDATE without HASH_INIT should fail";

    // HASH_FINALIZE without HASH_INIT should also fail.
    std::vector<std::uint8_t> outBuf(32U);

    common::RequestParameters finishOp{};
    finishOp.push_back(common::VirtualMemoryBuffer{outBuf.data(), outBuf.size()});

    auto finishResult = handler->Execute(MakeHashOp(ops::HASH_FINALIZE), finishOp);
    EXPECT_FALSE(finishResult.has_value()) << "HASH_FINALIZE without active stream should fail";
}

// ---------------------------------------------------------------------------
// True concurrent streaming: two handlers active simultaneously on separate sessions
// ---------------------------------------------------------------------------

TEST_F(Pkcs11ProviderHashTest, TrueConcurrentStreamingOnSeparateSessions)
{
    // This test validates the core session-pool requirement: two simultaneous
    // streaming digest operations must each have their own PKCS#11 session so
    // neither interferes with the other's active C_DigestInit/Update/Final state.

    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    // Create handler A (SHA256) -- acquires session A from pool
    auto handlerResultA = cryptoOps->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResultA.has_value());
    auto handlerA = handlerResultA.value();
    ASSERT_NE(handlerA, nullptr);

    // Create handler B (SHA384) -- acquires session B from pool (different from A)
    auto handlerResultB = cryptoOps->CreateHandler("HASH", "SHA384");
    ASSERT_TRUE(handlerResultB.has_value());
    auto handlerB = handlerResultB.value();
    ASSERT_NE(handlerB, nullptr);

    // INTERLEAVED streaming: A and B both active simultaneously.
    common::RequestParameters initOpA{};
    auto initA = handlerA->Execute(MakeHashOp(ops::HASH_INIT), initOpA);
    ASSERT_TRUE(initA.has_value()) << "HASH_INIT A failed";

    common::RequestParameters initOpB{};
    auto initB = handlerB->Execute(MakeHashOp(ops::HASH_INIT), initOpB);
    ASSERT_TRUE(initB.has_value()) << "HASH_INIT B failed";

    // Feed "Hello, " into A, "World!" into B -- interleaved
    const std::string chunk1A = "Hello, ";
    std::vector<std::uint8_t> bufA1(chunk1A.begin(), chunk1A.end());
    common::RequestParameters updateA1{};
    updateA1.push_back(common::VirtualMemoryBufferConst{bufA1.data(), bufA1.size()});
    auto updA1 = handlerA->Execute(MakeHashOp(ops::HASH_UPDATE), updateA1);
    ASSERT_TRUE(updA1.has_value()) << "HASH_UPDATE A1 failed";

    const std::string chunk1B = "Hello, ";
    std::vector<std::uint8_t> bufB1(chunk1B.begin(), chunk1B.end());
    common::RequestParameters updateB1{};
    updateB1.push_back(common::VirtualMemoryBufferConst{bufB1.data(), bufB1.size()});
    auto updB1 = handlerB->Execute(MakeHashOp(ops::HASH_UPDATE), updateB1);
    ASSERT_TRUE(updB1.has_value()) << "HASH_UPDATE B1 failed";

    const std::string chunk2A = "World!";
    std::vector<std::uint8_t> bufA2(chunk2A.begin(), chunk2A.end());
    common::RequestParameters updateA2{};
    updateA2.push_back(common::VirtualMemoryBufferConst{bufA2.data(), bufA2.size()});
    auto updA2 = handlerA->Execute(MakeHashOp(ops::HASH_UPDATE), updateA2);
    ASSERT_TRUE(updA2.has_value()) << "HASH_UPDATE A2 failed";

    const std::string chunk2B = "World!";
    std::vector<std::uint8_t> bufB2(chunk2B.begin(), chunk2B.end());
    common::RequestParameters updateB2{};
    updateB2.push_back(common::VirtualMemoryBufferConst{bufB2.data(), bufB2.size()});
    auto updB2 = handlerB->Execute(MakeHashOp(ops::HASH_UPDATE), updateB2);
    ASSERT_TRUE(updB2.has_value()) << "HASH_UPDATE B2 failed";

    // Finalize both -- A and B both complete "Hello, World!" but in different algorithms
    constexpr std::size_t kSha256Len{32U};
    std::vector<std::uint8_t> outA(kSha256Len);
    common::RequestParameters finishA{};
    finishA.push_back(common::VirtualMemoryBuffer{outA.data(), outA.size()});
    auto finA = handlerA->Execute(MakeHashOp(ops::HASH_FINALIZE), finishA);
    ASSERT_TRUE(finA.has_value()) << "HASH_FINALIZE A failed";

    constexpr std::size_t kSha384Len{48U};
    std::vector<std::uint8_t> outB(kSha384Len);
    common::RequestParameters finishB{};
    finishB.push_back(common::VirtualMemoryBuffer{outB.data(), outB.size()});
    auto finB = handlerB->Execute(MakeHashOp(ops::HASH_FINALIZE), finishB);
    ASSERT_TRUE(finB.has_value()) << "HASH_FINALIZE B failed";

    // Both handlers digested "Hello, World!" -- verify correctness
    const auto digestA = ExtractDigest(finA.value());
    const auto expectedSha256 = tests::utility::read_bin("tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expectedSha256.size(), kSha256Len);
    EXPECT_EQ(digestA, expectedSha256) << "Interleaved SHA-256 stream produced wrong digest";

    const auto digestB = ExtractDigest(finB.value());
    const auto expectedSha384 = tests::utility::read_bin("tests/test_vectors/hash/sha384_hello_world.bin");
    ASSERT_EQ(expectedSha384.size(), kSha384Len);
    EXPECT_EQ(digestB, expectedSha384) << "Interleaved SHA-384 stream produced wrong digest";

    // Destroying handlerA and handlerB releases sessions back to pool.
    handlerA.reset();
    handlerB.reset();
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
