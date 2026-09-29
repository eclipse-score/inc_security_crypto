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

#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/hash/pkcs11_hash_executor.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/hash/pkcs11_hash_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/tests/utility/test_utility.hpp"

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

/// @brief Helper to extract the digest bytes from response.
/// New protocol: response contains uint64_t size, data is already in the output buffer provided to Execute().
/// Old protocol (fallback): response contains OwnedBuffer or span with the data.
std::vector<std::uint8_t> ExtractDigest(const common::ResponseParameters& response,
                                        const std::vector<std::uint8_t>& outputBuffer)
{
    for (const auto& param : response)
    {
        // New protocol: uint64_t size (data already written to outputBuffer by handler)
        if (const auto* size_ptr = std::get_if<std::uint64_t>(&param))
        {
            const auto size = static_cast<std::size_t>(*size_ptr);
            if (size > outputBuffer.size())
            {
                return {};
            }
            return {outputBuffer.begin(), outputBuffer.begin() + size};
        }
        // Old protocol: full data in response (backward compatibility)
        if (const auto buf = std::get_if<common::OwnedBuffer>(&param))
        {
            return *buf;
        }
        if (const auto* buf = std::get_if<score::cpp::span<const uint8_t>>(&param))
        {
            return {buf->data(), buf->data() + buf->size()};
        }
    }
    return {};
}

struct HashAlgorithmTestData
{
    const char* algorithm;
    std::size_t digest_size;
    const char* hello_digest_path;
    const char* complete_digest_path;
    const char* empty_digest_path;
    const char* abc_digest_path;
};

struct HashVector
{
    const char* input_path;
    const char* digest_path;
};

struct DigestFinalStubState
{
    std::vector<CK_RV> results{};
    std::size_t call_count{0U};
};

struct DigestUpdateStubState
{
    CK_RV result{CKR_OK};
    std::size_t call_count{0U};
};

struct DigestStubState
{
    CK_RV init_result{CKR_OK};
    CK_RV digest_result{CKR_OK};
    std::size_t init_call_count{0U};
    std::size_t digest_call_count{0U};
};

DigestFinalStubState& GetDigestFinalStubState()
{
    static DigestFinalStubState state{};
    return state;
}

DigestUpdateStubState& GetDigestUpdateStubState()
{
    static DigestUpdateStubState state{};
    return state;
}

DigestStubState& GetDigestStubState()
{
    static DigestStubState state{};
    return state;
}

void ConfigureDigestFinalStub(std::initializer_list<CK_RV> results)
{
    auto& state = GetDigestFinalStubState();
    state.results.assign(results);
    state.call_count = 0U;
}

void ConfigureDigestUpdateStub(const CK_RV result)
{
    auto& state = GetDigestUpdateStubState();
    state.result = result;
    state.call_count = 0U;
}

void ConfigureDigestStub(const CK_RV initResult, const CK_RV digestResult = CKR_OK)
{
    auto& state = GetDigestStubState();
    state.init_result = initResult;
    state.digest_result = digestResult;
    state.init_call_count = 0U;
    state.digest_call_count = 0U;
}

CK_DEFINE_FUNCTION(CK_RV, DigestFinalStub)
(CK_SESSION_HANDLE /*session*/, CK_BYTE_PTR /*digest*/, CK_ULONG_PTR /*digest_length*/)
{
    auto& state = GetDigestFinalStubState();
    if (state.call_count >= state.results.size())
    {
        return CKR_GENERAL_ERROR;
    }
    return state.results[state.call_count++];
}

CK_DEFINE_FUNCTION(CK_RV, DigestUpdateStub)
(CK_SESSION_HANDLE /*session*/, CK_BYTE_PTR /*data*/, CK_ULONG /*data_length*/)
{
    auto& state = GetDigestUpdateStubState();
    ++state.call_count;
    return state.result;
}

CK_DEFINE_FUNCTION(CK_RV, DigestInitStub)
(CK_SESSION_HANDLE /*session*/, CK_MECHANISM_PTR /*mechanism*/)
{
    auto& state = GetDigestStubState();
    ++state.init_call_count;
    return state.init_result;
}

CK_DEFINE_FUNCTION(CK_RV, DigestStub)
(CK_SESSION_HANDLE /*session*/,
 CK_BYTE_PTR /*data*/,
 CK_ULONG /*data_length*/,
 CK_BYTE_PTR /*digest*/,
 CK_ULONG_PTR /*digest_length*/)
{
    auto& state = GetDigestStubState();
    ++state.digest_call_count;
    return state.digest_result;
}

pkcs11::Pkcs11HashExecutor MakeStubbedHashExecutor(CK_FUNCTION_LIST& functionList)
{
    functionList.C_DigestInit = &DigestInitStub;
    functionList.C_Digest = &DigestStub;
    functionList.C_DigestFinal = &DigestFinalStub;
    functionList.C_DigestUpdate = &DigestUpdateStub;
    return pkcs11::Pkcs11HashExecutor{functionList};
}

pkcs11::Pkcs11HashExecutionContext MakeHashExecutionContext()
{
    pkcs11::Pkcs11HashExecutionContext context{};
    context.session = 1U;
    context.mechanism.mechanism = CKM_SHA256;
    context.digest_size = 32U;
    return context;
}

TEST(Pkcs11HashExecutorErrorTest, AbortNormalizesNoActiveOperationAndPropagatesProviderFailure)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);

    ConfigureDigestFinalStub({CKR_OPERATION_NOT_INITIALIZED});
    EXPECT_TRUE(executor.Abort(1U).has_value());

    ConfigureDigestFinalStub({CKR_DEVICE_ERROR});
    const auto failedAbort = executor.Abort(1U);
    ASSERT_FALSE(failedAbort.has_value());
    EXPECT_EQ(failedAbort.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
}

TEST(Pkcs11HashExecutorErrorTest, InitializationFailureKeepsStreamIdle)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    common::RequestParameters request{};
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestStub(CKR_DEVICE_ERROR);
    const auto result =
        executor.Execute(context, ops::HASH_INIT, request, common::StreamOperationState::IDLE, nextState);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
    EXPECT_EQ(GetDigestStubState().init_call_count, 1U);
}

TEST(Pkcs11HashExecutorErrorTest, ReinitializationAbortsThePreviousStream)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    common::RequestParameters request{};
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestStub(CKR_OK);
    ConfigureDigestFinalStub({CKR_OK});
    const auto restarted =
        executor.Execute(context, ops::HASH_INIT, request, common::StreamOperationState::STREAM_ACTIVE, nextState);

    EXPECT_TRUE(restarted.has_value());
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_INITIALIZED);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 1U);
    EXPECT_EQ(GetDigestStubState().init_call_count, 1U);

    ConfigureDigestStub(CKR_OK);
    ConfigureDigestFinalStub({CKR_DEVICE_ERROR});
    const auto cleanupFailure =
        executor.Execute(context, ops::HASH_INIT, request, common::StreamOperationState::STREAM_ACTIVE, nextState);

    ASSERT_FALSE(cleanupFailure.has_value());
    EXPECT_EQ(cleanupFailure.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestStubState().init_call_count, 0U);
}

TEST(Pkcs11HashExecutorErrorTest, SingleShotFailureRestoresIdleTokenState)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    const std::array<std::uint8_t, 1U> input{0x42U};
    std::array<std::uint8_t, 32U> output{};
    common::RequestParameters request{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
    };
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestStub(CKR_OK, CKR_BUFFER_TOO_SMALL);
    ConfigureDigestFinalStub({CKR_OPERATION_NOT_INITIALIZED, CKR_OK});
    const auto recoveredFailure =
        executor.Execute(context, ops::HASH_SS, request, common::StreamOperationState::IDLE, nextState);

    ASSERT_FALSE(recoveredFailure.has_value());
    EXPECT_EQ(recoveredFailure.error(), common::DaemonErrorCode::kInsufficientBufferSize);
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
    EXPECT_EQ(GetDigestStubState().init_call_count, 1U);
    EXPECT_EQ(GetDigestStubState().digest_call_count, 1U);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 2U);

    ConfigureDigestStub(CKR_OK, CKR_BUFFER_TOO_SMALL);
    ConfigureDigestFinalStub({CKR_OPERATION_NOT_INITIALIZED, CKR_DEVICE_ERROR});
    const auto cleanupFailure =
        executor.Execute(context, ops::HASH_SS, request, common::StreamOperationState::IDLE, nextState);

    ASSERT_FALSE(cleanupFailure.has_value());
    EXPECT_EQ(cleanupFailure.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 2U);
}

TEST(Pkcs11HashExecutorErrorTest, ResetOnlyTransitionsToIdleAfterSuccessfulCleanup)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    common::RequestParameters request{};
    auto nextState = common::StreamOperationState::STREAM_ACTIVE;

    ConfigureDigestFinalStub({CKR_DEVICE_ERROR});
    const auto failedReset =
        executor.Execute(context, ops::HASH_RESET, request, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(failedReset.has_value());
    EXPECT_EQ(failedReset.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);

    ConfigureDigestFinalStub({CKR_OK});
    const auto successfulReset =
        executor.Execute(context, ops::HASH_RESET, request, common::StreamOperationState::STREAM_ACTIVE, nextState);
    EXPECT_TRUE(successfulReset.has_value());
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
}

TEST(Pkcs11HashExecutorErrorTest, FinalizePreservesOnlyRetryableOperationState)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    std::vector<std::uint8_t> output(32U, 0U);
    common::RequestParameters request{score::cpp::span<std::uint8_t>{output.data(), output.size()}};
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestFinalStub({CKR_BUFFER_TOO_SMALL});
    const auto retryableFailure =
        executor.Execute(context, ops::HASH_FINALIZE, request, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(retryableFailure.has_value());
    EXPECT_EQ(retryableFailure.error(), common::DaemonErrorCode::kInsufficientBufferSize);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 1U);

    ConfigureDigestFinalStub({CKR_DEVICE_ERROR, CKR_OK});
    const auto recoveredFailure =
        executor.Execute(context, ops::HASH_FINALIZE, request, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(recoveredFailure.has_value());
    EXPECT_EQ(recoveredFailure.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 2U);

    ConfigureDigestFinalStub({CKR_DEVICE_ERROR, CKR_DEVICE_ERROR});
    const auto unrecoveredFailure =
        executor.Execute(context, ops::HASH_FINALIZE, request, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(unrecoveredFailure.has_value());
    EXPECT_EQ(unrecoveredFailure.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 2U);
}

TEST(Pkcs11HashExecutorErrorTest, UpdatePreservesValidationFailuresAndCleansUpProviderFailures)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestUpdateStub(CKR_OK);
    ConfigureDigestFinalStub({CKR_OK});
    common::RequestParameters invalidRequest{std::uint64_t{1U}};
    const auto validationFailure = executor.Execute(
        context, ops::HASH_UPDATE, invalidRequest, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(validationFailure.has_value());
    EXPECT_EQ(validationFailure.error(), common::DaemonErrorCode::kInvalidDataType);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestUpdateStubState().call_count, 0U);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 0U);

    ConfigureDigestUpdateStub(CKR_DEVICE_ERROR);
    ConfigureDigestFinalStub({CKR_OK});
    const std::vector<std::uint8_t> input{0x01U};
    common::RequestParameters validRequest{score::cpp::span<const std::uint8_t>{input.data(), input.size()}};
    const auto providerFailure = executor.Execute(
        context, ops::HASH_UPDATE, validRequest, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(providerFailure.has_value());
    EXPECT_EQ(providerFailure.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(nextState, common::StreamOperationState::IDLE);
    EXPECT_EQ(GetDigestUpdateStubState().call_count, 1U);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 1U);
}

TEST(Pkcs11HashExecutorErrorTest, RejectsUnexpectedHashParametersBeforeCallingToken)
{
    CK_FUNCTION_LIST functionList{};
    auto executor = MakeStubbedHashExecutor(functionList);
    auto context = MakeHashExecutionContext();
    auto nextState = common::StreamOperationState::IDLE;

    ConfigureDigestStub(CKR_OK);
    common::RequestParameters invalidInit{std::uint64_t{1U}};
    const auto initResult =
        executor.Execute(context, ops::HASH_INIT, invalidInit, common::StreamOperationState::IDLE, nextState);
    ASSERT_FALSE(initResult.has_value());
    EXPECT_EQ(initResult.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(GetDigestStubState().init_call_count, 0U);

    const std::array<std::uint8_t, 1U> input{0x42U};
    std::array<std::uint8_t, 32U> output{};
    common::RequestParameters invalidSingleShot{
        score::cpp::span<const std::uint8_t>{input.data(), input.size()},
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
        std::uint64_t{1U},
    };
    const auto singleShotResult =
        executor.Execute(context, ops::HASH_SS, invalidSingleShot, common::StreamOperationState::IDLE, nextState);
    ASSERT_FALSE(singleShotResult.has_value());
    EXPECT_EQ(singleShotResult.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(GetDigestStubState().init_call_count, 0U);

    common::RequestParameters invalidReset{std::uint64_t{1U}};
    ConfigureDigestFinalStub({CKR_OK});
    const auto resetResult = executor.Execute(
        context, ops::HASH_RESET, invalidReset, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(resetResult.has_value());
    EXPECT_EQ(resetResult.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 0U);

    common::RequestParameters invalidFinalize{
        score::cpp::span<std::uint8_t>{output.data(), output.size()},
        std::uint64_t{1U},
    };
    ConfigureDigestFinalStub({CKR_OK});
    const auto finalizeResult = executor.Execute(
        context, ops::HASH_FINALIZE, invalidFinalize, common::StreamOperationState::STREAM_ACTIVE, nextState);
    ASSERT_FALSE(finalizeResult.has_value());
    EXPECT_EQ(finalizeResult.error(), common::DaemonErrorCode::kInvalidArgument);
    EXPECT_EQ(nextState, common::StreamOperationState::STREAM_ACTIVE);
    EXPECT_EQ(GetDigestFinalStubState().call_count, 0U);
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

#ifndef USE_RUST_PKCS11
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
#endif  // USE_RUST_PKCS11

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
        cfg.cleanupStrategy = CleanupStrategy();
        // sessionType removed: session type is now per-handler via kRequirements

        provider_ = std::make_shared<pkcs11::Pkcs11Provider>(std::move(cfg));
        provider::ProviderInitContext ctx{1, "SOFTHSM"};  // ID 1, name "SOFTHSM"
        ASSERT_TRUE(provider_->Initialize(ctx));
    }

    [[nodiscard]] virtual pkcs11::Pkcs11SessionCleanupStrategy CleanupStrategy() const noexcept
    {
        // Hard cleanup isolates the functional hash tests from token-specific
        // soft-cleanup behavior. Dedicated tests below exercise soft cleanup.
        return pkcs11::Pkcs11SessionCleanupStrategy::kHardCleanup;
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

class Pkcs11ProviderSoftCleanupHashTest : public Pkcs11ProviderHashTest
{
  protected:
    [[nodiscard]] pkcs11::Pkcs11SessionCleanupStrategy CleanupStrategy() const noexcept override
    {
        return pkcs11::Pkcs11SessionCleanupStrategy::kSoftCleanup;
    }
};

TEST_F(Pkcs11ProviderSoftCleanupHashTest, DiscardsSessionWhenHandlerCleanupFails)
{
    const auto sessionResult = provider_->AcquireSession(pkcs11::Pkcs11HashHandler::kRequirements);
    ASSERT_TRUE(sessionResult.has_value());
    const CK_SESSION_HANDLE session = sessionResult.value();

    CK_FUNCTION_LIST functionList{};
    functionList.C_DigestFinal = &DigestFinalStub;
    ConfigureDigestFinalStub({CKR_DEVICE_ERROR});
    {
        auto executor = std::make_unique<pkcs11::Pkcs11HashExecutor>(functionList);
        pkcs11::Pkcs11HashHandler hashHandler{std::move(executor), session, "SHA256", provider_.get()};
    }

    EXPECT_FALSE(provider_->ValidateSession(session));

    const auto replacement = provider_->AcquireSession(pkcs11::Pkcs11HashHandler::kRequirements);
    ASSERT_TRUE(replacement.has_value());
    EXPECT_TRUE(provider_->ValidateSession(replacement.value()));
    provider_->ReleaseSession(replacement.value(), pkcs11::Pkcs11HashHandler::kRequirements);
}

TEST_F(Pkcs11ProviderSoftCleanupHashTest, ReusesSessionWhenHandlerCleanupSucceeds)
{
    const auto sessionResult = provider_->AcquireSession(pkcs11::Pkcs11HashHandler::kRequirements);
    ASSERT_TRUE(sessionResult.has_value());
    const CK_SESSION_HANDLE session = sessionResult.value();

    CK_FUNCTION_LIST functionList{};
    functionList.C_DigestFinal = &DigestFinalStub;
    ConfigureDigestFinalStub({CKR_OPERATION_NOT_INITIALIZED});
    {
        auto executor = std::make_unique<pkcs11::Pkcs11HashExecutor>(functionList);
        pkcs11::Pkcs11HashHandler hashHandler{std::move(executor), session, "SHA256", provider_.get()};
    }

    EXPECT_TRUE(provider_->ValidateSession(session));
    const auto reused = provider_->AcquireSession(pkcs11::Pkcs11HashHandler::kRequirements);
    ASSERT_TRUE(reused.has_value());
    EXPECT_EQ(reused.value(), session);
    provider_->ReleaseSession(reused.value(), pkcs11::Pkcs11HashHandler::kRequirements);
}

// ---------------------------------------------------------------------------
// SHA-256/384/512 migration coverage
// ---------------------------------------------------------------------------

class Pkcs11ProviderHashAlgorithmTest : public Pkcs11ProviderHashTest,
                                        public ::testing::WithParamInterface<HashAlgorithmTestData>
{
};

TEST_P(Pkcs11ProviderHashAlgorithmTest, SupportsSingleShotStreamingResetAndDigestSize)
{
    const auto& testData = GetParam();
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    auto handlerResult = cryptoOps->CreateHandler("HASH", testData.algorithm);
    ASSERT_TRUE(handlerResult.has_value()) << "Failed to create HASH/" << testData.algorithm;
    auto hashHandler = handlerResult.value();
    ASSERT_NE(hashHandler, nullptr);
    ASSERT_TRUE(hashHandler->InitializeContext(handler::InitializationParams{}).has_value());

    const std::vector<HashVector> vectors{
        {"score/tests/test_vectors/hash/input_hello_world.bin", testData.hello_digest_path},
        {"score/tests/test_vectors/hash/input_complete_data.bin", testData.complete_digest_path},
        {"score/tests/test_vectors/hash/input_empty.bin", testData.empty_digest_path},
        {"score/tests/test_vectors/hash/input_abc.bin", testData.abc_digest_path},
    };

    for (const auto& vector : vectors)
    {
        SCOPED_TRACE(std::string{testData.algorithm} + " / " + vector.input_path);
        const auto input = tests::utility::read_bin(vector.input_path);
        const auto expectedDigest = tests::utility::read_bin(vector.digest_path);
        ASSERT_EQ(expectedDigest.size(), testData.digest_size);

        std::vector<std::uint8_t> output(testData.digest_size, 0U);
        common::RequestParameters request{
            score::cpp::span<const std::uint8_t>{input.data(), input.size()},
            score::cpp::span<std::uint8_t>{output.data(), output.size()},
        };

        const auto result = hashHandler->Execute(MakeHashOp(ops::HASH_SS), request);
        ASSERT_TRUE(result.has_value()) << "Single-shot hash failed";
        EXPECT_EQ(ExtractDigest(result.value(), output), expectedDigest);
    }

    common::RequestParameters digestSizeRequest{};
    const auto digestSizeResult = hashHandler->Execute(MakeHashOp(ops::HASH_GET_DIGEST_SIZE), digestSizeRequest);
    ASSERT_TRUE(digestSizeResult.has_value());
    ASSERT_EQ(digestSizeResult.value().size(), 1U);
    const auto* digestSize = std::get_if<std::uint64_t>(&digestSizeResult.value().front());
    ASSERT_NE(digestSize, nullptr);
    EXPECT_EQ(*digestSize, testData.digest_size);

    common::RequestParameters initRequest{};
    const auto empty = tests::utility::read_bin("score/tests/test_vectors/hash/input_empty.bin");
    const auto expectedEmpty = tests::utility::read_bin(testData.empty_digest_path);
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters emptyUpdate{
        score::cpp::span<const std::uint8_t>{empty.data(), empty.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), emptyUpdate).has_value());
    std::vector<std::uint8_t> emptyStreamingOutput(testData.digest_size, 0U);
    common::RequestParameters emptyFinalize{
        score::cpp::span<std::uint8_t>{emptyStreamingOutput.data(), emptyStreamingOutput.size()},
    };
    const auto emptyStreamingResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), emptyFinalize);
    ASSERT_TRUE(emptyStreamingResult.has_value());
    EXPECT_EQ(ExtractDigest(emptyStreamingResult.value(), emptyStreamingOutput), expectedEmpty);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    std::vector<std::uint8_t> zeroUpdateOutput(testData.digest_size, 0U);
    common::RequestParameters zeroUpdateFinalize{
        score::cpp::span<std::uint8_t>{zeroUpdateOutput.data(), zeroUpdateOutput.size()},
    };
    const auto zeroUpdateResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), zeroUpdateFinalize);
    ASSERT_TRUE(zeroUpdateResult.has_value());
    EXPECT_EQ(ExtractDigest(zeroUpdateResult.value(), zeroUpdateOutput), expectedEmpty)
        << "Init followed directly by Finalize must hash empty input";

    const auto hello = tests::utility::read_bin("score/tests/test_vectors/hash/input_hello_world.bin");
    const auto expectedHello = tests::utility::read_bin(testData.hello_digest_path);
    ASSERT_FALSE(hello.empty());
    ASSERT_EQ(expectedHello.size(), testData.digest_size);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    const auto split = static_cast<std::ptrdiff_t>(hello.size() / 2U);
    const std::vector<std::uint8_t> firstChunk{hello.begin(), hello.begin() + split};
    const std::vector<std::uint8_t> secondChunk{hello.begin() + split, hello.end()};
    common::RequestParameters firstUpdate{
        score::cpp::span<const std::uint8_t>{firstChunk.data(), firstChunk.size()},
    };
    common::RequestParameters secondUpdate{
        score::cpp::span<const std::uint8_t>{secondChunk.data(), secondChunk.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), secondUpdate).has_value());

    std::vector<std::uint8_t> streamingOutput(testData.digest_size, 0U);
    common::RequestParameters finalizeRequest{
        score::cpp::span<std::uint8_t>{streamingOutput.data(), streamingOutput.size()},
    };
    const auto streamingResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), finalizeRequest);
    ASSERT_TRUE(streamingResult.has_value());
    EXPECT_EQ(ExtractDigest(streamingResult.value(), streamingOutput), expectedHello);

    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), firstUpdate).has_value());
    common::RequestParameters resetRequest{};
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_RESET), resetRequest).has_value());

    const auto complete = tests::utility::read_bin("score/tests/test_vectors/hash/input_complete_data.bin");
    const auto expectedComplete = tests::utility::read_bin(testData.complete_digest_path);
    ASSERT_FALSE(complete.empty());
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters completeUpdate{
        score::cpp::span<const std::uint8_t>{complete.data(), complete.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), completeUpdate).has_value());
    std::vector<std::uint8_t> resetOutput(testData.digest_size, 0U);
    common::RequestParameters resetFinalize{
        score::cpp::span<std::uint8_t>{resetOutput.data(), resetOutput.size()},
    };
    const auto resetResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), resetFinalize);
    ASSERT_TRUE(resetResult.has_value());
    EXPECT_EQ(ExtractDigest(resetResult.value(), resetOutput), expectedComplete);

    std::vector<std::uint8_t> undersizedOutput(testData.digest_size - 1U, 0U);
    common::RequestParameters undersizedRequest{
        score::cpp::span<const std::uint8_t>{hello.data(), hello.size()},
        score::cpp::span<std::uint8_t>{undersizedOutput.data(), undersizedOutput.size()},
    };
    const auto undersizedSingleShot = hashHandler->Execute(MakeHashOp(ops::HASH_SS), undersizedRequest);
    ASSERT_FALSE(undersizedSingleShot.has_value());
    EXPECT_EQ(undersizedSingleShot.error(), common::DaemonErrorCode::kInsufficientBufferSize);

    // PKCS#11 keeps a digest operation active after CKR_BUFFER_TOO_SMALL.
    // Verify the handler preserves that retry contract and its stream state.
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());
    common::RequestParameters retryUpdate{
        score::cpp::span<const std::uint8_t>{hello.data(), hello.size()},
    };
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), retryUpdate).has_value());
    common::RequestParameters undersizedFinalize{
        score::cpp::span<std::uint8_t>{undersizedOutput.data(), undersizedOutput.size()},
    };
    const auto failedFinalize = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), undersizedFinalize);
    ASSERT_FALSE(failedFinalize.has_value());
    EXPECT_EQ(failedFinalize.error(), common::DaemonErrorCode::kInsufficientBufferSize);

    std::vector<std::uint8_t> retryOutput(testData.digest_size, 0U);
    common::RequestParameters retryFinalize{
        score::cpp::span<std::uint8_t>{retryOutput.data(), retryOutput.size()},
    };
    const auto retryResult = hashHandler->Execute(MakeHashOp(ops::HASH_FINALIZE), retryFinalize);
    ASSERT_TRUE(retryResult.has_value()) << "Finalize retry failed after an undersized output buffer";
    EXPECT_EQ(ExtractDigest(retryResult.value(), retryOutput), expectedHello);
}

TEST_F(Pkcs11ProviderHashTest, RejectsUnsupportedAlgorithm)
{
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);
    const auto result = cryptoOps->CreateHandler("HASH", "UNSUPPORTED_ALGORITHM");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(*result.error(),
              static_cast<score::result::ErrorCode>(score::crypto::CryptoErrorCode::kUnsupportedAlgorithm));
}

TEST_F(Pkcs11ProviderHashTest, QueriesSelectedTokenMechanisms)
{
    const auto sha256 = provider_->SupportsMechanism(CKM_SHA256, CKF_DIGEST);
    ASSERT_TRUE(sha256.has_value());
    EXPECT_TRUE(sha256.value());

    const auto sha256Encryption = provider_->SupportsMechanism(CKM_SHA256, CKF_ENCRYPT);
    ASSERT_TRUE(sha256Encryption.has_value());
    EXPECT_FALSE(sha256Encryption.value()) << "SHA-256 must not be accepted for an unsupported operation flag";

    constexpr CK_MECHANISM_TYPE kUnknownVendorMechanism{CKM_VENDOR_DEFINED | 0x0053434FUL};
    const auto unknown = provider_->SupportsMechanism(kUnknownVendorMechanism, CKF_DIGEST);
    ASSERT_TRUE(unknown.has_value());
    EXPECT_FALSE(unknown.value());
}

TEST_F(Pkcs11ProviderHashTest, ReportsExecutorUpdateFailure)
{
    auto cryptoOps = provider_->GetCryptoHandlerFactory();
    ASSERT_NE(cryptoOps, nullptr);

    auto handlerResult = cryptoOps->CreateHandler("HASH", "SHA256");
    ASSERT_TRUE(handlerResult.has_value());
    auto hashHandler = handlerResult.value();
    ASSERT_TRUE(hashHandler->InitializeContext(handler::InitializationParams{}).has_value());

    common::RequestParameters initRequest{};
    ASSERT_TRUE(hashHandler->Execute(MakeHashOp(ops::HASH_INIT), initRequest).has_value());

    common::RequestParameters invalidUpdate{std::uint64_t{1U}};
    EXPECT_FALSE(hashHandler->Execute(MakeHashOp(ops::HASH_UPDATE), invalidUpdate).has_value());
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
    updateOp.push_back(score::cpp::span<const uint8_t>{dataBuf.data(), dataBuf.size()});

    auto updateResult = handler->Execute(MakeHashOp(ops::HASH_UPDATE), updateOp);
    ASSERT_FALSE(updateResult.has_value()) << "HASH_UPDATE without HASH_INIT should fail";
    EXPECT_EQ(updateResult.error(), common::DaemonErrorCode::kStreamNotInitialized);

    // HASH_FINALIZE without HASH_INIT should also fail.
    std::vector<std::uint8_t> outBuf(32U);

    common::RequestParameters finishOp{};
    finishOp.push_back(score::cpp::span<uint8_t>{outBuf.data(), outBuf.size()});

    auto finishResult = handler->Execute(MakeHashOp(ops::HASH_FINALIZE), finishOp);
    ASSERT_FALSE(finishResult.has_value()) << "HASH_FINALIZE without active stream should fail";
    EXPECT_EQ(finishResult.error(), common::DaemonErrorCode::kStreamNotInitialized);

    common::RequestParameters initOp{};
    ASSERT_TRUE(handler->Execute(MakeHashOp(ops::HASH_INIT), initOp).has_value());
    EXPECT_TRUE(handler->Execute(MakeHashOp(ops::HASH_INIT), initOp).has_value())
        << "Init on an active stream must restart it";
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
    updateA1.push_back(score::cpp::span<const uint8_t>{bufA1.data(), bufA1.size()});
    auto updA1 = handlerA->Execute(MakeHashOp(ops::HASH_UPDATE), updateA1);
    ASSERT_TRUE(updA1.has_value()) << "HASH_UPDATE A1 failed";

    const std::string chunk1B = "Hello, ";
    std::vector<std::uint8_t> bufB1(chunk1B.begin(), chunk1B.end());
    common::RequestParameters updateB1{};
    updateB1.push_back(score::cpp::span<const uint8_t>{bufB1.data(), bufB1.size()});
    auto updB1 = handlerB->Execute(MakeHashOp(ops::HASH_UPDATE), updateB1);
    ASSERT_TRUE(updB1.has_value()) << "HASH_UPDATE B1 failed";

    const std::string chunk2A = "World!";
    std::vector<std::uint8_t> bufA2(chunk2A.begin(), chunk2A.end());
    common::RequestParameters updateA2{};
    updateA2.push_back(score::cpp::span<const uint8_t>{bufA2.data(), bufA2.size()});
    auto updA2 = handlerA->Execute(MakeHashOp(ops::HASH_UPDATE), updateA2);
    ASSERT_TRUE(updA2.has_value()) << "HASH_UPDATE A2 failed";

    const std::string chunk2B = "World!";
    std::vector<std::uint8_t> bufB2(chunk2B.begin(), chunk2B.end());
    common::RequestParameters updateB2{};
    updateB2.push_back(score::cpp::span<const uint8_t>{bufB2.data(), bufB2.size()});
    auto updB2 = handlerB->Execute(MakeHashOp(ops::HASH_UPDATE), updateB2);
    ASSERT_TRUE(updB2.has_value()) << "HASH_UPDATE B2 failed";

    // Finalize both -- A and B both complete "Hello, World!" but in different algorithms
    constexpr std::size_t kSha256Len{32U};
    std::vector<std::uint8_t> outA(kSha256Len);
    common::RequestParameters finishA{};
    finishA.push_back(score::cpp::span<uint8_t>{outA.data(), outA.size()});
    auto finA = handlerA->Execute(MakeHashOp(ops::HASH_FINALIZE), finishA);
    ASSERT_TRUE(finA.has_value()) << "HASH_FINALIZE A failed";

    constexpr std::size_t kSha384Len{48U};
    std::vector<std::uint8_t> outB(kSha384Len);
    common::RequestParameters finishB{};
    finishB.push_back(score::cpp::span<uint8_t>{outB.data(), outB.size()});
    auto finB = handlerB->Execute(MakeHashOp(ops::HASH_FINALIZE), finishB);
    ASSERT_TRUE(finB.has_value()) << "HASH_FINALIZE B failed";

    // Both handlers digested "Hello, World!" -- verify correctness
    const auto digestA = ExtractDigest(finA.value(), outA);
    const auto expectedSha256 = tests::utility::read_bin("score/tests/test_vectors/hash/sha256_hello_world.bin");
    ASSERT_EQ(expectedSha256.size(), kSha256Len);
    EXPECT_EQ(digestA, expectedSha256) << "Interleaved SHA-256 stream produced wrong digest";

    const auto digestB = ExtractDigest(finB.value(), outB);
    const auto expectedSha384 = tests::utility::read_bin("score/tests/test_vectors/hash/sha384_hello_world.bin");
    ASSERT_EQ(expectedSha384.size(), kSha384Len);
    EXPECT_EQ(digestB, expectedSha384) << "Interleaved SHA-384 stream produced wrong digest";

    // Destroying handlerA and handlerB releases sessions back to pool.
    handlerA.reset();
    handlerB.reset();
}

INSTANTIATE_TEST_SUITE_P(
    BaselibsMigrationAlgorithms,
    Pkcs11ProviderHashAlgorithmTest,
    ::testing::Values(HashAlgorithmTestData{"SHA256",
                                            32U,
                                            "score/tests/test_vectors/hash/sha256_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha256_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha256_empty.bin",
                                            "score/tests/test_vectors/hash/sha256_abc.bin"},
                      HashAlgorithmTestData{"SHA384",
                                            48U,
                                            "score/tests/test_vectors/hash/sha384_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha384_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha384_empty.bin",
                                            "score/tests/test_vectors/hash/sha384_abc.bin"},
                      HashAlgorithmTestData{"SHA512",
                                            64U,
                                            "score/tests/test_vectors/hash/sha512_hello_world.bin",
                                            "score/tests/test_vectors/hash/sha512_complete_data.bin",
                                            "score/tests/test_vectors/hash/sha512_empty.bin",
                                            "score/tests/test_vectors/hash/sha512_abc.bin"}),
    [](const ::testing::TestParamInfo<HashAlgorithmTestData>& info) {
        return info.param.algorithm;
    });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
