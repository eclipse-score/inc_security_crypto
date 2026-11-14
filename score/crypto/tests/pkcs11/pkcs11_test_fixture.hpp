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

/// @file pkcs11_test_fixture.hpp
/// @brief Reusable, vendor-neutral Google Test fixture that initialises a PKCS#11 token.
///
/// Provides a unified environment configuration supporting both SoftHSM2 and
/// Rust Cryptoki seamlessly without compile-time preprocessor macros.
///
/// ### Usage
/// @code
/// #include "score/crypto/tests/pkcs11/pkcs11_test_fixture.hpp"
///
/// class MyTest : public tests::pkcs11::Pkcs11TestFixture { ... };
/// @endcode
///
/// ### What SetUp() does
///  1. Creates temporary directories for SoftHSM and Rust Cryptoki storage in TEST_TMPDIR.
///  2. Sets both SOFTHSM2_CONF and CRYPTOKI_STORE environment variables.
///  3. C_GetFunctionList & C_Initialize
///  4. C_InitToken (label "TestToken", SO PIN "1234")
///  5. C_OpenSession (RW)
///  6. C_Login(SO) -> C_InitPIN(User PIN "1234") -> C_Logout(SO)
///  7. C_Login(User) — session is now user-authenticated.
///
/// TearDown(): C_CloseSession -> C_Finalize -> unsets environment variables.

#ifndef SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_FIXTURE_HPP
#define SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_FIXTURE_HPP

#include "score/crypto/tests/pkcs11/pkcs11_test_env_setup.hpp"

#include <gtest/gtest.h>
#include <pkcs11.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace tests::pkcs11
{

/// @brief Google Test fixture base-class for tests that need an initialised PKCS#11 token.
class Pkcs11TestFixture : public ::testing::Test
{
  public:
    // -------------------------------------------------------------------------
    // Public helpers callable from derived test bodies
    // -------------------------------------------------------------------------

    /// @brief Create an ephemeral (CKA_TOKEN=false) AES secret key on the token.
    /// @return The new CK_OBJECT_HANDLE, or CK_INVALID_HANDLE on failure.
    CK_OBJECT_HANDLE CreateAesKey(const std::vector<uint8_t>& key_data) noexcept
    {
        CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
        CK_KEY_TYPE key_type = CKK_AES;
        CK_BBOOL true_val = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE key_template[] = {
            {CKA_CLASS, &key_class, sizeof(key_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_TOKEN, &false_val, sizeof(false_val)},
            {CKA_ENCRYPT, &true_val, sizeof(true_val)},
            {CKA_DECRYPT, &true_val, sizeof(true_val)},
            {CKA_VALUE, const_cast<uint8_t*>(key_data.data()), static_cast<CK_ULONG>(key_data.size())},
        };

        CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
        CK_RV rv = function_list->C_CreateObject(
            session, key_template, static_cast<CK_ULONG>(sizeof(key_template) / sizeof(CK_ATTRIBUTE)), &handle);
        if (rv != CKR_OK)
        {
            ADD_FAILURE() << "CreateAesKey C_CreateObject failed: " << rv;
            return CK_INVALID_HANDLE;
        }
        return handle;
    }

    /// @brief Create a persistent (CKA_TOKEN=true) generic secret key with a label.
    ///
    /// Used by tests that verify LoadKey-by-label flows.
    ///
    /// @param key_data    Raw key bytes.
    /// @param label       CKA_LABEL string.
    /// @param key_type    CKK_GENERIC_SECRET, CKK_AES, etc.
    /// @param extractable Whether to set CKA_EXTRACTABLE=true.
    /// @return The new CK_OBJECT_HANDLE, or CK_INVALID_HANDLE on failure.
    CK_OBJECT_HANDLE CreateTokenKey(const std::vector<uint8_t>& key_data,
                                    const std::string& label,
                                    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET,
                                    bool extractable = false) noexcept
    {
        CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_BBOOL extractable_v = extractable ? CK_TRUE : CK_FALSE;

        CK_ATTRIBUTE key_template[] = {
            {CKA_CLASS, &key_class, sizeof(key_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_TOKEN, &true_val, sizeof(true_val)},
            {CKA_SENSITIVE, &true_val, sizeof(true_val)},
            {CKA_EXTRACTABLE, &extractable_v, sizeof(extractable_v)},
            {CKA_SIGN, &true_val, sizeof(true_val)},
            {CKA_VERIFY, &true_val, sizeof(true_val)},
            {CKA_LABEL, const_cast<char*>(label.c_str()), static_cast<CK_ULONG>(label.size())},
            {CKA_VALUE, const_cast<uint8_t*>(key_data.data()), static_cast<CK_ULONG>(key_data.size())},
        };

        CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
        CK_RV rv = function_list->C_CreateObject(
            session, key_template, static_cast<CK_ULONG>(sizeof(key_template) / sizeof(CK_ATTRIBUTE)), &handle);
        if (rv != CKR_OK)
        {
            ADD_FAILURE() << "CreateTokenKey C_CreateObject failed: " << rv;
            return CK_INVALID_HANDLE;
        }
        return handle;
    }

  protected:
    // -------------------------------------------------------------------------
    // State available to derived tests
    // -------------------------------------------------------------------------
    CK_FUNCTION_LIST_PTR function_list{nullptr};
    CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
    CK_SLOT_ID slot_id{0U};

    // -------------------------------------------------------------------------
    // SetUp / TearDown
    // -------------------------------------------------------------------------

    void SetUp() override
    {
        const std::string test_dir = env::UniqueTestDirectory("pkcs11_fixture");

        // Abstracted backend-specific filesystem and environment setup
        env::PrepareBackendEnvironments(test_dir);

        // --- C_GetFunctionList ---
        CK_RV rv = C_GetFunctionList(&function_list);
        ASSERT_EQ(rv, CKR_OK) << "C_GetFunctionList failed: " << rv;
        ASSERT_NE(function_list, nullptr);

        // --- C_Initialize ---
        rv = function_list->C_Initialize(nullptr);
        // CKR_CRYPTOKI_ALREADY_INITIALIZED is fine if library was loaded in prior test in same process
        ASSERT_TRUE((rv == CKR_OK) || (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED))
            << "C_Initialize failed: " << rv;

        // --- Discover first available slot (may be uninitialized) ---
        CK_ULONG slot_count = 0;
        rv = function_list->C_GetSlotList(CK_FALSE, nullptr, &slot_count);
        ASSERT_EQ(rv, CKR_OK) << "C_GetSlotList (count) failed: " << rv;
        ASSERT_GT(slot_count, 0U) << "No PKCS#11 slots available";

        std::vector<CK_SLOT_ID> slots(slot_count);
        rv = function_list->C_GetSlotList(CK_FALSE, slots.data(), &slot_count);
        ASSERT_EQ(rv, CKR_OK) << "C_GetSlotList failed: " << rv;
        slot_id = slots[0];

        // --- C_InitToken ---
        std::string label = "TestToken";
        label.resize(32, ' ');  // PKCS#11 standard mandates 32-character padded label buffer

        CK_UTF8CHAR so_pin[] = "1234";
        CK_UTF8CHAR user_pin[] = "1234";

        rv = function_list->C_InitToken(slot_id,
                                        so_pin,
                                        static_cast<CK_ULONG>(sizeof(so_pin) - 1),
                                        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(label.c_str())));
        ASSERT_EQ(rv, CKR_OK) << "C_InitToken failed: " << rv;

        // After InitToken a provider may re-assign or expose the initialized slot.
        // Re-query to get the slot that now has a present token.
        slot_id = ResolveInitializedSlot();
        ASSERT_NE(slot_id, static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION))
            << "Could not find initialized token slot after C_InitToken";

        // --- Open a RW session ---
        rv = function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
        ASSERT_EQ(rv, CKR_OK) << "C_OpenSession failed: " << rv;

        // --- SO login -> set user PIN ---
        rv = function_list->C_Login(session, CKU_SO, so_pin, static_cast<CK_ULONG>(sizeof(so_pin) - 1));
        ASSERT_EQ(rv, CKR_OK) << "C_Login (SO) failed: " << rv;

        rv = function_list->C_InitPIN(session, user_pin, static_cast<CK_ULONG>(sizeof(user_pin) - 1));
        ASSERT_EQ(rv, CKR_OK) << "C_InitPIN failed: " << rv;

        rv = function_list->C_Logout(session);
        ASSERT_EQ(rv, CKR_OK) << "C_Logout (SO) failed: " << rv;

        // --- User login ---
        rv = function_list->C_Login(session, CKU_USER, user_pin, static_cast<CK_ULONG>(sizeof(user_pin) - 1));
        ASSERT_EQ(rv, CKR_OK) << "C_Login (User) failed: " << rv;
    }

    void TearDown() override
    {
        if ((function_list != nullptr) && (session != CK_INVALID_HANDLE))
        {
            function_list->C_CloseSession(session);
            session = CK_INVALID_HANDLE;
        }
        if (function_list != nullptr)
        {
            function_list->C_Finalize(nullptr);
            function_list = nullptr;
        }
        env::CleanupBackendEnvironments();
    }

  private:
    /// @brief Return the slot ID of the first slot whose token is present.
    /// Returns CK_UNAVAILABLE_INFORMATION if none found.
    CK_SLOT_ID ResolveInitializedSlot() const noexcept
    {
        CK_ULONG count = 0;
        if (function_list->C_GetSlotList(CK_TRUE, nullptr, &count) != CKR_OK)
        {
            return static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION);
        }
        if (count == 0U)
        {
            return static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION);
        }
        std::vector<CK_SLOT_ID> slots(count);
        if (function_list->C_GetSlotList(CK_TRUE, slots.data(), &count) != CKR_OK)
        {
            return static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION);
        }
        return slots[0];
    }
};

}  // namespace tests::pkcs11

#endif  // SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_FIXTURE_HPP
