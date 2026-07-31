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

/// @file softhsm_test_fixture.hpp
/// @brief Reusable Google Test fixture that initialises a SoftHSM2 token.
///
/// Extracted from test_softhsm_ecb_aes128.cpp so that multiple test binaries
/// can share the same setup/teardown logic without code duplication.
///
/// ### Usage
/// @code
/// #include "tests/softhsm/softhsm_test_fixture.hpp"
///
/// class MyTest : public tests::softhsm::SofthsmTestFixture { ... };
/// @endcode
///
/// ### What SetUp() does
///  1. Creates a temporary SoftHSM2 config file in TEST_TMPDIR (falls back to /tmp).
///  2. Sets SOFTHSM2_CONF so the linked SoftHSM2 library finds the config.
///  3. C_Initialize
///  4. C_InitToken (label "Test Token", SO PIN "1234")
///  5. C_OpenSession (RW)
///  6. C_Login(SO) → C_InitPIN(User PIN "1234") → C_Logout(SO)
///  7. C_Login(User) — session is now user-authenticated.
///
/// TearDown(): C_CloseSession → C_Finalize.
///
/// ### Slot-id reuse warning
/// After C_InitToken the slot_id may change (SoftHSM2 assigns a new slot for
/// the initialised token). The fixture re-queries the slot list and picks the
/// first slot that has a present token, so the member `slot_id` is always the
/// correct one for the active token.

#ifndef TESTS_SOFTHSM_SOFTHSM_TEST_FIXTURE_HPP
#define TESTS_SOFTHSM_SOFTHSM_TEST_FIXTURE_HPP

#include <gtest/gtest.h>
#include <pkcs11.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace tests::softhsm
{

/// @brief Google Test fixture base-class for tests that need a live SoftHSM2 token.
class SofthsmTestFixture : public ::testing::Test
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
    /// @param key_data   Raw key bytes.
    /// @param label      CKA_LABEL string.
    /// @param key_type   CKK_GENERIC_SECRET, CKK_AES, etc.
    /// @param extractable Whether to set CKA_EXTRACTABLE=true.
    /// @return The new CK_OBJECT_HANDLE, or CK_INVALID_HANDLE on failure.
    CK_OBJECT_HANDLE CreateTokenKey(const std::vector<uint8_t>& key_data,
                                    const std::string& label,
                                    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET,
                                    bool extractable = false) noexcept
    {
        CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
        CK_BBOOL true_val = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
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
        const char* tmpdir = std::getenv("TEST_TMPDIR");
        std::string base = (tmpdir != nullptr) ? tmpdir : "/tmp";

        // --- Prepare SoftHSM2 token directory and config file ---
        std::string token_dir = base + "/softhsm_tokens";
        std::string config_path = base + "/softhsm2.conf";

        (void)std::system(("mkdir -p " + token_dir).c_str());

        {
            std::ofstream cfg(config_path);
            cfg << "directories.tokendir = " << token_dir << "\n";
            cfg << "objectstore.backend = file\n";
            cfg << "log.level = INFO\n";
        }
        ::setenv("SOFTHSM2_CONF", config_path.c_str(), 1);

        // --- C_GetFunctionList ---
        CK_RV rv = C_GetFunctionList(&function_list);
        ASSERT_EQ(rv, CKR_OK) << "C_GetFunctionList failed: " << rv;
        ASSERT_NE(function_list, nullptr);

        // --- C_Initialize ---
        rv = function_list->C_Initialize(nullptr);
        ASSERT_EQ(rv, CKR_OK) << "C_Initialize failed: " << rv;

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
        std::string label = "Test Token";
        label.resize(32, ' ');  // SoftHSM2 requires exactly 32 chars

        CK_UTF8CHAR so_pin[] = "1234";
        CK_UTF8CHAR user_pin[] = "1234";

        rv = function_list->C_InitToken(slot_id,
                                        so_pin,
                                        static_cast<CK_ULONG>(sizeof(so_pin) - 1),
                                        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(label.c_str())));
        ASSERT_EQ(rv, CKR_OK) << "C_InitToken failed: " << rv;

        // After InitToken SoftHSM2 may have moved the token to a new slot.
        // Re-query to get the slot that now has a present token.
        slot_id = ResolveInitializedSlot();
        ASSERT_NE(slot_id, static_cast<CK_SLOT_ID>(CK_UNAVAILABLE_INFORMATION))
            << "Could not find initialized token slot after C_InitToken";

        // --- Open a RW session ---
        rv = function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
        ASSERT_EQ(rv, CKR_OK) << "C_OpenSession failed: " << rv;

        // --- SO login → set user PIN ---
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

}  // namespace tests::softhsm

#endif  // TESTS_SOFTHSM_SOFTHSM_TEST_FIXTURE_HPP
