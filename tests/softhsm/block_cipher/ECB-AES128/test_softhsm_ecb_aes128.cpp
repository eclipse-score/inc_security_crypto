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

#include "tests/utility/test_utility.hpp"
#include <gtest/gtest.h>
#include <pkcs11.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using tests::utility::print_hex;
using tests::utility::read_bin;

class SoftHSMTest : public ::testing::Test
{
  protected:
    CK_FUNCTION_LIST_PTR function_list = nullptr;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slot_id = 0;

    void SetUp() override
    {
        // Set up SoftHSM configuration for testing
        // Create a temporary token directory in the test environment
        std::string token_dir =
            std::string(std::getenv("TEST_TMPDIR") ? std::getenv("TEST_TMPDIR") : "/tmp") + "/softhsm_tokens";
        system(("mkdir -p " + token_dir).c_str());

        // Create a minimal SoftHSM config file
        std::string config_path =
            std::string(std::getenv("TEST_TMPDIR") ? std::getenv("TEST_TMPDIR") : "/tmp") + "/softhsm2.conf";
        std::ofstream config(config_path);
        config << "directories.tokendir = " << token_dir << "\n";
        config << "objectstore.backend = file\n";
        config << "log.level = INFO\n";
        config.close();

        // Set environment variable for SoftHSM to find the config
        setenv("SOFTHSM2_CONF", config_path.c_str(), 1);

        // Get function list from linked SoftHSM library
        CK_RV rv = C_GetFunctionList(&function_list);
        ASSERT_EQ(rv, CKR_OK) << "C_GetFunctionList failed: " << rv;
        ASSERT_TRUE(function_list != nullptr);

        // Initialize PKCS#11
        rv = function_list->C_Initialize(nullptr);
        ASSERT_EQ(rv, CKR_OK) << "C_Initialize failed: " << rv;

        // Get all available slots (including those without tokens)
        CK_ULONG slot_count = 0;
        rv = function_list->C_GetSlotList(CK_FALSE, nullptr, &slot_count);
        ASSERT_EQ(rv, CKR_OK) << "C_GetSlotList failed: " << rv;
        ASSERT_GT(slot_count, 0) << "No slots available";

        std::vector<CK_SLOT_ID> slots(slot_count);
        rv = function_list->C_GetSlotList(CK_FALSE, slots.data(), &slot_count);
        ASSERT_EQ(rv, CKR_OK);
        slot_id = slots[0];

        // Initialize the token with a label and SO/User PINs
        std::string label = "Test Token      ";  // Must be padded to 32 chars for SoftHSM
        label.resize(32, ' ');
        CK_UTF8CHAR so_pin[] = "1234";
        CK_UTF8CHAR user_pin[] = "1234";

        rv = function_list->C_InitToken(
            slot_id, so_pin, sizeof(so_pin) - 1, reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(label.c_str())));
        ASSERT_EQ(rv, CKR_OK) << "C_InitToken failed: " << rv;

        // Open session
        rv = function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
        ASSERT_EQ(rv, CKR_OK) << "C_OpenSession failed: " << rv;

        // Login as SO to initialize the user PIN
        rv = function_list->C_Login(session, CKU_SO, so_pin, sizeof(so_pin) - 1);
        ASSERT_EQ(rv, CKR_OK) << "C_Login as SO failed: " << rv;

        // Initialize the user PIN
        rv = function_list->C_InitPIN(session, user_pin, sizeof(user_pin) - 1);
        ASSERT_EQ(rv, CKR_OK) << "C_InitPIN failed: " << rv;

        // Logout SO
        rv = function_list->C_Logout(session);
        ASSERT_EQ(rv, CKR_OK) << "C_Logout failed: " << rv;

        // Login as normal user (needed to create objects)
        rv = function_list->C_Login(session, CKU_USER, user_pin, sizeof(user_pin) - 1);
        ASSERT_EQ(rv, CKR_OK) << "C_Login as USER failed: " << rv;
    }

    void TearDown() override
    {
        if (function_list && session != CK_INVALID_HANDLE)
        {
            function_list->C_CloseSession(session);
        }
        if (function_list)
        {
            function_list->C_Finalize(nullptr);
        }
    }

    CK_OBJECT_HANDLE create_aes_key(const std::vector<uint8_t>& key_data)
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
            {CKA_VALUE, const_cast<uint8_t*>(key_data.data()), static_cast<CK_ULONG>(key_data.size())}};

        CK_OBJECT_HANDLE key_handle;
        CK_RV rv = function_list->C_CreateObject(
            session, key_template, sizeof(key_template) / sizeof(CK_ATTRIBUTE), &key_handle);
        EXPECT_EQ(rv, CKR_OK) << "C_CreateObject failed: " << rv;
        return key_handle;
    }
};

class AES128ECBSoftHSMTest : public SoftHSMTest, public ::testing::WithParamInterface<int>
{
};

TEST_P(AES128ECBSoftHSMTest, EncryptBlock)
{
    auto key_data = read_bin("tests/test_vectors/block_cipher/ECB-AES128/key.bin");
    auto num = std::to_string(GetParam());
    auto plaintext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".bin");
    auto expected_ciphertext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".enc");

    ASSERT_EQ(key_data.size(), 16) << "AES-128 key must be 16 bytes";
    ASSERT_EQ(plaintext.size(), 16) << "AES block must be 16 bytes";
    ASSERT_EQ(expected_ciphertext.size(), 16) << "Expected ciphertext must be 16 bytes";

    // Create AES key object
    CK_OBJECT_HANDLE key_handle = create_aes_key(key_data);
    ASSERT_NE(key_handle, CK_INVALID_HANDLE);

    // Initialize encryption operation
    CK_MECHANISM mechanism = {CKM_AES_ECB, nullptr, 0};
    CK_RV rv = function_list->C_EncryptInit(session, &mechanism, key_handle);
    ASSERT_EQ(rv, CKR_OK) << "C_EncryptInit failed: " << rv;

    // Perform encryption
    std::vector<uint8_t> ciphertext(16);
    CK_ULONG ciphertext_len = ciphertext.size();
    rv = function_list->C_Encrypt(session, plaintext.data(), plaintext.size(), ciphertext.data(), &ciphertext_len);
    ASSERT_EQ(rv, CKR_OK) << "C_Encrypt failed: " << rv;
    ASSERT_EQ(ciphertext_len, 16) << "Ciphertext length mismatch";

    print_hex("Ciphertext: ", ciphertext, ciphertext_len);
    print_hex("Expected  : ", expected_ciphertext, expected_ciphertext.size());

    EXPECT_EQ(ciphertext, expected_ciphertext);

    // Cleanup key object
    function_list->C_DestroyObject(session, key_handle);
}

TEST_P(AES128ECBSoftHSMTest, DecryptBlock)
{
    auto key_data = read_bin("tests/test_vectors/block_cipher/ECB-AES128/key.bin");
    auto num = std::to_string(GetParam());
    auto expected_plaintext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".bin");
    auto ciphertext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".enc");

    ASSERT_EQ(key_data.size(), 16);
    ASSERT_EQ(ciphertext.size(), 16);
    ASSERT_EQ(expected_plaintext.size(), 16);

    // Create AES key object
    CK_OBJECT_HANDLE key_handle = create_aes_key(key_data);
    ASSERT_NE(key_handle, CK_INVALID_HANDLE);

    // Initialize decryption operation
    CK_MECHANISM mechanism = {CKM_AES_ECB, nullptr, 0};
    CK_RV rv = function_list->C_DecryptInit(session, &mechanism, key_handle);
    ASSERT_EQ(rv, CKR_OK) << "C_DecryptInit failed: " << rv;

    // Perform decryption
    std::vector<uint8_t> plaintext(16);
    CK_ULONG plaintext_len = plaintext.size();
    rv = function_list->C_Decrypt(session, ciphertext.data(), ciphertext.size(), plaintext.data(), &plaintext_len);
    ASSERT_EQ(rv, CKR_OK) << "C_Decrypt failed: " << rv;
    ASSERT_EQ(plaintext_len, 16) << "Plaintext length mismatch";

    print_hex("Plaintext : ", plaintext, plaintext_len);
    print_hex("Expected  : ", expected_plaintext, expected_plaintext.size());

    EXPECT_EQ(plaintext, expected_plaintext);

    // Cleanup key object
    function_list->C_DestroyObject(session, key_handle);
}

INSTANTIATE_TEST_SUITE_P(ECB_AES128,
                         AES128ECBSoftHSMTest,
                         ::testing::Values(1, 2, 3, 4),
                         [](const ::testing::TestParamInfo<int>& info) {
                             return "block" + std::to_string(info.param);
                         });

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
