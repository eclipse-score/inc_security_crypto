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
#include <openssl/evp.h>
#include <string>
#include <vector>

using tests::utility::print_hex;
using tests::utility::read_bin;

// https://docs.openssl.org/3.0/man3/EVP_EncryptInit/#examples
// Adapted to ECB-AES128
class AES128ECBTest : public ::testing::TestWithParam<int>
{
};

TEST_P(AES128ECBTest, EncryptBlock)
{
    auto key = read_bin("tests/test_vectors/block_cipher/ECB-AES128/key.bin");
    auto num = std::to_string(GetParam());
    auto plaintext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".bin");
    auto expected_ciphertext = read_bin("tests/test_vectors/block_cipher/ECB-AES128/block" + num + ".enc");

    ASSERT_EQ(key.size(), 16);
    ASSERT_EQ(plaintext.size(), 16);
    ASSERT_EQ(expected_ciphertext.size(), 16);

    std::vector<uint8_t> ciphertext(16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ASSERT_TRUE(ctx != nullptr);
    ASSERT_EQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr), 1);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int update_len = 0;
    ASSERT_EQ(EVP_EncryptUpdate(ctx, ciphertext.data(), &update_len, plaintext.data(), 16), 1);
    ASSERT_EQ(update_len, 16);

    int final_len = 0;
    ASSERT_EQ(EVP_EncryptFinal_ex(ctx, ciphertext.data() + update_len, &final_len), 1);
    ASSERT_EQ(final_len, 0);
    EVP_CIPHER_CTX_free(ctx);

    print_hex("Ciphertext: ", ciphertext, ciphertext.size());
    print_hex("Expected  : ", expected_ciphertext, expected_ciphertext.size());
    EXPECT_EQ(ciphertext, expected_ciphertext);
}

INSTANTIATE_TEST_SUITE_P(ECB_AES128,
                         AES128ECBTest,
                         ::testing::Values(1, 2, 3, 4),
                         [](const ::testing::TestParamInfo<int>& info) {
                             return "block" + std::to_string(info.param);
                         });

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
