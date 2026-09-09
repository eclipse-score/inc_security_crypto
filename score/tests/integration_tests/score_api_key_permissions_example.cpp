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

/// @file score_api_key_permissions_example.cpp
/// @brief Verifies that KeyOperationPermission is enforced when a context binds a key.
///
/// A key generated with restricted permissions must be usable for exactly the
/// operations it was granted and no others. The daemon enforces this once, at
/// context creation: a context is bound to one key and one direction for its
/// whole life, so a context that was allowed to exist can never exceed its
/// grant afterwards.
///
/// Each case therefore asserts on CreateXxxContext() rather than on the
/// operation itself, and pairs every denial with the matching permitted case —
/// a test that only checks denials would also pass if context creation were
/// broken for every key.
///
/// Covered:
///   - MAC needs kMac
///   - Cipher needs kEncrypt or kDecrypt, per direction
///   - Signing needs kSign on the private half
///   - Verification needs kVerify on the public half, which defaults to
///     unrestricted when the caller does not narrow it
///   - Keyless contexts (hash, random) are unaffected

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/api/config/cipher_context_config.hpp"
#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/config/key_management_context_config.hpp"
#include "score/crypto/src/api/config/key_operation_params.hpp"
#include "score/crypto/src/api/config/mac_context_config.hpp"
#include "score/crypto/src/api/config/random_context_config.hpp"
#include "score/crypto/src/api/config/sign_context_config.hpp"
#include "score/crypto/src/api/config/verify_signature_context_config.hpp"
#include "score/crypto/src/api/contexts/i_cipher_context.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/contexts/i_key_management_context.hpp"
#include "score/crypto/src/api/contexts/i_mac_context.hpp"
#include "score/crypto/src/api/contexts/i_random_context.hpp"
#include "score/crypto/src/api/contexts/i_sign_context.hpp"
#include "score/crypto/src/api/contexts/i_verify_signature_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace score::crypto;

namespace
{

// =========================================================================
// Constants
// =========================================================================

/// Cipher, signature and EC key generation exist only in the OpenSSL provider,
/// so those cases pin kSoftware. Leaving the provider unset would resolve to the
/// daemon's DEFAULT provider, currently SoftHSM, which offers none of them.
constexpr ProviderType kSoftwareProvider = ProviderType::kSoftware;

/// MAC is the one keyed operation both providers implement, so the MAC cases run
/// against each. Enforcement is provider-independent — it happens in the mediator
/// — but the two key factories build their handles differently, and only the
/// PKCS#11 one also translates the grant into CKA_* attributes on the token
/// object. A permission that never reached the daemon would leave a SoftHSM key
/// fully permissive *and* extractable, so this axis is worth covering.
constexpr ProviderType kMacProviders[] = {ProviderType::kSoftware, ProviderType::kHardware};

// The daemon's algorithm tables spell these without a hyphen before the
// digest size — "HMAC-SHA-256" is not a recognised identifier.
constexpr const char* kMacAlgorithm = "HMAC-SHA256";
constexpr const char* kCipherAlgorithm = "AES-256-CBC";
constexpr const char* kEcKeyAlgorithm = "ECDSA-P256";
constexpr const char* kEcSignatureAlgorithm = "ECDSA-P256-SHA256";

/// A real permission that is not kMac, used for the "wrong grant" MAC cases.
///
/// kSign rather than kEncrypt: BuildUsageFlags maps it to CKA_SIGN, which is
/// valid on a PKCS#11 generic-secret key, whereas CKA_ENCRYPT is not. The point
/// of these cases is that the daemon rejects the context, so the key must be
/// creatable on both providers first.
constexpr KeyOperationPermission kNotMac = KeyOperationPermission::kSign;

// =========================================================================
// Fixture
// =========================================================================

/// Owns the stack and crypto context. The key management context is created
/// per test rather than here, because its provider varies: a key is generated by
/// whichever provider owns the key management context it was requested from.
class KeyPermissionTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        CryptoStackConfig stack_config;
        stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

        auto stack_result = CreateCryptoStack(stack_config);
        ASSERT_TRUE(stack_result.has_value()) << "Failed to create crypto stack";
        m_stack = std::move(stack_result.value());

        auto ctx_result = m_stack->CreateCryptoContext();
        ASSERT_TRUE(ctx_result.has_value()) << "Failed to create crypto context";
        m_ctx = std::move(ctx_result.value());
    }

    /// Creates a key management context on @p provider.
    ///
    /// Callers must keep it alive for as long as they use keys generated from
    /// it: an ephemeral key node is a child of the context that created it.
    std::unique_ptr<IKeyManagementContext> MakeKeyMgmtContext(ProviderType provider)
    {
        KeyManagementContextConfig config;
        config.SetProviderType(provider);
        auto result = m_ctx->CreateKeyManagementContext(config);
        EXPECT_TRUE(result.has_value()) << "Failed to create key management context";
        if (!result.has_value())
        {
            return nullptr;
        }
        return std::move(result.value());
    }

    /// Generates an ephemeral key with exactly the given permissions.
    ///
    /// Returns the Result rather than the guard: a guard cannot be
    /// default-constructed, so there is no inactive value to hand back on
    /// failure, and every caller has to check anyway.
    ///
    /// @param public_permissions Left unset to exercise the documented default
    ///        for the public half of an asymmetric key.
    static score::Result<CryptoResourceGuard> GenerateKey(
        IKeyManagementContext& key_mgmt,
        const std::string& algorithm,
        KeyOperationPermission permissions,
        std::optional<KeyOperationPermission> public_permissions = std::nullopt)
    {
        GenerateKeyParams params;
        params.SetAlgorithm(algorithm).SetPermissions(permissions);
        if (public_permissions.has_value())
        {
            params.SetPublicKeyPermissions(public_permissions.value());
        }

        // Generation itself is never permission-checked: the grant describes how
        // the key may later be used, so a kNone key must still be creatable.
        return key_mgmt.GenerateKey(params);
    }

    std::unique_ptr<ICryptoStack> m_stack;
    std::unique_ptr<ICryptoContext> m_ctx;
};

/// MAC cases, run once per provider that implements MAC.
class MacKeyPermissionTest : public KeyPermissionTest, public ::testing::WithParamInterface<ProviderType>
{
};

// =========================================================================
// Assertions
// =========================================================================

/// Asserts that a context creation failed specifically because the key policy
/// forbids the operation — not for some unrelated reason such as an unsupported
/// algorithm, which would make the test pass without testing anything.
template <typename ContextResult>
void ExpectNotPermitted(const ContextResult& result, const char* what)
{
    ASSERT_FALSE(result.has_value()) << what << " succeeded, but the key does not permit this operation";
    EXPECT_EQ(*result.error(), static_cast<score::result::ErrorCode>(CryptoErrorCode::kKeyOperationNotPermitted))
        << what << " failed with '" << result.error().Message() << "' instead of kKeyOperationNotPermitted";
}

// =========================================================================
// Context factories
// =========================================================================

auto MakeMacContext(ICryptoContext& ctx, const CryptoResourceGuard& key, ProviderType provider)
{
    MacContextConfig config;
    config.SetAlgorithm(kMacAlgorithm).SetKey(key).SetProviderType(provider);
    return ctx.CreateMacContext(config);
}

auto MakeCipherContext(ICryptoContext& ctx, const CryptoResourceGuard& key, CipherDirection direction)
{
    CipherContextConfig config;
    config.SetAlgorithm(kCipherAlgorithm).SetKey(key).SetDirection(direction).SetProviderType(kSoftwareProvider);
    return ctx.CreateCipherContext(config);
}

auto MakeSignContext(ICryptoContext& ctx, const CryptoResourceGuard& key)
{
    SignContextConfig config;
    config.SetAlgorithm(kEcSignatureAlgorithm).SetKey(key).SetProviderType(kSoftwareProvider);
    return ctx.CreateSignContext(config);
}

auto MakeVerifyContext(ICryptoContext& ctx, const CryptoResourceGuard& key)
{
    VerifySignatureContextConfig config;
    config.SetAlgorithm(kEcSignatureAlgorithm).SetKey(key).SetProviderType(kSoftwareProvider);
    return ctx.CreateVerifySignatureContext(config);
}

// =========================================================================
// MAC — run against every provider that implements it
// =========================================================================

TEST_P(MacKeyPermissionTest, MacContextRequiresMacPermission)
{
    // This is the regression test for permissions never reaching the daemon:
    // read at the wrong width, the grant below decoded as "unset" and silently
    // became kAll, so the context was created and nothing was enforced.
    auto key_mgmt = MakeKeyMgmtContext(GetParam());
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kMacAlgorithm, kNotMac);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    ExpectNotPermitted(MakeMacContext(*m_ctx, key, GetParam()), "CreateMacContext with a key that lacks kMac");
}

TEST_P(MacKeyPermissionTest, MacContextAcceptsMacPermission)
{
    auto key_mgmt = MakeKeyMgmtContext(GetParam());
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kMacAlgorithm, KeyOperationPermission::kMac);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto mac_ctx = MakeMacContext(*m_ctx, key, GetParam());
    ASSERT_TRUE(mac_ctx.has_value()) << "CreateMacContext rejected a key that grants kMac";
}

TEST_P(MacKeyPermissionTest, MacContextRejectsKeyWithNoPermissions)
{
    auto key_mgmt = MakeKeyMgmtContext(GetParam());
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kMacAlgorithm, KeyOperationPermission::kNone);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    ExpectNotPermitted(MakeMacContext(*m_ctx, key, GetParam()), "CreateMacContext with a kNone key");
}

TEST_P(MacKeyPermissionTest, MacVerifyModeUsesTheSamePermissionAsGenerate)
{
    // Verifying a MAC means recomputing it, so kMac covers both directions and
    // there is no separate "verify MAC" grant to withhold. On PKCS#11 this is
    // also why BuildUsageFlags maps kMac to CKA_SIGN *and* CKA_VERIFY.
    auto key_mgmt = MakeKeyMgmtContext(GetParam());
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kMacAlgorithm, KeyOperationPermission::kMac);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    MacContextConfig config;
    config.SetAlgorithm(kMacAlgorithm).SetKey(key).SetProviderType(GetParam()).SetOperationMode(OperationMode::kVerify);

    auto mac_ctx = m_ctx->CreateMacContext(config);
    ASSERT_TRUE(mac_ctx.has_value()) << "A kMac key must serve a verify-mode MAC context too";
}

INSTANTIATE_TEST_SUITE_P(PerProvider,
                         MacKeyPermissionTest,
                         ::testing::ValuesIn(kMacProviders),
                         [](const testing::TestParamInfo<MacKeyPermissionTest::ParamType>& info) {
                             return (info.param == ProviderType::kSoftware) ? "SoftwareProvider" : "HardwareProvider";
                         });

// =========================================================================
// Cipher — the direction selects which permission is required
// =========================================================================

TEST_F(KeyPermissionTest, EncryptOnlyKeyCannotDecrypt)
{
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kCipherAlgorithm, KeyOperationPermission::kEncrypt);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto encrypt_ctx = MakeCipherContext(*m_ctx, key, CipherDirection::kEncrypt);
    ASSERT_TRUE(encrypt_ctx.has_value()) << "An encrypt-permitted key must produce an encryption context";

    ExpectNotPermitted(MakeCipherContext(*m_ctx, key, CipherDirection::kDecrypt),
                       "CreateCipherContext(kDecrypt) with an encrypt-only key");
}

TEST_F(KeyPermissionTest, DecryptOnlyKeyCannotEncrypt)
{
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kCipherAlgorithm, KeyOperationPermission::kDecrypt);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto decrypt_ctx = MakeCipherContext(*m_ctx, key, CipherDirection::kDecrypt);
    ASSERT_TRUE(decrypt_ctx.has_value()) << "A decrypt-permitted key must produce a decryption context";

    ExpectNotPermitted(MakeCipherContext(*m_ctx, key, CipherDirection::kEncrypt),
                       "CreateCipherContext(kEncrypt) with a decrypt-only key");
}

TEST_F(KeyPermissionTest, KeyGrantingBothDirectionsRoundTrips)
{
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result =
        GenerateKey(*key_mgmt, kCipherAlgorithm, KeyOperationPermission::kEncrypt | KeyOperationPermission::kDecrypt);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto encrypt_ctx = MakeCipherContext(*m_ctx, key, CipherDirection::kEncrypt);
    ASSERT_TRUE(encrypt_ctx.has_value());
    auto decrypt_ctx = MakeCipherContext(*m_ctx, key, CipherDirection::kDecrypt);
    ASSERT_TRUE(decrypt_ctx.has_value());

    // Both contexts over one key must still work together — enforcement must not
    // have introduced a per-key exclusivity that a round trip would hit.
    constexpr std::size_t kBlockSize = 16U;
    const std::vector<uint8_t> plaintext(64U, 0xA5U);
    const std::vector<uint8_t> iv(kBlockSize, 0x11U);

    // SingleShot takes the IV itself, so no separate Init() is needed. One extra
    // block of headroom covers the CBC padding block emitted on finalisation.
    std::vector<uint8_t> ciphertext(plaintext.size() + kBlockSize, 0U);
    auto encrypted = encrypt_ctx.value()->SingleShot(
        {iv.data(), iv.size()}, {plaintext.data(), plaintext.size()}, {ciphertext.data(), ciphertext.size()});
    ASSERT_TRUE(encrypted.has_value()) << "Encryption failed";
    ciphertext.resize(encrypted.value());

    std::vector<uint8_t> recovered(ciphertext.size() + kBlockSize, 0U);
    auto decrypted = decrypt_ctx.value()->SingleShot(
        {iv.data(), iv.size()}, {ciphertext.data(), ciphertext.size()}, {recovered.data(), recovered.size()});
    ASSERT_TRUE(decrypted.has_value()) << "Decryption failed";
    recovered.resize(decrypted.value());

    EXPECT_EQ(recovered, plaintext) << "Round trip through two permitted contexts did not recover the plaintext";
}

// =========================================================================
// ECDSA — the two halves of a key pair carry separate permissions
// =========================================================================

TEST_F(KeyPermissionTest, SigningRequiresSignPermissionOnThePrivateHalf)
{
    // kVerify on the private half is deliberately the wrong grant: signing
    // consumes the private key, so only kSign unlocks it.
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kVerify);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    ExpectNotPermitted(MakeSignContext(*m_ctx, key), "CreateSignContext with a key that lacks kSign");
}

TEST_F(KeyPermissionTest, SigningAcceptsSignPermission)
{
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kSign);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto sign_ctx = MakeSignContext(*m_ctx, key);
    ASSERT_TRUE(sign_ctx.has_value()) << "CreateSignContext rejected a key that grants kSign";
}

TEST_F(KeyPermissionTest, VerificationHonoursExplicitPublicHalfPermissions)
{
    // The private half may sign; the public half is narrowed to kEncrypt, which
    // does not include kVerify. Without the public/private split this would
    // wrongly consult the private half's kSign and reject nothing.
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result =
        GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kSign, KeyOperationPermission::kEncrypt);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto sign_ctx = MakeSignContext(*m_ctx, key);
    ASSERT_TRUE(sign_ctx.has_value()) << "Restricting the public half must not affect signing";

    ExpectNotPermitted(MakeVerifyContext(*m_ctx, key),
                       "CreateVerifySignatureContext with a public half that lacks kVerify");
}

TEST_F(KeyPermissionTest, VerificationAcceptsExplicitVerifyOnThePublicHalf)
{
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result =
        GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kSign, KeyOperationPermission::kVerify);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto sign_ctx = MakeSignContext(*m_ctx, key);
    ASSERT_TRUE(sign_ctx.has_value()) << "Sign context rejected despite kSign on the private half";
    auto verify_ctx = MakeVerifyContext(*m_ctx, key);
    ASSERT_TRUE(verify_ctx.has_value()) << "Verify context rejected despite kVerify on the public half";
}

TEST_F(KeyPermissionTest, PublicHalfDefaultsToUnrestricted)
{
    // Documented contract of GenerateKeyParams::public_key_permissions: omitting
    // it leaves the public half unrestricted, so a sign-only key still verifies.
    // A public key is public information, so this default protects nothing that
    // withholding kVerify would.
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kSign);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    auto verify_ctx = MakeVerifyContext(*m_ctx, key);
    ASSERT_TRUE(verify_ctx.has_value()) << "An unrestricted public half must permit verification";
}

TEST_F(KeyPermissionTest, PrivateHalfRestrictionDoesNotLeakIntoThePublicHalf)
{
    // kNone on the private half must not be read as "nothing at all works":
    // the public half was left unrestricted and is a separate grant.
    auto key_mgmt = MakeKeyMgmtContext(kSoftwareProvider);
    ASSERT_NE(key_mgmt, nullptr);

    auto key_result = GenerateKey(*key_mgmt, kEcKeyAlgorithm, KeyOperationPermission::kNone);
    ASSERT_TRUE(key_result.has_value()) << "GenerateKey failed";
    auto& key = key_result.value();

    ExpectNotPermitted(MakeSignContext(*m_ctx, key), "CreateSignContext with a kNone private half");

    auto verify_ctx = MakeVerifyContext(*m_ctx, key);
    ASSERT_TRUE(verify_ctx.has_value()) << "The public half was not restricted, so verification must be permitted";
}

// =========================================================================
// Configured key slots — the slot's allowed_operations is the grant
// =========================================================================

/// One provider's pair of slots over the same key material.
///
/// The two slots deploy identical key material and differ only in
/// allowed_operations, so a denial on the restricted one cannot be explained by
/// the key, the algorithm or the provider — only by the policy. Without the
/// permitted slot as a control, a test that broke slot loading outright would
/// still "pass".
struct SlotPolicyTestData
{
    const char* test_case_name;
    ProviderType provider;
    const char* mac_slot;        ///< allowed_operations = "MAC"
    const char* sign_only_slot;  ///< allowed_operations = "SIGN" — same key material
};

class SlotPolicyTest : public KeyPermissionTest, public ::testing::WithParamInterface<SlotPolicyTestData>
{
  protected:
    /// Resolves a configured slot by name and loads its key material.
    score::Result<CryptoResourceGuard> LoadSlotKey(IKeyManagementContext& key_mgmt, const char* slot_name)
    {
        auto slot = m_ctx->ResolveResource(slot_name, ResourceType::kKeySlot);
        EXPECT_TRUE(slot.has_value()) << "Failed to resolve key slot: " << slot_name;
        if (!slot.has_value())
        {
            return score::Result<CryptoResourceGuard>{score::unexpect, slot.error()};
        }
        return key_mgmt.LoadKey(slot.value());
    }
};

TEST_P(SlotPolicyTest, SlotAllowedOperationsGovernsMacContext)
{
    const auto test_data = GetParam();

    auto key_mgmt = MakeKeyMgmtContext(test_data.provider);
    ASSERT_NE(key_mgmt, nullptr);

    // Control: the slot that grants MAC over this key material must work. This
    // is also what would fail if a slot handler dropped allowed_operations and
    // registered the key as kNone.
    {
        auto key_result = LoadSlotKey(*key_mgmt, test_data.mac_slot);
        ASSERT_TRUE(key_result.has_value()) << "Failed to load key from slot: " << test_data.mac_slot;
        auto& key = key_result.value();

        auto mac_ctx = MakeMacContext(*m_ctx, key, test_data.provider);
        ASSERT_TRUE(mac_ctx.has_value()) << "A slot granting MAC must produce a MAC context";
    }

    // Same key material, SIGN instead of MAC: loading still succeeds — the policy
    // governs use, not loading — and the MAC context is refused.
    {
        auto key_result = LoadSlotKey(*key_mgmt, test_data.sign_only_slot);
        ASSERT_TRUE(key_result.has_value())
            << "Loading a key from a slot must not depend on allowed_operations: " << test_data.sign_only_slot;
        auto& key = key_result.value();

        ExpectNotPermitted(MakeMacContext(*m_ctx, key, test_data.provider),
                           "CreateMacContext with a key from a slot restricted to SIGN");
    }
}

INSTANTIATE_TEST_SUITE_P(PerProvider,
                         SlotPolicyTest,
                         ::testing::Values(SlotPolicyTestData{"SoftwareProvider",
                                                              ProviderType::kSoftware,
                                                              "HMAC_SHA256_IntegrationTestKey_OpenSSL",
                                                              "HMAC_SHA256_SignOnlySlot_OpenSSL"},
                                           // Exercises the PKCS#11 token-object path, which registers
                                           // the slot policy separately from the file-backed one.
                                           SlotPolicyTestData{"HardwareProvider",
                                                              ProviderType::kHardware,
                                                              "HMAC_SHA256_IntegrationTestKey",
                                                              "HMAC_SHA256_SignOnlySlot"}),
                         [](const testing::TestParamInfo<SlotPolicyTest::ParamType>& info) {
                             return info.param.test_case_name;
                         });

// =========================================================================
// Keyless contexts
// =========================================================================

TEST_F(KeyPermissionTest, KeylessContextsAreUnaffected)
{
    // Hash and random bind no key, so there is no permission to check. This
    // guards the "no key permission required" branch of the enforcement path:
    // a mapping that fell through to a default grant would break these.
    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256").SetProviderType(kSoftwareProvider);
    auto hash_ctx = m_ctx->CreateHashContext(hash_config);
    EXPECT_TRUE(hash_ctx.has_value()) << "Hash context creation must not require a key permission";

    // No algorithm: the RNG context takes the provider's default generator.
    RandomContextConfig random_config;
    random_config.SetProviderType(kSoftwareProvider);
    auto random_ctx = m_ctx->CreateRandomContext(random_config);
    EXPECT_TRUE(random_ctx.has_value()) << "Random context creation must not require a key permission";
}

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
