#include "score/mw/crypto/api/common/types.hpp"
#include "score/mw/crypto/api/config/hash_context_config.hpp"
#include "score/mw/crypto/api/config/key_management_context_config.hpp"
#include "score/mw/crypto/api/config/mac_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_hash_context.hpp"
#include "score/mw/crypto/api/contexts/i_key_management_context.hpp"
#include "score/mw/crypto/api/contexts/i_mac_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace score::mw::crypto;

namespace {

void PrintHex(const char* label, const std::vector<std::uint8_t>& data)
{
    std::printf("%s (%zu bytes): ", label, data.size());
    for (auto b : data)
    {
        std::printf("%02x", static_cast<unsigned int>(b));
    }
    std::printf("\n");
}

int Fail(const char* msg)
{
    std::fprintf(stderr, "[FAIL] %s\n", msg);
    return 1;
}

}  // namespace

int main()
{
    const bool rust_mode = (std::getenv("USE_RUST_PKCS11") != nullptr);
    std::printf("[INFO] Starting Valeo PKCS#11 daemon demo client\n");
    std::printf("[INFO] USE_RUST_PKCS11=%s\n", rust_mode ? "1" : "0");
    std::printf("[INFO] endpoint=unix:///tmp/crypto_daemon.sock\n");

    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///tmp/crypto_daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    if (!stack_result.has_value())
    {
        return Fail("CreateCryptoStack failed (daemon not reachable?)");
    }
    auto& stack = stack_result.value();
    std::printf("[OK] Connected to daemon\n");

    auto ctx_result = stack->CreateCryptoContext();
    if (!ctx_result.has_value())
    {
        return Fail("CreateCryptoContext failed");
    }
    auto& ctx = ctx_result.value();
    std::printf("[OK] Created crypto context\n");

    // Demo 1: HASH on hardware provider.
    HashContextConfig hash_cfg;
    hash_cfg.SetAlgorithm("SHA256");
    hash_cfg.SetProviderType(ProviderType::kHardware);
    auto hash_result = ctx->CreateHashContext(hash_cfg);
    if (!hash_result.has_value())
    {
        return Fail("CreateHashContext(HARDWARE,SHA256) failed");
    }
    auto& hash = hash_result.value();

    const std::string hash_input = "valeo-cryptoki-daemon-demo";
    std::vector<std::uint8_t> digest(32U, 0U);
    auto hash_ss = hash->SingleShot(
        std::vector<std::uint8_t>(hash_input.begin(), hash_input.end()),
        digest);
    if (!hash_ss.has_value())
    {
        return Fail("Hash SingleShot failed");
    }
    std::printf("[OK] Hardware SHA256 succeeded\n");
    PrintHex("SHA256", digest);

    // Demo 2: MAC on hardware provider using our mapped key
    KeyManagementContextConfig km_cfg;
    auto km_result = ctx->CreateKeyManagementContext(km_cfg);
    if (!km_result.has_value())
    {
        return Fail("CreateKeyManagementContext failed");
    }
    auto& km = km_result.value();

    auto slot_result = ctx->ResolveResource("HMAC_SHA256_IntegrationTestKey_SoftHSM", ResourceType::kKeySlot);
    if (!slot_result.has_value())
    {
        return Fail("ResolveResource for HMAC key failed");
    }

    auto key_result = km->LoadKey(slot_result.value());
    if (!key_result.has_value())
    {
        return Fail("LoadKey failed");
    }
    auto key = std::move(key_result.value());

    MacContextConfig mac_cfg;
    mac_cfg.SetKey(key);
    mac_cfg.SetAlgorithm("HMAC-SHA256");
    mac_cfg.SetOperationMode(OperationMode::kGenerate);
    mac_cfg.SetProviderType(ProviderType::kHardware);

    auto mac_result = ctx->CreateMacContext(mac_cfg);
    if (!mac_result.has_value())
    {
        return Fail("CreateMacContext(HARDWARE,HMAC-SHA256) failed");
    }
    auto& mac = mac_result.value();

    if (!mac->Init().has_value())
    {
        return Fail("MAC Init failed");
    }

    if (!mac->Update(std::vector<std::uint8_t>(hash_input.begin(), hash_input.end())).has_value())
    {
        return Fail("MAC Update failed");
    }

    std::vector<std::uint8_t> signature(32U, 0U);
    auto mac_finalize = mac->Finalize(signature);
    
    if (!mac_finalize.has_value())
    {
        return Fail("MAC Finalize failed");
    }
    std::printf("[OK] Hardware HMAC-SHA256 Generate succeeded\n");
    PrintHex("MAC", signature);

    std::printf("[DONE] Demo client finished successfully\n");
    return 0;
}
