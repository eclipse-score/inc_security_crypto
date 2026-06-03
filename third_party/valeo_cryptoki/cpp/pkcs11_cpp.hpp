/**
 * @file pkcs11_cpp.hpp
 * @brief C++ RAII wrapper around the PKCS#11 v3.0 C API (dlopen-based).
 *
 * This header provides ergonomic, exception-safe C++ classes that wrap the
 * raw C API loaded via dlopen.  The Library class uses v3.0 interface
 * discovery (C_GetInterface) when available, falling back to the legacy
 * C_GetFunctionList for v2.40 modules.
 *
 * @example
 * @code{.cpp}
 * #include "pkcs11_cpp.hpp"
 *
 * int main() {
 *     using namespace pkcs11;
 *
 *     Library lib;                   // dlopen + C_Initialize
 *     Session session(lib, 0);       // opens R/W session on slot 0
 *     session.login("1234");
 *
 *     // RSA
 *     auto [pubKey, privKey] = session.generateRsaKeyPair(2048);
 *     std::vector<uint8_t> msg = {'H','e','l','l','o'};
 *     auto sig = session.sign(CKM_SHA256_RSA_PKCS, privKey, msg);
 *     session.verify(CKM_SHA256_RSA_PKCS, pubKey, msg, sig);
 *
 *     // EdDSA (v3.0)
 *     auto [edPub, edPriv] = session.generateEdKeyPair();
 *     auto edSig = session.sign(CKM_EDDSA, edPriv, msg);
 *     session.verify(CKM_EDDSA, edPub, msg, edSig);
 *
 *     // ChaCha20-Poly1305 (v3.0)
 *     auto chaKey = session.generateChaCha20Key();
 *     std::vector<uint8_t> nonce(12, 0x42);
 *     auto ct = session.encryptChaCha20Poly1305(chaKey, nonce, msg);
 *     auto pt = session.decryptChaCha20Poly1305(chaKey, nonce, ct);
 *
 *     // C_Finalize + dlclose called automatically.
 * }
 * @endcode
 */

#pragma once

#include "pkcs11.h"

#include <stdexcept>
#include <string>
#include <vector>
#include <utility>
#include <cstring>
#include <dlfcn.h>
#include <iostream>

namespace pkcs11 {

// ==========================================================================
// Exception
// ==========================================================================

/**
 * @brief Exception thrown for any non-CKR_OK return value.
 *
 * The `rv()` accessor returns the raw PKCS#11 return code so callers can
 * inspect the error programmatically.
 */
class Pkcs11Exception : public std::runtime_error {
public:
    explicit Pkcs11Exception(const std::string& func, CK_RV rv)
        : std::runtime_error(func + " failed: CKR 0x" + toHex(rv)),
          rv_(rv) {}

    /** The raw PKCS#11 return code. */
    CK_RV rv() const noexcept { return rv_; }

private:
    CK_RV rv_;

    static std::string toHex(CK_RV v) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%08lX", static_cast<unsigned long>(v));
        return buf;
    }
};

namespace detail {
inline void check(const char* func, CK_RV rv) {
    if (rv != CKR_OK) throw Pkcs11Exception(func, rv);
}
} // namespace detail

#define CK_CHECK(call) ::pkcs11::detail::check(#call, (call))

// ==========================================================================
// Library  (dlopen + C_Initialize / C_Finalize + dlclose)
// ==========================================================================

/**
 * @brief Owns the lifetime of the PKCS#11 library loaded via dlopen.
 *
 * Construct exactly one `Library` object per process.  The destructor calls
 * `C_Finalize` and `dlclose`.
 *
 * The constructor tries v3.0 interface discovery (`C_GetInterface`) first.
 * If the library doesn't export it, it falls back to `C_GetFunctionList`.
 */
class Library {
public:
    /**
     * @brief Load the PKCS#11 shared library and initialise it.
     *
     * Searches several common paths for libcryptoki.so.
     * @throws std::runtime_error if the library cannot be loaded.
     * @throws Pkcs11Exception if C_Initialize fails.
     */
    Library() : dlHandle_(nullptr), F_(nullptr), ownsInit_(false) {
        const char* paths[] = {
            "libcryptoki.so",                       // LD_LIBRARY_PATH
            "./target/release/libcryptoki.so",      // from project root
            "./target/debug/libcryptoki.so",        // from project root
            "../target/release/libcryptoki.so",     // from cpp/build/
            "../target/debug/libcryptoki.so",       // from cpp/build/
            "../../target/release/libcryptoki.so",  // from cpp/
            "../../target/debug/libcryptoki.so",    // from cpp/
            nullptr
        };

        for (int i = 0; paths[i]; i++) {
            dlHandle_ = dlopen(paths[i], RTLD_NOW);
            if (dlHandle_) {
                std::cout << "Successfully loaded: " << paths[i] << std::endl;
                break;
            }
        }
        if (!dlHandle_) {
            throw std::runtime_error(
                std::string("Failed to load libcryptoki.so: ") + dlerror() +
                "\nMake sure to run 'cargo build --release' first.");
        }

        // Try v3.0 interface discovery first
        using GetInterfaceFn = CK_RV (*)(const CK_UTF8CHAR*, CK_VERSION*,
                                          CK_INTERFACE_PTR*, CK_FLAGS);
        auto getInterface = reinterpret_cast<GetInterfaceFn>(
            dlsym(dlHandle_, "C_GetInterface"));

        if (getInterface) {
            CK_INTERFACE_PTR iface = nullptr;
            CK_RV rv = getInterface(nullptr, nullptr, &iface, 0);
            if (rv == CKR_OK && iface && iface->pFunctionList) {
                F_ = static_cast<CK_FUNCTION_LIST*>(iface->pFunctionList);
            }
        }

        // Fall back to legacy C_GetFunctionList
        if (!F_) {
            using GetFunctionListFn = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
            auto getFunctionList = reinterpret_cast<GetFunctionListFn>(
                dlsym(dlHandle_, "C_GetFunctionList"));
            if (!getFunctionList) {
                dlclose(dlHandle_);
                throw std::runtime_error("Neither C_GetInterface nor C_GetFunctionList found");
            }

            CK_RV rv = getFunctionList(&F_);
            if (rv != CKR_OK || !F_) {
                dlclose(dlHandle_);
                throw Pkcs11Exception("C_GetFunctionList", rv);
            }
        }

        CK_RV rv = F_->C_Initialize(nullptr);
        if (rv == CKR_OK) {
            ownsInit_ = true;
        } else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            dlclose(dlHandle_);
            throw Pkcs11Exception("C_Initialize", rv);
        }
    }

    ~Library() noexcept {
        if (F_ && ownsInit_) F_->C_Finalize(nullptr);
        if (dlHandle_) dlclose(dlHandle_);
    }

    // Non-copyable, non-movable
    Library(const Library&)            = delete;
    Library& operator=(const Library&) = delete;
    Library(Library&&)                 = delete;
    Library& operator=(Library&&)      = delete;

    /** @return The function list pointer (for direct C API access if needed). */
    CK_FUNCTION_LIST* functions() const noexcept { return F_; }

    /**
     * @brief Enumerate available slots.
     * @param tokenPresent If true, return only slots with a token present.
     * @return Vector of slot IDs.
     */
    std::vector<CK_SLOT_ID> getSlotList(bool tokenPresent = true) const {
        CK_ULONG count = 0;
        CK_CHECK(F_->C_GetSlotList(tokenPresent ? CK_TRUE : CK_FALSE, nullptr, &count));
        std::vector<CK_SLOT_ID> slots(count);
        CK_CHECK(F_->C_GetSlotList(tokenPresent ? CK_TRUE : CK_FALSE, slots.data(), &count));
        slots.resize(count);
        return slots;
    }

    /**
     * @brief Retrieve token information for a given slot.
     */
    CK_TOKEN_INFO getTokenInfo(CK_SLOT_ID slotId) const {
        CK_TOKEN_INFO info{};
        CK_CHECK(F_->C_GetTokenInfo(slotId, &info));
        return info;
    }

    // ------------------------------------------------------------------
    // Token management (v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Initialise the token in a given slot.
     * @param slotId   Slot containing the token to initialise.
     * @param soPin    Security Officer PIN.
     * @param label    Token label (padded/truncated to 32 bytes by the token).
     */
    void initToken(CK_SLOT_ID slotId, const std::string& soPin,
                   const std::string& label) {
        CK_CHECK(F_->C_InitToken(
            slotId,
            reinterpret_cast<const CK_UTF8CHAR*>(soPin.c_str()),
            static_cast<CK_ULONG>(soPin.size()),
            reinterpret_cast<const CK_UTF8CHAR*>(label.c_str())));
    }

private:
    void* dlHandle_;
    CK_FUNCTION_LIST* F_;
    bool ownsInit_;
};

// ==========================================================================
// Session
// ==========================================================================

/**
 * @brief RAII wrapper for a PKCS#11 session.
 *
 * The session is automatically closed when this object is destroyed.
 */
class Session {
public:
    /**
     * @brief Open a new session on @p slotId.
     * @param lib     The Library object (must outlive this Session).
     * @param slotId  The target slot identifier.
     * @param readWrite  If true (default), open an R/W session.
     */
    explicit Session(const Library& lib, CK_SLOT_ID slotId, bool readWrite = true)
        : F_(lib.functions()), handle_(0)
    {
        CK_FLAGS flags = CKF_SERIAL_SESSION;
        if (readWrite) flags |= CKF_RW_SESSION;
        CK_CHECK(F_->C_OpenSession(slotId, flags, nullptr, nullptr, &handle_));
    }

    ~Session() noexcept {
        if (handle_) F_->C_CloseSession(handle_);
    }

    // Non-copyable; movable
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    Session(Session&& other) noexcept : F_(other.F_), handle_(other.handle_) {
        other.handle_ = 0;
    }
    Session& operator=(Session&& other) noexcept {
        if (this != &other) {
            if (handle_) F_->C_CloseSession(handle_);
            F_            = other.F_;
            handle_       = other.handle_;
            other.handle_ = 0;
        }
        return *this;
    }

    /** @return The raw session handle. */
    CK_SESSION_HANDLE handle() const noexcept { return handle_; }

    // ------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------

    /**
     * @brief Log in as the normal user.
     * @param pin  User PIN string.
     */
    void login(const std::string& pin) {
        CK_CHECK(F_->C_Login(handle_, CKU_USER,
                              reinterpret_cast<const CK_UTF8CHAR*>(pin.c_str()),
                              static_cast<CK_ULONG>(pin.size())));
    }

    /** @brief Log out. */
    void logout() {
        CK_CHECK(F_->C_Logout(handle_));
    }

    // ------------------------------------------------------------------
    // Key Generation
    // ------------------------------------------------------------------

    /**
     * @brief Generate an RSA key pair.
     * @param modulusBits  RSA modulus size in bits (e.g. 2048, 4096).
     * @return {publicKeyHandle, privateKeyHandle}
     */
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>
    generateRsaKeyPair(CK_ULONG modulusBits = 2048) {
        CK_MECHANISM mech{ CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };

        CK_BYTE pubExp[] = { 0x01, 0x00, 0x01 };  // 65537
        CK_ATTRIBUTE pubTemplate[] = {
            { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
            { CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp) },
        };
        CK_ULONG pubCount = sizeof(pubTemplate) / sizeof(pubTemplate[0]);

        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_CHECK(F_->C_GenerateKeyPair(handle_, &mech,
                                        pubTemplate, pubCount,
                                        nullptr, 0,
                                        &hPub, &hPriv));
        return { hPub, hPriv };
    }

    /**
     * @brief Generate an EC key pair (P-256).
     * @return {publicKeyHandle, privateKeyHandle}
     */
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>
    generateEcKeyPair() {
        CK_MECHANISM mech{ CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
        CK_BYTE p256_oid[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        CK_ATTRIBUTE pubTemplate[] = {
            { CKA_EC_PARAMS, p256_oid, sizeof(p256_oid) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_CHECK(F_->C_GenerateKeyPair(handle_, &mech,
                                        pubTemplate, 1,
                                        nullptr, 0,
                                        &hPub, &hPriv));
        return { hPub, hPriv };
    }

    /**
     * @brief Generate an AES secret key.
     * @param keyLenBytes  Key length in bytes: 16, 24, or 32.
     */
    CK_OBJECT_HANDLE generateAesKey(CK_ULONG keyLenBytes = 32) {
        CK_MECHANISM mech{ CKM_AES_KEY_GEN, nullptr, 0 };
        CK_ATTRIBUTE tmpl[] = {
            { CKA_VALUE_LEN, &keyLenBytes, sizeof(keyLenBytes) },
        };
        CK_OBJECT_HANDLE hKey = 0;
        CK_CHECK(F_->C_GenerateKey(handle_, &mech, tmpl, 1, &hKey));
        return hKey;
    }

    // ------------------------------------------------------------------
    // Sign / Verify
    // ------------------------------------------------------------------

    /**
     * @brief Sign data with a private key.
     * @param mechanismType  e.g. CKM_SHA256_RSA_PKCS or CKM_ECDSA.
     * @param hPrivKey       Private key handle.
     * @param data           Data to sign.
     * @return Raw signature bytes.
     */
    std::vector<uint8_t> sign(CK_MECHANISM_TYPE   mechanismType,
                              CK_OBJECT_HANDLE    hPrivKey,
                              const std::vector<uint8_t>& data) {
        CK_MECHANISM mech{ mechanismType, nullptr, 0 };
        CK_CHECK(F_->C_SignInit(handle_, &mech, hPrivKey));

        // Allocate a generous buffer (512 bytes covers RSA-4096 and ECDSA).
        // C_Sign consumes the context even on a length query, so we avoid the
        // two-pass pattern which can fail for variable-length signatures (ECDSA).
        CK_ULONG sigLen = 512;
        std::vector<uint8_t> sig(sigLen);
        CK_CHECK(F_->C_Sign(handle_,
                             data.data(), static_cast<CK_ULONG>(data.size()),
                             sig.data(), &sigLen));
        sig.resize(sigLen);
        return sig;
    }

    /**
     * @brief Verify a signature.
     * @param mechanismType  Matching mechanism used for signing.
     * @param hPubKey        Public key handle.
     * @param data           Original data.
     * @param signature      Signature bytes.
     * @throws Pkcs11Exception with CKR_SIGNATURE_INVALID if verification fails.
     */
    void verify(CK_MECHANISM_TYPE   mechanismType,
                CK_OBJECT_HANDLE    hPubKey,
                const std::vector<uint8_t>& data,
                const std::vector<uint8_t>& signature) {
        CK_MECHANISM mech{ mechanismType, nullptr, 0 };
        CK_CHECK(F_->C_VerifyInit(handle_, &mech, hPubKey));
        CK_CHECK(F_->C_Verify(handle_,
                               data.data(),      static_cast<CK_ULONG>(data.size()),
                               signature.data(), static_cast<CK_ULONG>(signature.size())));
    }

    // ------------------------------------------------------------------
    // Encrypt / Decrypt (AES-GCM)
    // ------------------------------------------------------------------

    /**
     * @brief Encrypt data with AES-GCM.
     * @param hKey      AES key handle.
     * @param iv        Initialisation vector (12 bytes recommended).
     * @param plaintext Data to encrypt.
     * @param tagBits   Authentication tag length in bits (default 128).
     * @return Ciphertext || authentication tag.
     */
    std::vector<uint8_t> encryptAesGcm(CK_OBJECT_HANDLE hKey,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& plaintext,
                                        CK_ULONG tagBits = 128) {
        auto gcmParams = makeGcmParams(iv, tagBits);
        CK_MECHANISM mech{ CKM_AES_GCM, &gcmParams,
                           static_cast<CK_ULONG>(sizeof(gcmParams)) };

        CK_CHECK(F_->C_EncryptInit(handle_, &mech, hKey));

        CK_ULONG ctLen = static_cast<CK_ULONG>(plaintext.size()) + tagBits / 8;
        std::vector<uint8_t> ct(ctLen);
        CK_CHECK(F_->C_Encrypt(handle_,
                                plaintext.data(), static_cast<CK_ULONG>(plaintext.size()),
                                ct.data(), &ctLen));
        ct.resize(ctLen);
        return ct;
    }

    /**
     * @brief Decrypt data with AES-GCM.
     * @param hKey       AES key handle.
     * @param iv         Same IV used during encryption.
     * @param ciphertext Ciphertext || tag.
     * @param tagBits    Authentication tag length in bits (must match encryption).
     * @return Decrypted plaintext.
     * @throws Pkcs11Exception if authentication fails.
     */
    std::vector<uint8_t> decryptAesGcm(CK_OBJECT_HANDLE hKey,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& ciphertext,
                                        CK_ULONG tagBits = 128) {
        auto gcmParams = makeGcmParams(iv, tagBits);
        CK_MECHANISM mech{ CKM_AES_GCM, &gcmParams,
                           static_cast<CK_ULONG>(sizeof(gcmParams)) };

        CK_CHECK(F_->C_DecryptInit(handle_, &mech, hKey));

        CK_ULONG ptLen = static_cast<CK_ULONG>(ciphertext.size() + tagBits / 8);
        std::vector<uint8_t> pt(ptLen);
        CK_CHECK(F_->C_Decrypt(handle_,
                                ciphertext.data(), static_cast<CK_ULONG>(ciphertext.size()),
                                pt.data(), &ptLen));
        pt.resize(ptLen);
        return pt;
    }

    // ------------------------------------------------------------------
    // Encrypt / Decrypt (AES-CBC-PAD)
    // ------------------------------------------------------------------

    /**
     * @brief Encrypt data with AES-CBC-PAD.
     * @param hKey      AES key handle.
     * @param iv        Initialisation vector (16 bytes).
     * @param plaintext Data to encrypt.
     * @return Ciphertext with PKCS#7 padding.
     */
    std::vector<uint8_t> encryptAesCbc(CK_OBJECT_HANDLE hKey,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& plaintext) {
        CK_MECHANISM mech{ CKM_AES_CBC_PAD,
                           const_cast<CK_BYTE*>(iv.data()),
                           static_cast<CK_ULONG>(iv.size()) };

        CK_CHECK(F_->C_EncryptInit(handle_, &mech, hKey));

        CK_ULONG ctLen = static_cast<CK_ULONG>(plaintext.size()) + 16;
        std::vector<uint8_t> ct(ctLen);
        CK_CHECK(F_->C_Encrypt(handle_,
                                plaintext.data(), static_cast<CK_ULONG>(plaintext.size()),
                                ct.data(), &ctLen));
        ct.resize(ctLen);
        return ct;
    }

    /**
     * @brief Decrypt data with AES-CBC-PAD.
     * @param hKey       AES key handle.
     * @param iv         Same IV used during encryption (16 bytes).
     * @param ciphertext Ciphertext to decrypt.
     * @return Decrypted plaintext (padding removed).
     */
    std::vector<uint8_t> decryptAesCbc(CK_OBJECT_HANDLE hKey,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& ciphertext) {
        CK_MECHANISM mech{ CKM_AES_CBC_PAD,
                           const_cast<CK_BYTE*>(iv.data()),
                           static_cast<CK_ULONG>(iv.size()) };

        CK_CHECK(F_->C_DecryptInit(handle_, &mech, hKey));

        CK_ULONG ptLen = static_cast<CK_ULONG>(ciphertext.size());
        std::vector<uint8_t> pt(ptLen);
        CK_CHECK(F_->C_Decrypt(handle_,
                                ciphertext.data(), static_cast<CK_ULONG>(ciphertext.size()),
                                pt.data(), &ptLen));
        pt.resize(ptLen);
        return pt;
    }

    // ------------------------------------------------------------------
    // Encrypt / Decrypt (RSA-OAEP)
    // ------------------------------------------------------------------

    /**
     * @brief Encrypt data with RSA-OAEP.
     * @param hPubKey   RSA public key handle.
     * @param plaintext Data to encrypt.
     * @return Ciphertext.
     */
    std::vector<uint8_t> encryptRsaOaep(CK_OBJECT_HANDLE hPubKey,
                                         const std::vector<uint8_t>& plaintext) {
        CK_MECHANISM mech{ CKM_RSA_PKCS_OAEP, nullptr, 0 };
        CK_CHECK(F_->C_EncryptInit(handle_, &mech, hPubKey));

        std::vector<uint8_t> ct(512);
        CK_ULONG ctLen = static_cast<CK_ULONG>(ct.size());
        CK_CHECK(F_->C_Encrypt(handle_,
                                plaintext.data(), static_cast<CK_ULONG>(plaintext.size()),
                                ct.data(), &ctLen));
        ct.resize(ctLen);
        return ct;
    }

    /**
     * @brief Decrypt data with RSA-OAEP.
     * @param hPrivKey   RSA private key handle.
     * @param ciphertext Data to decrypt.
     * @return Decrypted plaintext.
     */
    std::vector<uint8_t> decryptRsaOaep(CK_OBJECT_HANDLE hPrivKey,
                                         const std::vector<uint8_t>& ciphertext) {
        CK_MECHANISM mech{ CKM_RSA_PKCS_OAEP, nullptr, 0 };
        CK_CHECK(F_->C_DecryptInit(handle_, &mech, hPrivKey));

        std::vector<uint8_t> pt(512);
        CK_ULONG ptLen = static_cast<CK_ULONG>(pt.size());
        CK_CHECK(F_->C_Decrypt(handle_,
                                ciphertext.data(), static_cast<CK_ULONG>(ciphertext.size()),
                                pt.data(), &ptLen));
        pt.resize(ptLen);
        return pt;
    }

    // ------------------------------------------------------------------
    // Digest
    // ------------------------------------------------------------------

    /**
     * @brief Compute a hash of `data`.
     * @param mechanismType  e.g. CKM_SHA256, CKM_SHA_1, CKM_MD5.
     * @param data           Input data.
     * @return Hash bytes.
     */
    std::vector<uint8_t> digest(CK_MECHANISM_TYPE mechanismType,
                                 const std::vector<uint8_t>& data) {
        CK_MECHANISM mech{ mechanismType, nullptr, 0 };
        CK_CHECK(F_->C_DigestInit(handle_, &mech));

        // 64 bytes covers SHA-512; no need for a two-pass size query.
        CK_ULONG hashLen = 64;
        std::vector<uint8_t> hash(hashLen);
        CK_CHECK(F_->C_Digest(handle_,
                               data.data(), static_cast<CK_ULONG>(data.size()),
                               hash.data(), &hashLen));
        hash.resize(hashLen);
        return hash;
    }

    // ------------------------------------------------------------------
    // Random
    // ------------------------------------------------------------------

    /**
     * @brief Generate `length` cryptographically strong random bytes.
     */
    std::vector<uint8_t> generateRandom(size_t length) {
        std::vector<uint8_t> buf(length);
        CK_CHECK(F_->C_GenerateRandom(handle_, buf.data(),
                                       static_cast<CK_ULONG>(length)));
        return buf;
    }

    // ------------------------------------------------------------------
    // EdDSA key generation (v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Generate an EdDSA key pair (Ed25519 by default).
     * @param curve  OID bytes for the curve. Defaults to Ed25519
     *               ({0x06, 0x03, 0x2b, 0x65, 0x70}).
     * @return {publicKeyHandle, privateKeyHandle}
     */
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>
    generateEdKeyPair(const std::vector<uint8_t>& curve = {0x06, 0x03, 0x2b, 0x65, 0x70}) {
        CK_MECHANISM mech{ CKM_EC_EDWARDS_KEY_PAIR_GEN, nullptr, 0 };
        CK_ATTRIBUTE pubTemplate[] = {
            { CKA_EC_PARAMS, const_cast<uint8_t*>(curve.data()),
              static_cast<CK_ULONG>(curve.size()) },
        };
        CK_OBJECT_HANDLE hPub = 0, hPriv = 0;
        CK_CHECK(F_->C_GenerateKeyPair(handle_, &mech,
                                        pubTemplate, 1,
                                        nullptr, 0,
                                        &hPub, &hPriv));
        return { hPub, hPriv };
    }

    // ------------------------------------------------------------------
    // ChaCha20 key generation (v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Generate a 256-bit ChaCha20 secret key.
     * @return Key object handle.
     */
    CK_OBJECT_HANDLE generateChaCha20Key() {
        CK_MECHANISM mech{ CKM_CHACHA20_KEY_GEN, nullptr, 0 };
        CK_OBJECT_HANDLE hKey = 0;
        CK_CHECK(F_->C_GenerateKey(handle_, &mech, nullptr, 0, &hKey));
        return hKey;
    }

    // ------------------------------------------------------------------
    // Encrypt / Decrypt (ChaCha20-Poly1305, v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Encrypt data with ChaCha20-Poly1305 AEAD.
     * @param hKey      ChaCha20 key handle.
     * @param nonce     12-byte nonce.
     * @param plaintext Data to encrypt.
     * @param aad       Additional authenticated data (optional).
     * @return Ciphertext || 16-byte authentication tag.
     */
    std::vector<uint8_t> encryptChaCha20Poly1305(
            CK_OBJECT_HANDLE hKey,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& aad = {}) {
        auto params = makeGcmParams(nonce, 128, aad);
        CK_MECHANISM mech{ CKM_CHACHA20_POLY1305, &params,
                           static_cast<CK_ULONG>(sizeof(params)) };

        CK_CHECK(F_->C_EncryptInit(handle_, &mech, hKey));

        CK_ULONG ctLen = static_cast<CK_ULONG>(plaintext.size()) + 16;
        std::vector<uint8_t> ct(ctLen);
        CK_CHECK(F_->C_Encrypt(handle_,
                                plaintext.data(), static_cast<CK_ULONG>(plaintext.size()),
                                ct.data(), &ctLen));
        ct.resize(ctLen);
        return ct;
    }

    /**
     * @brief Decrypt data with ChaCha20-Poly1305 AEAD.
     * @param hKey       ChaCha20 key handle.
     * @param nonce      Same 12-byte nonce used during encryption.
     * @param ciphertext Ciphertext || tag.
     * @param aad        Additional authenticated data (must match encryption).
     * @return Decrypted plaintext.
     * @throws Pkcs11Exception if authentication fails.
     */
    std::vector<uint8_t> decryptChaCha20Poly1305(
            CK_OBJECT_HANDLE hKey,
            const std::vector<uint8_t>& nonce,
            const std::vector<uint8_t>& ciphertext,
            const std::vector<uint8_t>& aad = {}) {
        auto params = makeGcmParams(nonce, 128, aad);
        CK_MECHANISM mech{ CKM_CHACHA20_POLY1305, &params,
                           static_cast<CK_ULONG>(sizeof(params)) };

        CK_CHECK(F_->C_DecryptInit(handle_, &mech, hKey));

        CK_ULONG ptLen = static_cast<CK_ULONG>(ciphertext.size());
        std::vector<uint8_t> pt(ptLen);
        CK_CHECK(F_->C_Decrypt(handle_,
                                ciphertext.data(), static_cast<CK_ULONG>(ciphertext.size()),
                                pt.data(), &ptLen));
        pt.resize(ptLen);
        return pt;
    }

    // ------------------------------------------------------------------
    // PIN management (v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Initialise the user PIN (requires SO login).
     * @param pin  The new user PIN.
     */
    void initPin(const std::string& pin) {
        CK_CHECK(F_->C_InitPIN(handle_,
                                reinterpret_cast<const CK_UTF8CHAR*>(pin.c_str()),
                                static_cast<CK_ULONG>(pin.size())));
    }

    /**
     * @brief Change the PIN of the currently logged-in user.
     * @param oldPin  Current PIN.
     * @param newPin  Desired new PIN.
     */
    void setPin(const std::string& oldPin, const std::string& newPin) {
        CK_CHECK(F_->C_SetPIN(handle_,
                               reinterpret_cast<const CK_UTF8CHAR*>(oldPin.c_str()),
                               static_cast<CK_ULONG>(oldPin.size()),
                               reinterpret_cast<const CK_UTF8CHAR*>(newPin.c_str()),
                               static_cast<CK_ULONG>(newPin.size())));
    }

    // ------------------------------------------------------------------
    // Session cancel (v3.0)
    // ------------------------------------------------------------------

    /**
     * @brief Cancel all active operations on this session.
     */
    void sessionCancel() {
        CK_CHECK(::C_SessionCancel(handle_, 0));
    }

    // ------------------------------------------------------------------
    // Object management
    // ------------------------------------------------------------------

    /**
     * @brief Find objects matching a template.
     * @param attrType   Attribute type to match (pass CKA_CLASS, etc.).
     * @param attrValue  Pointer to the attribute value.
     * @param attrLen    Length of the attribute value.
     * @return List of matching object handles.
     */
    std::vector<CK_OBJECT_HANDLE>
    findObjects(CK_ATTRIBUTE_TYPE attrType, void* attrValue, CK_ULONG attrLen) {
        CK_ATTRIBUTE tmpl{ attrType, attrValue, attrLen };
        return findObjectsImpl(&tmpl, 1);
    }

    /**
     * @brief Find all objects (empty template).
     */
    std::vector<CK_OBJECT_HANDLE> findAllObjects() {
        return findObjectsImpl(nullptr, 0);
    }

    /**
     * @brief Destroy an object.
     */
    void destroyObject(CK_OBJECT_HANDLE hObject) {
        CK_CHECK(F_->C_DestroyObject(handle_, hObject));
    }

private:
    CK_FUNCTION_LIST* F_;
    CK_SESSION_HANDLE handle_;

    std::vector<CK_OBJECT_HANDLE>
    findObjectsImpl(CK_ATTRIBUTE* pTemplate, CK_ULONG count) {
        CK_CHECK(F_->C_FindObjectsInit(handle_, pTemplate, count));
        std::vector<CK_OBJECT_HANDLE> results;
        CK_OBJECT_HANDLE batch[32];
        CK_ULONG found = 0;
        for (;;) {
            CK_CHECK(F_->C_FindObjects(handle_, batch, 32, &found));
            if (found == 0) break;
            results.insert(results.end(), batch, batch + found);
        }
        CK_CHECK(F_->C_FindObjectsFinal(handle_));
        return results;
    }

    static CK_GCM_PARAMS makeGcmParams(const std::vector<uint8_t>& iv,
                                         CK_ULONG tagBits,
                                         const std::vector<uint8_t>& aad = {}) {
        CK_GCM_PARAMS p{};
        p.pIv      = iv.data();
        p.ulIvLen  = static_cast<CK_ULONG>(iv.size());
        p.ulIvBits = static_cast<CK_ULONG>(iv.size() * 8);
        p.pAAD     = aad.empty() ? nullptr : aad.data();
        p.ulAADLen = static_cast<CK_ULONG>(aad.size());
        p.ulTagBits = tagBits;
        return p;
    }
};

} // namespace pkcs11
