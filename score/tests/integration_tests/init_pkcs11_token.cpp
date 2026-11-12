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

/// @brief Standalone helper binary that initialises a PKCS#11 token via the raw
/// PKCS#11 C API.
///
/// Usage:
///   init_pkcs11_token --token-label <label> --so-pin <pin> --user-pin <pin>
///                     [--import-key-file <path> --import-key-label <label> [--import-key-type <type>]]
///
/// The binary:
///   1. Calls C_Initialize and queries available uninitialised slots.
///   2. Calls C_InitToken to format the token with the given label and SO PIN.
///   3. Logs in as Security Officer (SO) and sets the User PIN (C_InitPIN).
///   4. Imports initial test keys into the token (C_CreateObject).
///   5. Calls C_Finalize and exits 0 on success, non-zero on any failure.
///
/// Designed as a pure OASIS PKCS#11 provisioning CLI tool to run inside target
/// integration test containers, supporting both SoftHSM2 and Rust Cryptoki backends.
/// Target filesystem directories and backend environment variables (SOFTHSM2_CONF,
/// CRYPTOKI_STORE) are prepared externally by the test orchestrator prior to invocation.

#include <pkcs11.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace
{

/// Print a CK_RV in human-readable decimal form.
std::string FormatRv(CK_RV rv)
{
    return "CK_RV=" + std::to_string(static_cast<unsigned long>(rv));
}

struct Args
{
    std::string tokenLabel{"PKCS11_TOKEN"};
    std::string soPin{"12345678"};
    std::string userPin{"1234"};
    /// Key import entries: each triplet is (file_path, label, key_type).
    /// key_type is "generic" (CKK_GENERIC_SECRET) or "aes" (CKK_AES).
    std::vector<std::tuple<std::string, std::string, std::string>> importKeys;
};

Args ParseArgs(int argc, char** argv)
{
    Args args;
    for (int i = 1; i < argc - 1; ++i)
    {
        const std::string flag{argv[i]};
        const std::string value{argv[i + 1]};
        if (flag == "--token-label")
        {
            args.tokenLabel = value;
            ++i;
        }
        else if (flag == "--so-pin")
        {
            args.soPin = value;
            ++i;
        }
        else if (flag == "--user-pin")
        {
            args.userPin = value;
            ++i;
        }
        else if (flag == "--import-key-file")
        {
            // Expect --import-key-file <path> --import-key-label <label> [--import-key-type <type>]
            std::string file = value;
            std::string label;
            std::string keyType = "generic";
            ++i;
            while ((i + 1) < argc)
            {
                const std::string nextFlag{argv[i + 1]};
                if (nextFlag == "--import-key-label" && (i + 2) < argc)
                {
                    label = argv[i + 2];
                    i += 2;
                }
                else if (nextFlag == "--import-key-type" && (i + 2) < argc)
                {
                    keyType = argv[i + 2];
                    i += 2;
                }
                else
                {
                    break;
                }
            }
            if (!label.empty())
            {
                args.importKeys.emplace_back(file, label, keyType);
            }
        }
    }
    return args;
}

/// @brief Obtain the PKCS#11 function list and initialise the library.
/// @return Non-null pointer on success.
CK_FUNCTION_LIST_PTR InitializePkcs11Library()
{
    CK_FUNCTION_LIST_PTR fl{nullptr};
    CK_RV rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK || fl == nullptr)
    {
        throw std::runtime_error("C_GetFunctionList failed: " + FormatRv(rv));
    }

    rv = fl->C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        throw std::runtime_error("C_Initialize failed: " + FormatRv(rv));
    }
    return fl;
}

/// @brief Query the first uninitialised slot available in the token.
CK_SLOT_ID FindUninitialisedSlot(CK_FUNCTION_LIST_PTR fl)
{
    CK_ULONG slotCount{0U};
    CK_RV rv = fl->C_GetSlotList(CK_FALSE, nullptr, &slotCount);
    if (rv != CKR_OK || slotCount == 0U)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_GetSlotList (count) failed or no slots: " + FormatRv(rv));
    }

    std::vector<CK_SLOT_ID> slots(slotCount);
    rv = fl->C_GetSlotList(CK_FALSE, slots.data(), &slotCount);
    if (rv != CKR_OK)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_GetSlotList failed: " + FormatRv(rv));
    }
    return slots[0];
}

/// @brief Initialise the token, set the SO and user PINs.
/// @return The slot ID of the newly initialised token.
CK_SLOT_ID InitialiseTokenAndPin(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID slot, const Args& args)
{
    // Build a 32-char padded label as required by the PKCS#11 spec.
    std::string label = args.tokenLabel;
    label.resize(32U, ' ');
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* labelPtr = reinterpret_cast<CK_UTF8CHAR_PTR>(label.data());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* soPin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(args.soPin.c_str()));
    auto soPinLen = static_cast<CK_ULONG>(args.soPin.size());

    CK_RV rv = fl->C_InitToken(slot, soPin, soPinLen, labelPtr);
    if (rv != CKR_OK)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_InitToken failed: " + FormatRv(rv));
    }

    // After C_InitToken the slot ID may have changed; re-query with tokens present.
    CK_ULONG initedCount{0U};
    rv = fl->C_GetSlotList(CK_TRUE, nullptr, &initedCount);
    if (rv != CKR_OK || initedCount == 0U)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_GetSlotList (with token) failed after InitToken: " + FormatRv(rv));
    }
    std::vector<CK_SLOT_ID> initedSlots(initedCount);
    rv = fl->C_GetSlotList(CK_TRUE, initedSlots.data(), &initedCount);
    if (rv != CKR_OK)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_GetSlotList (filled) failed: " + FormatRv(rv));
    }
    const CK_SLOT_ID tokenSlot = initedSlots[0];

    // Open a RW session, login as SO, and set the user PIN.
    CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
    rv = fl->C_OpenSession(tokenSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
    if (rv != CKR_OK)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_OpenSession failed: " + FormatRv(rv));
    }

    rv = fl->C_Login(session, CKU_SO, soPin, soPinLen);
    if (rv != CKR_OK)
    {
        fl->C_CloseSession(session);
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_Login (SO) failed: " + FormatRv(rv));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* userPin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(args.userPin.c_str()));
    auto userPinLen = static_cast<CK_ULONG>(args.userPin.size());

    rv = fl->C_InitPIN(session, userPin, userPinLen);
    if (rv != CKR_OK)
    {
        fl->C_Logout(session);
        fl->C_CloseSession(session);
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_InitPIN failed: " + FormatRv(rv));
    }

    fl->C_Logout(session);
    fl->C_CloseSession(session);

    std::cout << "[init_pkcs11_token] Token '" << args.tokenLabel << "' initialised successfully (slot " << tokenSlot
              << ")\n";
    return tokenSlot;
}

/// @brief Import persistent secret keys from files into the token.
void ImportKeys(CK_FUNCTION_LIST_PTR fl, CK_SLOT_ID tokenSlot, const Args& args)
{
    if (args.importKeys.empty())
    {
        return;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto* userPin = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(args.userPin.c_str()));
    auto userPinLen = static_cast<CK_ULONG>(args.userPin.size());

    CK_SESSION_HANDLE importSession{CK_INVALID_HANDLE};
    CK_RV rv = fl->C_OpenSession(tokenSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &importSession);
    if (rv != CKR_OK)
    {
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_OpenSession for key import failed: " + FormatRv(rv));
    }

    rv = fl->C_Login(importSession, CKU_USER, userPin, userPinLen);
    if (rv != CKR_OK)
    {
        fl->C_CloseSession(importSession);
        fl->C_Finalize(nullptr);
        throw std::runtime_error("C_Login (User) for key import failed: " + FormatRv(rv));
    }

    for (const auto& [keyFile, keyLabel, keyType] : args.importKeys)
    {
        // Read raw key bytes from file.
        std::ifstream ifs(keyFile, std::ios::binary | std::ios::ate);
        if (!ifs)
        {
            fl->C_Logout(importSession);
            fl->C_CloseSession(importSession);
            fl->C_Finalize(nullptr);
            throw std::runtime_error("Cannot open key file: " + keyFile);
        }
        const auto fileSize = static_cast<std::size_t>(ifs.tellg());
        ifs.seekg(0);
        std::vector<unsigned char> keyData(fileSize);
        ifs.read(reinterpret_cast<char*>(keyData.data()), static_cast<std::streamsize>(fileSize));

        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_KEY_TYPE ckKeyType = CKK_GENERIC_SECRET;
        if (keyType == "aes")
        {
            ckKeyType = CKK_AES;
        }
        CK_BBOOL ckTrue = CK_TRUE;
        CK_BBOOL ckFalse = CK_FALSE;

        std::string labelCopy = keyLabel;

        CK_ATTRIBUTE tmpl[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_KEY_TYPE, &ckKeyType, sizeof(ckKeyType)},
            {CKA_TOKEN, &ckTrue, sizeof(CK_BBOOL)},
            {CKA_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &ckTrue, sizeof(CK_BBOOL)},
            {CKA_SIGN, &ckTrue, sizeof(CK_BBOOL)},
            {CKA_VERIFY, &ckTrue, sizeof(CK_BBOOL)},
            {CKA_VALUE, keyData.data(), static_cast<CK_ULONG>(keyData.size())},
            {CKA_LABEL, labelCopy.data(), static_cast<CK_ULONG>(labelCopy.size())},
        };

        CK_OBJECT_HANDLE obj{CK_INVALID_HANDLE};
        const CK_RV importRv = fl->C_CreateObject(importSession, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), &obj);
        if (importRv != CKR_OK)
        {
            fl->C_Logout(importSession);
            fl->C_CloseSession(importSession);
            fl->C_Finalize(nullptr);
            throw std::runtime_error("C_CreateObject failed for key '" + keyLabel + "': " + FormatRv(importRv));
        }
        std::cout << "[init_pkcs11_token] Imported key '" << keyLabel << "' from " << keyFile << " (object=" << obj
                  << ")\n";
    }

    fl->C_Logout(importSession);
    fl->C_CloseSession(importSession);
}

/// @brief Top-level token initialisation orchestrator.
void InitToken(const Args& args)
{
    CK_FUNCTION_LIST_PTR fl = InitializePkcs11Library();
    const CK_SLOT_ID slot = FindUninitialisedSlot(fl);
    const CK_SLOT_ID tokenSlot = InitialiseTokenAndPin(fl, slot, args);
    ImportKeys(fl, tokenSlot, args);
    fl->C_Finalize(nullptr);
}

}  // namespace

int main(int argc, char** argv)
{
    try
    {
        const Args args = ParseArgs(argc, argv);
        InitToken(args);
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[init_pkcs11_token] ERROR: " << ex.what() << "\n";
        return 1;
    }
}
