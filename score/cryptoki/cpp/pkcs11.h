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

/*
 * pkcs11.h — PKCS#11 v3.0 type definitions for LP64 (Linux x86-64).
 *
 * This header matches the Rust struct layout in src/pkcs11/types.rs
 * (CK_ULONG = unsigned long = 8 bytes on LP64).
 */

#ifndef PKCS11_H
#define PKCS11_H

#include <cstdint>
#include <cstddef>

/* ── Primitive type aliases ────────────────────────────────────────────── */

typedef uint8_t            CK_BYTE;
typedef uint8_t            CK_CHAR;
typedef uint8_t            CK_UTF8CHAR;
typedef CK_BYTE            CK_BBOOL;
typedef unsigned long      CK_ULONG;        /* 8 bytes on LP64 */
typedef long               CK_LONG;
typedef CK_ULONG           CK_FLAGS;
typedef CK_ULONG           CK_SLOT_ID;
typedef CK_ULONG           CK_SESSION_HANDLE;
typedef CK_ULONG           CK_OBJECT_HANDLE;
typedef CK_ULONG           CK_OBJECT_CLASS;
typedef CK_ULONG           CK_KEY_TYPE;
typedef CK_ULONG           CK_ATTRIBUTE_TYPE;
typedef CK_ULONG           CK_MECHANISM_TYPE;
typedef CK_ULONG           CK_RV;
typedef CK_ULONG           CK_NOTIFICATION;
typedef CK_ULONG           CK_USER_TYPE;
typedef CK_ULONG           CK_STATE;
typedef CK_ULONG           CK_PROFILE_ID;

typedef CK_BYTE*           CK_BYTE_PTR;
typedef CK_ULONG*          CK_ULONG_PTR;
typedef void*              CK_VOID_PTR;
typedef CK_UTF8CHAR*       CK_UTF8CHAR_PTR;
typedef CK_SLOT_ID*        CK_SLOT_ID_PTR;
typedef CK_OBJECT_HANDLE*  CK_OBJECT_HANDLE_PTR;
typedef CK_MECHANISM_TYPE* CK_MECHANISM_TYPE_PTR;

#define CK_TRUE   1
#define CK_FALSE  0
#define CK_UNAVAILABLE_INFORMATION  (~(CK_ULONG)0)
#define CK_INVALID_HANDLE           0

/* ── Structs ───────────────────────────────────────────────────────────── */

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION    cryptokiVersion;
    CK_UTF8CHAR   manufacturerID[32];
    CK_FLAGS      flags;
    CK_UTF8CHAR   libraryDescription[32];
    CK_VERSION    libraryVersion;
} CK_INFO;

typedef CK_INFO* CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR   slotDescription[64];
    CK_UTF8CHAR   manufacturerID[32];
    CK_FLAGS      flags;
    CK_VERSION    hardwareVersion;
    CK_VERSION    firmwareVersion;
} CK_SLOT_INFO;

typedef CK_SLOT_INFO* CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR   label[32];
    CK_UTF8CHAR   manufacturerID[32];
    CK_UTF8CHAR   model[16];
    CK_CHAR       serialNumber[16];
    CK_FLAGS      flags;
    CK_ULONG      ulMaxSessionCount;
    CK_ULONG      ulSessionCount;
    CK_ULONG      ulMaxRwSessionCount;
    CK_ULONG      ulRwSessionCount;
    CK_ULONG      ulMaxPinLen;
    CK_ULONG      ulMinPinLen;
    CK_ULONG      ulTotalPublicMemory;
    CK_ULONG      ulFreePublicMemory;
    CK_ULONG      ulTotalPrivateMemory;
    CK_ULONG      ulFreePrivateMemory;
    CK_VERSION    hardwareVersion;
    CK_VERSION    firmwareVersion;
    CK_CHAR       utcTime[16];
} CK_TOKEN_INFO;

typedef CK_TOKEN_INFO* CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID    slotID;
    CK_STATE      state;
    CK_FLAGS      flags;
    CK_ULONG      ulDeviceError;
} CK_SESSION_INFO;

typedef CK_SESSION_INFO* CK_SESSION_INFO_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;

typedef const CK_MECHANISM* CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG     ulMinKeySize;
    CK_ULONG     ulMaxKeySize;
    CK_FLAGS     flags;
} CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO* CK_MECHANISM_INFO_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE*       CK_ATTRIBUTE_PTR;
typedef const CK_ATTRIBUTE* CK_ATTRIBUTE_CONST_PTR;

/* ── Mechanism parameter structs ───────────────────────────────────────── */

typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE  cb[16];
} CK_AES_CTR_PARAMS;

typedef struct CK_GCM_PARAMS {
    const CK_BYTE* pIv;
    CK_ULONG       ulIvLen;
    CK_ULONG       ulIvBits;
    const CK_BYTE* pAAD;
    CK_ULONG       ulAADLen;
    CK_ULONG       ulTagBits;
} CK_GCM_PARAMS;

/* ── Callback / init args ──────────────────────────────────────────────── */

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR);
typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR*);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX   CreateMutex;
    CK_DESTROYMUTEX  DestroyMutex;
    CK_LOCKMUTEX     LockMutex;
    CK_UNLOCKMUTEX   UnlockMutex;
    CK_FLAGS         flags;
    CK_VOID_PTR      pReserved;
} CK_C_INITIALIZE_ARGS;

typedef CK_C_INITIALIZE_ARGS* CK_C_INITIALIZE_ARGS_PTR;

/* ── CK_FUNCTION_LIST (v2.40 compat) ──────────────────────────────────── */

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST* CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR* CK_FUNCTION_LIST_PTR_PTR;

struct CK_FUNCTION_LIST {
    CK_VERSION version;

    CK_RV (*C_Initialize)(CK_C_INITIALIZE_ARGS_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    CK_RV (*C_GetInfo)(CK_INFO_PTR);
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO_PTR);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);

    CK_RV (*C_InitToken)(CK_SLOT_ID, const CK_UTF8CHAR*, CK_ULONG, const CK_UTF8CHAR*);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, const CK_UTF8CHAR*, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, const CK_UTF8CHAR*, CK_ULONG, const CK_UTF8CHAR*, CK_ULONG);

    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, const CK_UTF8CHAR*, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);

    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);

    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_CONST_PTR, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);

    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, const CK_BYTE*, CK_ULONG, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_CONST_PTR, CK_ULONG, CK_OBJECT_HANDLE*);
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE, const CK_BYTE*, CK_ULONG);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE);
    CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE);
    CK_RV (*C_WaitForSlotEvent)(CK_FLAGS, CK_SLOT_ID*, CK_VOID_PTR);
};

/* ── CK_INTERFACE (v3.0) ──────────────────────────────────────────────── */

typedef struct CK_INTERFACE {
    const CK_CHAR* pInterfaceName;
    CK_VOID_PTR    pFunctionList;
    CK_FLAGS       flags;
} CK_INTERFACE;

typedef CK_INTERFACE* CK_INTERFACE_PTR;

/* ── Return codes (CKR_*) ──────────────────────────────────────────────── */

#define CKR_OK                           0x00000000UL
#define CKR_CANCEL                       0x00000001UL
#define CKR_HOST_MEMORY                  0x00000002UL
#define CKR_SLOT_ID_INVALID              0x00000003UL
#define CKR_GENERAL_ERROR                0x00000005UL
#define CKR_FUNCTION_FAILED              0x00000006UL
#define CKR_ARGUMENTS_BAD                0x00000007UL
#define CKR_ATTRIBUTE_READ_ONLY          0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE          0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID       0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID      0x00000013UL
#define CKR_DATA_INVALID                 0x00000020UL
#define CKR_DATA_LEN_RANGE               0x00000021UL
#define CKR_DEVICE_ERROR                 0x00000030UL
#define CKR_DEVICE_MEMORY                0x00000031UL
#define CKR_DEVICE_REMOVED               0x00000032UL
#define CKR_AEAD_DECRYPT_FAILED          0x00000035UL
#define CKR_ENCRYPTED_DATA_INVALID       0x00000040UL
#define CKR_FUNCTION_NOT_SUPPORTED       0x00000054UL
#define CKR_STATE_UNSAVEABLE             0x00000180UL
#define CKR_KEY_HANDLE_INVALID           0x00000060UL
#define CKR_KEY_SIZE_RANGE               0x00000062UL
#define CKR_KEY_INDIGESTIBLE             0x00000067UL
#define CKR_MECHANISM_INVALID            0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID      0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID        0x00000082UL
#define CKR_OPERATION_ACTIVE             0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED    0x00000091UL
#define CKR_PIN_INCORRECT                0x000000A0UL
#define CKR_PIN_LOCKED                   0x000000A4UL
#define CKR_SESSION_CLOSED               0x000000B0UL
#define CKR_SESSION_COUNT                0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID       0x000000B3UL
#define CKR_SESSION_READ_ONLY            0x000000B5UL
#define CKR_SIGNATURE_INVALID            0x000000C0UL
#define CKR_TEMPLATE_INCOMPLETE          0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT        0x000000D1UL
#define CKR_BUFFER_TOO_SMALL             0x00000150UL
#define CKR_USER_ALREADY_LOGGED_IN       0x00000100UL
#define CKR_USER_NOT_LOGGED_IN           0x00000101UL
#define CKR_TOKEN_NOT_PRESENT            0x000000E0UL
#define CKR_CRYPTOKI_NOT_INITIALIZED     0x00000190UL
#define CKR_TOKEN_NOT_RECOGNIZED         0x000000e1UL
#define CKF_TOKEN_INITIALIZED            0x00000400UL
#define CKR_TOKEN_WRITE_PROTECTED        0x000000E2UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_FUNCTION_REJECTED            0x00000200UL
#define CKR_OPERATION_CANCEL_FAILED      0x00000202UL

/* ── Mechanism types (CKM_*) ───────────────────────────────────────────── */

#define CKM_RSA_PKCS_KEY_PAIR_GEN       0x00000000UL
#define CKM_RSA_PKCS                    0x00000001UL
#define CKM_RSA_PKCS_OAEP               0x00000009UL
#define CKM_SHA256_RSA_PKCS             0x00000040UL
#define CKM_SHA384_RSA_PKCS             0x00000041UL
#define CKM_SHA512_RSA_PKCS             0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS         0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS         0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS         0x00000045UL
#define CKM_MD5                         0x00000210UL
#define CKM_SHA_1                       0x00000220UL
#define CKM_SHA256                      0x00000250UL
#define CKM_SHA256_HMAC                 0x00000251UL
#define CKM_SHA224                      0x00000255UL
#define CKM_SHA384                      0x00000260UL
#define CKM_SHA384_HMAC                 0x00000261UL
#define CKM_SHA512                      0x00000270UL
#define CKM_SHA512_HMAC                 0x00000271UL
#define CKM_SHA3_256                    0x000002B0UL
#define CKM_SHA3_384                    0x000002C0UL
#define CKM_SHA3_512                    0x000002D0UL
#define CKM_GENERIC_SECRET_KEY_GEN      0x00000350UL
#define CKM_EC_KEY_PAIR_GEN             0x00001040UL
#define CKM_ECDSA                       0x00001041UL
#define CKM_ECDSA_SHA256                0x00001043UL
#define CKM_ECDSA_SHA384                0x00001044UL
#define CKM_ECDSA_SHA512                0x00001045UL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN     0x00001055UL
#define CKM_EDDSA                       0x00001057UL
#define CKM_AES_KEY_GEN                 0x00001080UL
#define CKM_AES_CBC_PAD                 0x00001085UL
#define CKM_AES_CTR                     0x00001086UL
#define CKM_AES_GCM                     0x00001087UL
#define CKM_CHACHA20_POLY1305           0x00004021UL
#define CKM_CHACHA20_KEY_GEN            0x00004022UL
#define CKM_HKDF_DERIVE                 0x0000402AUL
#define CKM_HKDF_KEY_GEN                0x0000402CUL

/* ── Object classes (CKO_*) ────────────────────────────────────────────── */

#define CKO_DATA           0x00000000UL
#define CKO_CERTIFICATE    0x00000001UL
#define CKO_PUBLIC_KEY     0x00000002UL
#define CKO_PRIVATE_KEY    0x00000003UL
#define CKO_SECRET_KEY     0x00000004UL
#define CKO_PROFILE        0x00000009UL

/* ── Key types (CKK_*) ────────────────────────────────────────────────── */

#define CKK_RSA            0x00000000UL
#define CKK_EC             0x00000003UL
#define CKK_AES            0x0000001FUL
#define CKK_GENERIC_SECRET 0x00000010UL
#define CKK_CHACHA20       0x00000033UL
#define CKK_EC_EDWARDS     0x00000040UL
#define CKK_EC_MONTGOMERY  0x00000041UL

/* ── Attribute types (CKA_*) ───────────────────────────────────────────── */

#define CKA_CLASS             0x00000000UL
#define CKA_TOKEN             0x00000001UL
#define CKA_PRIVATE           0x00000002UL
#define CKA_LABEL             0x00000003UL
#define CKA_VALUE             0x00000011UL
#define CKA_ID                0x00000102UL
#define CKA_PRIVATE_EXPONENT  0x00000123UL
#define CKA_PRIME_1           0x00000124UL
#define CKA_PRIME_2           0x00000125UL
#define CKA_EXPONENT_1        0x00000126UL
#define CKA_EXPONENT_2        0x00000127UL
#define CKA_COEFFICIENT       0x00000128UL
#define CKA_UNIQUE_ID         0x0000010AUL
#define CKA_KEY_TYPE          0x00000100UL
#define CKA_SENSITIVE         0x00000103UL
#define CKA_ENCRYPT           0x00000104UL
#define CKA_DECRYPT           0x00000105UL
#define CKA_WRAP              0x00000106UL
#define CKA_UNWRAP            0x00000107UL
#define CKA_SIGN              0x00000108UL
#define CKA_VERIFY            0x00000109UL
#define CKA_DERIVE            0x0000010CUL
#define CKA_MODULUS           0x00000120UL
#define CKA_MODULUS_BITS      0x00000121UL
#define CKA_PUBLIC_EXPONENT   0x00000122UL
#define CKA_VALUE_LEN         0x00000161UL
#define CKA_EXTRACTABLE       0x00000162UL
#define CKA_COPYABLE          0x00000171UL
#define CKA_DESTROYABLE       0x00000172UL
#define CKA_EC_PARAMS         0x00000180UL
#define CKA_EC_POINT          0x00000181UL
#define CKA_PROFILE_ID        0x00000601UL

/* ── Flags (CKF_*) ────────────────────────────────────────────────────── */

#define CKF_TOKEN_PRESENT     0x00000001UL
#define CKF_RNG               0x00000001UL
#define CKF_LOGIN_REQUIRED    0x00000004UL
#define CKF_RW_SESSION        0x00000002UL
#define CKF_SERIAL_SESSION    0x00000004UL

/* ── User types (CKU_*) ───────────────────────────────────────────────── */

#define CKU_SO                0UL
#define CKU_USER              1UL
#define CKU_CONTEXT_SPECIFIC  2UL

/* ── Entry points ──────────────────────────────────────────────────────── */

extern "C" {
    CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
    CK_RV C_Finalize(CK_VOID_PTR pReserved);
    CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount);
    CK_RV C_GetInterface(const CK_UTF8CHAR* pInterfaceName, CK_VERSION* pVersion,
                          CK_INTERFACE_PTR* ppInterface, CK_FLAGS flags);
    CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags);
    CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                       const CK_UTF8CHAR* pPin, CK_ULONG ulPinLen,
                       const CK_UTF8CHAR* pUsername, CK_ULONG ulUsernameLen);
}

#endif /* PKCS11_H */
