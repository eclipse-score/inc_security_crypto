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

#include "score/mw/log/logging.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <dlfcn.h>

#include <pkcs11.h>
#include <pkcs11_lib_path.h>

/// @brief Dynamic loader for PKCS#11 modules
///
/// This helper encapsulates the dynamic loading of a PKCS#11 provider
/// (typically SoftHSM or a hardware-backed implementation). The loader:
///
/// - Determines the module path either from the Bazel‑generated
///   kPkcs11LibPath (pkcs11_lib) or, if enabled, the PKCS11_LIB_OVERRIDE
///   environment variable. The override exists strictly for debugging and
///   test scenarios.
/// - Loads the shared library via dlopen() with RTLD_NOW | RTLD_LOCAL to
///   ensure symbol resolution is strict and isolated.
/// - Retrieves the PKCS#11 function list through C_GetFunctionList and
///   exposes it to callers.
/// - Avoids dlclose(), because many PKCS#11 implementations maintain
///   global state or background threads that make unloading unsafe.
///
/// The loader is constructed once using thread-safe C++11 static
/// initialization. All callers obtain the same function list and return
/// code via C_GetFunctionList(), matching the PKCS#11 API contract.

struct Pkcs11Dynload {
public:
    Pkcs11Dynload();
    ~Pkcs11Dynload();
    Pkcs11Dynload(const Pkcs11Dynload&) = delete;
    Pkcs11Dynload& operator=(const Pkcs11Dynload&) = delete;
    Pkcs11Dynload(Pkcs11Dynload&&) = delete;
    Pkcs11Dynload& operator=(Pkcs11Dynload&&) = delete;
    CK_FUNCTION_LIST* getFunctionList() const { return functionList; }
    CK_RV getRv() const { return rv; }

private:
    /// @brief Resolve PKCS#11 module path
    ///
    /// The module path is generated at build time via `pkcs11_lib_path.h`,
    /// which defines `kPkcs11LibPath` based on the Bazel build setting
    /// `--define pkcs11_lib=...`.
    ///
    /// An optional environment override (`PKCS11_LIB_OVERRIDE`) may be enabled
    /// for testing. In normal builds, `kPkcs11LibPath` is the authoritative
    /// module location.
    std::string libPath{kPkcs11LibPath};
    void* pkcs11Handle{nullptr};
    CK_RV rv{CKR_GENERAL_ERROR};
    CK_FUNCTION_LIST* functionList{nullptr};
};

Pkcs11Dynload::Pkcs11Dynload(void)
{
    score::mw::log::LogInfo() << "PkcsDynload called";

#ifdef ALLOW_PKCS11_LIB_OVERRIDE
    // must be used for testing and debug purposes only
    const char* env = std::getenv("PKCS11_LIB_OVERRIDE");
    if (env && std::strlen(env)) libPath=env;
#endif

    score::mw::log::LogInfo() << "Loading pkcs11 module " << libPath;

    pkcs11Handle = dlopen(libPath.c_str(), RTLD_NOW|RTLD_LOCAL);
    if (pkcs11Handle == nullptr) {
        score::mw::log::LogError() << "Could not open PKCS#11 module " << libPath << " - " << std::string(dlerror());
        rv = CKR_LIBRARY_LOAD_FAILED;
	return;
    }

    using GetFunctionListFn = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
    GetFunctionListFn C_GetFunctionList = reinterpret_cast<GetFunctionListFn>(dlsym(pkcs11Handle, "C_GetFunctionList"));
    if (!C_GetFunctionList) {
         score::mw::log::LogError() << "Could not get function list";
         rv = CKR_FUNCTION_NOT_SUPPORTED;
         return;
    }

    rv = C_GetFunctionList(&functionList);
    if (rv != CKR_OK) {
         score::mw::log::LogError() << "Could not get function list";
         functionList = nullptr;
         return;
    }
}

Pkcs11Dynload::~Pkcs11Dynload(void)
{
    score::mw::log::LogInfo() << "~PkcsDynload called";
    // Never dlclose() a PKCS#11 module — many keep global state or threads alive and 
    // unloading causes undefined behavior.
}

/// @brief Singleton-style accessor for the PKCS#11 function list
///
/// This wrapper exposes the PKCS#11 C_GetFunctionList() entry point in a
/// thread-safe and initialization-safe manner. A local static instance of
/// Pkcs11Dynload is created on first invocation; C++11 guarantees that this
/// initialization is atomic and performed exactly once, even under concurrent
/// access.
///
/// The returned CK_FUNCTION_LIST pointer and CK_RV status originate from the
/// dynamically loaded PKCS#11 module.

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **functionList) noexcept
{
    // Thread-safe by C++11: local static initialization is guaranteed to be atomic and executed only once.
    static Pkcs11Dynload pkcs11Lib;
    assert(functionList != nullptr);
    *functionList = pkcs11Lib.getFunctionList();
    return pkcs11Lib.getRv();
}
