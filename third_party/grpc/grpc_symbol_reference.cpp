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

// This file exists to work around a limitation when wrapping external libraries
// (like grpc) in cc_shared_library.
//
// Bazel's cc_shared_library expects libraries to use visibility attributes
// (__attribute__((visibility("default")))) or linker scripts to control symbol
// exports. However, grpc from Bazel Central Registry doesn't do this - it's
// designed for static linking where all symbols are naturally available.
//
// When we create a shared library from grpc++_unsecure, the linker only includes
// symbols that are directly referenced. Since our adapter code uses a limited
// subset of grpc APIs, many useful APIs (like ServerBuilder, CreateChannel) would
// be missing from the .so file, causing link errors in binaries.
//
// This helper file references commonly-used grpc APIs to ensure they're included
// in the shared library. The functions are never called (dead code eliminated at
// runtime) - they just create the references the linker needs.
//
// This approach is compiler-agnostic and doesn't rely on fragile mangled symbol names.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>

namespace score::crypto::ipc::internal
{

// Force inclusion of server-side symbols
void* ForceServerSymbols()
{
    // These will never be called, but create references the linker needs
    static bool initialized = false;
    if (initialized)
    {
        // Create references to server APIs
        grpc::ServerBuilder builder;
        builder.BuildAndStart();
    }
    return nullptr;
}

// Force inclusion of client-side symbols
void* ForceClientSymbols()
{
    static bool initialized = false;
    if (initialized)
    {
        // Create references to client APIs
        grpc::CreateChannel("", grpc::InsecureChannelCredentials());
        grpc::ClientContext context;
    }
    return nullptr;
}

}  // namespace score::crypto::ipc::internal
