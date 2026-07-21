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

#ifndef SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_SRC_I_CERTIFICATE_MANAGEMENT_CONTEXT_IMPL_GUIDE_HPP
#define SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_SRC_I_CERTIFICATE_MANAGEMENT_CONTEXT_IMPL_GUIDE_HPP

/// @file
/// @brief Implementation guidance for concrete ICertificateManagementContext subclasses.
///
/// This is an **internal header** — not part of the public API. Include it
/// in the concrete implementation `.cpp` or internal `.hpp`, not in any
/// application-visible header.
///
/// ---
///
/// ## How extracted public key lifetime works
///
/// `LoadCertificatePublicKey()` extracts a certificate's public key into an
/// ephemeral key resource (kKey, kEphemeral). The daemon ref-counts this key:
///
/// | Event                                | Daemon action              |
/// |--------------------------------------|----------------------------|
/// | LoadCertificatePublicKey()           | Creates key, ref = 1       |
/// | CreateContext(config with key_id)    | Validates key, ref++       |
/// | Guard destroyed (Release IPC)        | ref--; free if ref == 0    |
/// | Context destroyed                    | ref-- for bound key        |
/// | Client disconnect / crash            | Bulk-free all client keys  |
///
/// ---
///
/// ## How to produce guards in LoadCertificatePublicKey()
///
/// Use `CryptoResourceGuardFactory::Make()` (defined in
/// `score/mw/crypto/api/common/src/crypto_resource_guard_factory.hpp`).
///
/// @code
///   #include "score/mw/crypto/api/common/src/crypto_resource_guard_factory.hpp"
///   #include "score/mw/crypto/api/common/src/i_release_callback.hpp"
///
///   class ConcreteCertContext : public score::mw::crypto::ICertificateManagementContext {
///   public:
///       score::Result<std::pair<score::mw::crypto::CryptoResourceGuard,
///                               score::mw::crypto::AlgorithmId>>
///       LoadCertificatePublicKey(const score::mw::crypto::CryptoResourceId& cert) override
///       {
///           // 1. Send ExtractPublicKey IPC to daemon, receive assigned key ID
///           score::mw::crypto::CryptoResourceId key_id = /* IPC result */;
///           score::mw::crypto::AlgorithmId alg = /* IPC result */;
///
///           // 2. ipc_release_cb_ is std::shared_ptr<IReleaseCallback>
///           auto guard = score::mw::crypto::CryptoResourceGuardFactory::Make(
///               ipc_release_cb_, key_id);
///           return std::make_pair(std::move(guard), alg);
///       }
///
///   private:
///       std::shared_ptr<score::mw::crypto::IReleaseCallback> ipc_release_cb_;
///   };
/// @endcode

#include "score/mw/crypto/api/common/src/crypto_resource_guard_factory.hpp"
#include "score/mw/crypto/api/common/src/i_release_callback.hpp"

#endif  // SCORE_MW_CRYPTO_API_FUTURE_CONTEXTS_SRC_I_CERTIFICATE_MANAGEMENT_CONTEXT_IMPL_GUIDE_HPP
