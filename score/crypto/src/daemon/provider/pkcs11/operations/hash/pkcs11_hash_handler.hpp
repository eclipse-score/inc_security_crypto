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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_HANDLER_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_context.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_executor.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declaration: full definition not needed in the header -- only a pointer
// is stored.  pkcs11_hash_handler.cpp includes pkcs11_provider.hpp.
class Pkcs11Provider;

/// @brief Handler for PKCS#11 hash operations.
///
/// Each instance owns a dedicated PKCS#11 session acquired from the parent
/// Pkcs11Provider pool at construction and released on destruction.
/// This ensures fully independent concurrent streaming: two simultaneous
/// IHashContext operations each use their own session and never interfere.
///
/// kRequirements declares the session type and auth state needed by this
/// handler type so the factory and provider pool can allocate correctly.
class Pkcs11HashHandler final : public handler::Handler
{
  public:
    /// @brief Session and auth requirements for hash operations.
    ///
    /// Hash (digest) operations require no private key access -- a ReadOnly
    /// Public session is sufficient.  This is the least-privilege assignment.
    static constexpr Pkcs11HandlerRequirements kRequirements{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::Public};

    /// @brief Construct handler with executor, dedicated session, algorithm, and provider back-ref.
    /// @param executor  Owned executor for PKCS#11 API translation.
    /// @param session   Session handle acquired from the provider pool (non-owning reference).
    /// @param algorithm Algorithm ID (e.g., "SHA256").
    /// @param provider  Non-owning pointer to the parent provider for session release on destruction.
    explicit Pkcs11HashHandler(std::unique_ptr<Pkcs11HashExecutor> executor,
                               CK_SESSION_HANDLE session,
                               const common::AlgorithmId& algorithm,
                               Pkcs11Provider* provider);

    /// @brief Destructor: returns the dedicated session to the provider pool.
    ~Pkcs11HashHandler() override;

    Pkcs11HashHandler(const Pkcs11HashHandler&) = delete;
    Pkcs11HashHandler& operator=(const Pkcs11HashHandler&) = delete;
    Pkcs11HashHandler(Pkcs11HashHandler&&) = delete;
    Pkcs11HashHandler& operator=(Pkcs11HashHandler&&) = delete;

    // --- Handler interface ---
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operationId,
        common::RequestParameters& request) override;

    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Reset() override;

    /// @brief Returns a static handler configuration for PKCS#11 hash.
    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Map algorithm ID string to CK_MECHANISM_TYPE.
    [[nodiscard]] static CK_MECHANISM_TYPE MapAlgorithm(std::string_view algorithm) noexcept;

    /// @brief Return the digest output size for the current algorithm.
    [[nodiscard]] std::uint64_t GetDigestSize() const noexcept;

    std::unique_ptr<Pkcs11HashExecutor> m_executor;
    Pkcs11HashExecutionContext m_ctx;  ///< stable per-context parameters for executor
    Pkcs11Provider* m_provider;        ///< Non-owning; used for ReleaseSession on destruction
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state;
    std::vector<std::uint8_t> m_outputBuffer;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_HANDLER_HPP
