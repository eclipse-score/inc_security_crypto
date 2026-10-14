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
#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_MANAGEMENT_SERVICE_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CORE_CERT_MANAGEMENT_SERVICE_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/crypto/src/daemon/cert_management/core/cert_registry.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace score::crypto::daemon::cert_management
{
class CertEntry;

/// @brief Shared handle to a certificate instance managed by the certificate registry.
using CertInstance = std::shared_ptr<CertEntry>;

/// @brief Identifies a certificate data node and its associated instance.
struct CertDataNodeResult
{
    data_manager::DataNodeId node_id{};  ///< Client-scoped data-manager identifier for the certificate node.
    CertInstance instance;               ///< Certificate instance associated with the node.
};

/// @brief A certificate slot handle and a non-owning reference to its configuration.
///
/// The configuration is owned by CertSlotRegistry, populated during startup,
/// and immutable afterward. The reference remains valid while that registry
/// remains alive; this result does not extend the registry's lifetime.
struct ResolvedCertSlot
{
    CertSlotHandle handle;                                ///< Registry handle identifying the slot.
    std::reference_wrapper<const CertSlotConfig> config;  ///< Required non-owning reference to the slot configuration.
};

/// @brief Certificate data and metadata for its associated CRL, when available.
struct ResolvedCertWithCrlMetadata
{
    CertObject::Sptr cert;                                   ///< Parsed certificate object.
    std::optional<score::crypto::CrlMetadata> crl_metadata;  ///< Metadata for the associated CRL, if available.
};

/// @brief Coordinates certificate resources, registry entries, and slot operations.
///
/// @note Thread safety: Concurrent resource resolutions are supported. Other
/// operations are not globally serialized, and removing a resource does not
/// cancel work already using it. Before CleanupClient(), the lifecycle owner
/// must stop admitting operations for the client and drain its in-flight work.
class CertManagementService final
{
  public:
    /// @brief Shared ownership handle to a certificate management service.
    using Sptr = std::shared_ptr<CertManagementService>;

    /// @brief Construct a service with the managers used to resolve and operate on certificate resources.
    /// @param data_manager Stores client-scoped certificate and resource nodes.
    /// @param slot_registry Resolves certificate slot handles and configurations.
    /// @param trust_store_manager Resolves trust stores and updates their slot memberships.
    /// @param slot_manager Performs certificate and CRL operations on slots; may be empty when slot operations are
    /// unavailable.
    /// @note Thread safety: Publish the service to other threads only after construction has completed.
    CertManagementService(data_manager::IDataManager::Sptr data_manager,
                          CertSlotRegistry::Sptr slot_registry,
                          TrustStoreManager::Sptr trust_store_manager,
                          CertSlotManager::Sptr slot_manager = {});

    // -----------------------------------------------------------------------
    // Certificate lifecycle
    // -----------------------------------------------------------------------

    /// @brief Register a parsed certificate and create its client-scoped data node.
    /// @param params Client, parent-node, and optional source-slot information for the registration.
    /// @param object Parsed certificate to register; must be non-null.
    /// @return The data-node identifier and registered certificate instance, or an error if registration fails.
    /// @note Thread safety: Concurrent calls create and register independent certificate instances.
    score::crypto::Expected<CertDataNodeResult, common::DaemonErrorCode> RegisterCertMaterial(
        const CertRegistrationParams& params,
        CertObject::Sptr object);

    /// @brief Load a certificate from a slot and register it for a client.
    ///
    /// Each successful call creates a distinct certificate instance for the client.
    /// The parsed certificate value may be shared when the slot manager has it cached.
    /// @param params Client, parent-node, and source-slot information for the load.
    /// @return The data-node identifier and registered certificate instance, or an error if loading or registration
    /// fails.
    /// @note Thread safety: Concurrent calls create independent certificate instances. Loads for the same slot are
    /// not serialized by this service.
    score::crypto::Expected<CertDataNodeResult, common::DaemonErrorCode> Load(const CertRegistrationParams& params);

    /// @brief Delete a client's certificate data node.
    /// @param client_id Client that owns the node.
    /// @param node_id Identifier of the certificate data node to delete.
    /// @return An empty value on success, or kInvalidResourceId if the node is absent for the client or cannot be
    /// removed.
    /// @note Thread safety: Concurrent calls are safe.
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ReleaseCert(data_manager::ClientId client_id,
                                                                                 data_manager::DataNodeId node_id);

    /// @brief Remove cached certificate and trust-store state during client application teardown.
    /// @param client_id Client whose state is to be cleaned up.
    /// @note Daemon-side teardown sweep; it does not stop requests or delete the client's resource nodes. The caller
    /// must follow the class-level lifecycle ordering.
    void CleanupClient(data_manager::ClientId client_id);

    /// @brief Get the trust-store manager used by this service.
    /// @return Shared ownership handle to the manager, or an empty handle if none is configured.
    /// @note Thread safety: May be called concurrently after construction while the service remains alive.
    TrustStoreManager::Sptr GetTrustStoreManager() const
    {
        return m_trust_store_manager;
    }

    /// @brief Get the certificate slot manager used by this service.
    /// @return Shared ownership handle to the manager, or an empty handle if none is configured.
    /// @note Thread safety: May be called concurrently after construction while the service remains alive.
    /// @note Read-only slot operations (LoadCertificate, GetSlotInfo, HasCrl, GetCrlNextUpdate, ...) may be called
    /// directly on the returned manager. Slot-content mutations must go through this service's own
    /// StoreCertificate()/ClearSlot()/ImportCrl()/DeleteCrl() instead of calling the slot manager directly, so that
    /// trust-store notification happens structurally rather than depending on every caller remembering it.
    CertSlotManager::Sptr GetSlotManager() const
    {
        return m_slot_manager;
    }

    // -----------------------------------------------------------------------
    // Slot mutation — wraps CertSlotManager and notifies trust stores on success so
    // the pairing cannot be skipped by a caller. Mirrors CertSlotManager's own
    // signatures; see its doc comments for parameter and error semantics.
    // -----------------------------------------------------------------------

    /// @brief Store a certificate in a slot and notify trust stores that reference it.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @param cert Certificate to store.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode>
    StoreCertificate(CertSlotHandle slot, data_manager::ClientId client_id, const CertObject& cert);

    /// @brief Clear a slot's certificate and notify trust stores that reference it.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlot(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// @brief Store a slot's CRL and push it into trust stores that reference the slot.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @param crl_data Encoded CRL bytes.
    /// @param format Encoding of @p crl_data.
    /// @param metadata Optional parsed CRL metadata.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ImportCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id,
        score::crypto::span<const uint8_t> crl_data,
        score::crypto::FormatType format,
        std::optional<score::crypto::CrlMetadata> metadata = std::nullopt);

    /// @brief Delete a slot's CRL and notify trust stores that reference the slot.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> DeleteCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Resource resolution — called by mediator resource resolvers
    // -----------------------------------------------------------------------

    /// @brief Resolve an application certificate-slot resource name for a client.
    ///
    /// Creates or reuses the client's data node for the resolved slot.
    /// @param resource_name Application resource name identifying the certificate slot.
    /// @param client_id Client for whom the slot resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the resource cannot be resolved.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same slot repeatedly for one client
    /// reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveCertSlot(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    /// @brief Resolve a certificate slot handle to a client-scoped data node.
    /// @param slot_handle Registry handle identifying the certificate slot.
    /// @param client_id Client for whom the slot resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the handle is invalid or the node cannot be
    /// created.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same slot repeatedly for one client
    /// reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveCertSlot(
        CertSlotHandle slot_handle,
        data_manager::ClientId client_id);

    /// @brief Resolve an application trust-store resource name for a client.
    ///
    /// Creates or reuses the client's data node for the resolved trust store.
    /// @param resource_name Application resource name identifying the trust store.
    /// @param client_id Client for whom the trust-store resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the resource cannot be resolved.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same trust store repeatedly for one
    /// client reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveTrustStore(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Operation helpers — called by the cert management executor
    // -----------------------------------------------------------------------

    /// @brief Resolve a certificate-slot data node to its handle and configuration.
    /// @param client_id Client that owns the data node.
    /// @param slot_node_id Identifier of the certificate-slot data node.
    /// @return The slot handle and configuration reference, or an error if the node cannot be resolved.
    /// @note The result contains a non-owning reference to immutable slot configuration. It is valid only while the
    /// configuration registry remains alive.
    score::crypto::Expected<ResolvedCertSlot, common::DaemonErrorCode> ResolveSlotForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId slot_node_id);

    /// @brief Resolve a certificate or certificate-slot data node to a certificate object.
    ///
    /// Shares its implementation with ResolveCertWithCrlMetadataForOperation() but skips that method's
    /// CRL-metadata lookup, which reads a slot's deployment descriptor from storage.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @return The parsed certificate object, or an error if resolution or loading fails.
    /// @note Thread safety: This service does not serialize slot loads; concurrent calls for the same slot may reach
    /// the slot backend concurrently.
    score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> ResolveCertForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// @brief Resolve a certificate and metadata for its associated CRL.
    ///
    /// For a certificate instance, session CRL metadata takes precedence over metadata
    /// from its backing slot. For a slot node, metadata is read from that slot.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @return The parsed certificate and optional CRL metadata, or an error if resolution or loading fails.
    /// @note Thread safety: Certificate lookup and CRL-metadata lookup are separate operations. Session metadata is
    /// read using the certificate instance's internally synchronized accessor.
    score::crypto::Expected<ResolvedCertWithCrlMetadata, common::DaemonErrorCode>
    ResolveCertWithCrlMetadataForOperation(data_manager::ClientId client_id, data_manager::DataNodeId cert_node_id);

    /// @brief Resolve a certificate data node to its registered instance.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate data node.
    /// @return The certificate instance, or an error if the node is not a valid certificate data node.
    /// @note Thread safety: The returned shared instance may outlive its data node; its mutable session state is
    /// synchronized internally.
    score::crypto::Expected<CertInstance, common::DaemonErrorCode> ResolveCertInstanceForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// @brief Resolve CRL data associated with a certificate or certificate slot.
    ///
    /// A session-scoped CRL takes precedence over a persistent CRL on the backing
    /// slot. A certificate-slot node resolves its persistent CRL directly.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @return The resolved CRL, an empty optional if no CRL is available, or an error if resolution or loading fails.
    /// @note Thread safety: Session CRL data is obtained as a consistent snapshot from the certificate instance. The
    /// service does not serialize persistent CRL reads with concurrent slot updates.
    score::crypto::Expected<std::optional<CrlData>, common::DaemonErrorCode> ResolveCrlForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// @brief Resolve a trust-store data node to its registry handle.
    /// @param client_id Client that owns the data node.
    /// @param ts_node_id Identifier of the trust-store data node.
    /// @return The trust-store handle, or an error if the node cannot be resolved.
    /// @note Thread safety: Returns the trust-store handle stored in the resolved node; this method maintains no
    /// additional mutable service state.
    score::crypto::Expected<TrustStoreHandle, common::DaemonErrorCode> ResolveTrustStoreForOperation(
        data_manager::ClientId client_id,
        data_manager::DataNodeId ts_node_id);

    /// @brief Notify trust stores that a member certificate slot has changed.
    /// @details Each referencing member's anchor and CRL entries are reloaded from the slot. A certificate write
    /// clears the slot's CRL, so the refreshed CRL entry is empty until a new CRL is imported.
    /// @param slot_handle Handle identifying the certificate slot whose content changed.
    /// @note Thread safety: Concurrent notifications are not serialized by this service.
    void NotifySlotCertChanged(CertSlotHandle slot_handle);

    /// @brief Push an updated CRL to trust stores that reference the given certificate slot.
    /// @param slot_handle Handle identifying the certificate slot whose CRL changed.
    /// @param data The slot's new CRL, or an empty optional if the CRL was deleted.
    /// @note Thread safety: Concurrent notifications are not serialized by this service.
    void NotifySlotCrlChanged(CertSlotHandle slot_handle, const std::optional<CrlData>& data);

  private:
    /// @brief Shared implementation for ResolveCertForOperation() and ResolveCertWithCrlMetadataForOperation().
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @param include_crl_metadata When false, skips the CRL-metadata lookup entirely; the result's crl_metadata is
    /// always an empty optional in that case. CRL-metadata lookups read a slot's deployment descriptor from storage,
    /// so callers that only need the certificate should pass false to avoid that cost.
    /// @return The parsed certificate and, if requested, its optional CRL metadata; or an error if resolution or
    /// loading fails.
    score::crypto::Expected<ResolvedCertWithCrlMetadata, common::DaemonErrorCode> ResolveCertWithOptionalCrlMetadata(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id,
        bool include_crl_metadata);

    /// Dependencies retained by resource nodes are declared before the DataManager reference so service teardown
    /// releases its DataManager reference before these dependencies.
    CertSlotRegistry::Sptr m_slot_registry;         ///< Resolves certificate slot handles and configurations.
    CertSlotManager::Sptr m_slot_manager;           ///< Performs certificate and CRL operations on slots.
    TrustStoreManager::Sptr m_trust_store_manager;  ///< Resolves trust stores and tracks their slot memberships.
    /// Shared with CertDataNodes so registry callbacks remain valid if nodes outlive this service.
    CertRegistry::Sptr m_cert_registry{std::make_shared<CertRegistry>()};
    data_manager::IDataManager::Sptr m_data_manager;  ///< Owns and resolves client-scoped data nodes.

    std::mutex m_cert_slot_dedup_cache_mutex;  ///< Protects the certificate-slot node cache.
    /// Maps each client and canonical slot index to its certificate-slot data-node identifier.
    std::unordered_map<data_manager::ClientId, std::unordered_map<uint32_t, data_manager::DataNodeId>>
        m_cert_slot_dedup_cache;

    std::mutex m_trust_store_dedup_cache_mutex;  ///< Protects the trust-store node cache.
    /// Maps each client and canonical trust-store index to its trust-store data-node identifier.
    std::unordered_map<data_manager::ClientId, std::unordered_map<uint32_t, data_manager::DataNodeId>>
        m_trust_store_dedup_cache;
};
}  // namespace score::crypto::daemon::cert_management
#endif
