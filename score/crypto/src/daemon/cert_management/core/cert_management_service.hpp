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
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/slot/cert_slot_manager.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/data_manager/data_node.hpp"
#include "score/crypto/src/daemon/data_manager/i_data_manager.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace score::crypto::daemon::cert_management
{
class CertEntry;

/// @brief A registered certificate data node and its associated instance.
struct RegisteredCert
{
    data_manager::DataNodeId node_id{};   ///< Client-scoped data-manager identifier for the certificate node.
    std::shared_ptr<CertEntry> instance;  ///< Certificate instance associated with the node.
};

/// @brief Certificate data and metadata for its associated CRL, when available.
struct ResolvedCertObjectWithCrlMetadata
{
    CertObject::Sptr cert;                                   ///< Parsed certificate object.
    std::optional<score::crypto::CrlMetadata> crl_metadata;  ///< Metadata for the associated CRL, if available.
};

/// @brief Registration context for creating a client-scoped certificate data node.
struct CertRegistrationParams
{
    /// Client that owns the certificate data node being registered.
    data_manager::ClientId client_id{0U};
    /// Parent data node under which the certificate node is created.
    data_manager::DataNodeId parent_id{0U};
    /// Source slot handle, or a default invalid handle for an ephemeral certificate.
    CertSlotHandle slot_handle{};
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

    /// @brief Register a parsed certificate as a client-visible data node.
    /// @param params Client, parent-node, and optional source-slot information for the registration.
    /// @param object Parsed certificate to register; must be non-null.
    /// @return The data-node identifier and registered certificate instance, or an error if registration fails.
    /// @note Thread safety: Concurrent calls create additional client-visible data nodes (within DataManager).
    score::crypto::Expected<RegisteredCert, common::DaemonErrorCode> RegisterCertificate(
        const CertRegistrationParams& params,
        CertObject::Sptr object);

    /// @brief Load a certificate from a slot and register it as a client-visible data node.
    ///
    /// Each successful call creates a client-visible data node.
    /// The parsed certificate value may be shared when the slot manager has it cached.
    /// @param params Client, parent-node, and source-slot information for the load.
    /// @return The data-node identifier and registered certificate instance, or an error if loading or registration
    /// fails.
    /// @note Thread safety: Concurrent calls create additional client-visible data nodes (within DataManager).
    /// Loads for the same slot are not serialized by this service.
    score::crypto::Expected<RegisteredCert, common::DaemonErrorCode> LoadCertificate(
        const CertRegistrationParams& params);

    /// @brief Delete a client's certificate data node.
    /// @param client_id Client that owns the node.
    /// @param node_id Identifier of the certificate data node to delete.
    /// @return An empty value on success, or kInvalidResourceId if the node is absent for the client or cannot be
    /// removed.
    /// @note Thread safety: Concurrent calls are safe.
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ReleaseCertificate(
        data_manager::ClientId client_id,
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

    /// @brief Get the read-only view of the certificate slot manager used by this service.
    /// @return Shared ownership handle to the read-only view, or an empty handle if none is configured.
    /// @note Thread safety: May be called concurrently after construction while the service remains alive.
    /// @note The view exposes the read operations only. Slot-content mutations go through this service's own
    /// UpdateSlot()/ClearSlot()/ClearSlotCrl(), which keep trust-store notification structural.
    ICertSlotManager::Sptr GetSlotManager() const
    {
        return m_slot_manager;
    }

    // -----------------------------------------------------------------------
    // Slot mutation — wraps CertSlotManager and notifies trust stores after each write that reaches the backend.
    // A write refused by the access check does not notify, because it cannot have changed stored content. Failed
    // backend writes still notify, because they can have partially changed it. Mirrors CertSlotManager's own
    // signatures; see its doc comments for parameter and error semantics.
    // -----------------------------------------------------------------------

    /// @brief Update a slot's certificate content and notify trust stores that reference it.
    /// @details Any CRL associated with the slot is discarded. Referencing trust stores are refreshed
    /// whenever the backend write may have changed the slot, including when the write reports an error.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @param cert Certificate content to store in the slot.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode>
    UpdateSlot(CertSlotHandle slot, data_manager::ClientId client_id, const CertObject& cert);

    /// @brief Clear a slot's certificate and notify trust stores that reference it.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlot(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    /// @brief Update a slot's CRL and refresh trust stores that reference the slot.
    /// @details Referencing trust stores are refreshed whenever the backend write may have changed the CRL, including
    /// when the write reports an error.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @param crl Encoded CRL bytes, encoding, and optional parsed metadata.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @details The bytes are stored without validation. The caller validates the CRL against the slot's issuer
    /// certificate (ICertParser::ValidateCrl) and supplies the resulting metadata.
    /// @note Thread safety: Writes to one slot are serialized by that slot's handler. Direct slot readers observe the
    /// new state once the write completes. Trust-store readers observe it only after trust-store notification
    /// completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode>
    UpdateSlot(CertSlotHandle slot, data_manager::ClientId client_id, const CrlData& crl);

    /// @brief Delete a slot's CRL and notify trust stores that reference the slot.
    /// @param slot Handle identifying the certificate slot.
    /// @param client_id Client performing the write.
    /// @return An empty value on success, or an error if the write fails or is not permitted.
    /// @note Thread safety: Slot writes are serialized by CertSlotManager. Direct slot readers observe the new state
    /// once the write completes. Trust-store readers observe it only after trust-store notification completes.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlotCrl(
        CertSlotHandle slot,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Resource resolution — called by mediator resource resolvers
    // -----------------------------------------------------------------------

    /// @brief Resolve an application certificate-slot resource name to a client-scoped data node.
    ///
    /// Creates or reuses the client's data node for the resolved slot.
    /// @param resource_name Application resource name identifying the certificate slot.
    /// @param client_id Client for whom the slot resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the resource cannot be resolved.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same slot repeatedly for one client
    /// reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveCertSlotNode(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    /// @brief Resolve a certificate slot handle to a client-scoped data node.
    /// @param slot_handle Registry handle identifying the certificate slot.
    /// @param client_id Client for whom the slot resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the handle is invalid or the node cannot be
    /// created.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same slot repeatedly for one client
    /// reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveCertSlotNode(
        CertSlotHandle slot_handle,
        data_manager::ClientId client_id);

    /// @brief Resolve an application trust-store resource name to a client-scoped data node.
    ///
    /// Creates or reuses the client's data node for the resolved trust store.
    /// @param resource_name Application resource name identifying the trust store.
    /// @param client_id Client for whom the trust-store resource is resolved.
    /// @return The client-scoped data-node identifier, or an error if the resource cannot be resolved.
    /// @note Thread safety: Concurrent resolutions are supported; resolving the same trust store repeatedly for one
    /// client reuses its resource node.
    score::crypto::Expected<data_manager::DataNodeId, common::DaemonErrorCode> ResolveTrustStoreNode(
        const std::string& resource_name,
        data_manager::ClientId client_id);

    // -----------------------------------------------------------------------
    // Operation helpers — called by the cert management executor
    // -----------------------------------------------------------------------

    /// @brief Resolve a certificate-slot data node to its slot handle.
    /// @param client_id Client that owns the data node.
    /// @param slot_node_id Identifier of the certificate-slot data node.
    /// @return The registered slot handle, or an error if the node cannot be resolved or its handle is invalid.
    score::crypto::Expected<CertSlotHandle, common::DaemonErrorCode> ResolveCertSlotHandle(
        data_manager::ClientId client_id,
        data_manager::DataNodeId slot_node_id);

    /// @brief Resolve a certificate or certificate-slot data node to a certificate object.
    ///
    /// Shares its implementation with ResolveCertObjectWithCrlMetadata() but skips that method's
    /// CRL-metadata lookup, which reads a slot's deployment descriptor from storage.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @return The parsed certificate object, or an error if resolution or loading fails.
    /// @note Thread safety: This service does not serialize slot loads; concurrent calls for the same slot may reach
    /// the slot backend concurrently.
    score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> ResolveCertObject(
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
    score::crypto::Expected<ResolvedCertObjectWithCrlMetadata, common::DaemonErrorCode>
    ResolveCertObjectWithCrlMetadata(data_manager::ClientId client_id, data_manager::DataNodeId cert_node_id);

    /// @brief Resolve a certificate data node to its registered instance.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate data node.
    /// @return The certificate instance, or an error if the node is not a valid certificate data node.
    /// @note Thread safety: The returned shared instance may outlive its data node; its mutable session state is
    /// synchronized internally.
    score::crypto::Expected<std::shared_ptr<CertEntry>, common::DaemonErrorCode> ResolveCertEntry(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// @brief Resolve CRL data associated with a certificate or certificate slot.
    ///
    /// A session-scoped CRL takes precedence over a persistent CRL on the backing
    /// slot. A certificate-slot node resolves its persistent CRL directly.
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @return The resolved CRL as an immutable shared snapshot, a null pointer if no CRL is available, or an error if
    /// resolution or loading fails. kInvalidResourceId is returned when the node is neither a certificate nor a
    /// certificate slot of the client.
    /// @note Thread safety: Session CRL data is obtained as a consistent snapshot from the certificate instance, and a
    /// persistent CRL as one snapshot from the slot manager. The service does not serialize CRL reads with concurrent
    /// slot updates; each read reflects the slot as of some point before the call returns.
    score::crypto::Expected<CrlData::Sptrc, common::DaemonErrorCode> ResolveCrlData(
        data_manager::ClientId client_id,
        data_manager::DataNodeId cert_node_id);

    /// @brief Resolve a trust-store data node to its registry handle.
    /// @param client_id Client that owns the data node.
    /// @param ts_node_id Identifier of the trust-store data node.
    /// @return The trust-store handle, or an error if the node cannot be resolved.
    /// @note Thread safety: Returns the trust-store handle stored in the resolved node; this method maintains no
    /// additional mutable service state.
    score::crypto::Expected<TrustStoreHandle, common::DaemonErrorCode> ResolveTrustStoreHandle(
        data_manager::ClientId client_id,
        data_manager::DataNodeId ts_node_id);

  private:
    /// @brief Notify trust stores that a member certificate slot has changed.
    /// @details Each referencing member's anchor and CRL entries are reloaded from the slot. A certificate write
    /// clears the slot's CRL, so the refreshed CRL entry is empty until a new CRL is imported. Called by the slot
    /// mutators after a successful write; it does not invalidate the slot manager's caches.
    /// @param slot_handle Handle identifying the certificate slot whose content changed.
    /// @note Thread safety: Concurrent notifications are not serialized by this service.
    void NotifySlotCertChanged(CertSlotHandle slot_handle);

    /// @brief Notify trust stores that the CRL of the given certificate slot has changed.
    /// @details Each referencing store refreshes the member's CRL from the slot's current CRL snapshot. Called by the
    /// slot mutators after a successful write.
    /// @param slot_handle Handle identifying the certificate slot whose CRL changed.
    /// @note Thread safety: Concurrent notifications are not serialized by this service.
    void NotifySlotCrlChanged(CertSlotHandle slot_handle);

    /// @brief Shared implementation for ResolveCertObject() and ResolveCertObjectWithCrlMetadata().
    /// @param client_id Client that owns the data node.
    /// @param cert_node_id Identifier of the certificate or certificate-slot data node.
    /// @param include_crl_metadata When false, skips the CRL-metadata lookup entirely; the result's crl_metadata is
    /// always an empty optional in that case. CRL-metadata lookups read a slot's deployment descriptor from storage,
    /// so callers that only need the certificate should pass false to avoid that cost.
    /// @return The parsed certificate and, if requested, its optional CRL metadata; or an error if resolution or
    /// loading fails.
    score::crypto::Expected<ResolvedCertObjectWithCrlMetadata, common::DaemonErrorCode>
    ResolveCertObjectWithOptionalCrlMetadata(data_manager::ClientId client_id,
                                             data_manager::DataNodeId cert_node_id,
                                             bool include_crl_metadata);

    /// Dependencies retained by resource nodes are declared before the DataManager reference so service teardown
    /// releases its DataManager reference before these dependencies.
    CertSlotRegistry::Sptr m_slot_registry;         ///< Resolves certificate slot handles and configurations.
    CertSlotManager::Sptr m_slot_manager;           ///< Performs certificate and CRL operations on slots.
    TrustStoreManager::Sptr m_trust_store_manager;  ///< Resolves trust stores and tracks their slot memberships.
    /// Shared with CertDataNodes so the registry stays alive while any node holds it, even after this service is
    /// destroyed.
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
