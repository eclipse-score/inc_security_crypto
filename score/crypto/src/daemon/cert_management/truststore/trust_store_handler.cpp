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
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/hex.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"

#include "score/mw/log/logging.h"

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace score::crypto::daemon::cert_management
{
namespace
{
using Error = common::DaemonErrorCode;

std::optional<std::array<uint8_t, score::crypto::kSha256FingerprintSize>> CopyFingerprint(
    score::crypto::span<const uint8_t> fingerprint)
{
    if (fingerprint.size() != score::crypto::kSha256FingerprintSize)
    {
        return std::nullopt;
    }

    std::array<uint8_t, score::crypto::kSha256FingerprintSize> copy{};
    std::copy(fingerprint.begin(), fingerprint.end(), copy.begin());
    return copy;
}

}  // namespace

TrustStoreHandler::TrustStoreHandler(TrustStoreHandle handle,
                                     TrustStoreConfig config,
                                     CertSlotRegistry::Sptr registry,
                                     CertSlotManager::Sptr slot_manager)
    : m_handle{handle},
      m_config{std::move(config)},
      m_registry{std::move(registry)},
      m_slot_manager{std::move(slot_manager)}
{
    m_valid = ValidateMembers() && LoadState();
}

TrustStoreHandle TrustStoreHandler::GetHandle() const noexcept
{
    return m_handle;
}

const TrustStoreConfig& TrustStoreHandler::GetConfig() const noexcept
{
    return m_config;
}

// ---------------------------------------------------------------------------
// Persisted member state
// ---------------------------------------------------------------------------

bool TrustStoreHandler::ValidateMembers() const
{
    // Without a registry, member names cannot be resolved, so there is nothing to check.
    if (!m_registry)
    {
        return true;
    }
    std::unordered_set<uint32_t> seen;
    bool valid = true;
    for (const auto& member : m_config.members)
    {
        const auto slot = m_registry->ResolveSlotInternal(member.slot_name);
        // An unknown name has no slot to trust. Skipping it would silently shrink the trust set.
        if (!slot.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "Trust store " << m_config.store_name << " lists member "
                                       << member.slot_name << ", which is not a configured certificate slot";
            valid = false;
            continue;
        }
        // A slot listed twice would be counted twice, so the configuration is refused.
        if (!seen.insert(slot.value().index).second)
        {
            score::mw::log::LogError() << kLogPrefix << "Trust store " << m_config.store_name << " lists member "
                                       << member.slot_name << " more than once";
            valid = false;
        }
    }
    // Reached after every member has been checked, so each error above is already logged.
    if (!valid)
    {
        score::mw::log::LogError() << kLogPrefix << "Trust store " << m_config.store_name
                                   << " is unavailable until its configuration is corrected";
    }
    return valid;
}

bool TrustStoreHandler::LoadState()
{
    // Nothing is persisted without a registry or a state path, so there is nothing to read.
    if (!m_registry || m_config.deployment_path.empty())
    {
        return true;
    }

    // An absent state file is the first run: members start from the configuration. A state file
    // that exists but cannot be used makes the store unavailable. Falling back to defaults would
    // enable members that were disabled, so a damaged state is never treated as an empty one.
    const auto exists = common::storage::FileExists(m_config.deployment_path);
    // Existence is unknown. Treating the file as absent would reset disabled members to enabled.
    if (!exists.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "The persisted state of trust store " << m_config.store_name
                                   << " cannot be located; the store is unavailable until it is repaired";
        return false;
    }
    // First run: no state has been written, so members keep their configured defaults.
    if (!exists.value())
    {
        return true;
    }

    const auto descriptor = DeploymentLoader::Load(m_config.deployment_path, m_config.deployment_format);
    // A file that exists but cannot be read is not an empty state, for the same reason as above.
    if (!descriptor.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "The persisted state of trust store " << m_config.store_name
                                   << " cannot be read; the store is unavailable until it is repaired";
        return false;
    }
    // A file without the state section holds no member state, so members keep their configured defaults.
    const std::string section_name{cert_section_names::kTrustStoreState};
    if (!descriptor.value().HasSection(section_name))
    {
        return true;
    }
    const auto& section = descriptor.value().GetSection(section_name);
    for (const auto& member : m_config.members)
    {
        const auto slot = m_registry->ResolveSlotInternal(member.slot_name);
        // ValidateMembers rejects unresolved members before this runs, so this is only a guard.
        if (!slot.has_value())
        {
            continue;
        }
        const auto prefix = std::string{"slot."} + member.slot_name + ".";
        const auto enabled = section.find(prefix + "enabled");
        const auto fingerprint = section.find(prefix + "accepted_fingerprint");
        if (enabled == section.end() && fingerprint == section.end())
        {
            // Not persisted yet, for example a member added by a configuration change.
            continue;
        }

        MemberState state;
        bool usable = true;
        if (enabled != section.end())
        {
            if (enabled->second == "true")
            {
                state.enabled = true;
            }
            else if (enabled->second == "false")
            {
                state.enabled = false;
            }
            else
            {
                usable = false;
            }
        }
        if (fingerprint != section.end())
        {
            const auto decoded = common::DecodeHex(fingerprint->second);
            if (decoded.has_value() && decoded.value().size() == score::crypto::kSha256FingerprintSize)
            {
                std::array<uint8_t, score::crypto::kSha256FingerprintSize> accepted{};
                std::copy(decoded.value().begin(), decoded.value().end(), accepted.begin());
                state.accepted_fingerprint = accepted;
            }
            else
            {
                usable = false;
            }
        }
        // A malformed value cannot be recovered without guessing, and a guess could re-enable a member.
        if (!usable)
        {
            score::mw::log::LogError() << kLogPrefix << "The persisted state of member " << member.slot_name
                                       << " in trust store " << m_config.store_name
                                       << " is malformed; the store is unavailable until it is repaired";
            return false;
        }
        m_states[slot.value().index] = state;
    }
    return true;
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::PersistStateLocked() const
{
    if (!m_registry || m_config.deployment_path.empty())
    {
        return std::monostate{};
    }
    common::storage::DeploymentDescriptor descriptor;
    const auto existing = DeploymentLoader::Load(m_config.deployment_path, m_config.deployment_format);
    if (existing.has_value())
    {
        descriptor = existing.value();
    }
    for (const auto& member : m_config.members)
    {
        const auto slot = m_registry->ResolveSlotInternal(member.slot_name);
        if (!slot.has_value())
        {
            continue;
        }
        const auto state_it = m_states.find(slot.value().index);
        if (state_it == m_states.end())
        {
            continue;
        }
        const auto& state = state_it->second;
        const auto prefix = std::string{"slot."} + member.slot_name + ".";
        descriptor.Set(
            std::string{cert_section_names::kTrustStoreState}, prefix + "enabled", state.enabled ? "true" : "false");
        if (state.accepted_fingerprint.has_value())
        {
            const auto& accepted = state.accepted_fingerprint.value();
            descriptor.Set(std::string{cert_section_names::kTrustStoreState},
                           prefix + "accepted_fingerprint",
                           common::EncodeHex(score::crypto::span<const uint8_t>{accepted.data(), accepted.size()}));
        }
    }
    return DeploymentWriter::Write(m_config.deployment_path, m_config.deployment_format, descriptor);
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::CommitStateLocked(CertSlotHandle slot,
                                                                                    const MemberState& next)
{
    const auto existing = m_states.find(slot.index);
    const std::optional<MemberState> previous =
        existing != m_states.end() ? std::optional<MemberState>{existing->second} : std::nullopt;

    m_states[slot.index] = next;
    const auto persisted = PersistStateLocked();
    if (!persisted.has_value())
    {
        // Restore the state that is on storage, so memory never runs ahead of it.
        if (previous.has_value())
        {
            m_states[slot.index] = previous.value();
        }
        else
        {
            m_states.erase(slot.index);
        }
        return score::crypto::make_unexpected(persisted.error());
    }
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Slot access helpers (m_mutex held)
// ---------------------------------------------------------------------------

std::optional<TrustStoreHandler::ResolvedMember> TrustStoreHandler::ResolveSlot(CertSlotHandle slot) const
{
    if (!m_registry || !m_slot_manager)
    {
        return std::nullopt;
    }
    const auto cfg = m_registry->GetConfig(slot);
    if (!cfg.has_value())
    {
        return std::nullopt;
    }
    // The returned handler is owned by CertSlotManager for the daemon lifetime, so the raw
    // pointer is valid for any call made here.
    auto* handler = m_slot_manager->GetTrustStoreCertSlotHandler(slot).get();
    if (handler == nullptr)
    {
        return std::nullopt;
    }
    return ResolvedMember{slot, handler, &cfg.value().get()};
}

std::optional<TrustStoreHandler::ResolvedMember> TrustStoreHandler::ResolveMember(
    const TrustStoreMemberConfig& member) const
{
    if (!m_registry)
    {
        return std::nullopt;
    }
    const auto slot = m_registry->ResolveSlotInternal(member.slot_name);
    if (!slot.has_value())
    {
        return std::nullopt;
    }
    return ResolveSlot(slot.value());
}

const TrustStoreMemberConfig* TrustStoreHandler::FindMember(CertSlotHandle slot) const
{
    if (!m_registry)
    {
        return nullptr;
    }
    for (const auto& member : m_config.members)
    {
        const auto member_slot = m_registry->ResolveSlotInternal(member.slot_name);
        if (member_slot.has_value() && member_slot.value() == slot)
        {
            return &member;
        }
    }
    return nullptr;
}

CertObject::Sptr TrustStoreHandler::LoadCertificateCached(CertSlotHandle slot)
{
    if (!m_slot_manager)
    {
        return nullptr;
    }
    auto loaded = m_slot_manager->LoadCertificateForTrustStore(slot);
    if (!loaded.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to load certificate for trust-store slot";
        return nullptr;
    }
    return std::move(loaded.value());
}

void TrustStoreHandler::InvalidateSlotCaches(CertSlotHandle slot)
{
    if (m_slot_manager)
    {
        m_slot_manager->InvalidateSlotCaches(slot);
    }
}

void TrustStoreHandler::InvalidateCrl(CertSlotHandle slot)
{
    if (m_slot_manager)
    {
        m_slot_manager->InvalidateCrl(slot);
    }
}

// ---------------------------------------------------------------------------
// Cache
//
// The cache exists only while the store is warm (m_loaded). LoadCache() builds it and
// ClearCache() drops it. Member mutations and slot notifications update it only while
// it is warm. A read on a store that is not warm resolves its members from the slot manager,
// returns the result, and does not cache it.
// ---------------------------------------------------------------------------

void TrustStoreHandler::SetAnchorLocked(CertSlotHandle slot, CertObject::Sptr cert)
{
    if (!m_loaded)
    {
        return;
    }
    if (cert)
    {
        m_slots[slot.index] = std::move(cert);
    }
    else
    {
        m_slots.erase(slot.index);
    }
}

void TrustStoreHandler::SetCrlLocked(CertSlotHandle slot, CrlData::Sptrc data)
{
    if (!m_loaded)
    {
        return;
    }
    if (data)
    {
        m_crls[slot.index] = std::move(data);
    }
    else
    {
        m_crls.erase(slot.index);
    }
}

void TrustStoreHandler::ClearCacheLocked()
{
    m_slots.clear();
    m_crls.clear();
    m_loaded = false;
}

std::vector<CertObject::Sptr> TrustStoreHandler::AnchorsLocked() const
{
    std::vector<CertObject::Sptr> all;
    all.reserve(m_slots.size());
    for (const auto& [slot, cert] : m_slots)
    {
        all.push_back(cert);
    }
    return all;
}

score::crypto::Expected<TrustStoreHandler::MemberContent, Error> TrustStoreHandler::ResolveMemberContentLocked(
    const TrustStoreMemberConfig& member,
    CertSlotHandle slot,
    bool& state_changed)
{
    MemberContent content;
    auto& state = m_states[slot.index];
    if (!state.enabled || !m_slot_manager)
    {
        return content;
    }

    auto loaded = m_slot_manager->LoadCertificateForTrustStore(slot);
    if (!loaded.has_value())
    {
        // An empty slot is a valid member state; any other failure is reported to the caller.
        if (loaded.error() == Error::kKeySlotEmpty || loaded.error() == Error::kResourceNotAllocated)
        {
            return content;
        }
        score::mw::log::LogError() << kLogPrefix << "Failed to load certificate for member " << member.slot_name
                                   << " of store " << m_config.store_name;
        return score::crypto::make_unexpected(loaded.error());
    }
    CertObject::Sptr cert = std::move(loaded.value());
    if (!cert)
    {
        return content;
    }

    if (member.kind == TrustStoreMemberKind::kConditionalExternal)
    {
        const auto fingerprint = cert->GetFingerprint();
        if (state.accepted_fingerprint.has_value())
        {
            const auto& accepted = state.accepted_fingerprint.value();
            const bool unchanged = fingerprint.size() == accepted.size() &&
                                   std::equal(fingerprint.begin(), fingerprint.end(), accepted.begin());
            if (!unchanged)
            {
                // Content changed without acknowledgement: disable for this store only.
                state.enabled = false;
                state_changed = true;
                score::mw::log::LogWarn()
                    << kLogPrefix << "Conditional slot " << member.slot_name << " fingerprint mismatch in store "
                    << m_config.store_name << ": disabled until acknowledged";
                return content;
            }
        }
        else if (m_config.conditional_slot_initialization == ConditionalSlotInitialization::kEnableAndAcceptCurrent)
        {
            state.accepted_fingerprint = CopyFingerprint(fingerprint);
            state_changed = true;
        }
        else
        {
            state.enabled = false;
            state_changed = true;
            return content;
        }
    }

    auto crl = m_slot_manager->LoadCrlDataForTrustStore(slot);
    if (!crl.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "Failed to load CRL for member " << member.slot_name << " of store "
                                   << m_config.store_name;
        return score::crypto::make_unexpected(crl.error());
    }
    content.anchor = std::move(cert);
    content.crl = std::move(crl.value());
    return content;
}

score::crypto::Expected<std::vector<std::pair<CertSlotHandle, TrustStoreHandler::MemberContent>>, Error>
TrustStoreHandler::ResolveAllLocked()
{
    std::vector<std::pair<CertSlotHandle, MemberContent>> all;
    bool state_changed = false;
    std::optional<Error> failure;
    if (m_registry)
    {
        for (const auto& member : m_config.members)
        {
            const auto slot = m_registry->ResolveSlotInternal(member.slot_name);
            if (!slot.has_value())
            {
                continue;
            }
            auto content = ResolveMemberContentLocked(member, slot.value(), state_changed);
            if (!content.has_value())
            {
                failure = content.error();
                break;
            }
            all.emplace_back(slot.value(), std::move(content.value()));
        }
    }
    // Conditional-member state changes are persisted whether or not a later member failed.
    if (state_changed)
    {
        const auto persisted = PersistStateLocked();
        if (!persisted.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "Failed to persist member state after resolving members";
        }
    }
    if (failure.has_value())
    {
        return score::crypto::make_unexpected(failure.value());
    }
    return all;
}

void TrustStoreHandler::RefreshMemberLocked(const TrustStoreMemberConfig& member,
                                            CertSlotHandle slot,
                                            bool& state_changed)
{
    auto content = ResolveMemberContentLocked(member, slot, state_changed);
    if (!content.has_value())
    {
        // The failure is logged by the resolution. Leave the store cold so that the next read
        // resolves every member again and reports the failure to its caller.
        ClearCacheLocked();
        return;
    }
    SetAnchorLocked(slot, std::move(content.value().anchor));
    SetCrlLocked(slot, std::move(content.value().crl));
}

void TrustStoreHandler::RefreshMemberCrlLocked(CertSlotHandle slot, bool usable)
{
    if (!m_loaded)
    {
        return;
    }
    CrlData::Sptrc entry;
    if (usable && m_slot_manager)
    {
        auto loaded = m_slot_manager->LoadCrlDataForTrustStore(slot);
        if (!loaded.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "Failed to load CRL for trust-store slot";
            ClearCacheLocked();
            return;
        }
        entry = std::move(loaded.value());
    }
    SetCrlLocked(slot, std::move(entry));
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::LoadCache()
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    if (m_loaded)
    {
        return std::monostate{};
    }

    auto all = ResolveAllLocked();
    if (!all.has_value())
    {
        return score::crypto::make_unexpected(all.error());
    }

    m_slots.clear();
    m_crls.clear();
    for (auto& [slot, content] : all.value())
    {
        if (content.anchor)
        {
            m_slots[slot.index] = std::move(content.anchor);
        }
        if (content.crl)
        {
            m_crls[slot.index] = std::move(content.crl);
        }
    }
    m_loaded = true;
    return std::monostate{};
}

void TrustStoreHandler::ClearCache()
{
    std::lock_guard lock(m_mutex);
    ClearCacheLocked();
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

score::crypto::Expected<std::vector<std::pair<CertSlotHandle, TrustStoreHandler::MemberContent>>, Error>
TrustStoreHandler::ResolveUnboundLocked()
{
    if (!m_unbound_read_logged)
    {
        m_unbound_read_logged = true;
        score::mw::log::LogWarn() << kLogPrefix << "Read on store " << m_config.store_name
                                  << " that is not bound to a client; the result is not cached";
    }
    return ResolveAllLocked();
}

score::crypto::Expected<std::vector<CertObject::Sptr>, Error> TrustStoreHandler::GetAnchors()
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    if (m_loaded)
    {
        return AnchorsLocked();
    }

    auto all = ResolveUnboundLocked();
    if (!all.has_value())
    {
        return score::crypto::make_unexpected(all.error());
    }
    std::vector<CertObject::Sptr> anchors;
    for (auto& [slot, content] : all.value())
    {
        if (content.anchor)
        {
            anchors.push_back(std::move(content.anchor));
        }
    }
    return anchors;
}

score::crypto::Expected<std::vector<CrlData::Sptrc>, Error> TrustStoreHandler::GetCrls()
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    std::vector<CrlData::Sptrc> result;
    if (m_loaded)
    {
        result.reserve(m_crls.size());
        for (const auto& [slot_index, entry] : m_crls)
        {
            result.push_back(entry);
        }
        return result;
    }

    auto all = ResolveUnboundLocked();
    if (!all.has_value())
    {
        return score::crypto::make_unexpected(all.error());
    }
    for (auto& [slot, content] : all.value())
    {
        if (content.crl)
        {
            result.push_back(std::move(content.crl));
        }
    }
    return result;
}

CertObject::Sptr TrustStoreHandler::FindBySubject(const std::string& subject)
{
    const auto anchors = GetAnchors();
    if (!anchors.has_value())
    {
        return nullptr;
    }
    for (const auto& cert : anchors.value())
    {
        if (cert->GetSubject() == subject)
        {
            return cert;
        }
    }
    return nullptr;
}

CertObject::Sptr TrustStoreHandler::FindBySkid(score::crypto::span<const uint8_t> skid)
{
    const auto anchors = GetAnchors();
    if (!anchors.has_value())
    {
        return nullptr;
    }
    for (const auto& cert : anchors.value())
    {
        if (cert->GetSkid().size() == skid.size() && std::equal(skid.begin(), skid.end(), cert->GetSkid().begin()))
        {
            return cert;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Slot change notification
// ---------------------------------------------------------------------------

bool TrustStoreHandler::AcceptedFingerprintMatchesLocked(CertSlotHandle slot)
{
    const auto& state = m_states[slot.index];
    if (!state.accepted_fingerprint.has_value())
    {
        return false;
    }
    const auto cert = LoadCertificateCached(slot);
    if (!cert)
    {
        return false;
    }
    const auto& fingerprint = cert->GetFingerprint();
    const auto& accepted = state.accepted_fingerprint.value();
    return fingerprint.size() == accepted.size() &&
           std::equal(fingerprint.begin(), fingerprint.end(), accepted.begin());
}

void TrustStoreHandler::OnSlotChanged(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return;
    }
    // Evict the slot so the member reload below reads fresh content.
    InvalidateSlotCaches(slot);

    bool state_changed = false;
    for (const auto& member : m_config.members)
    {
        if (!m_registry)
        {
            break;
        }
        const auto member_slot = m_registry->ResolveSlotInternal(member.slot_name);
        if (!member_slot.has_value() || !(member_slot.value() == slot))
        {
            continue;
        }

        if (member.kind == TrustStoreMemberKind::kConditionalExternal)
        {
            // Disable only on a content change. accepted_fingerprint is kept so that
            // AcknowledgeMemberUpdate compares the replacement against the last accepted value.
            if (!AcceptedFingerprintMatchesLocked(slot))
            {
                auto& state = m_states[slot.index];
                if (state.enabled)
                {
                    state.enabled = false;
                    state_changed = true;
                }
                SetAnchorLocked(slot, nullptr);
                SetCrlLocked(slot, nullptr);
            }
            else if (m_loaded)
            {
                RefreshMemberLocked(member, slot, state_changed);
            }
        }
        else if (m_loaded)
        {
            RefreshMemberLocked(member, slot, state_changed);
        }
    }

    if (state_changed)
    {
        const auto persisted = PersistStateLocked();
        if (!persisted.has_value())
        {
            score::mw::log::LogError() << kLogPrefix << "Failed to persist conditional member state after slot update";
        }
    }
}

void TrustStoreHandler::OnSlotCrlChanged(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    RefreshActiveMemberCrlLocked(slot);
}

void TrustStoreHandler::RefreshActiveMemberCrlLocked(CertSlotHandle slot)
{
    if (!m_loaded)
    {
        return;
    }
    RefreshMemberCrlLocked(slot, m_slots.count(slot.index) != 0U);
}

// ---------------------------------------------------------------------------
// Member mutations
// ---------------------------------------------------------------------------

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::AddMember(const CertObject::Sptr& cert,
                                                                            CrlData::Sptrc crl)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    const auto& cert_fp = cert->GetFingerprint();
    const bool has_crl = crl && !crl->bytes.empty();

    // Dedup: check all member types before consuming an exclusive slot.
    for (const auto& member : m_config.members)
    {
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value())
        {
            continue;
        }
        const auto& target = resolved.value();
        const auto current = target.handler->LoadCertificate(*target.cfg);
        if (!current.has_value())
        {
            if (current.error() == Error::kResourceNotAllocated || current.error() == Error::kKeySlotEmpty)
            {
                continue;
            }
            return score::crypto::make_unexpected(current.error());
        }
        const auto& current_fp = current.value()->GetFingerprint();
        if (current_fp.size() != cert_fp.size() || !std::equal(current_fp.begin(), current_fp.end(), cert_fp.begin()))
        {
            continue;
        }

        // Fingerprint match — cert is already a member.
        if (member.kind == TrustStoreMemberKind::kExclusiveMutable)
        {
            // Upsert CRL if provided — trust store owns this exclusive slot. A failed write may
            // still have changed the slot, so its CRL cache is dropped either way.
            if (has_crl)
            {
                const auto stored = target.handler->StoreCrl(*target.cfg, *crl);
                InvalidateCrl(target.slot);
                if (!stored.has_value())
                {
                    return score::crypto::make_unexpected(stored.error());
                }
                RefreshMemberCrlLocked(target.slot, true);
            }
            // Re-enable in case it was disabled: persist the state, then publish the anchor.
            auto next = m_states[target.slot.index];
            next.enabled = true;
            const auto committed = CommitStateLocked(target.slot, next);
            if (!committed.has_value())
            {
                return committed;
            }
            SetAnchorLocked(target.slot, cert);
            return std::monostate{};
        }

        // Shared-static or conditional-external: trust store does not own this slot.
        // CRL writes on externally-managed slots must go through ImportCrl directly.
        if (has_crl)
        {
            score::mw::log::LogError() << kLogPrefix << "AddMember: cannot write CRL to non-exclusive member "
                                       << member.slot_name << " of store " << m_config.store_name
                                       << "; use ImportCrl on the slot resource directly";
            return score::crypto::make_unexpected(Error::kUnsupportedOperation);
        }
        return std::monostate{};
    }

    // No fingerprint match — find an empty exclusive slot and store the cert.
    for (const auto& member : m_config.members)
    {
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
        {
            continue;
        }
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value())
        {
            continue;
        }
        const auto& target = resolved.value();
        const auto state = target.handler->GetSlotState(*target.cfg);
        if (!state.has_value() || state.value() != score::crypto::CertificateSlotState::kEmpty)
        {
            // Occupied by a different cert.
            continue;
        }

        // An error must leave nothing trusted: if a later step fails, the certificate stored
        // here is cleared again (best effort) so the slot is not left holding an anchor that
        // the caller was told was not added.
        const auto roll_back = [&] {
            static_cast<void>(target.handler->ClearSlot(*target.cfg));
            InvalidateSlotCaches(target.slot);
        };

        const auto stored = target.handler->StoreCertificate(*target.cfg, *cert);
        InvalidateSlotCaches(target.slot);
        if (!stored.has_value())
        {
            return score::crypto::make_unexpected(stored.error());
        }

        if (has_crl)
        {
            const auto crl_stored = target.handler->StoreCrl(*target.cfg, *crl);
            InvalidateCrl(target.slot);
            if (!crl_stored.has_value())
            {
                roll_back();
                return score::crypto::make_unexpected(crl_stored.error());
            }
        }

        auto next = m_states[target.slot.index];
        next.enabled = true;
        const auto committed = CommitStateLocked(target.slot, next);
        if (!committed.has_value())
        {
            roll_back();
            return committed;
        }
        RefreshMemberCrlLocked(target.slot, true);
        SetAnchorLocked(target.slot, cert);
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kTrustStoreCapacityExceeded);
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::StoreCrlForMember(CertSlotHandle slot,
                                                                                    const CrlData& crl)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    for (const auto& member : m_config.members)
    {
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value() || resolved.value().slot.index != slot.index)
        {
            continue;
        }
        const auto& target = resolved.value();
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
        {
            return score::crypto::make_unexpected(Error::kUnsupportedOperation);
        }
        const auto stored = target.handler->StoreCrl(*target.cfg, crl);
        InvalidateCrl(target.slot);
        if (!stored.has_value())
        {
            return score::crypto::make_unexpected(stored.error());
        }
        RefreshActiveMemberCrlLocked(target.slot);
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kInvalidResourceId);
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::ClearCrlForMember(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    for (const auto& member : m_config.members)
    {
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value() || resolved.value().slot.index != slot.index)
        {
            continue;
        }
        const auto& target = resolved.value();
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
        {
            return score::crypto::make_unexpected(Error::kUnsupportedOperation);
        }

        const auto cleared = target.handler->ClearCrl(*target.cfg);
        InvalidateCrl(target.slot);
        if (!cleared.has_value())
        {
            return score::crypto::make_unexpected(cleared.error());
        }
        SetCrlLocked(slot, nullptr);
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kInvalidResourceId);
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::RemoveMember(const std::vector<uint8_t>& fingerprint)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    for (const auto& member : m_config.members)
    {
        if (member.kind != TrustStoreMemberKind::kExclusiveMutable)
        {
            continue;
        }
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value())
        {
            continue;
        }
        const auto& target = resolved.value();
        const auto current = target.handler->LoadCertificate(*target.cfg);
        if (!current.has_value())
        {
            continue;
        }
        const auto& current_fp = current.value()->GetFingerprint();
        if (current_fp.size() != fingerprint.size() ||
            !std::equal(current_fp.begin(), current_fp.end(), fingerprint.begin()))
        {
            continue;
        }
        const auto cleared = target.handler->ClearSlot(*target.cfg);
        InvalidateSlotCaches(target.slot);
        if (!cleared.has_value())
        {
            return score::crypto::make_unexpected(cleared.error());
        }
        // The certificate is gone, so the anchor leaves the cache whether or not the member
        // state can be persisted. A trust reduction takes effect immediately.
        m_states[target.slot.index].enabled = false;
        SetAnchorLocked(target.slot, nullptr);
        SetCrlLocked(target.slot, nullptr);
        const auto persisted = PersistStateLocked();
        if (!persisted.has_value())
        {
            return score::crypto::make_unexpected(persisted.error());
        }
        return std::monostate{};
    }
    return score::crypto::make_unexpected(Error::kInvalidArgument);
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::EnableMember(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    const auto* member = FindMember(slot);
    if (member == nullptr)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    CertObject::Sptr cert;
    if (member->kind == TrustStoreMemberKind::kConditionalExternal)
    {
        const auto backend = ResolveSlot(slot);
        if (!backend.has_value())
        {
            return score::crypto::make_unexpected(Error::kInvalidResourceId);
        }
        const auto& target = backend.value();
        auto fresh_cert = target.handler->LoadCertificate(*target.cfg);
        if (!fresh_cert.has_value() || !fresh_cert.value())
        {
            return score::crypto::make_unexpected(Error::kInvalidOperation);
        }

        const auto fingerprint = fresh_cert.value()->GetFingerprint();
        const auto& accepted = m_states[slot.index].accepted_fingerprint;
        if (!accepted.has_value() || fingerprint.size() != accepted.value().size() ||
            !std::equal(fingerprint.begin(), fingerprint.end(), accepted.value().begin()))
        {
            return score::crypto::make_unexpected(Error::kInvalidOperation);
        }

        cert = std::move(fresh_cert.value());
        InvalidateSlotCaches(slot);
    }
    else
    {
        cert = LoadCertificateCached(slot);
    }

    // A trust increase is persisted before it is published.
    auto next = m_states[slot.index];
    next.enabled = true;
    const auto committed = CommitStateLocked(slot, next);
    if (!committed.has_value())
    {
        return committed;
    }
    SetAnchorLocked(slot, std::move(cert));
    return std::monostate{};
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::DisableMember(CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    if (FindMember(slot) == nullptr)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    // A trust reduction takes effect immediately. If the state cannot be persisted the member
    // stays disabled for this run and the error tells the caller it is not durable.
    m_states[slot.index].enabled = false;
    SetAnchorLocked(slot, nullptr);
    SetCrlLocked(slot, nullptr);
    const auto persisted = PersistStateLocked();
    if (!persisted.has_value())
    {
        return score::crypto::make_unexpected(persisted.error());
    }
    return std::monostate{};
}

score::crypto::Expected<std::monostate, Error> TrustStoreHandler::AcknowledgeMemberUpdate(
    CertSlotHandle slot,
    score::crypto::span<const uint8_t> expected_sha256_fingerprint)
{
    if (expected_sha256_fingerprint.size() != score::crypto::kSha256FingerprintSize)
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    std::lock_guard lock(m_mutex);
    if (!m_valid)
    {
        return score::crypto::make_unexpected(Error::kTrustStoreInvalid);
    }
    const auto* member = FindMember(slot);
    if (member == nullptr || member->kind != TrustStoreMemberKind::kConditionalExternal)
    {
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    }

    // Fresh load to capture the new cert.
    const auto resolved = ResolveSlot(slot);
    if (!resolved.has_value())
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }
    const auto& target = resolved.value();
    auto loaded = target.handler->LoadCertificate(*target.cfg);
    if (!loaded.has_value() || !loaded.value())
    {
        return score::crypto::make_unexpected(Error::kInvalidOperation);
    }
    auto cert = std::move(loaded.value());
    const auto fingerprint = cert->GetFingerprint();
    if (fingerprint.size() != expected_sha256_fingerprint.size() ||
        !std::equal(fingerprint.begin(), fingerprint.end(), expected_sha256_fingerprint.begin()))
    {
        return score::crypto::make_unexpected(Error::kInvalidOperation);
    }
    InvalidateSlotCaches(slot);

    // Accepting new content is a trust increase: persist before publishing.
    auto next = m_states[slot.index];
    next.accepted_fingerprint = CopyFingerprint(fingerprint);
    next.enabled = true;
    const auto committed = CommitStateLocked(slot, next);
    if (!committed.has_value())
    {
        return committed;
    }
    SetAnchorLocked(slot, cert);
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Member inspection
// ---------------------------------------------------------------------------

score::crypto::Expected<std::vector<CertSlotHandle>, Error> TrustStoreHandler::GetMemberSlotHandles()
{
    std::lock_guard lock(m_mutex);
    if (!m_registry)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }

    std::vector<CertSlotHandle> result;
    result.reserve(m_config.members.size());
    for (const auto& member : m_config.members)
    {
        const auto resolved = ResolveMember(member);
        if (!resolved.has_value())
        {
            continue;
        }
        const auto& target = resolved.value();
        const auto state = target.handler->GetSlotState(*target.cfg);
        if (!state.has_value() || state.value() != score::crypto::CertificateSlotState::kOccupied)
        {
            continue;
        }
        result.push_back(target.slot);
    }
    return result;
}

score::crypto::Expected<TrustStoreHandler::MemberSnapshot, Error> TrustStoreHandler::GetMemberSnapshot(
    CertSlotHandle slot)
{
    std::lock_guard lock(m_mutex);
    if (!m_registry)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }

    const auto* member = FindMember(slot);
    if (member == nullptr)
    {
        return score::crypto::make_unexpected(Error::kInvalidResourceId);
    }

    CertObject::Sptr cert;
    if (member->kind == TrustStoreMemberKind::kConditionalExternal)
    {
        const auto backend = ResolveSlot(slot);
        if (!backend.has_value())
        {
            return score::crypto::make_unexpected(Error::kResourceNotFound);
        }
        const auto& target = backend.value();
        auto fresh_cert = target.handler->LoadCertificate(*target.cfg);
        if (!fresh_cert.has_value() || !fresh_cert.value())
        {
            return score::crypto::make_unexpected(Error::kResourceNotFound);
        }
        cert = std::move(fresh_cert.value());
    }
    else
    {
        cert = LoadCertificateCached(slot);
    }
    if (!cert)
    {
        // The slot is currently empty.
        return score::crypto::make_unexpected(Error::kResourceNotFound);
    }

    MemberSnapshot snap;
    snap.slot_handle = slot;
    snap.slot_name = member->slot_name;
    snap.kind = member->kind;

    const auto& meta = cert->GetChainMetadata();
    snap.subject = meta.subject_canonical;
    snap.issuer = meta.issuer_canonical;
    snap.serial_number = meta.serial_number_hex;

    const auto fp = cert->GetFingerprint();
    if (fp.size() == score::crypto::kSha256FingerprintSize)
    {
        std::copy(fp.begin(), fp.end(), snap.fingerprint.begin());
    }

    // Default enabled=true, no baseline; override from state if present.
    bool enabled = true;
    std::optional<std::array<uint8_t, score::crypto::kSha256FingerprintSize>> accepted;
    const auto state_it = m_states.find(slot.index);
    if (state_it != m_states.end())
    {
        enabled = state_it->second.enabled;
        accepted = state_it->second.accepted_fingerprint;
    }

    snap.status = enabled ? score::crypto::MemberStatus::kEnabled : score::crypto::MemberStatus::kDisabled;
    if (member->kind == TrustStoreMemberKind::kConditionalExternal)
    {
        // The certificate above is a fresh load, so this reflects current slot content.
        if (accepted.has_value())
        {
            if (!std::equal(accepted.value().begin(), accepted.value().end(), snap.fingerprint.begin()))
            {
                snap.status = score::crypto::MemberStatus::kFingerprintMismatch;
            }
        }
        else if (m_config.conditional_slot_initialization == ConditionalSlotInitialization::kDisableUntilAccepted)
        {
            snap.status = score::crypto::MemberStatus::kAwaitingAcknowledgement;
        }
    }

    return snap;
}

}  // namespace score::crypto::daemon::cert_management
