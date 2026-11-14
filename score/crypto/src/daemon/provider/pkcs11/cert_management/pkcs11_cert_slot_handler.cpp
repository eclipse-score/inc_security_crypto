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

#include "score/crypto/src/daemon/provider/pkcs11/cert_management/pkcs11_cert_slot_handler.hpp"

#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_session_guard.hpp"

#include "score/mw/log/logging.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{
namespace
{

using Error = daemon_common::DaemonErrorCode;
using Descriptor = daemon_common::storage::DeploymentDescriptor;
namespace file_io = daemon_common::storage;

/// Mirrors FileBackedSlotHandler::kMaxCertSize.
constexpr std::size_t kMaxCertSize = 64U * 1024U;

/// Number of object handles requested per C_FindObjects call.
constexpr std::size_t kFindBatchSize = 8U;

/// Certificate identity recorded in the deployment descriptor.
/// Byte vectors are kept non-const so PKCS#11 attribute templates can point at them
/// without a const_cast.
struct TokenIdentity
{
    std::vector<CK_BYTE> label;
    std::vector<CK_BYTE> id;

    [[nodiscard]] bool Empty() const noexcept
    {
        return label.empty() && id.empty();
    }
};

CK_ATTRIBUTE MakeAttribute(CK_ATTRIBUTE_TYPE type, void* value, std::size_t length) noexcept
{
    return CK_ATTRIBUTE{type, value, static_cast<CK_ULONG>(length)};
}

Pkcs11HandlerRequirements ReadRequirements() noexcept
{
    return {Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::Public};
}

Pkcs11HandlerRequirements WriteRequirements() noexcept
{
    return {Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
}

score::crypto::Expected<Descriptor, Error> LoadDescriptor(const daemon_cert_management::CertSlotConfig& slot)
{
    return daemon_cert_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
}

score::crypto::Expected<std::monostate, Error> SaveDescriptor(const daemon_cert_management::CertSlotConfig& slot,
                                                              const Descriptor& descriptor,
                                                              const file_io::FileWriter& writer)
{
    return daemon_cert_management::DeploymentWriter::Write(
        slot.deployment_path, slot.deployment_format, descriptor, writer);
}

score::crypto::Expected<TokenIdentity, Error> ReadIdentity(const Descriptor& descriptor)
{
    TokenIdentity identity{};
    const auto label = descriptor.Get("certificate", "pkcs11.label");
    identity.label.reserve(label.size());
    for (const char c : label)
    {
        identity.label.push_back(static_cast<CK_BYTE>(c));
    }

    const auto object_id = descriptor.Get("certificate", "pkcs11.object_id");
    if (!object_id.empty())
    {
        identity.id = detail::HexDecode(object_id);
        if (identity.id.empty())
            return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    return identity;
}

score::crypto::Expected<CK_FUNCTION_LIST*, Error> GetFunctions(const std::weak_ptr<Pkcs11Module>& module_ref)
{
    const auto module = module_ref.lock();
    if (!module || module->GetFunctionList() == nullptr)
        return score::crypto::make_unexpected(Error::kInternalError);
    return module->GetFunctionList();
}

/// Every CKO_CERTIFICATE (CKC_X_509) object matching the identity. An empty result means no object matches.
score::crypto::Expected<std::vector<CK_OBJECT_HANDLE>, Error> FindCertificates(CK_FUNCTION_LIST* functions,
                                                                               CK_SESSION_HANDLE session,
                                                                               TokenIdentity identity)
{
    CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
    std::vector<CK_ATTRIBUTE> attributes{
        MakeAttribute(CKA_CLASS, &object_class, sizeof(object_class)),
        MakeAttribute(CKA_CERTIFICATE_TYPE, &certificate_type, sizeof(certificate_type))};
    if (!identity.label.empty())
        attributes.push_back(MakeAttribute(CKA_LABEL, identity.label.data(), identity.label.size()));
    if (!identity.id.empty())
        attributes.push_back(MakeAttribute(CKA_ID, identity.id.data(), identity.id.size()));

    if (functions->C_FindObjectsInit(session, attributes.data(), static_cast<CK_ULONG>(attributes.size())) != CKR_OK)
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);

    std::vector<CK_OBJECT_HANDLE> matches;
    std::array<CK_OBJECT_HANDLE, kFindBatchSize> batch{};
    CK_RV find_rv = CKR_OK;
    CK_ULONG count = 0U;
    do
    {
        find_rv = functions->C_FindObjects(session, batch.data(), static_cast<CK_ULONG>(kFindBatchSize), &count);
        if (find_rv != CKR_OK)
            break;
        matches.insert(matches.end(), batch.begin(), batch.begin() + static_cast<std::ptrdiff_t>(count));
    } while (count == static_cast<CK_ULONG>(kFindBatchSize));

    const CK_RV final_rv = functions->C_FindObjectsFinal(session);
    if (find_rv != CKR_OK || final_rv != CKR_OK)
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);
    return matches;
}

/// Destroy each listed object, stopping at the first failure.
score::crypto::Expected<std::monostate, Error> DestroyObjects(CK_FUNCTION_LIST* functions,
                                                              CK_SESSION_HANDLE session,
                                                              const std::vector<CK_OBJECT_HANDLE>& objects)
{
    for (const CK_OBJECT_HANDLE object : objects)
    {
        if (functions->C_DestroyObject(session, object) != CKR_OK)
            return score::crypto::make_unexpected(Error::kPersistFailed);
    }
    return std::monostate{};
}

/// Read CKA_VALUE of a certificate object using the size-then-bytes two-call pattern.
score::crypto::Expected<std::vector<CK_BYTE>, Error> ReadCertificateValue(CK_FUNCTION_LIST* functions,
                                                                          CK_SESSION_HANDLE session,
                                                                          CK_OBJECT_HANDLE object)
{
    CK_ATTRIBUTE size_query{CKA_VALUE, nullptr, 0U};
    if (functions->C_GetAttributeValue(session, object, &size_query, 1U) != CKR_OK ||
        size_query.ulValueLen == CK_UNAVAILABLE_INFORMATION || size_query.ulValueLen == 0U ||
        static_cast<std::size_t>(size_query.ulValueLen) > kMaxCertSize)
    {
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }

    std::vector<CK_BYTE> value(static_cast<std::size_t>(size_query.ulValueLen));
    CK_ATTRIBUTE value_query{CKA_VALUE, value.data(), size_query.ulValueLen};
    if (functions->C_GetAttributeValue(session, object, &value_query, 1U) != CKR_OK ||
        value_query.ulValueLen != size_query.ulValueLen)
    {
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }
    return value;
}

/// Create a persistent (CKA_TOKEN) X.509 certificate object. Returns kPersistFailed on error.
score::crypto::Expected<CK_OBJECT_HANDLE, Error> CreateCertificateObject(CK_FUNCTION_LIST* functions,
                                                                         CK_SESSION_HANDLE session,
                                                                         TokenIdentity identity,
                                                                         std::vector<CK_BYTE> der,
                                                                         std::vector<CK_BYTE> subject_name_der,
                                                                         std::vector<CK_BYTE> issuer_name_der,
                                                                         std::vector<CK_BYTE> serial_number_der)
{
    CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
    CK_BBOOL token = CK_TRUE;
    std::vector<CK_ATTRIBUTE> attributes{
        MakeAttribute(CKA_CLASS, &object_class, sizeof(object_class)),
        MakeAttribute(CKA_CERTIFICATE_TYPE, &certificate_type, sizeof(certificate_type)),
        MakeAttribute(CKA_TOKEN, &token, sizeof(token)),
        MakeAttribute(CKA_VALUE, der.data(), der.size()),
        MakeAttribute(CKA_SUBJECT, subject_name_der.data(), subject_name_der.size()),
        MakeAttribute(CKA_ISSUER, issuer_name_der.data(), issuer_name_der.size()),
        MakeAttribute(CKA_SERIAL_NUMBER, serial_number_der.data(), serial_number_der.size())};
    if (!identity.label.empty())
        attributes.push_back(MakeAttribute(CKA_LABEL, identity.label.data(), identity.label.size()));
    if (!identity.id.empty())
        attributes.push_back(MakeAttribute(CKA_ID, identity.id.data(), identity.id.size()));

    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    const CK_RV create_result =
        functions->C_CreateObject(session, attributes.data(), static_cast<CK_ULONG>(attributes.size()), &handle);
    if (create_result != CKR_OK)
    {
        score::mw::log::LogWarn() << "[PKCS#11 cert slot] C_CreateObject failed: rv="
                                  << static_cast<unsigned long>(create_result);
        return score::crypto::make_unexpected(Error::kPersistFailed);
    }
    return handle;
}

}  // namespace

Pkcs11CertSlotHandler::Pkcs11CertSlotHandler(daemon_cert_management::CertSlotConfig config,
                                             std::shared_ptr<Pkcs11Provider> provider,
                                             std::weak_ptr<Pkcs11Module> module,
                                             provider::cert_management::ICertParser::Sptr parser,
                                             daemon_common::storage::FileWriter writer)
    : ICertSlotHandler{std::move(config)},
      m_provider{std::move(provider)},
      m_module{std::move(module)},
      m_parser{std::move(parser)},
      m_write_file{writer},
      m_crl{GetConfig(), std::move(writer)}
{
}

Pkcs11CertSlotHandler::~Pkcs11CertSlotHandler() = default;

score::crypto::Expected<daemon_cert_management::CertObject::Sptr, Error> Pkcs11CertSlotHandler::LoadCertificate()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return LoadCertificateUnlocked();
}

score::crypto::Expected<daemon_cert_management::CertObject::Sptr, Error>
Pkcs11CertSlotHandler::LoadCertificateUnlocked()
{
    if (!m_parser)
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);

    auto descriptor = LoadDescriptor(GetConfig());
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto identity = ReadIdentity(*descriptor);
    if (!identity)
        return score::crypto::make_unexpected(identity.error());
    if (identity->Empty())
        return score::crypto::make_unexpected(Error::kKeySlotEmpty);

    Pkcs11SessionGuard guard{*m_provider, ReadRequirements()};
    if (!guard)
        return score::crypto::make_unexpected(guard.error());
    auto functions = GetFunctions(m_module);
    if (!functions)
        return score::crypto::make_unexpected(functions.error());

    auto matches = FindCertificates(*functions, guard.get(), *identity);
    if (!matches)
        return score::crypto::make_unexpected(matches.error());
    if (matches->empty())
        return score::crypto::make_unexpected(Error::kKeySlotEmpty);
    if (matches->size() > 1U)
    {
        score::mw::log::LogError() << "[PKCS#11 cert slot] " << matches->size()
                                   << " certificate objects match the slot identity; storing or clearing the slot "
                                      "leaves one";
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);
    }

    auto der = ReadCertificateValue(*functions, guard.get(), matches->front());
    if (!der)
        return score::crypto::make_unexpected(der.error());

    return m_parser->ParseCertificate(der->data(), der->size(), score::crypto::FormatType::kDer);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::StoreCertificate(
    const daemon_cert_management::CertObject& cert)
{
    const std::lock_guard lock{m_slot_operation_mutex};

    // CKA_VALUE holds DER bytes only.
    if (cert.GetFormat() != score::crypto::FormatType::kDer)
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);
    const auto raw = cert.GetRawBytes();
    if (raw.empty() || raw.size() > kMaxCertSize)
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    const auto& metadata = cert.GetChainMetadata();
    if (metadata.subject_name_der.empty() || metadata.issuer_name_der.empty() || metadata.serial_number_der.empty())
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);

    const auto& slot = GetConfig();
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto identity = ReadIdentity(*descriptor);
    if (!identity)
        return score::crypto::make_unexpected(identity.error());
    if (identity->Empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    Pkcs11SessionGuard guard{*m_provider, WriteRequirements()};
    if (!guard)
        return score::crypto::make_unexpected(guard.error());
    auto functions = GetFunctions(m_module);
    if (!functions)
        return score::crypto::make_unexpected(functions.error());

    auto previous = FindCertificates(*functions, guard.get(), *identity);
    if (!previous)
        return score::crypto::make_unexpected(previous.error());

    const std::vector<CK_BYTE> der(raw.begin(), raw.end());
    const std::vector<CK_BYTE> subject_name_der(metadata.subject_name_der.begin(), metadata.subject_name_der.end());
    const std::vector<CK_BYTE> issuer_name_der(metadata.issuer_name_der.begin(), metadata.issuer_name_der.end());
    const std::vector<CK_BYTE> serial_number_der(metadata.serial_number_der.begin(), metadata.serial_number_der.end());

    // Create the new object before removing the earlier ones, so a failed creation keeps the existing
    // certificate. A token that refuses a second object with the same class, label and ID fails this
    // creation; in that case the earlier objects are removed and creation is retried. If the retry also
    // fails, the slot is left without a certificate and the descriptor still describes the earlier one.
    auto created = CreateCertificateObject(
        *functions, guard.get(), *identity, der, subject_name_der, issuer_name_der, serial_number_der);
    bool earlier_removed = false;
    if (!created && !previous->empty())
    {
        if (const auto destroyed = DestroyObjects(*functions, guard.get(), *previous); !destroyed)
            return score::crypto::make_unexpected(destroyed.error());
        earlier_removed = true;
        created = CreateCertificateObject(
            *functions, guard.get(), *identity, der, subject_name_der, issuer_name_der, serial_number_der);
    }
    if (!created)
        return score::crypto::make_unexpected(created.error());

    // Remove every earlier match, which also clears duplicates left by an interrupted store. If one
    // cannot be removed, the new object is removed again so the token does not hold a certificate the
    // descriptor does not describe.
    if (!earlier_removed)
    {
        if (const auto destroyed = DestroyObjects(*functions, guard.get(), *previous); !destroyed)
        {
            static_cast<void>((*functions)->C_DestroyObject(guard.get(), *created));
            return score::crypto::make_unexpected(destroyed.error());
        }
    }

    // Clear any stale CRL: it was issued for the previous certificate. Keep crl_path so
    // a later StoreCrl reuses the same location. Metadata is cleared unconditionally so
    // the descriptor never reports a stale CRL as current, even if the file removal
    // below fails.
    const auto old_crl_path = descriptor->Get("crl", "crl_path");
    descriptor->RemoveSection("crl");
    if (!old_crl_path.empty())
    {
        descriptor->Set("crl", "crl_path", old_crl_path);
        static_cast<void>(file_io::RemoveFile(old_crl_path));
    }

    descriptor->Set("certificate_metadata", "subject", std::string(cert.GetSubject()));
    descriptor->Set("certificate_metadata", "issuer", std::string(cert.GetIssuer()));
    descriptor->Set("certificate_metadata", "not_before", std::to_string(cert.GetNotBefore()));
    descriptor->Set("certificate_metadata", "not_after", std::to_string(cert.GetNotAfter()));
    descriptor->Set("certificate_metadata", "is_ca", cert.IsCA() ? "true" : "false");
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::ClearSlot()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    const auto& slot = GetConfig();
    auto descriptor = LoadDescriptor(slot);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto identity = ReadIdentity(*descriptor);
    if (!identity)
        return score::crypto::make_unexpected(identity.error());

    if (!identity->Empty())
    {
        Pkcs11SessionGuard guard{*m_provider, WriteRequirements()};
        if (!guard)
            return score::crypto::make_unexpected(guard.error());
        auto functions = GetFunctions(m_module);
        if (!functions)
            return score::crypto::make_unexpected(functions.error());

        auto matches = FindCertificates(*functions, guard.get(), *identity);
        if (!matches)
            return score::crypto::make_unexpected(matches.error());
        if (const auto destroyed = DestroyObjects(*functions, guard.get(), *matches); !destroyed)
            return score::crypto::make_unexpected(destroyed.error());
    }

    // Remove the CRL file (errors propagate) and keep crl_path for a future StoreCrl.
    const auto crl_path = descriptor->Get("crl", "crl_path");
    if (!crl_path.empty())
    {
        if (const auto rm = file_io::RemoveFile(crl_path); !rm)
            return rm;
    }
    descriptor->RemoveSection("crl");
    if (!crl_path.empty())
        descriptor->Set("crl", "crl_path", crl_path);
    descriptor->RemoveSection("certificate_metadata");
    return SaveDescriptor(slot, *descriptor, m_write_file);
}

score::crypto::Expected<score::crypto::CertificateSlotState, Error> Pkcs11CertSlotHandler::GetSlotStateUnlocked()
{
    auto descriptor = LoadDescriptor(GetConfig());
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());
    auto identity = ReadIdentity(*descriptor);
    if (!identity)
        return score::crypto::make_unexpected(identity.error());
    if (identity->Empty())
        return score::crypto::CertificateSlotState::kEmpty;

    Pkcs11SessionGuard guard{*m_provider, ReadRequirements()};
    if (!guard)
    {
        if (guard.error() == Error::kAccessDenied || guard.error() == Error::kProviderBusy)
            return score::crypto::CertificateSlotState::kLocked;
        return score::crypto::make_unexpected(guard.error());
    }
    auto functions = GetFunctions(m_module);
    if (!functions)
        return score::crypto::make_unexpected(functions.error());

    auto matches = FindCertificates(*functions, guard.get(), *identity);
    if (!matches)
        return score::crypto::make_unexpected(matches.error());
    return matches->empty() ? score::crypto::CertificateSlotState::kEmpty
                            : score::crypto::CertificateSlotState::kOccupied;
}

score::crypto::Expected<score::crypto::CertificateSlotState, Error> Pkcs11CertSlotHandler::GetSlotState()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return GetSlotStateUnlocked();
}

score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> Pkcs11CertSlotHandler::GetSlotInfo()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto state = GetSlotStateUnlocked();
    if (!state)
        return score::crypto::make_unexpected(state.error());
    score::crypto::CertificateSlotInfo info{};
    info.state = *state;
    const auto has_crl = m_crl.HasCrl();
    if (!has_crl)
        return score::crypto::make_unexpected(has_crl.error());
    info.has_crl = has_crl.value();
    return info;
}

score::crypto::Expected<bool, Error> Pkcs11CertSlotHandler::HasCrl()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.HasCrl();
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::StoreCrl(
    const daemon_cert_management::CrlData& crl)
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.StoreCrl(crl);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::ClearCrl()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    return m_crl.ClearCrl();
}

score::crypto::Expected<std::optional<score::crypto::CrlMetadata>, Error> Pkcs11CertSlotHandler::GetCrlMetadata()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto metadata = m_crl.GetCrlMetadata();
    if (!metadata.has_value() || metadata->has_value())
        return metadata;
    // The descriptor caches no metadata. If a CRL exists (for example, one placed on disk
    // outside the daemon), derive the metadata from it.
    const auto crl = m_crl.LoadCrlData();
    if (!crl.has_value() || !crl->has_value())
        return std::optional<score::crypto::CrlMetadata>{};
    return DeriveCrlMetadata(**crl);
}

score::crypto::Expected<std::optional<daemon_cert_management::CrlData>, Error> Pkcs11CertSlotHandler::LoadCrlData()
{
    const std::lock_guard lock{m_slot_operation_mutex};
    auto crl = m_crl.LoadCrlData();
    if (!crl.has_value() || !crl->has_value() || (*crl)->metadata.has_value())
        return crl;
    // Revocation checking does not use a CRL without metadata, so the metadata is derived here, as
    // FileBackedSlotHandler does for the same case.
    (*crl)->metadata = DeriveCrlMetadata(**crl);
    return crl;
}

std::optional<score::crypto::CrlMetadata> Pkcs11CertSlotHandler::DeriveCrlMetadata(
    const daemon_cert_management::CrlData& crl)
{
    if (!m_parser)
        return std::nullopt;
    const auto certificate = LoadCertificateUnlocked();
    if (!certificate.has_value())
        return std::nullopt;

    const auto issuer = (*certificate)->GetRawBytes();
    const auto result = m_parser->ValidateCrl(crl, issuer.data(), issuer.size(), (*certificate)->GetFormat());
    return result.has_value() ? std::optional<score::crypto::CrlMetadata>{result.value()} : std::nullopt;
}

}  // namespace score::crypto::daemon::provider::pkcs11
