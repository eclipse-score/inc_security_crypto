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

#pragma once

#include <cstdint>

#include "score/mw/com/types.h"
#include "score/tests/ipc_poc/ipc_buffer.h"

namespace score::crypto::ipc::control
{

/// S-CORE com service interface for the async crypto daemon control plane POC.
///
/// The new communication model uses a two-phase interaction:
///
///   Phase 1 — Short-lived Method call:
///     The client sends a ControlRequest (IpcBuffer) via the "Request" method.
///     The skeleton handler enqueues the work and immediately returns the
///     request_id (== ticket number) to the caller.  The round-trip is very
///     short; no processing happens on the calling thread.
///
///   Phase 2 — Event-based response:
///     A server-side background worker dequeues the request, does the actual
///     work, then calls response.Send() to broadcast a ControlResponse
///     (IpcBuffer) to all subscribers.  The IpcBuffer carries the original
///     request_id so every client can match the event to its outstanding ticket.
template <typename Trait>
class AsyncControlInterface : public Trait::Base
{
  public:
    using Trait::Base::Base;

    /// Phase 1: client sends a ControlRequest, server returns the ticket number.
    typename Trait::template Method<std::uint64_t(IpcBuffer)> request{*this, "Request"};

    /// Phase 2: server broadcasts a ControlResponse when work is complete.
    /// The IpcBuffer payload is a size-prefixed ControlResponse FlatBuffer
    /// whose request_id field equals the ticket returned by Phase 1.
    typename Trait::template Event<IpcBuffer> response{*this, "Response"};
};

using AsyncControlProxy = score::mw::com::AsProxy<AsyncControlInterface>;
using AsyncControlSkeleton = score::mw::com::AsSkeleton<AsyncControlInterface>;

}  // namespace score::crypto::ipc::control
