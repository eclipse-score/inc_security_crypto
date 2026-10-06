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

/// @file operation_names_test.cpp
/// @brief Pins the actor and action names the mediator prints on a failed operation.
///
/// A missing entry degrades silently: the operation still runs, and only the
/// error log loses the symbolic name. These cases make that visible instead.

#include "score/crypto/src/daemon/common/operation_names.hpp"

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/cipher_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/random_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"

#include <gtest/gtest.h>

namespace
{

namespace common = score::crypto::daemon::common;
namespace actors = score::crypto::daemon::common::actors;
namespace cipher_ops = score::crypto::daemon::provider::handler::cipher_handler_operations;
namespace sign_ops = score::crypto::daemon::provider::handler::sign_handler_operations;
namespace verify_ops = score::crypto::daemon::provider::handler::verify_handler_operations;
namespace random_ops = score::crypto::daemon::provider::handler::random_handler_operations;

/// Every actor the daemon registers resolves to a name.
TEST(OperationNamesTest, EveryRegisteredActorIsNamed)
{
    for (const auto actor : {actors::OP_ACTOR_CONTROL,
                             actors::OP_ACTOR_MEDIATOR,
                             actors::OP_ACTOR_PROVIDER,
                             actors::OP_ACTOR_HASH_HANDLER,
                             actors::OP_ACTOR_KEY_MANAGEMENT,
                             actors::OP_ACTOR_MAC_HANDLER,
                             actors::OP_ACTOR_CIPHER_HANDLER,
                             actors::OP_ACTOR_SIGN_HANDLER,
                             actors::OP_ACTOR_VERIFY_HANDLER,
                             actors::OP_ACTOR_RANDOM_HANDLER})
    {
        EXPECT_NE(common::ActorName(actor), "<unknown_actor>")
            << "actor " << static_cast<std::uint32_t>(actor) << " has no name";
    }
}

/// An actor outside the registered set still prints something, not a crash.
TEST(OperationNamesTest, UnregisteredActorFallsBack)
{
    EXPECT_EQ(common::ActorName(actors::CUSTOM_ACTOR_START), "<unknown_actor>");
}

/// The cipher, sign, verify and random actions all resolve within their actor.
TEST(OperationNamesTest, EveryActionOfTheNewActorsIsNamed)
{
    const auto named = [](common::OperationActor actor, common::OperationAction action) {
        const auto name = common::ActionName(actor, action);
        return (name.find("<unknown") == std::string_view::npos);
    };

    for (const auto action : {cipher_ops::CIPHER_INIT,
                              cipher_ops::CIPHER_UPDATE,
                              cipher_ops::CIPHER_FINALIZE,
                              cipher_ops::CIPHER_SS,
                              cipher_ops::CIPHER_GET_OUTPUT_SIZE,
                              cipher_ops::CIPHER_RESET,
                              cipher_ops::CIPHER_GET_IV_SIZE})
    {
        EXPECT_TRUE(named(actors::OP_ACTOR_CIPHER_HANDLER, action)) << "cipher action " << action;
    }

    for (const auto action : {sign_ops::SIGN_INIT,
                              sign_ops::SIGN_UPDATE,
                              sign_ops::SIGN_FINALIZE,
                              sign_ops::SIGN_SS,
                              sign_ops::SIGN_GET_SIZE,
                              sign_ops::SIGN_RESET})
    {
        EXPECT_TRUE(named(actors::OP_ACTOR_SIGN_HANDLER, action)) << "sign action " << action;
    }

    for (const auto action : {verify_ops::VERIFY_INIT,
                              verify_ops::VERIFY_UPDATE,
                              verify_ops::VERIFY_FINALIZE,
                              verify_ops::VERIFY_SS,
                              verify_ops::VERIFY_GET_SIZE,
                              verify_ops::VERIFY_RESET})
    {
        EXPECT_TRUE(named(actors::OP_ACTOR_VERIFY_HANDLER, action)) << "verify action " << action;
    }

    for (const auto action : {random_ops::RANDOM_GENERATE, random_ops::RANDOM_SEED})
    {
        EXPECT_TRUE(named(actors::OP_ACTOR_RANDOM_HANDLER, action)) << "random action " << action;
    }
}

/// The same action integer means different things under different actors.
TEST(OperationNamesTest, ActionNamesAreScopedToTheirActor)
{
    EXPECT_EQ(common::ActionName(actors::OP_ACTOR_SIGN_HANDLER, sign_ops::SIGN_FINALIZE), "SIGN_FINALIZE");
    EXPECT_EQ(common::ActionName(actors::OP_ACTOR_VERIFY_HANDLER, verify_ops::VERIFY_FINALIZE), "VERIFY_FINALIZE");
    EXPECT_EQ(common::ActionName(actors::OP_ACTOR_CIPHER_HANDLER, cipher_ops::CIPHER_FINALIZE), "CIPHER_FINALIZE");
}

/// An action outside an actor's range is reported against that actor.
TEST(OperationNamesTest, UnknownActionNamesItsActor)
{
    EXPECT_EQ(common::ActionName(actors::OP_ACTOR_RANDOM_HANDLER, 99U), "<unknown_random_op>");
    EXPECT_EQ(common::ActionName(actors::OP_ACTOR_SIGN_HANDLER, 99U), "<unknown_sign_op>");
}

}  // namespace
