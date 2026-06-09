// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

//! Persistent token storage — serializes token objects to disk.
//!
//! Only objects with `CKA_TOKEN = CK_TRUE` are persisted.
//! Storage path: `$CRYPTOKI_STORE` or `~/.cryptoki/token.json`.
//!
//! This is a thin hub that re-exports storage model, IO, locking, and helper modules.

mod helpers;
mod io;
mod locks;
mod models;
mod path;

pub use helpers::*;
pub use io::*;
pub use locks::*;
pub use models::*;
pub use path::*;
