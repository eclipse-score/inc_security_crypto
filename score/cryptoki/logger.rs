// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

use score_log_bridge::ScoreLogBridgeBuilder;
use std::path::PathBuf;
use std::sync::Once;

static LOGGER_INIT: Once = Once::new();

/// Safe, one-time global initialization of the ScoreLogBridge.
pub fn init() {
    LOGGER_INIT.call_once(|| {
        // Safe path fallback for a shared library context
        let config_path = std::env::var("PKCS11_LOG_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/pkcs11/logging.json"));

        ScoreLogBridgeBuilder::new()
            .context("P11M") // 4-character identifier for your PKCS#11 Module
            .show_module(false)
            .show_file(true)
            .show_line(true)
            .config(config_path)
            .set_as_default_logger();
    });
}
