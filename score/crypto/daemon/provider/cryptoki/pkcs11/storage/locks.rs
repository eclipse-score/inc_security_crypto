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
#[cfg(unix)]
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(unix)]
pub(crate) static LOCK_FILE_FD: AtomicI32 = AtomicI32::new(-1);

pub fn release_locks() {
    #[cfg(unix)]
    {
        let fd = LOCK_FILE_FD.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
