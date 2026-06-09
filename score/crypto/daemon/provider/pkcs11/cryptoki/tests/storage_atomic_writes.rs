/********************************************************************************
 * Copyright (c) 2026 Valeo
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
//! Tests for: atomic writes + file locking.
//!
//! ## What is verified
//!
//! * After a successful `save_state()` call the storage file has `0600`
//!   permissions and the parent directory has `0700` permissions (Unix only).
//! * `save_state()` blocks while another writer holds the exclusive `flock` on
//!   the sidecar `.lock` file, and proceeds correctly once the lock is released.
//!   This validates that concurrent writers in different **processes** (each of
//!   which would open the lock file separately) are serialised.  Within a
//!   single process the same behaviour is exercised because Linux `flock(2)`
//!   locks are per open-file-description: two distinct `open(2)` calls on the
//!   same path produce independent descriptions that block each other.
//!
//! All tests that touch `CRYPTOKI_STORE` are serialised with `STORE_LOCK`
//! to prevent parallel tests inside this binary from racing on the env var.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, Once};
use std::time::Duration;

use cryptoki::pkcs11::storage::{save_state, StoredState};

// ── Process-wide init ─────────────────────────────────────────────────────

static INIT: Once = Once::new();
fn init() {
    INIT.call_once(|| {
        // Nothing to do here for storage-only tests; marker kept for symmetry
        // with other test files that call C_Initialize.
    });
}

/// Serialise all tests that mutate `CRYPTOKI_STORE`.
static STORE_LOCK: Mutex<()> = Mutex::new(());

fn lock_store() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Return a path `<tmp>/pkcs11_storage_test_<tag>/token.json`.
///
/// The *subdirectory* is unique per tag so that the parent-directory
/// permission test can verify a directory we fully own (not `/tmp` itself).
/// Any pre-existing directory is removed first to start from a clean slate.
fn fresh_store_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pkcs11_storage_test_{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("token.json")
}

/// Minimal valid `StoredState` with no objects and no token.
fn empty_state() -> StoredState {
    StoredState {
        version:     1,
        tokens:      HashMap::new(),
        token:       None,
        objects:     vec![],
        next_handle: 1,
    }
}

// ── Permission tests (Unix-only) ──────────────────────────────────────────

/// After `save_state()` the storage file must have mode `0600`.
#[test]
#[cfg(unix)]
fn storage_file_has_0600_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("perms_file");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    save_state(&empty_state()).expect("save_state failed");

    let meta = std::fs::metadata(&store_path)
        .expect("metadata failed — file was not created");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "storage file must have 0600 permissions, got {:04o}",
        mode
    );

    // Cleanup
    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::remove_dir_all(store_path.parent().unwrap());
}

/// After `save_state()` the parent directory must have mode `0700`.
#[test]
#[cfg(unix)]
fn storage_dir_has_0700_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("perms_dir");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    save_state(&empty_state()).expect("save_state failed");

    let parent = store_path.parent().unwrap();
    let meta   = std::fs::metadata(parent).expect("dir metadata failed");
    let mode   = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "storage directory must have 0700 permissions, got {:04o}",
        mode
    );

    // Cleanup — restore world-readable so remove_dir_all works normally.
    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::set_permissions(
        parent,
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::remove_dir_all(parent);
}

/// Permissions must be enforced even when the directory already exists with
/// wrong permissions (e.g. created by an older version of the library).
#[test]
#[cfg(unix)]
fn save_state_corrects_existing_dir_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("perms_fix");
    let parent = store_path.parent().unwrap();

    // Pre-create the directory with lax permissions.
    std::fs::create_dir_all(parent).unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    std::env::set_var("CRYPTOKI_STORE", &store_path);
    save_state(&empty_state()).expect("save_state failed");

    let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700,
        "save_state must tighten existing directory to 0700, got {:04o}", mode);

    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(parent);
}

// ── Atomic write correctness ──────────────────────────────────────────────

/// The resulting file must contain valid JSON after a `save_state()` call.
#[test]
fn save_state_produces_valid_json() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("valid_json");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    save_state(&empty_state()).expect("save_state failed");

    let raw = std::fs::read_to_string(&store_path).expect("file not created");
    let _: serde_json::Value =
        serde_json::from_str(&raw).expect("file does not contain valid JSON");

    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::remove_dir_all(store_path.parent().unwrap());
}

/// Two concurrent `save_state()` calls must both complete successfully and
/// leave the file in a valid state (no torn writes).
#[test]
fn concurrent_saves_do_not_corrupt_file() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("concurrent");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    // Spawn two threads that both call save_state() immediately.
    let path_clone = store_path.clone();
    let t1 = std::thread::spawn(move || {
        std::env::set_var("CRYPTOKI_STORE", &path_clone);
        save_state(&empty_state())
    });
    let path_clone2 = store_path.clone();
    let t2 = std::thread::spawn(move || {
        std::env::set_var("CRYPTOKI_STORE", &path_clone2);
        save_state(&empty_state())
    });

    t1.join().unwrap().expect("thread 1 save_state failed");
    t2.join().unwrap().expect("thread 2 save_state failed");

    // File must be valid JSON regardless of which write won the rename race.
    let raw = std::fs::read_to_string(&store_path).expect("file not created");
    let _: serde_json::Value =
        serde_json::from_str(&raw).expect("concurrent saves corrupted the file");

    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::remove_dir_all(store_path.parent().unwrap());
}

// ── flock serialisation test ──────────────────────────────────────────────

/// `save_state()` must block while another writer holds the exclusive flock
/// on the `.lock` sidecar file, and succeed once the lock is released.
///
/// This mirrors the inter-process scenario: each process opens the lock file
/// independently (`open(2)`), producing separate open-file-descriptions.
/// Linux `flock(2)` treats distinct open-file-descriptions as independent lock
/// holders, so the second opener blocks until the first releases the lock.
/// The same mechanism is exercised here using two threads, each of which calls
/// `open` on the lock file separately (once via the pre-acquired fd below, and
/// once inside `save_state()`).
#[test]
fn flock_blocks_save_while_lock_held_then_unblocks() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("flock");
    let parent = store_path.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();

    // Derive the lock file path the same way save_state() does.
    let lock_path = store_path.with_extension("lock");

    // Pre-acquire an exclusive flock from the test thread.
    // This simulates another process already holding the write lock.
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .expect("could not open lock file");
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd as _;
        assert_eq!(unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) }, 0, "could not acquire exclusive flock: {}", std::io::Error::last_os_error());
    }

    std::env::set_var("CRYPTOKI_STORE", &store_path);

    // Spawn a thread that calls save_state(); it must block on the flock
    // because we already hold it.
    let t = std::thread::spawn(|| save_state(&empty_state()));

    // Give the thread time to reach the flock() call and block.
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        !t.is_finished(),
        "save_state() must block while the exclusive flock is held by another opener"
    );

    // Release our lock — the background save must now proceed.
    drop(lock_file);

    // Allow generous time for the save to complete after unblocking.
    let result = t.join().expect("save_state thread panicked");
    result.expect("save_state() failed after lock was released");

    // The file must now exist and contain valid JSON.
    let raw = std::fs::read_to_string(&store_path)
        .expect("storage file was not created after flock released");
    serde_json::from_str::<serde_json::Value>(&raw)
        .expect("storage file is not valid JSON after flock-gated save");

    // Cleanup
    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::remove_dir_all(parent);
}

/// Verifies that `save_state()` followed by a second `save_state()` is
/// idempotent — the file remains valid JSON and contains the expected data.
#[test]
fn save_state_is_idempotent() {
    init();
    let _guard = lock_store();
    let store_path = fresh_store_path("idempotent");
    std::env::set_var("CRYPTOKI_STORE", &store_path);

    save_state(&empty_state()).expect("first save failed");
    save_state(&empty_state()).expect("second save failed");

    let raw = std::fs::read_to_string(&store_path).expect("file not found");
    let v: serde_json::Value =
        serde_json::from_str(&raw).expect("file is not valid JSON after two saves");
    assert_eq!(v["version"], 1, "version field mismatch");

    std::env::remove_var("CRYPTOKI_STORE");
    let _ = std::fs::remove_dir_all(store_path.parent().unwrap());
}
