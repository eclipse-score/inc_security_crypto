# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************
"""Backend configuration helpers for score crypto backends."""

def backend_defines(enable_score_backend, enable_openssl, enable_primula):
    """Generate preprocessor defines for enabled backends.

    Args:
        enable_score_backend: Whether score backend family is enabled
        enable_openssl: Whether OpenSSL backend is enabled
        enable_primula: Whether Primula backend is enabled

    Returns:
        List of preprocessor defines (e.g., ["SCORE_BACKEND_ENABLED=1",
                                              "SCORE_BACKEND_OPENSSL_ENABLED=1"])
    """
    if not enable_score_backend:
        return []

    defines = ["SCORE_BACKEND_ENABLED=1"]
    if enable_openssl:
        defines.append("SCORE_BACKEND_OPENSSL_ENABLED=1")
    if enable_primula:
        defines.append("SCORE_BACKEND_PRIMULA_ENABLED=1")
    return defines

def backend_deps(enable_score_backend, enable_openssl, enable_primula):
    """Generate backend adapter dependencies.

    Args:
        enable_score_backend: Whether score backend family is enabled
        enable_openssl: Whether OpenSSL backend is enabled
        enable_primula: Whether Primula backend is enabled

    Returns:
        List of backend adapter dependency labels
    """
    if not enable_score_backend:
        return []

    deps = []
    if enable_openssl:
        deps.append("//score/crypto/src/backend/openssl:openssl_backend_adapter")
    if enable_primula:
        deps.append("//score/crypto/src/backend/primula:primula_backend_adapter")
    return deps

def _pkcs11_backend_map():
    """Return the mapping of PKCS#11 backend names to Bazel labels."""
    return {
        "softhsm": "//third_party/soft_hsm:softhsm",
        # Future backends point directly to their library target, e.g.:
        # "vendor_hsm": "//third_party/vendor_hsm:vendor_hsm",
    }

def pkcs11_backend_label(backend_name):
    """Map a PKCS#11 backend name to its Bazel label.

    Args:
        backend_name: Name of PKCS#11 backend ("softhsm", "vendor_hsm", etc.)

    Returns:
        Bazel label string for the selected backend

    Raises:
        fail: If the backend name is unknown
    """
    backend_map = _pkcs11_backend_map()
    target = backend_map.get(backend_name)
    if not target:
        fail("Unknown PKCS#11 backend: '{}'. Valid options: {}".format(
            backend_name,
            ", ".join(backend_map.keys()),
        ))
    return target

def pkcs11_backend_deps(enable_pkcs11, backend_name):
    """Generate PKCS#11 backend dependency.

    Maps the backend name to its build target. The selected target provides
    the PKCS#11 library and headers. Config parsing is a fixed dep, independent
    of which backend library is selected.

    Args:
        enable_pkcs11: Whether PKCS#11 backend family is enabled
        backend_name: Name of PKCS#11 backend ("softhsm", "vendor_hsm", etc.)

    Returns:
        List containing the selected backend target, or empty list if disabled
    """
    if not enable_pkcs11:
        return []

    return [pkcs11_backend_label(backend_name)]
