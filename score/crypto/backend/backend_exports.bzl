"""Backend selection and build dependency exports.

This file contains the master backend configuration flags and exports
computed dependency lists for consumption by other BUILD files.

This is the SINGLE SOURCE OF TRUTH for backend selection.
To enable/disable backends, modify the flags below.
"""

load(":backend_config.bzl",
     "backend_defines",
     "backend_deps",
     "pkcs11_backend_deps",
     "pkcs11_backend_label")

# ============================================================================
# MASTER BACKEND CONFIGURATION FLAGS
#
# Modify these flags to enable/disable backends.
# Changes here automatically propagate to both compilation and runtime linking.
# ============================================================================

# ============================================================================
# PKCS#11 Backend Selection
# ============================================================================

# PKCS#11 backend family (True = enabled, False = excluded)
ENABLE_PKCS11_BACKEND = True

# Active PKCS#11 backend implementation (only one at a time)
# Options: "softhsm", "vendor_hsm", "cryptoki", etc.
PKCS11_BACKEND = "softhsm"

# ============================================================================
# Score Provider Backend Selection
# ============================================================================

# Score provider backend family (True = enabled, False = excluded all)
ENABLE_SCORE_BACKEND = True

# Individual score provider backends (multiple can be active simultaneously)
ENABLE_BACKEND_OPENSSL = True
ENABLE_BACKEND_PRIMULA = False

# ============================================================================
# COMPUTED EXPORTS (Do not modify below this line)
# ============================================================================

# Preprocessor defines for conditional compilation
BACKEND_DEFINES = backend_defines(
    ENABLE_SCORE_BACKEND,
    ENABLE_BACKEND_OPENSSL,
    ENABLE_BACKEND_PRIMULA,
)

# Build-time dependencies (backend adapters)
SCORE_BACKEND_DEPS = backend_deps(
    ENABLE_SCORE_BACKEND,
    ENABLE_BACKEND_OPENSSL,
    ENABLE_BACKEND_PRIMULA,
)

PKCS11_BACKEND_DEPS = pkcs11_backend_deps(
    ENABLE_PKCS11_BACKEND,
    PKCS11_BACKEND,
)

# Default PKCS#11 backend label (used as label_flag default).
# Can be overridden at build time with:
#   --//score/crypto/backend:pkcs11_backend=//some/other:target
PKCS11_BACKEND_DEFAULT_LABEL = pkcs11_backend_label(PKCS11_BACKEND)
