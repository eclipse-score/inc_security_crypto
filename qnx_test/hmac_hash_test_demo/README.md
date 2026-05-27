# HMAC-SHA256 Demo — Architecture & Sequence Documentation

## Overview

The `score_hmac_demo` demonstrates HMAC-SHA256 computation using the Score Crypto Middleware's
daemon-client architecture on QNX 7.1.0S (AARCH64). It exercises the full flow:
slot-based key resolution, provider selection, key binding to session contexts, and streaming MAC operations.

## Architecture Diagrams

Open `architecture.drawio` in draw.io or VS Code with the Draw.io extension. It contains 3 pages:

| Page | Description |
|------|-------------|
| **HMAC-SHA256 Sequence** | Full sequence diagram from client `CreateMacContext()` through daemon processing to MAC computation |
| **Daemon Architecture** | Component-level view of the crypto daemon internals |
| **Key Lifecycle & Session Binding** | Session node hierarchy and key material state machine |

---

## Daemon Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Client Process (score_hmac_demo)                       │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────┐  │
│  │CryptoStack   │→ │CryptoContext   │→ │MacContext  │  │
│  │Factory       │  │Impl           │  │Impl       │  │
│  └──────────────┘  └────────────────┘  └───────────┘  │
└───────────────────────────┬─────────────────────────────┘
                            │ gRPC + FlatBuffers
                            │ unix:///tmp/crypto_daemon.sock
┌───────────────────────────▼─────────────────────────────┐
│  Crypto Daemon                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ MediatorImpl (Request Dispatcher)                  │ │
│  └──┬──────────┬──────────────┬───────────────────────┘ │
│     │          │              │                          │
│  ┌──▼───┐  ┌──▼────────┐  ┌─▼───────────────┐         │
│  │Data  │  │KeyMgmt    │  │ProviderManager  │         │
│  │Mgr   │  │Service    │  │                 │         │
│  └──────┘  └─────┬─────┘  └───────┬─────────┘         │
│                   │                │                     │
│            ┌──────▼──────┐  ┌──────▼──────────┐        │
│            │SlotRegistry │  │OpenSSL Provider │        │
│            └─────────────┘  │ ├─HandlerFactory│        │
│                             │ ├─HmacHandler   │        │
│                             │ ├─SlotHandler   │        │
│                             │ └─KeyHandler    │        │
│                             └─────────────────┘        │
└─────────────────────────────────────────────────────────┘
```

---

## Full Sequence: HMAC-SHA256 CreateMacContext

### Phase 0: Connection Setup

```
Client                        Daemon
  │                             │
  │─ CreateCryptoStack() ──────→│
  │  endpoint=unix:///tmp/      │
  │  crypto_daemon.sock         │
  │                             │── Extract client_id=(pid, uid)
  │                             │── Create ConnectionDataNode
  │←── connection_node_id ──────│
  │                             │
  │─ CreateCryptoContext() ─────│  (local — wraps IPC connection)
```

### Phase 1: Resolve KeySlot

```
Client                  Mediator              SlotRegistry        DataManager
  │                        │                      │                   │
  │─ ResolveResource() ───→│                      │                   │
  │  name="HMAC_SHA256_    │                      │                   │
  │   IntegrationTestKey   │                      │                   │
  │   _OpenSSL"            │                      │                   │
  │  type=kKeySlot         │                      │                   │
  │                        │─ ResolveSlot() ─────→│                   │
  │                        │                      │── Check UID       │
  │                        │                      │   in allowed_uids │
  │                        │←── SlotHandle ───────│                   │
  │                        │                      │                   │
  │                        │─ addNode(KeySlotDataNode) ──────────────→│
  │                        │                                          │
  │←── key_node_id ────────│←── node_id ──────────────────────────────│
```

### Phase 2: Create MAC Context (Provider Resolution & Key Binding)

```
Client       Mediator        KeyMgmtService    SlotRegistry    ProviderMgr    OpenSSL Handler
  │             │                  │                │               │               │
  │─CreateMac──→│                  │                │               │               │
  │ algo=HMAC   │                  │                │               │               │
  │ key=node_id │                  │                │               │               │
  │             │                  │                │               │               │
  │             │─ResolveTarget───→│                │               │               │
  │             │ Provider()       │                │               │               │
  │             │                  │─GetPrimary────→│               │               │
  │             │                  │ ProviderId()   │               │               │
  │             │                  │←─provider_id───│               │               │
  │             │←─provider_id─────│                │               │               │
  │             │                  │                │               │               │
  │             │─GetProvider(id)──────────────────────────────────→│               │
  │             │←─IProvider(OpenSSL)───────────────────────────────│               │
  │             │                  │                │               │               │
  │             │─Factory.CreateHandler("MAC","HMAC-SHA256")────────────────────────→│
  │             │←─new OpenSslHmacHandler──────────────────────────────────────────│
  │             │                  │                │               │               │
  │             │─── addChildNode(ContextDataNode) under connection ───→ DataManager │
  │             │←── context_node_id ──────────────────────────────────────────────│
  │             │                  │                │               │               │
  │             │─BindKeyToCtx()──→│                │               │               │
  │             │                  │── GetNodeAccessor(key_node_id) → KeySlotDataNode│
  │             │                  │                │               │               │
  │             │                  │─ LoadOrShare()─────────────────────────────────→│
  │             │                  │  (reads deployment_path:                        │
  │             │                  │   /bmw/platform/opt/.../key_aes_256.key)        │
  │             │                  │←─ IKeyHandler (raw key bytes) ─────────────────│
  │             │                  │                │               │               │
  │             │                  │── CreateKeyDataNode (child of ContextDataNode)  │
  │             │←─KeyBindResult───│                │               │               │
  │             │                  │                │               │               │
  │             │─InitializeContext(InitParams)─────────────────────────────────────→│
  │             │  {client_id, context_id,          │               │   EVP_MAC_fetch│
  │             │   provider_id, key_handler}       │               │   EVP_MAC_CTX  │
  │             │←─OK──────────────────────────────────────────────────────────────│
  │             │                  │                │               │               │
  │←─ctx_id────│                  │                │               │               │
```

### Phase 3: Streaming MAC Operations

```
Client              Daemon (OpenSslHmacHandler)
  │                        │
  │─── Init() ────────────→│── EVP_MAC_init(key_bytes, digest="SHA256")
  │←── OK ─────────────────│
  │                        │
  │─── Update(message) ───→│── EVP_MAC_update(data, len)
  │←── OK ─────────────────│
  │                        │
  │─── Finalize(output) ──→│── EVP_MAC_final() → 32-byte tag
  │←── HMAC-SHA256 tag ────│
  │                        │
  │  (Context goes out of scope → RAII cleanup)
  │                        │── Key zeroized when last ref drops
```

---

## Key Handling & Session Binding

### Session Node Hierarchy

Each connected client gets an isolated node tree in the `DataManager`:

```
CLIENT_ENTRY (per pid+uid)
├── ConnectionDataNode (connection_id)  ← lifetime: connection open→close
│   ├── ContextDataNode (MAC context)   ← lifetime: CreateMacContext→close
│   │   └── KeyDataNode (bound key)     ← lifetime: bound to context
│   └── ContextDataNode (HASH context)  ← (other contexts)
└── KeySlotDataNode (resolved slot)     ← lifetime: ResolveResource→release
```

### Key Material Lifecycle

| State | Trigger | Where | Description |
|-------|---------|-------|-------------|
| **Configured** | Daemon startup | SlotRegistry | `crypto_config.json` parsed, slots registered by name |
| **Resolved** | `ResolveResource()` | DataManager | Client gets `key_node_id` handle to KeySlotDataNode |
| **Loaded** | `LoadOrShare()` | Provider (FileBackedSlotHandler) | Key bytes read from `deployment_path`. Deduplicated: already-loaded keys are shared |
| **Bound** | `BindKeyToContext()` | DataManager | `KeyDataNode` created as child of `ContextDataNode`. Provider affinity enforced |
| **Active** | `InitializeContext()` | OpenSslHmacHandler | `EVP_MAC_CTX` initialized, key bytes accessible via `IKeyHandler` |
| **Released** | Context close / disconnect | DataManager + Provider | Cascade delete removes `KeyDataNode`. When ref count → 0, key material zeroized |

### Provider Resolution Strategy

Provider is determined **at context creation time**, not at MAC operation time:

1. **Key-Affinity Path** (used when key is provided):
   - KeySlotDataNode → SlotConfig → `provider_ids[0]` (primary provider)
   - This ensures the key's associated provider handles the operation

2. **Type-Based Path** (fallback when no key):
   - `ProviderType::kSoftware` → OpenSSL provider
   - `ProviderType::kHardware` → PKCS#11/SoftHSM provider

3. **Cross-Provider Guard**:
   - If `target_provider_id != slot_provider_id` → error
   - Prevents binding an OpenSSL key to a PKCS#11 handler (or vice versa)

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Key Isolation** | Key material never crosses IPC boundary; operations execute in daemon |
| **Provider Affinity** | Slot config determines provider, not client request |
| **Key Deduplication** | `LoadOrShare()` — same slot loaded once, shared via ref-count |
| **RAII Zeroization** | `IKeyHandler` destructor zeros key bytes on last reference drop |
| **Access Control** | `allowed_uids` in slot config checked during `ResolveResource()` |
| **Path Safety** | `IsDeploymentPathSafe()` rejects relative paths (must start with `/`) |
| **Session Isolation** | Each `client_id=(pid,uid)` has independent node tree |

---

## Configuration Files

### `crypto_config.json` (Slot Definition)

```json
{
  "slot_entries": [
    {
      "slot_name": "HMAC_SHA256_IntegrationTestKey_OpenSSL",
      "algorithm": "HMAC-SHA256",
      "allowed_operations": "C_Sign",
      "deployment_path": "/bmw/platform/opt/score_crypto_daemon/etc/integration_openssl_hmac.kv",
      "deployment_format": "RAW",
      "allowed_uids": [10038],
      "provider_names": ["openssl"]
    }
  ]
}
```

### `integration_openssl_hmac.kv` (Key Vector)

```
key_path=/bmw/platform/opt/score_crypto_daemon/etc/key_aes_256.key
```

### Important Constraints

- `deployment_path` and `key_path` **must be absolute** (starting with `/`)
- `IsDeploymentPathSafe()` rejects relative paths at daemon startup
- CWD for daemon on target: `/bmw/platform/opt/score_crypto_daemon/`

---

## Build & Deploy

```bash
# Build
bazel build --config=ipn10_qnx7 \
  //ecu/xpad/xpad-shared/packaging/ipnext:deployment_artifacts \
  --//ecu/xpad/xpad-shared/packaging/flags:debugconsole \
  --//ecu/xpad/xpad-shared/packaging/flags:dlt_output_enable=True

# Deploy
scp -r bazel-bin/ecu/xpad/xpad-shared/packaging/ipnext/isoc/safe_posix_platform/image/IPNext_HLOS_safe_posix_platform.tar.gz \
  QMGDT0L@clid2087666.muc:/home/qmgdt0l/Downloads/ugesh/poc

# On target
cd /bmw/platform/opt/score_crypto_daemon/
./bin/score_hmac_demo
```

---

## Demo Output (Expected)

```
═══════════════════════════════════════
  Demo: HMAC-SHA256 with slot-based keys on multiple provider
═══════════════════════════════════════
[Setup] Connecting to daemon
✓ IPC connection established
[Phase 1] Resolve KeySlot Resource
✓ Resolved KeySlot resource: HMAC_SHA256_IntegrationTestKey_OpenSSL
[Phase 2] Configure and Create MAC Context
- Algorithm: HMAC-SHA256
- With KeySlot: HMAC_SHA256_IntegrationTestKey_OpenSSL
- With Provider: OpenSSL (Software)
✓ MAC context created
✓ Key bound to context
[Phase 3] Streaming MAC computation
✓ Init
✓ Update
✓ Finalize
- Computed MAC: <32 bytes hex>
- Expected MAC: <32 bytes hex>
✓ Computed MAC matches expected test vector
```
