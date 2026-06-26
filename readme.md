# NDCrypt Security Review and Patch Notes

This branch documents and patches issues found during an authorized review of
NDCrypt's encryption and message transport layer.

The most important fix is that encrypted chunks now authenticate the plaintext
metadata that tells the receiver where a chunk belongs. Before this change, a
relay or active network attacker could move a valid encrypted chunk into a
different transfer or chunk slot without breaking the ciphertext tag.

Branch:

```text
codex/patch-authenticated-metadata-replay
```

Commit:

```text
5a283f1 Bind chunk metadata and reject replayed nonces
```

## Summary

### Fixed in this branch

- Message chunk metadata is now bound into the MAC as authenticated data.
- The browser client now rejects duplicate message nonces.
- WASM exposes explicit AAD encrypt/decrypt methods.
- Decryption failures in the AAD path are reported explicitly instead of being
  confused with valid empty plaintext.
- A runnable POC/regression test demonstrates the old relabeling attack and the
  patched rejection behavior.

### Still not fixed by this branch

- The key exchange still does not authenticate user identity.
- The cryptographic design is custom and should not be described as proven
  post-quantum secure.
- The raw WASM API still exposes caller-managed nonce methods for compatibility.
- The protocol remains very inefficient for large files because each encrypted
  point carries at most 31 bytes of plaintext.

## Architecture Reviewed

NDCrypt has two main cryptographic layers:

1. A custom Ring-LWE-style key encapsulation flow in Rust.
2. A coordinate-hiding symmetric message layer used after both peers derive a
   shared 32-byte seed.

The browser-facing Rust code is compiled to WebAssembly and used by the client
embedded in `server.py`. The Python server is a relay. It forwards public keys,
encapsulation ciphertexts, confirmations, nonces, plaintext chunk metadata, and
encrypted chunk arrays.

Important files:

```text
src/keygen.rs     Ring-LWE keypair generation
src/encrypt.rs    Seed encapsulation and FO-style deterministic re-encryption
src/decrypt.rs    Seed decapsulation and ciphertext validity check
src/gka.rs        Ring arithmetic, NTT multiplication, seed encoding, indices
src/ndcrypt.rs    Symmetric coordinate-hiding encryption and MAC
src/lib.rs        WASM API exposed to browser JavaScript
server.py         Relay server plus embedded browser client
```

Core parameters:

```text
N = 1024
Q = 12289
SIGNAL_COUNT = 32
Payload per point = 31 bytes
```

## Main Finding: Metadata Was Not Authenticated

### Vulnerable behavior

Before this patch, `compute_mac` in `src/ndcrypt.rs` authenticated:

```text
mac_key || nonce || ciphertext_coefficients
```

It did not authenticate the plaintext envelope fields sent next to the
ciphertext in `server.py`:

```json
{
  "kind": "data",
  "transferId": 10,
  "chunkIndex": 0,
  "totalChunks": 1,
  "totalBytes": 7,
  "nonce": 44,
  "array": [...]
}
```

Those fields control how the receiver buffers and reassembles decrypted chunks.
Because they were not covered by the MAC, an active relay could take a valid
ciphertext and change only the envelope:

```json
{
  "kind": "data",
  "transferId": 99,
  "chunkIndex": 3,
  "totalChunks": 4,
  "totalBytes": 7,
  "nonce": 44,
  "array": [...]
}
```

The ciphertext tag still verified because the encrypted array and nonce were
unchanged. The receiver would then place the plaintext into the attacker-chosen
transfer/chunk slot.

### Impact

An attacker controlling the relay could:

- Move a valid encrypted chunk into another transfer.
- Change whether a chunk is treated as `meta` or `data`.
- Reorder chunks by changing `chunkIndex`.
- Corrupt reassembly while still passing ciphertext authentication.
- Replay old valid chunks unless the nonce was tracked separately.

This did not reveal the shared seed directly, but it broke message integrity at
the protocol layer. Authenticated encryption must bind all metadata that affects
how plaintext is interpreted.

## Working POC

Run:

```powershell
cargo test poc_legacy_mac_allows_metadata_relabel_attack -- --nocapture
```

Expected output:

```text
POC vulnerable path: ciphertext for "{\"kind\":\"data\",\"transferId\":10,\"chunkIndex\":0,\"totalChunks\":1,\"totalBytes\":7}" was accepted after relabeling to "{\"kind\":\"data\",\"transferId\":99,\"chunkIndex\":3,\"totalChunks\":4,\"totalBytes\":7}"
POC patched path: relabeled metadata was rejected by the AAD MAC
```

The POC is implemented as a Rust test in `src/ndcrypt.rs`.

It demonstrates both sides:

1. Legacy behavior: `encrypt_authenticated` / `decrypt_authenticated` accept the
   ciphertext even though the surrounding metadata is relabeled, because the
   legacy MAC has no metadata input.
2. Patched behavior: `encrypt_authenticated_with_aad` /
   `decrypt_authenticated_with_aad` reject the same relabeling attempt with
   `AuthenticationFailed`.

## Patch Details

### 1. Added AAD MAC support

File:

```text
src/ndcrypt.rs
```

The MAC now has an AAD-aware path:

```text
mac_key || nonce || aad_length || aad || ciphertext_coefficients
```

The `aad_length` prefix prevents ambiguous concatenation between different AAD
byte strings.

New functions:

```rust
pub fn encrypt_authenticated_with_aad(
    payload: &[u8],
    seed: &[u8; 32],
    nonce: u64,
    aad: &[u8],
) -> Result<Vec<u16>, NdCryptError>

pub fn decrypt_authenticated_with_aad(
    cipher: &[u16],
    seed: &[u8; 32],
    nonce: u64,
    aad: &[u8],
) -> Result<Vec<u8>, NdCryptError>
```

The existing `encrypt_authenticated` and `decrypt_authenticated` functions still
exist for compatibility. They call the AAD versions with empty AAD.

### 2. Exposed AAD methods to WASM

File:

```text
src/lib.rs
```

New browser-facing methods:

```rust
pub fn encrypt_bytes_aad(
    &self,
    payload: &[u8],
    nonce: u32,
    aad: &[u8],
) -> Result<Vec<u16>, JsValue>

pub fn decrypt_bytes_aad(
    &self,
    cipher: &[u16],
    nonce: u32,
    aad: &[u8],
) -> Result<Vec<u8>, JsValue>
```

These return a `Result`, so authentication failure is distinguishable from a
valid empty plaintext.

### 3. Bound chunk metadata in the browser client

File:

```text
server.py
```

The embedded JavaScript client now constructs AAD from the chunk envelope:

```javascript
function chunkAad(kind, transferId, chunkIndex, totalChunks, totalBytes) {
  return encoder.encode(JSON.stringify({
    kind,
    transferId,
    chunkIndex,
    totalChunks,
    totalBytes: totalBytes == null ? null : totalBytes,
  }));
}
```

Encryption uses:

```javascript
cryptoEngine.encrypt_bytes_aad(chunks[i], myNonce, aad)
```

Decryption uses:

```javascript
cryptoEngine.decrypt_bytes_aad(arr, nonce, aad)
```

If an attacker changes `kind`, `transferId`, `chunkIndex`, `totalChunks`, or
`totalBytes`, the receiver derives different AAD and the MAC verification fails.

### 4. Added nonce replay rejection

File:

```text
server.py
```

The receiver tracks nonces seen in the current secure session:

```javascript
const seenNonces = new Set();
```

Incoming encrypted chunks are rejected if:

- `nonce` is not an integer.
- `nonce` is outside the application range.
- `nonce` has already been seen.

The set is cleared when a new key exchange is marked secure.

### 5. Added regression tests

File:

```text
src/ndcrypt.rs
```

Tests added:

```text
authenticated_metadata_must_match
empty_plaintext_is_distinct_from_authentication_failure
poc_legacy_mac_allows_metadata_relabel_attack
```

## Validation

Run:

```powershell
cargo test
```

Result:

```text
running 3 tests
test ndcrypt::tests::authenticated_metadata_must_match ... ok
test ndcrypt::tests::empty_plaintext_is_distinct_from_authentication_failure ... ok
test ndcrypt::tests::poc_legacy_mac_allows_metadata_relabel_attack ... ok

test result: ok. 3 passed; 0 failed
```

## Other Findings From Review

### Anonymous key exchange

The confirmation messages prove both peers derived the same session key. They do
not prove the human identity of the remote peer.

An active relay can still impersonate participants by starting independent
handshakes unless the application adds one of:

- Long-term signing keys.
- User-verifiable fingerprints.
- TOFU identity binding.
- Certificates or another external trust mechanism.

### Custom cryptography risk

NDCrypt uses a custom Ring-LWE-style KEM and custom message encryption layer.
Even if the design is inspired by post-quantum primitives, it should not be
described as proven post-quantum secure without:

- A concrete security reduction or parameter estimate.
- Independent cryptographic review.
- Test vectors.
- Side-channel analysis.
- Comparison against standardized schemes.

For production post-quantum key establishment, prefer a standardized KEM such
as ML-KEM.

### Nonce management remains sharp-edged

The internal `NdCryptSession` type increments nonces safely, but the public WASM
API still exposes raw nonce arguments for compatibility:

```rust
encrypt_bytes(payload, nonce)
decrypt_bytes(cipher, nonce)
encrypt_bytes_aad(payload, nonce, aad)
decrypt_bytes_aad(cipher, nonce, aad)
```

The browser client now increments and tracks nonces, but any external caller of
the raw WASM API can still misuse the cipher by reusing `(seed, nonce)`.

Recommended future improvement:

- Expose a stateful WASM session API that owns send and receive counters.
- Avoid exposing low-level nonce-taking encryption methods to application code.

### Metadata is still visible

This patch authenticates metadata. It does not hide metadata.

The relay can still observe:

- Packet timing.
- Transfer sizes.
- Number of chunks.
- Message frequency.
- Connection patterns.

### Expansion ratio

Each encrypted point carries at most 31 plaintext bytes and serializes to 1040
`u16` values after authentication. This is very large for file transfer. The
protocol is better suited to small messages than bulk data.

## Threat Model After This Patch

### The relay can still do

- Drop messages.
- Delay messages.
- Observe timing and chunk counts.
- Refuse connections.
- Attempt identity impersonation if users do not verify identities.

### The relay should no longer be able to do

- Relabel a valid chunk into a different transfer without detection.
- Reorder chunks by editing `chunkIndex` without detection.
- Change `kind`, `totalChunks`, or `totalBytes` without detection.
- Replay the same nonce within a secure browser session without detection.

## Recommended Next Steps

1. Add authenticated identity.
2. Replace the custom KEM with ML-KEM or clearly label this as experimental.
3. Move nonce ownership fully into WASM session state.
4. Add more tests for malformed ciphertexts, replay attempts, duplicate chunk
   indices, and end-to-end browser message handling.
5. Remove or clearly deprecate compatibility APIs that return empty plaintext on
   failure.

## How To Review This Branch

Run the POC:

```powershell
cargo test poc_legacy_mac_allows_metadata_relabel_attack -- --nocapture
```

Run the full test suite:

```powershell
cargo test
```

Inspect the patch:

```powershell
git show --stat
git show
```
