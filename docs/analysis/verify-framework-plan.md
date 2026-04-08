# Verification Framework — Redundancy & Correctness Plan

**Date:** 2026-04-08  
**Scope:** `src/bin/manifest_builder_service.rs` — `verify_manifest`, `verify_signatures`,
`verify_signatures_against_uploaded_content`, `verify_one_sig`; `src/models.rs` —
`VerifyResponse`, `VerifyRequest`, `VerificationCheck`

---

## Phase 0 — Documentation Discovery (COMPLETE)

All findings below come from direct source reading. No external docs apply; the code
is the specification.

### Key files read

| File | Lines examined | Purpose |
|------|---------------|---------|
| `src/models.rs` | 237–392 | `VerifyRequest`, `VerifyResponse`, `VerificationCheck`, `VerificationMetadata` |
| `manifest_builder_service.rs` | 456–1013 | `verify_manifest` handler — full verification pipeline |
| `manifest_builder_service.rs` | 1232–1451 | `verify_signatures` — stored-manifest signature pass |
| `manifest_builder_service.rs` | 1453–1667 | `verify_signatures_against_uploaded_content` — uploaded-content signature pass |
| `manifest_builder_service.rs` | 1669–1730 | `verify_one_sig` — generic per-algorithm helper |

### Allowed patterns

- `add_check(checks, "namespace.check_name", passed: bool, details: &str)` — sole way to push a `VerificationCheck`
- `verify_one_sig(signing_bytes, sig_b64, required, check_key, label, verify_fn, timing, checks, errors)` — generic per-algorithm helper
- `signatures_satisfy_service_profile(profile, sigs)` — profile conformance gate (in `models.rs`)

---

## Findings

### F1 — CORRECTNESS BUG: duplicate check names from `verify_one_sig` across both passes

`verify_one_sig` (L1669) hardcodes the check name prefix `"signature."`:

```rust
// L1689
add_check(checks, &format!("signature.{}_valid", check_key), …);
// L1724
add_check(checks, &format!("signature.{}_present", check_key), …);
```

It is called from **both** `verify_signatures` (stored-manifest pass) and
`verify_signatures_against_uploaded_content` (uploaded-content pass) with the same
`check_key` values (`"eddsa"`, `"ecdsa_p256"`, `"hmac_sha256"`, `"ml_dsa"`,
`"slh_dsa"`, `"fn_dsa"`).

When `provided_hash` is supplied, **both passes run**, so the `checks` Vec ends up
with two entries named `signature.eddsa_valid`, two entries named `signature.ml_dsa_valid`,
etc. Consumers (web UI, benchmark analyzer, audit log) cannot distinguish which entry
belongs to which pass.

RSA is handled **inline** in both functions, so RSA gets the correct names:
- `verify_signatures` → `"signature.rsa_pss_valid"`
- `verify_signatures_against_uploaded_content` → `"file.signature_rsa_pss_matches_uploaded_content"`

The six non-RSA algorithms using `verify_one_sig` in the uploaded-content pass should
emit `"file.signature_{key}_matches_uploaded_content"` but instead emit `"signature.{key}_valid"`.

### F2 — REDUNDANCY: ~220 lines of near-identical code in two functions

`verify_signatures` (L1232–1451) and `verify_signatures_against_uploaded_content`
(L1453–1667) are structurally identical. Differences:

| Aspect | `verify_signatures` | `verify_signatures_against_uploaded_content` |
|--------|--------------------|--------------------------------------------|
| Input `signing_bytes` | canonical bytes of stored manifest | re-canonicalized from caller-provided values |
| RSA check name | `signature.rsa_pss_valid` | `file.signature_rsa_pss_matches_uploaded_content` |
| Aggregation variable | `signature_ok` | `signature_match_uploaded_content` |
| Extra guard in aggregation | none | extra `is_none()` checks for non-required sigs |

Everything else — profile-flag computation, `verify_one_sig` calls, `SignatureTimingMetrics`
accumulation — is copy-pasted verbatim.

### F3 — CORRECTNESS BUG: `file_hash_match` double-counted in `overall_ok`

```rust
// L967–977
let overall_ok = signature_ok
    && object_ok
    && file_hash_match          // ← direct inclusion
    && provided_manifest_match  // ← = file_hash_match && size_match && algorithm_match && …
    && file_signature_match
    …;
```

`provided_manifest_match` is defined as:
```rust
let provided_manifest_match = file_hash_match && size_match && algorithm_match
    && immutable_object_id_match && storage_bucket_match && storage_key_match;
```

`file_hash_match` is ANDed into `overall_ok` twice. While boolean AND is idempotent
(so the _result_ is not wrong), the expression is misleading and `size_match`,
`algorithm_match`, etc. are only guarded via `provided_manifest_match`, creating
an inconsistent abstraction level.

### F4 — CORRECTNESS: misleading check name and `passed: true` for skipped object verification

```rust
// L694–701 — when verify_object = false
add_check(&mut checks, "storage.object_verification_requested", true,
    "Stored-object verification skipped for this benchmark scenario");
```

- The name `_requested` implies the check is asking "was this requested?" and passing
  means "yes, it was requested" — but the check fires precisely when it was **not** requested.
- `passed: true` for a skipped check is semantically wrong; it causes the check to
  appear green in any consumer that renders `passed`.

### F5 — NAMESPACE: storage coordinate checks under `file.*`

`file.provided_storage_bucket_match` (L839) and `file.provided_storage_key_match`
(L869) are about S3 storage coordinates, not file-derived content. They belong in the
`storage.*` namespace alongside `storage.object_size_within_verification_limit` and
`storage.object_verification_requested`.

### F6 — MINOR REDUNDANCY: `VerifyResponse.file_hash_match` top-level field

`VerifyResponse` exposes `file_hash_match: bool` as a named field (models.rs L264),
but this is already derivable from `checks` (look up `file.provided_hash_match`).
More importantly, `size_match`, `algorithm_match`, etc. get no equivalent top-level
field, making the API surface inconsistent. This is minor — keeping it for backwards
compat is fine — but worth noting.

---

## Implementation Phases

### Phase 1 — Fix duplicate check names (F1) — HIGH PRIORITY

**What:** Add a `check_prefix: &str` parameter to `verify_one_sig` so callers can
control whether checks land under `"signature."` or `"file."`.

**File:** `src/bin/manifest_builder_service.rs`

**Change `verify_one_sig` signature:**
```rust
fn verify_one_sig(
    signing_bytes: &[u8],
    sig_b64: Option<&str>,
    required: bool,
    check_key: &str,
    label: &str,
    verify_fn: impl Fn(&[u8], &str) -> Result<bool>,
    timing: &mut Option<f64>,
    checks: &mut Vec<VerificationCheck>,
    errors: &mut Vec<String>,
    check_prefix: &str,   // NEW — e.g. "signature" or "file.signature"
) -> bool
```

**Update check name lines inside `verify_one_sig`:**
```rust
// was: &format!("signature.{}_valid", check_key)
&format!("{}.{}_valid", check_prefix, check_key)

// was: &format!("signature.{}_present", check_key)
&format!("{}.{}_present", check_prefix, check_key)
```

**Update all callers in `verify_signatures`** — pass `"signature"`:
```rust
verify_one_sig(…, checks, errors, "signature")
```

**Update all callers in `verify_signatures_against_uploaded_content`** — pass
`"file.signature"`:
```rust
verify_one_sig(…, checks, errors, "file.signature")
```

The non-RSA check names in the uploaded-content pass become:
- `file.signature.eddsa_valid`
- `file.signature.ecdsa_p256_valid`
- etc.

This mirrors the RSA inline check name `file.signature_rsa_pss_matches_uploaded_content`
in spirit (though the format is slightly different — optionally align RSA to the same
pattern in the same PR).

**Verification checklist:**
- Grep for `"signature.{}_valid"` — should only appear in `verify_one_sig` (via the
  format! template), and only when `check_prefix == "signature"`.
- Grep for `"file.signature"` — should appear for all 6 non-RSA algorithms in the
  uploaded-content pass.
- No duplicate check names when both passes run (test by constructing a `VerifyRequest`
  with `provided_hash` set).

**Anti-patterns to avoid:**
- Do NOT change the check names for the stored-manifest pass (`verify_signatures`) —
  these are stable and may be consumed by the benchmark analyzer.
- Do NOT rename the RSA inline block in `verify_signatures_against_uploaded_content`
  without also updating any consumers.

---

### Phase 2 — Eliminate function duplication (F2) — MEDIUM PRIORITY

**What:** Merge `verify_signatures` and `verify_signatures_against_uploaded_content`
into a single `verify_signatures_inner` (or keep two thin wrappers that call a shared
core). After Phase 1 the only structural difference is `check_prefix` and the extra
`is_none()` guards in the uploaded-content aggregation.

**Approach:** Extract a shared function:
```rust
fn run_signature_verification(
    signed: &SignedManifest,
    signing_bytes: &[u8],
    checks: &mut Vec<VerificationCheck>,
    errors: &mut Vec<String>,
    check_prefix: &str,             // "signature" or "file.signature"
    enforce_no_extra_sigs: bool,    // true for uploaded-content pass
) -> (bool, SignatureTimingMetrics)
```

Keep `verify_signatures` and `verify_signatures_against_uploaded_content` as thin
wrappers delegating to this inner function. This preserves the public call-sites in
`verify_manifest`.

**RSA inline block:** Parameterise the RSA check name too:
```rust
let rsa_check_name = if check_prefix == "signature" {
    "signature.rsa_pss_valid".to_string()
} else {
    format!("{}.rsa_pss_matches_uploaded_content", check_prefix)
};
```

Or simply pass a format string. Keep it simple — a `check_prefix` string is enough.

**Verification checklist:**
- Both thin wrappers produce identical check sequences as before Phase 2.
- `verify_manifest` call-sites unchanged.
- Run `cargo build` with no warnings.

**Anti-patterns to avoid:**
- Do not merge the two wrappers into one exported function and force callers to pass
  a boolean mode flag — keep the existing named call-sites.

---

### Phase 3 — Fix `overall_ok` double-counting of `file_hash_match` (F3)

**What:** Remove the standalone `&& file_hash_match` from `overall_ok`; rely solely
on `provided_manifest_match` (which already contains it).

**File:** `src/bin/manifest_builder_service.rs`, L967–977

```rust
// Before
let overall_ok = signature_ok
    && object_ok
    && file_hash_match          // ← remove this line
    && provided_manifest_match
    && file_signature_match
    && request_id_match
    && created_at_not_future
    && not_expired
    && not_revoked
    && algorithm_supported
    && errors.is_empty();

// After
let overall_ok = signature_ok
    && object_ok
    && provided_manifest_match
    && file_signature_match
    && request_id_match
    && created_at_not_future
    && not_expired
    && not_revoked
    && algorithm_supported
    && errors.is_empty();
```

`VerifyResponse.file_hash_match` field remains — it is still set from the `file_hash_match`
variable (which is part of `provided_manifest_match`). No API change.

**Verification checklist:**
- `overall_ok` is `false` iff any of its constituent variables are `false` — unchanged
  semantics (double-AND is idempotent, so no behaviour change).
- `VerifyResponse.file_hash_match` still populated correctly.

---

### Phase 4 — Fix misleading skipped-object check (F4)

**File:** `src/bin/manifest_builder_service.rs`, L694–701

```rust
// Before
add_check(&mut checks, "storage.object_verification_requested", true,
    "Stored-object verification skipped for this benchmark scenario");

// After
add_check(&mut checks, "storage.object_verification_skipped", true,
    "Stored-object verification not requested; check skipped");
```

`passed: true` is acceptable here because the check is informational — skipping is
not a failure. But the name must not say `_requested` when the feature was deliberately
not requested.

**Verification checklist:**
- Grep for `"storage.object_verification_requested"` — should be zero after change.
- Any consumer (web UI, benchmark CLI, tests) using this exact check name must be
  updated to `"storage.object_verification_skipped"`.

**Anti-patterns:** Do not change to `passed: false` — that would cause `overall_ok`
to be `false` when object verification is intentionally skipped (benchmark scenario).

---

### Phase 5 — Fix `file.*` namespace for storage checks (F5)

**File:** `src/bin/manifest_builder_service.rs`, L829–887

Rename:
- `"file.provided_storage_bucket_match"` → `"storage.provided_bucket_match"`
- `"file.provided_storage_key_match"` → `"storage.provided_key_match"`

Update the rollup check that references them to include storage coords under the
`file.provided_manifest_attributes_match` summary (logic unchanged — `storage_bucket_match`
and `storage_key_match` variables still feed `provided_manifest_match`).

**Verification checklist:**
- Grep for `"file.provided_storage_bucket_match"` and `"file.provided_storage_key_match"`
  — both should be zero.
- Any consumer filtering on these check names must be updated.
- `provided_manifest_match` boolean logic unchanged.

---

### Phase 6 — Final verification pass

1. `cargo build` — zero warnings.
2. Grep for `"signature\."` in checks emitted during the uploaded-content pass — should
   be zero (all should be `"file.signature."` or equivalent).
3. Grep for duplicate check names — no two `add_check` calls in the same execution
   path should produce the same name string.
4. Review `VerifyResponse` struct fields against the check list — confirm
   `file_hash_match`, `signature_ok`, `object_ok`, `overall_ok` all semantically
   match the check names visible to consumers.
5. If tests exist under `tests/` — run them and confirm green.

---

## Summary Table

| # | Issue | Type | Priority | Phase |
|---|-------|------|----------|-------|
| F1 | Duplicate `signature.*` names in uploaded-content pass | Correctness bug | High | 1 |
| F2 | ~220 lines of duplicate code across two verify functions | Redundancy | Medium | 2 |
| F3 | `file_hash_match` double-counted in `overall_ok` | Semantic redundancy | Low | 3 |
| F4 | `storage.object_verification_requested` — wrong name & misleading `passed` | Correctness | Medium | 4 |
| F5 | Storage coordinate checks under `file.*` namespace | Namespace clarity | Low | 5 |
| F6 | `VerifyResponse.file_hash_match` inconsistent top-level field | Minor API smell | Info only | — |
