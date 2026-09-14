# CHAKRAVYUH v1.0.0 — API Stability & Deprecation Discipline

> Effective: 2026-08-05
> Applies to: All `pub` types, functions, traits, and methods in the `chakravyuh` crate
> Canonical API surface: [`docs/api_surface_v1.md`](api_surface_v1.md)

---

## 1. Core Freeze Policy

As of v1.0.0, the CHAKRAVYUH public API surface is **frozen**. This means:

1. **No signature changes** — The parameter list, return type, generic bounds, and
   visibility of every `pub fn`, `pub struct`, `pub enum`, and `pub trait` documented
   in `api_surface_v1.md` MUST NOT change.

2. **No new rings** — The 9-ring architecture (Shield → Identity → Threat →
   Execution → Agent → Memory → Reasoning → Governance → RecoverySec) is locked.
   No new top-level ring modules may be added.

3. **No new public types** — No new `pub struct`, `pub enum`, `pub trait`, or `pub fn`
   may be added to the public API without following the deprecation process below.

4. **No behavioral changes** — The semantic meaning of existing functions and methods
   must not change. A function that returns `Allow` today must not silently start
   returning `Deny` in a patch release.

---

## 2. Versioning Scheme

CHAKRAVYUH follows [Semantic Versioning 2.0.0](https://semver.org/):

| Bump | When |
|---|---|
| **Patch** (1.0.x) | Bug fixes, internal refactors, documentation. Zero public API change. |
| **Minor** (1.x.0) | New `pub` types/functions added via `v2` module path or non-breaking additions. |
| **Major** (2.0.0) | Any signature change, removal, or breaking behavioral change to frozen APIs. |

### Version Locking

- `Cargo.toml` version is the single source of truth.
- Git tags MUST match Cargo.toml version exactly (`v1.0.0`, `v1.1.0`, etc.).
- Pre-release versions use `-rc.N` suffix (e.g., `1.1.0-rc.1`).

---

## 3. Change Classification

Every proposed change MUST be classified before implementation:

### 3.1 Non-Breaking (Patch)

- Fixing a bug where the API behaved contrary to its documented contract
- Performance improvements that do not change observable behavior
- Adding new **private** helper functions or modules
- Adding/fixing tests
- Documentation updates
- Internal refactoring (renaming private types, restructuring modules)

**Process**: Standard PR with 2 reviewer approvals.

### 3.2 Additive (Minor)

- Adding a new `pub` type in a **new submodule** (not modifying existing)
- Adding a new `pub fn` to an existing type (only if it doesn't conflict)
- Adding a new enum variant to a **non-exhaustive** enum
- Adding a new feature flag that defaults to off

**Process**:
1. RFC document describing the addition
2. API review to ensure no existing signature is affected
3. Update `api_surface_v1.md` with the new entries
4. Bump minor version

### 3.3 Breaking (Major)

- Changing any function signature in `api_surface_v1.md`
- Removing any `pub` type, function, trait, or method
- Changing the behavior of an existing function (e.g., different return values for same inputs)
- Renaming any public type or function
- Changing the variant set of an exhaustive enum
- Modifying struct field visibility or types
- Changing trait method signatures

**Process**:
1. **Deprecation cycle** (see Section 4) — the old API MUST remain functional for at
   least one minor release with compiler warnings
2. RFC document with migration guide
3. Two-release deprecation window minimum
4. Bump major version

---

## 4. Deprecation Protocol

### 4.1 Marking Deprecated

```rust
#[deprecated(
    since = "1.1.0",
    note = "Use `new_method` instead. See migration guide: docs/migration/v1_to_v2.md"
)]
pub fn old_method(&self) -> OldReturn {
    // ... existing implementation unchanged ...
}
```

Rules:
- Every deprecated item MUST have `since`, `note`, and an RFC reference
- The `note` field MUST point to the replacement and a migration guide
- Deprecated items MUST continue to compile and pass all existing tests
- `#[allow(deprecated)]` is acceptable in test code

### 4.2 Deprecation Timeline

``nv1.0.0  ── Frozen API surface
v1.1.0  ── New API added, old API marked #[deprecated]
v1.2.0  ── Deprecation warning active for >=1 full minor cycle
v2.0.0  ── Deprecated API removed (minimum 2 minor releases after deprecation)
```

### 4.3 Removal

- Removal requires a major version bump
- A compile-time error MUST replace the deprecation warning
- The migration guide MUST be updated to reflect the final state
- Any downstream crate depending on the removed API will fail to compile — this is
  intentional and expected

---

## 5. The `v2` Module Pattern

For additions that anticipate future breaking changes, use a versioned module:

```rust
// In src/lib.rs or appropriate module
#[cfg(feature = "v2-api")]
pub mod v2 {
    /// Next-generation policy evaluation. Will replace `keshav::decide::evaluate` in v2.0.0.
    pub fn evaluate_v2(/* ... */) -> V2Decision {
        // ...
    }
}
```

Rules:
- `v2` module MUST be gated behind a feature flag (`v2-api`)
- `v2` APIs are explicitly **not stable** — they may change without deprecation
- When v2.0.0 ships, `v2` contents move to their final module paths
- Documentation MUST clearly mark v2 APIs as "unstable / preview"

---

## 6. Internal Stability (Non-Public)

Items that are NOT `pub` (private functions, `pub(crate)` items, `pub(super)` items)
 are not covered by this policy. However:

- Changing a `pub(crate)` item that is used across module boundaries requires a
  module-owner review
- Renaming private types should be done carefully to avoid breaking `#[cfg(test)]`
  code
- Internal APIs should still document their contracts

---

## 7. Safety Invariants (Immutable)

The following safety properties are permanent invariants — they MUST NOT be relaxed
in any version:

1. **`#![deny(unsafe_code)]`** at crate root — NO unsafe blocks in the entire codebase
2. **Zero production `unwrap()`/`expect()`** — All fallible operations return `Result` or
   use `?` propagation. Test code may use unwrap/expect freely.
3. **No panics in production paths** — Ring evaluation, Keshav decide, ANANTA loops
   must never panic. Use `std::panic::catch_unwind` at loop boundaries if needed.

These invariants are enforced by CI and may NOT be disabled even behind feature flags.

---

## 8. Compliance Checklist

Before any PR merging:

- [ ] Does this change any signature in `api_surface_v1.md`? → If yes, stop. Follow breaking change process.
- [ ] Does this add new `pub` items? → If yes, follow additive change process.
- [ ] Does this remove deprecated items? → If yes, confirm major version bump.
- [ ] Does this change observable behavior? → If yes, follow breaking change process.
- [ ] Does this maintain `deny(unsafe_code)`? → Must be yes.
- [ ] Does this maintain zero production unwrap/expect? → Must be yes.
- [ ] Is `api_surface_v1.md` updated if needed? → Required for any additive change.
- [ ] Is `Cargo.toml` version bumped correctly? → Follow semver rules.

---

## 9. Emergency Security Fixes

If a critical security vulnerability requires breaking the API:

1. An emergency patch may be released as `1.0.x-security.N` (pre-release)
2. The fix MUST include a migration path
3. A full deprecation cycle MUST still follow for the permanent fix
4. The security advisory MUST document the API impact

---

## 10. Review Authority

- **API changes** (additive/breaking): 2 maintainers + 1 API owner
- **Deprecation**: 2 maintainers
- **Emergency security**: 1 maintainer (fast-track, retroactive review within 72h)
- **Internal (non-pub) changes**: 1 reviewer

---

*This policy is effective immediately upon v1.0.0 release. All contributors MUST
read and acknowledge this document before submitting PRs that touch public APIs.*