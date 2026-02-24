********
# Embedded Cedar PDP + Postgres ABAC governance 

## 1.1 Embedded Cedar PDP inside the Postgres backend

Remove the decentralized Cedar agent and execute authorization decisions inside the DB process.

**Key elements**
- **C bindings** (e.g., `libcedar`) and call Cedar evaluation from the extension.
- **decision caching** keyed by `(principal, action, resource, policy_version, attrs_version)`.

## 1.2 Postgres-native ABAC vocabulary and governance (control plane)

Make ABAC manageable by DBAs without relying on external control planes.

**Mechanism (no parser changes)**
- Store everything in **extension-managed tables**:
	- principals/objects, attributes, policies, policysets, bindings, audit logs  
- Expose a **DDL-like API via SQL functions**:
    - `abac_create_attribute(...)`
    - `abac_set_principal_attr(...)`
    - `abac_create_policyset(...)`
    - `abac_validate_policyset(...)`
    - `abac_activate_policyset(...)`
    - `abac_rollback_policyset(...)`
    - `abac_effective_policies(...)`
    - `abac_explain_decision(...)`

**Lifecycle (safe operations)**
- **Stage → Validate → Shadow → Activate** with atomic activation and rollback.

## 1.3 Transactional semantics for policy/attribute snapshots (MVCC-aligned)

Precisely define “which policy and attributes were used” for every query.

**Approach**
- Policysets are **versioned**; activation flips an “active pointer.”
- Enforcement reads policies/attrs under the query’s MVCC snapshot (statement-snapshot or transaction-snapshot semantics).
---

# 2) Client-side ABAC administration (recommended to avoid core parser modifications)

Since Postgres core does **not** support extensible parsing for new keywords (the “extensible parsing” patch was rejected), “real” ABAC DDL like `CREATE ATTRIBUTE ...` is not available without core patches. A client-side admin layer is the clean alternative.

## 2.1 ABAC admin CLI (`abacctl`) that compiles to canonical SQL

Provide a friendly DSL/commands while the DB remains authoritative.

**What it does**

- Accepts commands like:
    - `abacctl attribute create dept text`
    - `abacctl principal set alice dept=hr`
    - `abacctl policyset apply prod ./policies`
    - `abacctl validate prod`
    - `abacctl shadow prod`
    - `abacctl activate prod`
- Emits SQL function calls in a single transaction.

## 2.2 GitOps policy workflow

Reproducible policies, diffs, rollbacks.

**Features**
- `diff/apply/activate/rollback`
- policy version hashes and “what changed” reports
- staged rollout + shadow-mode mismatch reports
## 2.3 UI dashboard (thin client)

DBA/compliance-friendly interface without adding kernel code.
- view principals/attrs/policies
- manage staging/activation
- inspect audit logs and “why denied?”

**Important constraint**
- All activation authority stays in Postgres (RBAC on functions); UI is convenience only.

---

# 3) Minimal/no kernel modifications: feasibility statement

### What is feasible without core patches

- Embedded Cedar evaluation inside the backend via extension + C bindings
- ABAC catalogs, lifecycle, shadow mode, activation/rollback
- Table-level enforcement and most column-level enforcement
- Audit/explain functions
- Client-side CLI/GitOps/UI for administration

### Where core patches would be required

- **New SQL keywords/grammar** (`CREATE ATTRIBUTE ...`) → requires parser changes  
    - **Hack:** client-side DSL → SQL functions; optionally “piggyback” on existing statements (security labels/comments) for bindings.

---
# 4) Deliverables checklist

- Extension code (catalogs + SQL functions)
- `libcedar` integration (C ABI + PG extension interface)
- Admin CLI (`abacctl`) and GitOps repo format
- Benchmarks (pgbench + microbench)
- A conformance test suite for policy semantics and enforcement coverage
- Security/threat model + documented exclusions (superuser, certain extension/FDW boundaries)
