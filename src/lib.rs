//! libcedar — C bindings for the Cedar policy engine
//!
//! Provides an opaque `CedarEngine` handle that wraps the `cedar-policy` crate's
//! `Authorizer`, `PolicySet`, `Entities`, and `Schema` types behind a C ABI.
//!
//! # Thread Safety
//!
//! Each `CedarEngine` instance is **not** thread-safe. In the PostgreSQL context
//! this is fine because each backend process gets its own instance.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema};

// ---------------------------------------------------------------------------
// Public C types
// ---------------------------------------------------------------------------

/// Decision returned by `cedar_engine_is_authorized`.
///
/// - `Allow  = 0`
/// - `Deny   = 1`
/// - `Error  = -1` (query could not be evaluated; check `cedar_engine_last_error`)
#[repr(C)]
pub enum CedarDecision {
    Allow = 0,
    Deny = 1,
    Error = -1,
}

// ---------------------------------------------------------------------------
// Internal engine state (opaque to C)
// ---------------------------------------------------------------------------

/// Opaque engine handle. Never exposed to C directly — only via `*mut CedarEngine`.
pub struct CedarEngine {
    authorizer: Authorizer,
    policies: PolicySet,
    /// Raw policy source text, kept for `add_policies` to re-parse the combined text.
    policies_source: String,
    entities: Entities,
    schema: Option<Schema>,
    last_error: Option<CString>,
    last_diagnostics: Option<CString>,
}

impl CedarEngine {
    fn new() -> Self {
        CedarEngine {
            authorizer: Authorizer::new(),
            policies: PolicySet::new(),
            policies_source: String::new(),
            entities: Entities::empty(),
            schema: None,
            last_error: None,
            last_diagnostics: None,
        }
    }

    fn set_error(&mut self, msg: String) {
        self.last_error = CString::new(msg).ok();
    }

    fn clear_error(&mut self) {
        self.last_error = None;
    }
}

// ---------------------------------------------------------------------------
// Helper: safely convert a `*const c_char` to a `&str`
// ---------------------------------------------------------------------------

unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|e| format!("invalid UTF-8: {e}"))
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Create a new Cedar engine.
///
/// Returns an opaque pointer. The caller **must** eventually call
/// `cedar_engine_free` to release the memory.
///
/// Returns `NULL` on allocation failure (should never happen in practice).
#[no_mangle]
pub extern "C" fn cedar_engine_new() -> *mut CedarEngine {
    Box::into_raw(Box::new(CedarEngine::new()))
}

/// Destroy a Cedar engine and free all associated memory.
///
/// Passing `NULL` is safe (no-op).
#[no_mangle]
pub extern "C" fn cedar_engine_free(engine: *mut CedarEngine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

/// Load Cedar policies from a policy text string (Cedar syntax).
///
/// The existing policy set is **replaced** entirely.
///
/// # Returns
/// - `0` on success
/// - `-1` on error (call `cedar_engine_last_error` for details)
#[no_mangle]
pub extern "C" fn cedar_engine_set_policies(
    engine: *mut CedarEngine,
    policies_text: *const c_char,
) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();

    let text = match unsafe { cstr_to_str(policies_text) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("policies_text: {e}"));
            return -1;
        }
    };

    match text.parse::<PolicySet>() {
        Ok(ps) => {
            engine.policies = ps;
            engine.policies_source = text.to_string();
            0
        }
        Err(e) => {
            engine.set_error(format!("policy parse error: {e}"));
            -1
        }
    }
}

/// Add (append) Cedar policies from a policy text string.
///
/// Unlike `cedar_engine_set_policies`, this does **not** replace existing
/// policies — the new policies are merged into the current set by
/// re-parsing the combined policy text.
///
/// # Returns
/// - The number of new policies added on success (>= 0)
/// - `-1` on error
#[no_mangle]
pub extern "C" fn cedar_engine_add_policies(
    engine: *mut CedarEngine,
    policies_text: *const c_char,
) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();

    let text = match unsafe { cstr_to_str(policies_text) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("policies_text: {e}"));
            return -1;
        }
    };

    // Count existing policies before merge
    let old_count = engine.policies.policies().count() + engine.policies.templates().count();

    // Concatenate old + new policy text and re-parse to avoid ID collisions
    let combined = format!("{}\n{}", engine.policies_source, text);
    match combined.parse::<PolicySet>() {
        Ok(ps) => {
            let new_count = ps.policies().count() + ps.templates().count();
            engine.policies = ps;
            engine.policies_source = combined;
            (new_count - old_count) as i32
        }
        Err(e) => {
            engine.set_error(format!("policy parse error: {e}"));
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Schema management
// ---------------------------------------------------------------------------

/// Set the Cedar schema from a JSON string.
///
/// The schema is used for request validation and entity parsing.
/// Pass `NULL` to clear the schema.
///
/// # Returns
/// - `0` on success
/// - `-1` on error
#[no_mangle]
pub extern "C" fn cedar_engine_set_schema_json(
    engine: *mut CedarEngine,
    schema_json: *const c_char,
) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();

    if schema_json.is_null() {
        engine.schema = None;
        return 0;
    }

    let json_str = match unsafe { cstr_to_str(schema_json) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("schema_json: {e}"));
            return -1;
        }
    };

    let json_value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            engine.set_error(format!("schema JSON parse error: {e}"));
            return -1;
        }
    };

    match Schema::from_json_value(json_value) {
        Ok(schema) => {
            engine.schema = Some(schema);
            0
        }
        Err(e) => {
            engine.set_error(format!("schema error: {e}"));
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Entity management
// ---------------------------------------------------------------------------

/// Set the entity store from a JSON string (Cedar entity JSON format).
///
/// The existing entity store is **replaced** entirely.
///
/// # Returns
/// - `0` on success
/// - `-1` on error
#[no_mangle]
pub extern "C" fn cedar_engine_set_entities_json(
    engine: *mut CedarEngine,
    entities_json: *const c_char,
) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();

    let json_str = match unsafe { cstr_to_str(entities_json) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("entities_json: {e}"));
            return -1;
        }
    };

    let json_value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            engine.set_error(format!("entities JSON parse error: {e}"));
            return -1;
        }
    };

    match Entities::from_json_value(json_value, engine.schema.as_ref()) {
        Ok(entities) => {
            engine.entities = entities;
            0
        }
        Err(e) => {
            engine.set_error(format!("entities error: {e}"));
            -1
        }
    }
}

/// Clear all entities from the store.
#[no_mangle]
pub extern "C" fn cedar_engine_clear_entities(engine: *mut CedarEngine) {
    if engine.is_null() {
        return;
    }
    let engine = unsafe { &mut *engine };
    engine.entities = Entities::empty();
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Evaluate an authorization request.
///
/// All string parameters use Cedar entity UID syntax:
/// - `principal`: e.g. `User::"alice"` or `MyApp::User::"alice"`
/// - `action`:    e.g. `Action::"SELECT"` or `MyApp::Action::"view"`
/// - `resource`:  e.g. `Table::"public.employees"`
/// - `context_json`: JSON object for the request context, or `NULL` for empty context
///
/// # Returns
/// - `CedarDecision::Allow` (0) if the request is allowed
/// - `CedarDecision::Deny` (1) if the request is denied
/// - `CedarDecision::Error` (-1) if the request could not be evaluated
#[no_mangle]
pub extern "C" fn cedar_engine_is_authorized(
    engine: *mut CedarEngine,
    principal: *const c_char,
    action: *const c_char,
    resource: *const c_char,
    context_json: *const c_char,
) -> CedarDecision {
    if engine.is_null() {
        return CedarDecision::Error;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();
    engine.last_diagnostics = None;

    // Parse principal
    let principal_str = match unsafe { cstr_to_str(principal) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("principal: {e}"));
            return CedarDecision::Error;
        }
    };
    let principal_euid = match EntityUid::from_str(principal_str) {
        Ok(euid) => euid,
        Err(e) => {
            engine.set_error(format!("principal parse error: {e}"));
            return CedarDecision::Error;
        }
    };

    // Parse action
    let action_str = match unsafe { cstr_to_str(action) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("action: {e}"));
            return CedarDecision::Error;
        }
    };
    let action_euid = match EntityUid::from_str(action_str) {
        Ok(euid) => euid,
        Err(e) => {
            engine.set_error(format!("action parse error: {e}"));
            return CedarDecision::Error;
        }
    };

    // Parse resource
    let resource_str = match unsafe { cstr_to_str(resource) } {
        Ok(s) => s,
        Err(e) => {
            engine.set_error(format!("resource: {e}"));
            return CedarDecision::Error;
        }
    };
    let resource_euid = match EntityUid::from_str(resource_str) {
        Ok(euid) => euid,
        Err(e) => {
            engine.set_error(format!("resource parse error: {e}"));
            return CedarDecision::Error;
        }
    };

    // Parse context
    let context = if context_json.is_null() {
        Context::empty()
    } else {
        let ctx_str = match unsafe { cstr_to_str(context_json) } {
            Ok(s) => s,
            Err(e) => {
                engine.set_error(format!("context_json: {e}"));
                return CedarDecision::Error;
            }
        };
        let ctx_value: serde_json::Value = match serde_json::from_str(ctx_str) {
            Ok(v) => v,
            Err(e) => {
                engine.set_error(format!("context JSON parse error: {e}"));
                return CedarDecision::Error;
            }
        };
        // v4.9.0: Context::from_json_value takes Option<(&Schema, &EntityUid)>
        // We pass the action_euid so schema-based context validation works.
        let schema_and_action = engine.schema.as_ref().map(|s| (s, &action_euid));
        match Context::from_json_value(ctx_value, schema_and_action) {
            Ok(c) => c,
            Err(e) => {
                engine.set_error(format!("context error: {e}"));
                return CedarDecision::Error;
            }
        }
    };

    // Build the request
    let request = match Request::new(
        principal_euid,
        action_euid,
        resource_euid,
        context,
        engine.schema.as_ref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            engine.set_error(format!("request error: {e}"));
            return CedarDecision::Error;
        }
    };

    // Evaluate
    let response = engine
        .authorizer
        .is_authorized(&request, &engine.policies, &engine.entities);

    // Store diagnostics
    let diag = response.diagnostics();
    let reasons: Vec<String> = diag.reason().map(|r| r.to_string()).collect();
    let errors: Vec<String> = diag.errors().map(|e| e.to_string()).collect();
    let diag_str = format!(
        "{{\"reasons\":[{}],\"errors\":[{}]}}",
        reasons
            .iter()
            .map(|r| format!("\"{}\"", r.replace('\"', "\\\"")))
            .collect::<Vec<_>>()
            .join(","),
        errors
            .iter()
            .map(|e| format!("\"{}\"", e.replace('\"', "\\\"")))
            .collect::<Vec<_>>()
            .join(","),
    );
    engine.last_diagnostics = CString::new(diag_str).ok();

    match response.decision() {
        cedar_policy::Decision::Allow => CedarDecision::Allow,
        cedar_policy::Decision::Deny => CedarDecision::Deny,
    }
}

// ---------------------------------------------------------------------------
// Error / diagnostics retrieval
// ---------------------------------------------------------------------------

/// Get the last error message.
///
/// Returns a pointer to a null-terminated C string, or `NULL` if no error is set.
/// The pointer is valid until the next call to any `cedar_engine_*` function on
/// the same engine.
#[no_mangle]
pub extern "C" fn cedar_engine_last_error(engine: *const CedarEngine) -> *const c_char {
    if engine.is_null() {
        return std::ptr::null();
    }
    let engine = unsafe { &*engine };
    match &engine.last_error {
        Some(cstr) => cstr.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Clear the last error.
#[no_mangle]
pub extern "C" fn cedar_engine_clear_error(engine: *mut CedarEngine) {
    if engine.is_null() {
        return;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();
}

/// Get diagnostics from the last `cedar_engine_is_authorized` call.
///
/// Returns a pointer to a null-terminated JSON string containing `reasons`
/// and `errors` arrays, or `NULL` if no authorization has been performed.
///
/// Example output: `{"reasons":["policy0"],"errors":[]}`
///
/// The pointer is valid until the next call to `cedar_engine_is_authorized`
/// or `cedar_engine_free`.
#[no_mangle]
pub extern "C" fn cedar_engine_get_diagnostics(engine: *const CedarEngine) -> *const c_char {
    if engine.is_null() {
        return std::ptr::null();
    }
    let engine = unsafe { &*engine };
    match &engine.last_diagnostics {
        Some(cstr) => cstr.as_ptr(),
        None => std::ptr::null(),
    }
}

// ---------------------------------------------------------------------------
// Convenience: policy validation
// ---------------------------------------------------------------------------

/// Validate the current policy set against the loaded schema.
///
/// # Returns
/// - `0` if validation passes (or no schema is loaded)
/// - `-1` if validation fails (call `cedar_engine_last_error` for details)
#[no_mangle]
pub extern "C" fn cedar_engine_validate(engine: *mut CedarEngine) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let engine = unsafe { &mut *engine };
    engine.clear_error();

    let schema = match &engine.schema {
        Some(s) => s,
        None => return 0, // No schema → nothing to validate against
    };

    let validator = cedar_policy::Validator::new(schema.clone());
    let result = validator.validate(&engine.policies, cedar_policy::ValidationMode::default());

    if result.validation_passed() {
        0
    } else {
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        let warnings: Vec<String> = result
            .validation_warnings()
            .map(|w| w.to_string())
            .collect();
        let mut msg = String::from("validation failed: ");
        if !errors.is_empty() {
            msg.push_str(&format!("errors: [{}]", errors.join("; ")));
        }
        if !warnings.is_empty() {
            if !errors.is_empty() {
                msg.push_str(", ");
            }
            msg.push_str(&format!("warnings: [{}]", warnings.join("; ")));
        }
        engine.set_error(msg);
        -1
    }
}

// ---------------------------------------------------------------------------
// Unit tests (run with `cargo test`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_engine_lifecycle() {
        let engine = cedar_engine_new();
        assert!(!engine.is_null());
        cedar_engine_free(engine);
    }

    #[test]
    fn test_free_null_is_safe() {
        cedar_engine_free(std::ptr::null_mut());
    }

    #[test]
    fn test_simple_allow() {
        let engine = cedar_engine_new();

        let policy = CString::new(
            r#"permit(principal == User::"alice", action == Action::"view", resource == File::"93");"#,
        )
        .unwrap();
        let rc = cedar_engine_set_policies(engine, policy.as_ptr());
        assert_eq!(rc, 0, "set_policies should succeed");

        let principal = CString::new(r#"User::"alice""#).unwrap();
        let action = CString::new(r#"Action::"view""#).unwrap();
        let resource = CString::new(r#"File::"93""#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            std::ptr::null(),
        );
        assert!(matches!(decision, CedarDecision::Allow));

        cedar_engine_free(engine);
    }

    #[test]
    fn test_simple_deny() {
        let engine = cedar_engine_new();

        let policy = CString::new(
            r#"permit(principal == User::"alice", action == Action::"view", resource == File::"93");"#,
        )
        .unwrap();
        cedar_engine_set_policies(engine, policy.as_ptr());

        // Bob is not alice → should be denied
        let principal = CString::new(r#"User::"bob""#).unwrap();
        let action = CString::new(r#"Action::"view""#).unwrap();
        let resource = CString::new(r#"File::"93""#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            std::ptr::null(),
        );
        assert!(matches!(decision, CedarDecision::Deny));

        cedar_engine_free(engine);
    }

    #[test]
    fn test_policy_parse_error() {
        let engine = cedar_engine_new();

        let policy = CString::new("this is not valid cedar").unwrap();
        let rc = cedar_engine_set_policies(engine, policy.as_ptr());
        assert_eq!(rc, -1);

        let err = cedar_engine_last_error(engine);
        assert!(!err.is_null());
        let err_str = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(
            err_str.contains("parse error") || err_str.contains("policy"),
            "unexpected error: {err_str}"
        );

        cedar_engine_free(engine);
    }

    #[test]
    fn test_context_json() {
        let engine = cedar_engine_new();

        let policy = CString::new(
            r#"permit(principal, action, resource) when { context.role == "admin" };"#,
        )
        .unwrap();
        cedar_engine_set_policies(engine, policy.as_ptr());

        let principal = CString::new(r#"User::"alice""#).unwrap();
        let action = CString::new(r#"Action::"view""#).unwrap();
        let resource = CString::new(r#"File::"93""#).unwrap();
        let context = CString::new(r#"{"role": "admin"}"#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            context.as_ptr(),
        );
        assert!(matches!(decision, CedarDecision::Allow));

        // Non-admin should be denied
        let context2 = CString::new(r#"{"role": "viewer"}"#).unwrap();
        let decision2 = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            context2.as_ptr(),
        );
        assert!(matches!(decision2, CedarDecision::Deny));

        cedar_engine_free(engine);
    }

    #[test]
    fn test_entities_json() {
        let engine = cedar_engine_new();

        // Policy: allow if principal is in group "admins"
        let policy =
            CString::new(r#"permit(principal in Group::"admins", action, resource);"#).unwrap();
        cedar_engine_set_policies(engine, policy.as_ptr());

        // Entity: alice is a member of admins group
        let entities = CString::new(
            r#"[
                {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": [{"type": "Group", "id": "admins"}]},
                {"uid": {"type": "Group", "id": "admins"}, "attrs": {}, "parents": []}
            ]"#,
        )
        .unwrap();
        let rc = cedar_engine_set_entities_json(engine, entities.as_ptr());
        assert_eq!(rc, 0, "set_entities should succeed");

        let principal = CString::new(r#"User::"alice""#).unwrap();
        let action = CString::new(r#"Action::"view""#).unwrap();
        let resource = CString::new(r#"File::"93""#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            std::ptr::null(),
        );
        assert!(matches!(decision, CedarDecision::Allow));

        cedar_engine_free(engine);
    }

    #[test]
    fn test_diagnostics() {
        let engine = cedar_engine_new();

        let policy = CString::new(
            r#"permit(principal == User::"alice", action == Action::"view", resource == File::"93");"#,
        )
        .unwrap();
        cedar_engine_set_policies(engine, policy.as_ptr());

        let principal = CString::new(r#"User::"alice""#).unwrap();
        let action = CString::new(r#"Action::"view""#).unwrap();
        let resource = CString::new(r#"File::"93""#).unwrap();

        cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            std::ptr::null(),
        );

        let diag = cedar_engine_get_diagnostics(engine);
        assert!(!diag.is_null());
        let diag_str = unsafe { CStr::from_ptr(diag) }.to_str().unwrap();
        assert!(
            diag_str.contains("reasons"),
            "diagnostics should have reasons: {diag_str}"
        );

        cedar_engine_free(engine);
    }

    #[test]
    fn test_add_policies() {
        let engine = cedar_engine_new();

        let policy1 = CString::new(
            r#"permit(principal == User::"alice", action == Action::"view", resource == File::"93");"#,
        )
        .unwrap();
        let rc = cedar_engine_set_policies(engine, policy1.as_ptr());
        assert_eq!(rc, 0);

        let policy2 = CString::new(
            r#"permit(principal == User::"bob", action == Action::"edit", resource == File::"42");"#,
        )
        .unwrap();
        let count = cedar_engine_add_policies(engine, policy2.as_ptr());
        assert!(count > 0, "should add at least one policy");

        // Now bob should be able to edit file 42
        let principal = CString::new(r#"User::"bob""#).unwrap();
        let action = CString::new(r#"Action::"edit""#).unwrap();
        let resource = CString::new(r#"File::"42""#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            std::ptr::null(),
        );
        assert!(matches!(decision, CedarDecision::Allow));

        cedar_engine_free(engine);
    }

    #[test]
    fn test_null_engine_safety() {
        // All functions should handle null engine gracefully
        let null_engine: *mut CedarEngine = std::ptr::null_mut();
        let null_const: *const CedarEngine = std::ptr::null();

        assert_eq!(cedar_engine_set_policies(null_engine, std::ptr::null()), -1);
        assert_eq!(
            cedar_engine_set_entities_json(null_engine, std::ptr::null()),
            -1
        );
        assert_eq!(
            cedar_engine_set_schema_json(null_engine, std::ptr::null()),
            -1
        );
        assert!(matches!(
            cedar_engine_is_authorized(
                null_engine,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null()
            ),
            CedarDecision::Error
        ));
        assert!(cedar_engine_last_error(null_const).is_null());
        assert!(cedar_engine_get_diagnostics(null_const).is_null());
        cedar_engine_clear_error(null_engine);
        cedar_engine_clear_entities(null_engine);
        cedar_engine_free(null_engine);
        assert_eq!(cedar_engine_validate(null_engine), -1);
    }

    #[test]
    fn test_postgres_like_scenario() {
        // Simulate the pg_authorization use case:
        // User performing SELECT on a table
        let engine = cedar_engine_new();

        let policies = CString::new(
            r#"
            // Allow alice to SELECT on any table in public schema
            permit(
                principal == User::"alice",
                action == Action::"SELECT",
                resource
            );
            // Deny bob from everything
            forbid(
                principal == User::"bob",
                action,
                resource
            );
            "#,
        )
        .unwrap();
        cedar_engine_set_policies(engine, policies.as_ptr());

        // alice SELECT on public.employees → ALLOW
        let principal = CString::new(r#"User::"alice""#).unwrap();
        let action = CString::new(r#"Action::"SELECT""#).unwrap();
        let resource = CString::new(r#"Table::"public.employees""#).unwrap();
        let ctx = CString::new(r#"{"day":"mon","date":20260224}"#).unwrap();

        let decision = cedar_engine_is_authorized(
            engine,
            principal.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            ctx.as_ptr(),
        );
        assert!(matches!(decision, CedarDecision::Allow));

        // bob SELECT on public.employees → DENY
        let bob = CString::new(r#"User::"bob""#).unwrap();
        let decision2 = cedar_engine_is_authorized(
            engine,
            bob.as_ptr(),
            action.as_ptr(),
            resource.as_ptr(),
            ctx.as_ptr(),
        );
        assert!(matches!(decision2, CedarDecision::Deny));

        cedar_engine_free(engine);
    }
}
