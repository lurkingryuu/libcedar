/*
 * fuzz_authz.rs — LibFuzzer target for the full authorization request path.
 *
 * Goal: fuzz the combination of (principal, action, resource, context_json)
 * strings fed to cedar_engine_is_authorized().  The fuzzer controls all four
 * inputs simultaneously to discover edge cases in UID parsing, context JSON
 * parsing, and the Cedar evaluation engine.
 *
 * Input format (structured via arbitrary bytes split on NUL):
 *   byte 0        : split index for principal / rest
 *   byte 1        : split index for action / rest
 *   byte 2        : split index for resource / rest
 *   remaining     : context JSON (UTF-8)
 *
 * Run:
 *   cargo +nightly fuzz run fuzz_authz
 */
#![no_main]
use cedar::*;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

/// Attempt to construct a CString from a byte slice; return None for invalid
/// UTF-8 or interior NUL bytes.
fn try_cstr(bytes: &[u8]) -> Option<CString> {
    let s = std::str::from_utf8(bytes).ok()?;
    CString::new(s).ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Use the first 3 bytes as split indices into the remaining payload.
    let len = data.len() - 3;
    let s0 = (data[0] as usize).min(len);
    let s1 = (data[1] as usize).min(len);
    let s2 = (data[2] as usize).min(len);

    let payload = &data[3..];

    // Extract four slices (overlapping is fine; Cedar will reject invalid UIDs).
    let principal_bytes = &payload[..s0.min(payload.len())];
    let action_bytes    = &payload[..s1.min(payload.len())];
    let resource_bytes  = &payload[..s2.min(payload.len())];
    let context_bytes   = payload; // full payload as context JSON

    // Convert to CStrings; skip if any conversion fails.
    let Some(principal_cstr) = try_cstr(principal_bytes) else { return };
    let Some(action_cstr)    = try_cstr(action_bytes)    else { return };
    let Some(resource_cstr)  = try_cstr(resource_bytes)  else { return };
    // Context is optional; use NULL if conversion fails.
    let context_cstr = try_cstr(context_bytes);

    unsafe {
        let engine = cedar_engine_new();
        if engine.is_null() {
            return;
        }

        // Load a permissive policy so evaluation always reaches the Cedar engine.
        let policy = c"permit(principal, action, resource);";
        cedar_engine_set_policies(engine, policy.as_ptr());

        let ctx_ptr = match &context_cstr {
            Some(c) => c.as_ptr(),
            None    => std::ptr::null(),
        };

        // Primary target: authorization must not crash regardless of inputs.
        let decision = cedar_engine_is_authorized(
            engine,
            principal_cstr.as_ptr(),
            action_cstr.as_ptr(),
            resource_cstr.as_ptr(),
            ctx_ptr,
        );

        // Any valid CedarDecision value is acceptable; just ensure no UB.
        match decision {
            CedarDecision::Allow | CedarDecision::Deny | CedarDecision::Error => {}
        }

        // Diagnostics must be accessible after every evaluation.
        let diag = cedar_engine_get_diagnostics(engine);
        if !diag.is_null() {
            let _ = std::ffi::CStr::from_ptr(diag).to_bytes();
        }

        // Error message (if any) must be a valid C string.
        let err = cedar_engine_last_error(engine);
        if !err.is_null() {
            let _ = std::ffi::CStr::from_ptr(err).to_bytes();
        }

        cedar_engine_free(engine);
    }
});
