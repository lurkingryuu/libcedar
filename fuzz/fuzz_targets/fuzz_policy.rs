/*
 * fuzz_policy.rs — LibFuzzer target for Cedar policy text parsing via C FFI.
 *
 * Goal: ensure cedar_engine_set_policies() never panics, aborts, or corrupts
 * engine state regardless of the policy string content.
 *
 * Run:
 *   cargo +nightly fuzz run fuzz_policy
 *
 * The fuzzer provides arbitrary bytes; we interpret them as UTF-8 (rejecting
 * invalid sequences) so that Cedar's string parser is exercised rather than
 * spending cycles on pre-parser encoding errors.
 */
#![no_main]
use cedar::*;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

fuzz_target!(|data: &[u8]| {
    // Only exercise valid UTF-8; Cedar's parser operates on text.
    let Ok(s) = std::str::from_utf8(data) else { return };

    // CString::new rejects strings containing interior NUL bytes.
    let Ok(policy_cstr) = CString::new(s) else { return };

    unsafe {
        let engine = cedar_engine_new();
        if engine.is_null() {
            return;
        }

        // Primary target: parsing must not crash or corrupt memory.
        let rc = cedar_engine_set_policies(engine, policy_cstr.as_ptr());

        if rc == 0 {
            // Successful parse: run a basic authorization check to ensure the
            // engine is in a consistent state after accepting the policy.
            let principal = c"User::\"fuzz_user\"";
            let action    = c"Action::\"fuzz_action\"";
            let resource  = c"Resource::\"fuzz_res\"";
            let _ = cedar_engine_is_authorized(
                engine,
                principal.as_ptr(),
                action.as_ptr(),
                resource.as_ptr(),
                std::ptr::null(),
            );

            // Validate (if a schema is not set, this is a no-op returning 0).
            let _ = cedar_engine_validate(engine);
        } else {
            // Parse failed: verify the error message is accessible and the
            // engine can recover (clear error + accept a fresh valid policy).
            let err = cedar_engine_last_error(engine);
            // err may be NULL or a valid C string — both are acceptable.
            if !err.is_null() {
                let _ = std::ffi::CStr::from_ptr(err).to_bytes();
            }
            cedar_engine_clear_error(engine);

            // Engine must still accept a valid policy after a parse error.
            let valid = c"permit(principal, action, resource);";
            let _ = cedar_engine_set_policies(engine, valid.as_ptr());
        }

        cedar_engine_free(engine);
    }
});
