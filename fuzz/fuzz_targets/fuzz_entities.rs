/*
 * fuzz_entities.rs — LibFuzzer target for Cedar entity JSON parsing via C FFI.
 *
 * Goal: ensure cedar_engine_set_entities_json() never panics, aborts, or
 * corrupts memory regardless of the JSON input.  Entity JSON includes:
 *   - uid  : { type, id }
 *   - attrs: arbitrary attribute map
 *   - parents: array of entity UIDs
 *
 * Run:
 *   cargo +nightly fuzz run fuzz_entities
 */
#![no_main]
use cedar::*;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(entities_cstr) = CString::new(s) else { return };

    unsafe {
        let engine = cedar_engine_new();
        if engine.is_null() {
            return;
        }

        // Load a simple policy so the engine has something to evaluate against.
        let policy = c"permit(principal, action, resource);";
        cedar_engine_set_policies(engine, policy.as_ptr());

        // Primary target: entity JSON parsing.
        let rc = cedar_engine_set_entities_json(engine, entities_cstr.as_ptr());

        if rc == 0 {
            // Valid entity store: try an authorization check.
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

            // Exercise clear_entities on a valid store.
            cedar_engine_clear_entities(engine);

            // After clearing, authorization should still work (empty store = no hierarchy).
            let _ = cedar_engine_is_authorized(
                engine,
                principal.as_ptr(),
                action.as_ptr(),
                resource.as_ptr(),
                std::ptr::null(),
            );
        } else {
            // Parse error: check that last_error returns something reasonable.
            let err = cedar_engine_last_error(engine);
            if !err.is_null() {
                let _ = std::ffi::CStr::from_ptr(err).to_bytes();
            }
            cedar_engine_clear_error(engine);

            // Engine must still accept valid entities after a parse error.
            let valid_entities = c"[]";
            let _ = cedar_engine_set_entities_json(engine, valid_entities.as_ptr());
        }

        cedar_engine_free(engine);
    }
});
