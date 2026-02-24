# libcedar

A C ABI wrapper for the [Cedar policy engine](https://github.com/cedar-policy/cedar), allowing you to embed Cedar directly in C/C++ applications.

Instead of making external HTTP calls to `cedar-agent`, `libcedar` lets you evaluate policies **in-process**, saving network overhead and simplifying deployments.

## Features

- **C-compatible API** for the `cedar-policy` Rust crate (v4.9.0)
- **Zero-overhead FFI**: Directly passes memory without HTTP serialization
- **Full Cedar Support**: Handles policies, schemas, contexts, and entities
- Auto-generates `libcedar.h` using `cbindgen`
- Builds as both static (`.a`) and dynamic (`.dylib` / `.so`) libraries

## Usage

### 1. Build the library

You will need the [Rust toolchain](https://rustup.rs/) installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/libcedar.git
cd libcedar

# Build in release mode
cargo build --release
```

This generates:
- `target/release/libcedar.a` (Static Library)
- `target/release/libcedar.dylib` / `.so` (Dynamic Library)
- `include/libcedar.h` (C Header)

### 2. Include in your C project

Add `-Iinclude` and `-Ltarget/release -lcedar` to your compiler flags.

```c
#include <stdio.h>
#include "libcedar.h"

int main() {
    // 1. Initialize the engine
    CedarEngine *engine = cedar_engine_new();

    // 2. Set policies
    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"view\", resource == File::\"93\");"
    );

    // 3. Evaluate a request
    CedarDecision decision = cedar_engine_is_authorized(
        engine,
        "User::\"alice\"", 
        "Action::\"view\"", 
        "File::\"93\"", 
        NULL // Optional JSON context
    );

    if (decision == Allow) {
        printf("Access Granted!\n");
    } else {
        printf("Access Denied.\n");
    }

    // 4. Cleanup
    cedar_engine_free(engine);
    return 0;
}
```

## API Highlights

- `cedar_engine_new()` - Create a new evaluation engine.
- `cedar_engine_set_policies(engine, text)` - Load Cedar policies from a string.
- `cedar_engine_add_policies(engine, text)` - Append Cedar policies conceptually.
- `cedar_engine_set_schema_json(engine, json)` - Load Cedar schema.
- `cedar_engine_set_entities_json(engine, json)` - Load entity data.
- `cedar_engine_is_authorized(engine, principal, action, resource, context_json)` - Evaluate an authorization request. Returns `Allow` (0), `Deny` (1), or `Error` (-1).
- `cedar_engine_last_error(engine)` - Retrieve error details.
- `cedar_engine_get_diagnostics(engine)` - Retrieve evaluation diagnostics (reasons/errors) as JSON.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
