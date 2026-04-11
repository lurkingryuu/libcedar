# libcedar

`libcedar` is an installable C SDK for the
[Cedar policy engine](https://github.com/cedar-policy/cedar). It exposes a
stable C ABI so C, C++, MySQL plugins, and PostgreSQL extensions can evaluate
Cedar policies in-process without calling `cedar-agent` over HTTP.

## Features

- C-compatible API for the `cedar-policy` Rust crate (`4.7.0`)
- In-process evaluation for policies, schema, entities, context, and diagnostics
- Installs as a standard C library package with:
  - `include/libcedar.h`
  - `lib/libcedar.{so,dylib}` and `lib/libcedar.a`
  - `lib/pkgconfig/libcedar.pc`
- Generated headers via `cbindgen`
- Release-friendly packaging via `cargo-c`

## Install Contract

Consumers should treat `libcedar` like a normal installed package. The
supported contract is the installed prefix, not the Cargo build tree.

Typical installed layout:

```text
<prefix>/
  include/libcedar.h
  lib/libcedar.so        # Linux
  lib/libcedar.dylib     # macOS
  lib/libcedar.a
  lib/pkgconfig/libcedar.pc
```

The recommended discovery mechanism is `pkg-config`.

## Building And Installing

### Preferred: install from an existing package/release artifact

GitHub Releases should publish prebuilt package tarballs for supported
platforms. The release archives are intended to be extracted into
`/opt/libcedar`, matching the packaged `pkg-config` prefix used by downstream
Docker builds.

```bash
mkdir -p /opt/libcedar
tar -xzf libcedar-<version>-<target>.tar.gz -C /opt/libcedar
export PKG_CONFIG_PATH=/opt/libcedar/lib/pkgconfig:$PKG_CONFIG_PATH
```

For a different install prefix, prefer building from source with `cargo-c`.

### Source install with `cargo-c`

You will need the Rust toolchain and [`cargo-c`](https://crates.io/crates/cargo-c).

```bash
git clone https://github.com/lurkingryuu/libcedar.git
cd libcedar

cargo install cargo-c --locked --version 0.10.19+cargo-0.93.0
cargo cbuild --release
cargo cinstall --release --prefix=/usr/local
```

For staged packaging:

```bash
cargo cinstall --release --prefix=/usr/local --destdir="$PWD/stage"
```

## Using From C Or C++

Use `pkg-config` rather than direct `target/release` paths:

```bash
cc app.c $(pkg-config --cflags --libs libcedar)
```

If the package is installed in a non-default prefix:

```bash
export PKG_CONFIG_PATH=/opt/libcedar/lib/pkgconfig:$PKG_CONFIG_PATH
cc app.c $(pkg-config --cflags --libs libcedar)
```

Example:

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
- `cedar_engine_is_authorized_no_diagnostics(engine, principal, action, resource, context_json)` - Evaluate without materializing diagnostics on the success path.
- `cedar_engine_last_error(engine)` - Retrieve error details.
- `cedar_engine_get_diagnostics(engine)` - Retrieve evaluation diagnostics (reasons/errors) as JSON.

## Consumer Guidance

- Do not depend on `target/release` paths from a local checkout.
- Do not clone `libcedar` inside downstream builds just to compile it.
- Install `libcedar` into a prefix and consume it via `pkg-config`.
- Use GitHub release artifacts in CI, Docker builds, and packaged deployments.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
