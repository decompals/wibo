# Repository Guidelines

## Project Structure & Module Organization
- Core launcher logic lives in `main.cpp`, `loader.cpp`, `files.cpp`, `handles.cpp` and `module_registry.cpp`; shared interfaces in headers near them.
- Windows API shims reside in `dll/`, grouped by emulated DLL name; keep new APIs in the matching file instead of creating ad-hoc helpers.
- Reusable utilities sit in `strutil.*`, `processes.*` and `resources.*`; prefer extending these before introducing new singleton modules.
- Sample fixtures for exercising the loader live in `test/`; keep new repros small and self-contained.

## Build, Test, and Development Commands
- `cmake -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` configures a 32-bit toolchain; ensure multilib packages are present.
- `cmake --build build --target wibo` compiles the shim; switch to `-DCMAKE_BUILD_TYPE=Release` for optimised binaries.
- `./build/wibo /path/to/program.exe` runs a Windows binary. Use `WIBO_DEBUG=1` (or `--debug`/`-D`) for verbose logging. Use `--chdir`/`-C` to set the working directory.
- `cmake -B build -DBUILD_TESTING=ON` + `ctest --test-dir build --output-on-failure` runs the self-checking WinAPI fixtures (requires `i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`).
- `clang-format -i path/to/file.cpp` and `clang-tidy path/to/file.cpp -p build` keep contributions aligned with the repo's tooling.
- DON'T use `clang-format` on existing files, only new or heavily modified ones; the repo hasn't been fully formatted yet.

## Coding Style & Naming Conventions
- Formatting follows `.clang-format` (LLVM base, tabbed indentation width 4, 120 column limit); never hand-wrap differently.
- Prefer PascalCase for emulated Win32 entry points, camelCase for internal helpers, and SCREAMING_SNAKE_CASE for constants or macros.
- Document non-obvious control flow with short comments and keep platform-specific code paths behind descriptive helper functions.

## Shim Implementation Guidelines
- Target pre-XP behavior; our binaries are old and don't expect modern WinAPI behavior.
- Use the `microsoft_docs` tools to fetch WinAPI signatures and documentation; always fetch the documentation when working on an API function.
- Create minimal, self-contained repros in `test/` when implementing or debugging APIs; this aids both development and future testing.
- Stub unimplemented APIs with `DEBUG_LOG` calls to track usage; prioritize based on the needs of real-world binaries.

## Testing Guidelines
- Fixture binaries live in `test/` and are compiled automatically when `BUILD_TESTING` is enabled; keep new repros small and self-contained (`test_<feature>.c`).
- All fixtures must self-assert; use `test_assert.h` helpers so `ctest` fails on mismatched WinAPI behaviour.
- Cross-compile new repros with `i686-w64-mingw32-gcc` (and `i686-w64-mingw32-windres` for resources); CMake handles this during the build, but direct invocation is useful while iterating.
- Run `ctest --test-dir build --output-on-failure` after rebuilding to verify changes; ensure failures print actionable diagnostics.

## Debugging Workflow
- Reproduce crashes under `gdb` (or `lldb`) with `-q -batch` to capture backtraces, register state, and the faulting instruction without interactive prompts.
- Enable `WIBO_DEBUG=1` and tee output to a log when running the guest binary; loader traces often pinpoint missing imports, resource lookups, or API shims that misbehave.
- Inspect relevant source right away—most issues stem from stubbed shims in `dll/`; compare the guest stack from `gdb` with those implementations.
- When host-side behaviour is suspect (filesystem, execve, etc.), rerun under `strace -f -o <log>`; this highlights missing files or permissions before the shim faults.
- If the `ghidra` MCP tool is available, request that the user import and analyze the guest binary; you can then use it to disassemble/decompile code around the crash site.
