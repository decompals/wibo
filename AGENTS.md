# Repository Guidelines

## Project Structure & Module Organization
- Core launcher logic lives in `main.cpp`, `loader.cpp`, `files.cpp`, `handles.cpp` and `module_registry.cpp`; shared interfaces in headers near them.
- Windows API shims reside in `dll/`, grouped by emulated DLL name; keep new APIs in the matching file instead of creating ad-hoc helpers.
- Reusable utilities sit in `strutil.*`, `processes.*` and `resources.*`; prefer extending these before introducing new singleton modules.
- Sample fixtures for exercising the loader live in `test/`.

## Build, Test, and Development Commands
- `cmake -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=ON` configures a 32-bit toolchain; ensure multilib packages are present.
- `cmake --build build --target wibo` compiles the program and tests.
- `./build/wibo /path/to/program.exe` runs a Windows binary. Use `WIBO_DEBUG=1` (or `--debug`/`-D`) for verbose logging. Use `--chdir`/`-C` to set the working directory.
- `cmake -B build -DBUILD_TESTING=ON` + `ctest --test-dir build --output-on-failure` runs the self-checking WinAPI fixtures (requires `i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`).
- `clang-format -i path/to/file.cpp` and `clang-tidy path/to/file.cpp -p build` keep contributions aligned with the repo's tooling.

## Coding Style & Naming Conventions
- Formatting follows `.clang-format` (LLVM base, tabbed indentation width 4, 120 column limit); never hand-wrap differently.
- Use PascalCase for Win32 entry points, camelCase for internal helpers, SCREAMING_SNAKE_CASE for Win32 constants, kCamelCase for internal constants, and g_camelCase for globals.
- Put static functions and variables in anonymous namespaces at the top of the file.
- Prefer scoping types to the header or source file that uses them; avoid polluting `common.h` unless widely shared.

## Shim Implementation Guidelines
- Target pre-XP behavior; our binaries are old and don't expect modern WinAPI behavior.
- Use the `microsoft_docs` tools to fetch WinAPI signatures and documentation; always fetch the documentation when working on an API function.
- Create minimal, self-contained repros in `test/` when implementing or debugging APIs; this aids both development and future testing.
- Add `DEBUG_LOG` calls to trace execution and parameter values; these are invaluable when diagnosing issues with real-world binaries.

## Testing Guidelines
- Fixture tests live in `test/` and are compiled automatically with `i686-w64-mingw32-gcc` when `BUILD_TESTING` is enabled.
- Keep new repros small and self-contained (`test_<feature>.c`).
- All fixtures must self-assert; use `test_assert.h` helpers so `ctest` fails on mismatched WinAPI behaviour.
- Update `CMakeLists.txt` to add new fixture sources.
- Rebuild, then run tests with `ctest --test-dir build --output-on-failure`.
- ALWAYS run tests against `wine` manually to confirm expected behaviour. If `wine` fails, the expected behaviour is likely wrong. (`wine` is not perfect, but we can assume it's closer to Windows than we are.)

## Debugging Workflow
- Reproduce crashes under `gdb` (or `lldb`) with `-q -batch` to capture backtraces, register state, and the faulting instruction without interactive prompts.
- Enable `WIBO_DEBUG=1` and output to a log (i.e. `&>/tmp/wibo.log`) when running the guest binary; loader traces often pinpoint missing imports, resource lookups, or API shims that misbehave. The answer is usually in the last few dozen lines before the crash.
- Inspect relevant source right away—most issues stem from stubbed shims in `dll/`.
- Missing stubs generally do _not_ cause a crash; we return valid function pointers for unknown imports. Only when the missing stub is _called_ do we abort with a message. Therefore, don't preemptively add stubs for every missing import; wait until the binary actually calls it.
