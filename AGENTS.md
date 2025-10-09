# Repository Guidelines

## Project Structure & Module Organization
- Core loader logic and headers live in `src/`.
- Windows API shims reside in `dll/`; source files grouped by DLL (e.g. `dll/kernel32/`).
- Sample fixtures for exercising the loader live in `test/`.

## Build, Test, and Development Commands
- `cmake --preset debug` configures a 32-bit toolchain; ensure multilib packages are present. (`--preset release` for optimized builds.)
- `cmake --build --preset debug` compiles the program and tests.
- `./build/debug/wibo /path/to/program.exe` runs a Windows binary. Use `-D` (or `WIBO_DEBUG=1`) for verbose logging. Use `-C` to set the working directory.
- `ctest --preset fixtures` runs the self-checking WinAPI fixtures (requires `i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`).
- `clang-format -i path/to/file.cpp` and `clang-tidy -p build/debug path/to/file.cpp` keep contributions aligned with the repo's tooling.

## Coding Style & Naming Conventions
- Formatting follows `.clang-format` (LLVM base, tabbed indentation width 4, 120 column limit).
- Use PascalCase for Win32 entry points, camelCase for internal helpers, SCREAMING_SNAKE_CASE for Win32 constants, kCamelCase for internal constants, g_camelCase for globals, and mPascalCase for member variables.
- Put static functions and variables in anonymous namespaces at the top of the file.
- Prefer scoping types to the header or source file that uses them; avoid polluting `common.h` unless widely shared.
- Win32 APIs generally do NOT set `ERROR_SUCCESS` on success, though there are a few exceptions; check the docs.

## Shim Implementation Guidelines
- Target pre-XP behavior; our binaries are old and don't expect modern WinAPI behavior.
- Use the `microsoft_docs` tools to fetch WinAPI signatures and documentation; always fetch the documentation when working on an API function.
- Create minimal, self-contained repros in `test/` when implementing or debugging APIs; this aids both development and future testing.
- Add `DEBUG_LOG` calls to trace execution and parameter values; these are invaluable when diagnosing issues with real-world binaries.

## Testing Guidelines
- Fixture tests live in `test/` and are compiled automatically with `i686-w64-mingw32-gcc`.
- Keep new repros small and self-contained (`test_<feature>.c`).
- All fixtures must self-assert; use `test_assert.h` helpers so `ctest` fails on mismatched WinAPI behaviour.
- Update `CMakeLists.txt` to add new fixture sources.
- Rebuild, then run with `ctest --preset fixtures`.
- ALWAYS run tests against `wine` manually to confirm expected behaviour. If `wine` fails, the expected behaviour is VERY LIKELY wrong. (`wine` is not perfect, but we can assume it's closer to Windows than we are.)

## Debugging Workflow
- Reproduce crashes under `gdb` (or `lldb`) with `-q -batch` to capture backtraces, register state, and the faulting instruction without interactive prompts.
- Use `-D` (or `WIBO_DEBUG=1`) and output to a log (i.e. `&>/tmp/wibo.log`) when running the guest binary; loader traces often pinpoint missing imports, resource lookups, or API shims that misbehave. The answer is usually in the last few dozen lines before the crash.
- Inspect relevant source right away—most issues stem from stubbed shims in `dll/`.
- Missing stubs generally do _not_ cause a crash; we return valid function pointers for unknown imports. Only when the missing stub is _called_ do we abort with a message. Therefore, don't preemptively add stubs for every missing import; wait until the binary actually calls it.

## Implementation Workflow
- Fetch API documentation with `microsoft_docs`
- Create test cases in `test/test_<feature>.c`
- Build, then run the test(s) against `wine` (`wine build/debug/test/test_<feature>.exe`) to establish baseline behaviour (important!)
- Plan and implement the API
- Build, then run tests against `wibo` (`ctest --preset fixtures`) for validation
- Format with `clang-format` and lint with `clang-tidy`
