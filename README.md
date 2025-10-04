# wibo

A minimal, low-fuss wrapper that can run simple command-line 32-bit Windows binaries on 32-bit Linux - developed to run Windows compilers faster than Wine.

## Building

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=ON
cmake --build build
```

Set `-DCMAKE_BUILD_TYPE=Release` to produce an optimized binary instead.

## Running

```sh
./build/wibo /path/to/program.exe [arguments...]
```

Supported command line options:

- `--help`: Print usage information.
- `-D`, `--debug`: Enable shim debug logging (equivalent to `WIBO_DEBUG=1`).
- `-C DIR`, `--chdir DIR`, `--chdir=DIR`: Change to `DIR` before running the guest program.
- `--cmdline STRING`, `--cmdline=STRING`: Use `STRING` as the exact guest command line. (Including the program name as the first argument.)
- `--`: Stop option parsing; following arguments are interpreted as the exact guest command line. (Including the program name as the first argument.)

## Tests

Self-checking Windows fixtures run through CTest. They require a 32-bit MinGW cross toolchain (`i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`).

```sh
ctest --test-dir build --output-on-failure
```

This will cross-compile the fixture executables, run them through `wibo`, and fail if any WinAPI expectations are not met.

---

See also:
* [taviso/loadlibrary](https://github.com/taviso/loadlibrary) - Initial inspiration for this project.
* [evmar/retrowin32](https://github.com/evmar/retrowin32) - A similar project with different goals and architecture.
* [decomp.me](https://decomp.me) - Collaborative decompilation website; uses wibo to run Windows compilers.
