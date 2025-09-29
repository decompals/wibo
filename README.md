# wibo

A minimal, low-fuss wrapper that can run really simple command-line 32-bit Windows binaries on Linux - with less faff and fewer dependencies than WINE.

Don't run this on any untrusted executables, I implore you. (Or probably just don't run it at all... :p)

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target wibo
```

`cmake -B build -DCMAKE_BUILD_TYPE=Release` to produce an optimized binary instead.

## Running

```sh
./build/wibo /path/to/program.exe [arguments...]
```

Supported command line options:

- `--help`: Print usage information.
- `-D`, `--debug`: Enable shim debug logging (equivalent to `WIBO_DEBUG=1`).
- `-C DIR`, `--chdir DIR`, `--chdir=DIR`: Change to `DIR` before running the program.
- `--`: Stop option parsing; following arguments are interpreted as the program command line.

## Tests

Self-checking Windows fixtures run through CTest. They require a 32-bit MinGW cross toolchain (`i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`).

With the toolchain installed:

```sh
cmake -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

This will cross-compile the fixture executables, run them through `wibo`, and fail if any WinAPI expectations are not met.

---

Rough to-do list:

- Implement more APIs

---

Related projects:
* [taviso/loadlibrary](https://github.com/taviso/loadlibrary)
* [evmar/retrowin32](https://github.com/evmar/retrowin32)
