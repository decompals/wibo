# wibo

A minimal, low-fuss wrapper that can run really simple command-line 32-bit Windows binaries on Linux - with less faff and less dependencies than WINE.

Don't run this on any untrusted executables, I implore you. (Or probably just don't run it at all... :p)

    cmake -B build
    cmake --build build
    build/wibo

---

Rough to-do list:

- Implement more APIs
- Do something intelligent with Windows `HANDLE`s
- Convert paths in environment variables (and the structure of `PATH` itself, maybe) to Windows format
- Implement PE relocations rather than just failing unceremoniously
- Make the PE loader work for DLLs as well in case we ever want to load some

---

Related projects:
* [taviso/loadlibrary](https://github.com/taviso/loadlibrary)
