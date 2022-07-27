# WiBo

> A minimal and low-fuss wrapper allows Linux to run Windows binaries with less faff and requires fewer dependencies than WINE.

## Features
- Currently, Wibo can handle simple 32-bit command-line Windows executables.

## How to Build
```bash
cmake -B build
cmake --build build
build/wibo
```
    
Warning: Don't run this on any untrusted executables, I implore you. (Or probably just don't run it at all... :p)

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
