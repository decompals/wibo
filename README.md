# WiBo

An experiment to try and write a minimal, low-fuss wrapper that can run really simple command-line 32-bit Windows binaries on Linux - with less faff and less dependencies than WINE.

Don't run this on any untrusted executables, I implore you. (Or probably just don't run it at all... :p)

    g++ -g -m32 -std=c++20 -lstdc++ main.cpp version.cpp user32.cpp kernel32.cpp advapi32.cpp loader.cpp

If you need something like this project (but more mature), you might find [taviso/loadlibrary](https://github.com/taviso/loadlibrary) more interesting.

---

Rough to-do list:

- Implement more APIs
- Do something intelligent with Windows `HANDLE`s
- Pass the command line properly
- Convert paths in environment variables (and the structure of `PATH` itself, maybe) to Windows format
- Implement PE relocations rather than just failing unceremoniously
- Make the PE loader work for DLLs as well in case we ever want to load some
