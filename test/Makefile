CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2

DLL_SRC = external_exports.c
EXE_SRC = test_external_dll.c
DLL = external_exports.dll
EXE = test_external_dll.exe

all: $(DLL) $(EXE)

$(DLL): $(DLL_SRC)
  $(CC) $(CFLAGS) -shared -o $@ $<

$(EXE): $(EXE_SRC)
  $(CC) $(CFLAGS) -o $@ $<

clean:
  rm -f $(DLL) $(EXE)

.PHONY: all clean
