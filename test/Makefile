CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS = -Wall -Wextra -O2

DLL_SRC = external_exports.c
EXE_SRC = test_external_dll.c
DLL = external_exports.dll
EXE = test_external_dll.exe

RES_EXE_SRC = test_resources.c
RES_RC = test_resources.rc
RES_OBJ = test_resources_res.o
RES_EXE = test_resources.exe

all: $(DLL) $(EXE) $(RES_EXE)

$(DLL): $(DLL_SRC)
	$(CC) $(CFLAGS) -shared -o $@ $<

$(EXE): $(EXE_SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(RES_OBJ): $(RES_RC)
	$(WINDRES) $< -O coff -o $@

$(RES_EXE): $(RES_EXE_SRC) $(RES_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lversion

clean:
	rm -f $(DLL) $(EXE) $(RES_EXE) $(RES_OBJ)

.PHONY: all clean
