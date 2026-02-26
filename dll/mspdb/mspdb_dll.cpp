// Cross-compiled 32-bit PE DLL providing fake PDB COM interfaces.
// Built by i686-w64-mingw32-g++ -shared, loaded by wibo as an embedded DLL.
//
// The X360 linker requires a working mspdb DLL with COM-style vtable objects.
// Each class has virtual methods matching the interface slots the linker calls.
// No virtual destructors (MSVC: 1 slot, GCC: 2 slots - would shift all indices).

#include <cstdint>
#include <cstring>

#define DLLEXPORT extern "C" __declspec(dllexport)

// PDB version constants (VS2010 era - matches X360 linker)
static constexpr uint32_t PDB_INTV = 20091201;
static constexpr uint32_t PDB_IMPV = 20091201;

// Helper: write a uint32_t to an output pointer if non-null
static void writeOut32(void *ptr, uint32_t val) {
	if (ptr) *(uint32_t *)ptr = val;
}

// Forward-declared addresses (defined after all struct definitions)
struct FakePDB;
struct FakeDBI;
struct FakeMod;
struct FakeTPI;
struct FakeGSI;
struct FakeDbg;
struct FakeNameMap;
struct FakeStream;
extern FakePDB g_pdb;
extern FakeDBI g_dbi;
extern FakeMod g_mod;
extern FakeTPI g_tpi;
extern FakeGSI g_gsi;
extern FakeDbg g_dbg;
extern FakeNameMap g_namemap;
extern FakeStream g_stream;

// --- PDB interface (64 vtable slots) ---
struct FakePDB {
	// 0: QueryInterfaceVersion
	virtual uint32_t __thiscall QueryInterfaceVersion() { return PDB_INTV; }
	// 1: QueryImplementationVersion
	virtual uint32_t __thiscall QueryImplementationVersion() { return PDB_IMPV; }
	// 2: QueryLastError(char szError[])
	virtual uint32_t __thiscall QueryLastError(char *sz) { if (sz) *sz = 0; return 0; }
	// 3: QueryPDBName(char szPDB[])
	virtual char * __thiscall QueryPDBName(char *sz) { if (sz) *sz = 0; return nullptr; }
	// 4: QuerySignature
	virtual uint32_t __thiscall QuerySignature() { return 0; }
	// 5: QueryAge
	virtual uint32_t __thiscall QueryAge() { return 1; }
	// 6: CreateDBI(szTarget, DBI**)
	virtual int __thiscall CreateDBI(const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_dbi); return 1; }
	// 7: OpenDBI(szTarget, szMode, DBI**)
	virtual int __thiscall OpenDBI(const char *, const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_dbi); return 1; }
	// 8: OpenTpi(szMode, TPI**)
	virtual int __thiscall OpenTpi(const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_tpi); return 1; }
	// 9: OpenIpi(szMode, TPI**)
	virtual int __thiscall OpenIpi(const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_tpi); return 1; }
	// 10: Commit
	virtual int __thiscall Commit() { return 1; }
	// 11: Close
	virtual int __thiscall Close() { return 1; }
	// 12: OpenStream(szStream, Stream**)
	virtual int __thiscall OpenStream(const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_stream); return 1; }
	// 13: GetEnumStreamNameMap
	virtual int __thiscall GetEnumStreamNameMap(void *) { return 0; }
	// 14: GetRawBytes
	virtual int __thiscall GetRawBytes(void *) { return 0; }
	// 15: QueryPdbImplementationVersion
	virtual uint32_t __thiscall QueryPdbImplementationVersion() { return PDB_IMPV; }
	// 16: OpenDBIEx(szTarget, szMode, DBI**, pfn)
	virtual int __thiscall OpenDBIEx(const char *, const char *, void **pp, void *) { writeOut32(pp, (uint32_t)(uintptr_t)&g_dbi); return 1; }
	// 17: CopyTo
	virtual int __thiscall CopyTo(const char *, uint32_t, uint32_t) { return 1; }
	// 18: OpenSrc
	virtual int __thiscall OpenSrc(void *) { return 0; }
	// 19: QueryLastErrorExW(wchar_t*, uint32_t)
	virtual uint32_t __thiscall QueryLastErrorExW(wchar_t *sz, uint32_t) { if (sz) *sz = 0; return 0; }
	// 20: QueryPDBNameExW(wchar_t*, uint32_t)
	virtual wchar_t * __thiscall QueryPDBNameExW(wchar_t *sz) { if (sz) *sz = 0; return nullptr; }
	// 21: QuerySignature2
	virtual int __thiscall QuerySignature2(void *) { return 1; }
	// 22: CopyToW
	virtual int __thiscall CopyToW(const wchar_t *, uint32_t, uint32_t) { return 1; }
	// 23: fIsSZPDB
	virtual int __thiscall fIsSZPDB() { return 1; }
	// 24: OpenStreamW(szStream, Stream**)
	virtual int __thiscall OpenStreamW(const wchar_t *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_stream); return 1; }
	// 25: CopyToW2
	virtual int __thiscall CopyToW2(const wchar_t *, uint32_t, void *, void *) { return 1; }
	// 26: OpenStreamEx(szStream, szMode, Stream**)
	virtual int __thiscall OpenStreamEx(const char *, const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_stream); return 1; }
	// 27: RegisterPDBMapping
	virtual int __thiscall RegisterPDBMapping(const char *, const char *) { return 1; }
	// 28: EnablePrefetching
	virtual int __thiscall EnablePrefetching() { return 1; }
	// 29: FLazy
	virtual int __thiscall FLazy() { return 0; }
	// 30: FMinimal
	virtual int __thiscall FMinimal() { return 0; }
	// 31: ResetGUID
	virtual int __thiscall ResetGUID(void *, uint32_t) { return 1; }
	// Padding to 64 slots
	virtual int __thiscall _pad32() { return 0; }
	virtual int __thiscall _pad33() { return 0; }
	virtual int __thiscall _pad34() { return 0; }
	virtual int __thiscall _pad35() { return 0; }
	virtual int __thiscall _pad36() { return 0; }
	virtual int __thiscall _pad37() { return 0; }
	virtual int __thiscall _pad38() { return 0; }
	virtual int __thiscall _pad39() { return 0; }
	virtual int __thiscall _pad40() { return 0; }
	virtual int __thiscall _pad41() { return 0; }
	virtual int __thiscall _pad42() { return 0; }
	virtual int __thiscall _pad43() { return 0; }
	virtual int __thiscall _pad44() { return 0; }
	virtual int __thiscall _pad45() { return 0; }
	virtual int __thiscall _pad46() { return 0; }
	virtual int __thiscall _pad47() { return 0; }
	virtual int __thiscall _pad48() { return 0; }
	virtual int __thiscall _pad49() { return 0; }
	virtual int __thiscall _pad50() { return 0; }
	virtual int __thiscall _pad51() { return 0; }
	virtual int __thiscall _pad52() { return 0; }
	virtual int __thiscall _pad53() { return 0; }
	virtual int __thiscall _pad54() { return 0; }
	virtual int __thiscall _pad55() { return 0; }
	virtual int __thiscall _pad56() { return 0; }
	virtual int __thiscall _pad57() { return 0; }
	virtual int __thiscall _pad58() { return 0; }
	virtual int __thiscall _pad59() { return 0; }
	virtual int __thiscall _pad60() { return 0; }
	virtual int __thiscall _pad61() { return 0; }
	virtual int __thiscall _pad62() { return 0; }
	virtual int __thiscall _pad63() { return 0; }
};

// --- DBI interface (64 vtable slots) ---
struct FakeDBI {
	// 0: QueryImplementationVersion
	virtual uint32_t __thiscall QueryImplementationVersion() { return PDB_IMPV; }
	// 1: QueryInterfaceVersion
	virtual uint32_t __thiscall QueryInterfaceVersion() { return PDB_INTV; }
	// 2: OpenMod(szModule, szFile, Mod**)
	virtual int __thiscall OpenMod(const char *, const char *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_mod); return 1; }
	// 3: DeleteMod
	virtual int __thiscall DeleteMod(const char *) { return 1; }
	// 4: QueryNextMod(pmod, ppmodNext) -> *ppmodNext = NULL
	virtual int __thiscall QueryNextMod(void *, void **pp) { writeOut32(pp, 0); return 1; }
	// 5: OpenGlobals(GSI**)
	virtual int __thiscall OpenGlobals(void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_gsi); return 1; }
	// 6: OpenPublics(GSI**)
	virtual int __thiscall OpenPublics(void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_gsi); return 1; }
	// 7: AddSec
	virtual int __thiscall AddSec(uint16_t, uint16_t, uint32_t, uint32_t) { return 1; }
	// 8: QueryModFromAddr
	virtual int __thiscall QueryModFromAddr(uint16_t, uint32_t, void **, uint16_t *, uint32_t *, uint32_t *) { return 0; }
	// 9: QuerySecMap(pb, pcb)
	virtual int __thiscall QuerySecMap(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 10: QueryFileInfo(pb, pcb)
	virtual int __thiscall QueryFileInfo(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 11: DumpMods
	virtual void __thiscall DumpMods() {}
	// 12: DumpSecContribs
	virtual void __thiscall DumpSecContribs() {}
	// 13: DumpSecMap
	virtual void __thiscall DumpSecMap() {}
	// 14: Close
	virtual int __thiscall Close() { return 1; }
	// 15: AddThunkMap(7 args)
	virtual int __thiscall AddThunkMap(uint32_t *, uint32_t, uint32_t, void *, uint32_t, uint16_t, uint32_t) { return 1; }
	// 16: AddPublic
	virtual int __thiscall AddPublic(const char *, uint16_t, uint32_t) { return 1; }
	// 17: getEnumContrib
	virtual int __thiscall getEnumContrib(void *) { return 0; }
	// 18: QueryTypeServer
	virtual int __thiscall QueryTypeServer(uint32_t, void **) { return 0; }
	// 19: QueryItsmForTi
	virtual int __thiscall QueryItsmForTi(uint32_t, uint32_t *) { return 0; }
	// 20: QueryNextItsm
	virtual int __thiscall QueryNextItsm(uint32_t, uint32_t *) { return 0; }
	// 21: QueryLazyTypes
	virtual int __thiscall QueryLazyTypes() { return 0; }
	// 22: SetLazyTypes
	virtual int __thiscall SetLazyTypes(int) { return 1; }
	// 23: FindTypeServers
	virtual int __thiscall FindTypeServers(void *, char *) { return 1; }
	// 24: DumpTypeServers
	virtual void __thiscall DumpTypeServers() {}
	// 25: OpenDbg(dbgtype, Dbg**)
	virtual int __thiscall OpenDbg(uint32_t, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_dbg); return 1; }
	// 26: QueryDbgTypes(pdbgtype, pcDbgtype)
	virtual int __thiscall QueryDbgTypes(uint32_t *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 27: QueryAddrForSec
	virtual int __thiscall QueryAddrForSec(uint16_t, uint32_t, uint16_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 28: QueryAddrForSecEx
	virtual int __thiscall QueryAddrForSecEx(uint16_t, uint32_t, uint32_t, uint16_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 29: QuerySupportsEC
	virtual int __thiscall QuerySupportsEC() { return 0; }
	// 30: QueryPdb(PDB**)
	virtual int __thiscall QueryPdb(void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_pdb); return 1; }
	// 31: AddLinkInfo
	virtual int __thiscall AddLinkInfo(void *) { return 1; }
	// 32: QueryLinkInfo(pli, pcb)
	virtual int __thiscall QueryLinkInfo(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 33: QueryAge
	virtual uint32_t __thiscall QueryAge() { return 1; }
	// 34: QueryHeader
	virtual void * __thiscall QueryHeader() { return nullptr; }
	// 35: FlushTypeServers
	virtual void __thiscall FlushTypeServers() {}
	// 36: QueryTypeServerByPdb
	virtual int __thiscall QueryTypeServerByPdb(const char *, uint32_t *) { return 0; }
	// 37: OpenModW(szModule, szFile, Mod**)
	virtual int __thiscall OpenModW(const wchar_t *, const wchar_t *, void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_mod); return 1; }
	// 38: DeleteModW
	virtual int __thiscall DeleteModW(const wchar_t *) { return 1; }
	// 39: AddPublicW
	virtual int __thiscall AddPublicW(const wchar_t *, uint16_t, uint32_t, uint32_t) { return 1; }
	// 40: QueryTypeServerByPdbW
	virtual int __thiscall QueryTypeServerByPdbW(const wchar_t *, uint32_t *) { return 0; }
	// 41: AddLinkInfoW
	virtual int __thiscall AddLinkInfoW(void *) { return 1; }
	// 42: AddPublic2
	virtual int __thiscall AddPublic2(const char *, uint16_t, uint32_t, uint32_t) { return 1; }
	// 43: QueryMachineType
	virtual uint16_t __thiscall QueryMachineType() { return 0; }
	// 44: SetMachineType
	virtual void __thiscall SetMachineType(uint16_t) {}
	// 45: RemoveDataForRva
	virtual void __thiscall RemoveDataForRva(uint32_t, uint32_t) {}
	// 46: FStripped
	virtual int __thiscall FStripped() { return 0; }
	// 47: QueryModFromAddr2
	virtual int __thiscall QueryModFromAddr2(uint16_t, uint32_t, void **, uint16_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 48: QueryNoOfMods(pcMods)
	virtual int __thiscall QueryNoOfMods(uint32_t *pcMods) { writeOut32(pcMods, 0); return 1; }
	// 49: QueryMods
	virtual int __thiscall QueryMods(void **, uint32_t) { return 1; }
	// 50: QueryImodFromAddr
	virtual int __thiscall QueryImodFromAddr(uint16_t, uint32_t, void **, uint16_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 51: OpenModFromImod
	virtual int __thiscall OpenModFromImod(uint32_t, void **) { return 0; }
	// 52: QueryHeader2(cb, pb, pcbOut)
	virtual int __thiscall QueryHeader2(uint32_t, void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 53: FAddSourceMappingItem
	virtual int __thiscall FAddSourceMappingItem(const wchar_t *, const wchar_t *, uint32_t) { return 1; }
	// 54: FSetPfnNotePdbUsed
	virtual int __thiscall FSetPfnNotePdbUsed(void *, void *) { return 1; }
	// 55: FCTypes
	virtual int __thiscall FCTypes() { return 0; }
	// 56: QueryFileInfo2(pb, pcb)
	virtual int __thiscall QueryFileInfo2(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 57: FSetPfnQueryCallback
	virtual int __thiscall FSetPfnQueryCallback(void *, void *) { return 1; }
	// 58: FSetPfnNoteTypeMismatch
	virtual int __thiscall FSetPfnNoteTypeMismatch(void *, void *) { return 1; }
	// 59: FSetPfnTmdTypeFilter
	virtual int __thiscall FSetPfnTmdTypeFilter(void *, void *) { return 1; }
	// 60: RemovePublic
	virtual int __thiscall RemovePublic(const char *) { return 1; }
	// 61: getEnumContrib2
	virtual int __thiscall getEnumContrib2(void *) { return 0; }
	// 62: QueryModFromAddrEx
	virtual int __thiscall QueryModFromAddrEx(uint16_t, uint32_t, void **, uint16_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 63: QueryImodFromAddrEx
	virtual int __thiscall QueryImodFromAddrEx(uint16_t, uint32_t, void **, uint16_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
};

// --- Mod interface (64 vtable slots) ---
struct FakeMod {
	// 0: QueryInterfaceVersion
	virtual uint32_t __thiscall QueryInterfaceVersion() { return PDB_INTV; }
	// 1: QueryImplementationVersion
	virtual uint32_t __thiscall QueryImplementationVersion() { return PDB_IMPV; }
	// 2: AddTypes
	virtual int __thiscall AddTypes(void *, uint32_t) { return 1; }
	// 3: AddSymbols
	virtual int __thiscall AddSymbols(void *, uint32_t) { return 1; }
	// 4: AddPublic
	virtual int __thiscall AddPublic(const char *, uint16_t, uint32_t) { return 1; }
	// 5: AddLines(8 args)
	virtual int __thiscall AddLines(const char *, uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, void *, uint32_t) { return 1; }
	// 6: AddSecContrib
	virtual int __thiscall AddSecContrib(uint16_t, uint32_t, uint32_t, uint32_t) { return 1; }
	// 7: QueryCBName(pcb)
	virtual int __thiscall QueryCBName(uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 8: QueryName(szName, pcb)
	virtual int __thiscall QueryName(char *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 9: QuerySymbols(pbSym, pcb)
	virtual int __thiscall QuerySymbols(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 10: QueryLines(pbLines, pcb)
	virtual int __thiscall QueryLines(void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 11: SetPvClient
	virtual int __thiscall SetPvClient(void *) { return 1; }
	// 12: GetPvClient(ppvClient)
	virtual int __thiscall GetPvClient(void **pp) { writeOut32(pp, 0); return 1; }
	// 13: QueryFirstCodeSecContrib
	virtual int __thiscall QueryFirstCodeSecContrib(uint16_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 14: QueryImod(pimod)
	virtual int __thiscall QueryImod(uint32_t *p) { writeOut32(p, 0); return 1; }
	// 15: QueryDBI(ppdbi)
	virtual int __thiscall QueryDBI(void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_dbi); return 1; }
	// 16: Close
	virtual int __thiscall Close() { return 1; }
	// 17: QueryCBFile(pcb)
	virtual int __thiscall QueryCBFile(uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// 18: QueryFile(szFile, pcb)
	virtual int __thiscall QueryFile(char *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 19: QueryTpi(pptpi)
	virtual int __thiscall QueryTpi(void **pp) { writeOut32(pp, (uint32_t)(uintptr_t)&g_tpi); return 1; }
	// 20: AddSecContribEx
	virtual int __thiscall AddSecContribEx(uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
	// 21: QueryItsm(pitsm)
	virtual int __thiscall QueryItsm(uint32_t *p) { writeOut32(p, 0); return 1; }
	// 22: QuerySrcFile(szFile, pcb)
	virtual int __thiscall QuerySrcFile(char *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 23: QuerySupportsEC
	virtual int __thiscall QuerySupportsEC() { return 0; }
	// 24: QueryPdbFile(szFile, pcb)
	virtual int __thiscall QueryPdbFile(char *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 25: ReplaceLines
	virtual int __thiscall ReplaceLines(void *, uint32_t) { return 1; }
	// 26: GetEnumLines
	virtual int __thiscall GetEnumLines(void *) { return 0; }
	// 27: QueryLineFlags
	virtual int __thiscall QueryLineFlags(uint32_t *) { return 0; }
	// 28: QueryFileNameInfo
	virtual int __thiscall QueryFileNameInfo(uint32_t, wchar_t *, uint32_t *, uint32_t *, uint32_t *) { return 0; }
	// 29: AddPublicW
	virtual int __thiscall AddPublicW(const wchar_t *, uint16_t, uint32_t, uint32_t) { return 1; }
	// 30: AddLinesW(8 args)
	virtual int __thiscall AddLinesW(const wchar_t *, uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, void *, uint32_t) { return 1; }
	// 31: QueryNameW(szName, pcb)
	virtual int __thiscall QueryNameW(wchar_t *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 32: QueryFileW(szFile, pcb)
	virtual int __thiscall QueryFileW(wchar_t *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 33: QuerySrcFileW(szFile, pcb)
	virtual int __thiscall QuerySrcFileW(wchar_t *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 34: QueryPdbFileW(szFile, pcb)
	virtual int __thiscall QueryPdbFileW(wchar_t *sz, uint32_t *) { if (sz) *sz = 0; return 1; }
	// 35: AddPublic2
	virtual int __thiscall AddPublic2(const char *, uint16_t, uint32_t, uint32_t) { return 1; }
	// 36: InsertLines
	virtual int __thiscall InsertLines(void *, uint32_t) { return 1; }
	// 37: QueryLines2(cbLines, pbLines, pcbLines)
	virtual int __thiscall QueryLines2(uint32_t, void *, uint32_t *pcb) { writeOut32(pcb, 0); return 1; }
	// Padding 38-63
	virtual int __thiscall _pad38() { return 0; }
	virtual int __thiscall _pad39() { return 0; }
	virtual int __thiscall _pad40() { return 0; }
	virtual int __thiscall _pad41() { return 0; }
	virtual int __thiscall _pad42() { return 0; }
	virtual int __thiscall _pad43() { return 0; }
	virtual int __thiscall _pad44() { return 0; }
	virtual int __thiscall _pad45() { return 0; }
	virtual int __thiscall _pad46() { return 0; }
	virtual int __thiscall _pad47() { return 0; }
	virtual int __thiscall _pad48() { return 0; }
	virtual int __thiscall _pad49() { return 0; }
	virtual int __thiscall _pad50() { return 0; }
	virtual int __thiscall _pad51() { return 0; }
	virtual int __thiscall _pad52() { return 0; }
	virtual int __thiscall _pad53() { return 0; }
	virtual int __thiscall _pad54() { return 0; }
	virtual int __thiscall _pad55() { return 0; }
	virtual int __thiscall _pad56() { return 0; }
	virtual int __thiscall _pad57() { return 0; }
	virtual int __thiscall _pad58() { return 0; }
	virtual int __thiscall _pad59() { return 0; }
	virtual int __thiscall _pad60() { return 0; }
	virtual int __thiscall _pad61() { return 0; }
	virtual int __thiscall _pad62() { return 0; }
	virtual int __thiscall _pad63() { return 0; }
};

// --- TPI interface (32 vtable slots) ---
struct FakeTPI {
	// 0: QueryInterfaceVersion
	virtual uint32_t __thiscall QueryInterfaceVersion() { return PDB_INTV; }
	// 1: QueryImplementationVersion
	virtual uint32_t __thiscall QueryImplementationVersion() { return PDB_IMPV; }
	// 2-4: Ti16 queries
	virtual int __thiscall QueryTi16ForCVRecord(void *, void *) { return 0; }
	virtual int __thiscall QueryCVRecordForTi16(uint32_t, void *, uint32_t *) { return 0; }
	virtual int __thiscall QueryPbCVRecordForTi16(uint32_t, void **) { return 0; }
	// 5-7: Ti16 range + size
	virtual uint16_t __thiscall QueryTi16Min() { return 0; }
	virtual uint16_t __thiscall QueryTi16Mac() { return 0; }
	virtual int32_t __thiscall QueryCb() { return 0; }
	// 8: Close
	virtual int __thiscall Close() { return 1; }
	// 9: Commit
	virtual int __thiscall Commit() { return 1; }
	// 10: QueryTi16ForUDT
	virtual int __thiscall QueryTi16ForUDT(const char *, int, void *) { return 0; }
	// 11: SupportQueryTiForUDT
	virtual int __thiscall SupportQueryTiForUDT() { return 0; }
	// 12: fIs16bitTypePool
	virtual int __thiscall fIs16bitTypePool() { return 0; }
	// 13: QueryTiForUDT
	virtual int __thiscall QueryTiForUDT(const char *, int, void *) { return 0; }
	// 14: QueryTiForCVRecord
	virtual int __thiscall QueryTiForCVRecord(void *, void *) { return 0; }
	// 15: QueryCVRecordForTi
	virtual int __thiscall QueryCVRecordForTi(uint32_t, void *, uint32_t *) { return 0; }
	// 16: QueryPbCVRecordForTi
	virtual int __thiscall QueryPbCVRecordForTi(uint32_t, void **) { return 0; }
	// 17: QueryTiMin
	virtual uint32_t __thiscall QueryTiMin() { return 0x1000; }
	// 18: QueryTiMac
	virtual uint32_t __thiscall QueryTiMac() { return 0x1000; }
	// 19: AreTypesEqual
	virtual int __thiscall AreTypesEqual(uint32_t, uint32_t) { return 0; }
	// 20: IsTypeServed
	virtual int __thiscall IsTypeServed(uint32_t) { return 0; }
	// 21: QueryTiForUDTW
	virtual int __thiscall QueryTiForUDTW(const wchar_t *, int, void *) { return 0; }
	// 22: QueryModSrcLineForUDTDefn
	virtual int __thiscall QueryModSrcLineForUDTDefn(uint32_t, void *, void *, uint32_t *) { return 0; }
	// Padding 23-31
	virtual int __thiscall _pad23() { return 0; }
	virtual int __thiscall _pad24() { return 0; }
	virtual int __thiscall _pad25() { return 0; }
	virtual int __thiscall _pad26() { return 0; }
	virtual int __thiscall _pad27() { return 0; }
	virtual int __thiscall _pad28() { return 0; }
	virtual int __thiscall _pad29() { return 0; }
	virtual int __thiscall _pad30() { return 0; }
	virtual int __thiscall _pad31() { return 0; }
};

// --- GSI interface (16 vtable slots) ---
struct FakeGSI {
	virtual uint32_t __thiscall QueryInterfaceVersion() { return PDB_INTV; }
	virtual uint32_t __thiscall QueryImplementationVersion() { return PDB_IMPV; }
	virtual void * __thiscall NextSym(void *) { return nullptr; }
	virtual void * __thiscall HashSym(const char *, void *) { return nullptr; }
	virtual void * __thiscall NearestSym(uint16_t, uint32_t, int32_t *) { return nullptr; }
	virtual int __thiscall Close() { return 1; }
	virtual int __thiscall getEnumThunk(uint16_t, uint32_t, void **) { return 0; }
	virtual uint32_t __thiscall OffForSym(void *) { return 0; }
	virtual void * __thiscall SymForOff(uint32_t) { return nullptr; }
	virtual void * __thiscall HashSymW(const wchar_t *, void *) { return nullptr; }
	virtual int __thiscall getEnumByAddr(void **) { return 0; }
	// Padding 11-15
	virtual int __thiscall _pad11() { return 0; }
	virtual int __thiscall _pad12() { return 0; }
	virtual int __thiscall _pad13() { return 0; }
	virtual int __thiscall _pad14() { return 0; }
	virtual int __thiscall _pad15() { return 0; }
};

// --- Dbg interface (16 vtable slots) ---
struct FakeDbg {
	virtual int __thiscall Close() { return 1; }
	virtual int32_t __thiscall QuerySize() { return 0; }
	virtual void __thiscall Reset() {}
	virtual int __thiscall Skip(uint32_t) { return 1; }
	virtual int __thiscall QueryNext(uint32_t, void *) { return 0; }
	virtual int __thiscall Find(void *) { return 0; }
	virtual int __thiscall Clear() { return 1; }
	virtual int __thiscall Append(uint32_t, void *) { return 1; }
	virtual int __thiscall ReplaceNext(uint32_t, void *) { return 1; }
	virtual int __thiscall Clone(void **) { return 0; }
	virtual int32_t __thiscall QueryElementSize() { return 0; }
	// Padding 11-15
	virtual int __thiscall _pad11() { return 0; }
	virtual int __thiscall _pad12() { return 0; }
	virtual int __thiscall _pad13() { return 0; }
	virtual int __thiscall _pad14() { return 0; }
	virtual int __thiscall _pad15() { return 0; }
};

// --- NameMap interface (20 vtable slots) ---
struct FakeNameMap {
	virtual int __thiscall close() { return 1; }
	virtual int __thiscall reinitialize() { return 1; }
	virtual int __thiscall getNi(const char *, uint32_t *pni) { writeOut32(pni, 0); return 1; }
	virtual int __thiscall getName(uint32_t, const char **) { return 0; }
	virtual int __thiscall getEnumNameMap(void **) { return 0; }
	virtual int __thiscall contains(const char *, uint32_t *) { return 0; }
	virtual int __thiscall commit() { return 1; }
	virtual int __thiscall isValidNi(uint32_t) { return 0; }
	virtual int __thiscall getNiW(const wchar_t *, uint32_t *pni) { writeOut32(pni, 0); return 1; }
	virtual int __thiscall getNameW(uint32_t, const wchar_t *, uint32_t *) { return 0; }
	virtual int __thiscall containsW(const wchar_t *, uint32_t *) { return 0; }
	virtual int __thiscall containsUTF8(const char *, uint32_t *) { return 0; }
	virtual int __thiscall getNiUTF8(const char *, uint32_t *pni) { writeOut32(pni, 0); return 1; }
	virtual int __thiscall getNameA(uint32_t, const char **) { return 0; }
	virtual int __thiscall getNameW2(uint32_t, const wchar_t **) { return 0; }
	// Padding 15-19
	virtual int __thiscall _pad15() { return 0; }
	virtual int __thiscall _pad16() { return 0; }
	virtual int __thiscall _pad17() { return 0; }
	virtual int __thiscall _pad18() { return 0; }
	virtual int __thiscall _pad19() { return 0; }
};

// --- Stream interface (12 vtable slots) ---
struct FakeStream {
	virtual int32_t __thiscall QueryCb() { return 0; }
	virtual int __thiscall Read(uint32_t, void *, uint32_t *) { return 1; }
	virtual int __thiscall Write(uint32_t, void *, uint32_t) { return 1; }
	virtual int __thiscall Replace(void *, uint32_t) { return 1; }
	virtual int __thiscall Append(void *, uint32_t) { return 1; }
	virtual int __thiscall Delete() { return 1; }
	virtual int __thiscall Release() { return 1; }
	virtual int __thiscall Read2(uint32_t, void *, uint32_t) { return 1; }
	virtual int __thiscall Truncate(uint32_t) { return 1; }
	// Padding 9-11
	virtual int __thiscall _pad9() { return 0; }
	virtual int __thiscall _pad10() { return 0; }
	virtual int __thiscall _pad11() { return 0; }
};

// Global instances (matching extern declarations above)
FakePDB g_pdb;
FakeDBI g_dbi;
FakeMod g_mod;
FakeTPI g_tpi;
FakeGSI g_gsi;
FakeDbg g_dbg;
FakeNameMap g_namemap;
FakeStream g_stream;

// Legacy sentinel for PDBOpenStreamEx
static uint32_t g_fakeStreamLegacy = 0;

// --- C-style exports ---

static int openPDB(int32_t *pec, void **ppPDB) {
	if (pec) *pec = 0;
	if (ppPDB) *(uint32_t *)ppPDB = (uint32_t)(uintptr_t)&g_pdb;
	return 1;
}

DLLEXPORT int __cdecl PDB_Open2W(const wchar_t *, const char *, int32_t *pec, wchar_t *, unsigned int, void **ppPDB) {
	return openPDB(pec, ppPDB);
}

DLLEXPORT int __cdecl PDB_Open3W(const wchar_t *, const char *, uint32_t, void *, uint32_t, int32_t *pec,
                                  wchar_t *, unsigned int, void **ppPDB) {
	return openPDB(pec, ppPDB);
}

DLLEXPORT int __cdecl PDB_OpenValidate5(const wchar_t *, const wchar_t *, void *, void *, void *, uint32_t,
                                         int32_t *pec, wchar_t *, unsigned int, void **ppPDB) {
	return openPDB(pec, ppPDB);
}

DLLEXPORT int __cdecl PDBExportValidateInterface(uint32_t) {
	return 1;
}

// CRC-32 with reflected polynomial 0xEDB88320 (ISO 3309).
// Used by the linker to hash string literal content for ??_C@_ symbol names.
DLLEXPORT uint32_t __cdecl SigForPbCb(const unsigned char *pb, uint32_t cb, uint32_t dwInitial) {
	uint32_t crc = dwInitial;
	for (uint32_t i = 0; i < cb; i++) {
		uint32_t index = (crc ^ pb[i]) & 0xff;
		uint32_t entry = index;
		for (int j = 0; j < 8; j++) {
			if (entry & 1) {
				entry = (entry >> 1) ^ 0xEDB88320;
			} else {
				entry >>= 1;
			}
		}
		crc = (crc >> 8) ^ entry;
	}
	return crc;
}

DLLEXPORT const char * __cdecl SzCanonFilename(const char *sz) {
	return sz;
}

DLLEXPORT int __cdecl PDB_Open2W_C(const wchar_t *, const char *, int32_t *pec, wchar_t *, unsigned int, void **ppPDB) {
	return openPDB(pec, ppPDB);
}

DLLEXPORT int __cdecl PDBOpenStreamEx(void *, const char *, uint32_t, void **ppStream) {
	if (ppStream) *(uint32_t *)ppStream = (uint32_t)(uintptr_t)&g_fakeStreamLegacy;
	return 1;
}

DLLEXPORT int __cdecl PDBCommit(void *) {
	return 1;
}

DLLEXPORT int __cdecl PDBClose(void *) {
	return 1;
}

DLLEXPORT int __cdecl NameMap_open(void *, int, void **ppNameMap) {
	if (ppNameMap) *(uint32_t *)ppNameMap = (uint32_t)(uintptr_t)&g_namemap;
	return 1;
}

DLLEXPORT int __cdecl StreamAppend(void *, void *, int32_t) {
	return 1;
}

DLLEXPORT int32_t __cdecl StreamQueryCb(void *) {
	return 0;
}

DLLEXPORT int __cdecl StreamRead(void *, int32_t, void *, int32_t *pcb) {
	if (pcb) *pcb = 0;
	return 1;
}

DLLEXPORT int __cdecl StreamRelease(void *) {
	return 1;
}

DLLEXPORT int __cdecl StreamReplace(void *, void *, int32_t) {
	return 1;
}

DLLEXPORT int __cdecl StreamTruncate(void *, int32_t) {
	return 1;
}

DLLEXPORT int __cdecl StreamWrite(void *, int32_t, void *, int32_t) {
	return 1;
}
