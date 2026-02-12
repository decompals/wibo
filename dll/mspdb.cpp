#include "mspdb.h"

#include "common.h"
#include "context.h"
#include "kernel32/memoryapi.h"
#include "modules.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

// ============================================================================
// Fake PDB vtable infrastructure
//
// The X360 linker requires a working PDB/XDB interface to complete PE writing.
// We provide fake COM-style objects with vtables full of x86 __thiscall stubs
// that accept all calls and return success/no-op values. The stubs are tiny
// snippets of x86 machine code generated at runtime into mmap'd executable
// memory.
//
// __thiscall convention: this in ECX, args on stack, callee pops args.
// Vtable dispatch: mov eax,[ecx]; call [eax+N*4]
// ============================================================================

// 32-bit COM-style object: first dword is vtable pointer
struct FakeVtObj {
	uint32_t vptr;
};

// Fake objects - allocated from MAP_32BIT code page (must be <4GB for guest pointers)
static FakeVtObj *g_obj_pdb;
static FakeVtObj *g_obj_dbi;
static FakeVtObj *g_obj_mod;
static FakeVtObj *g_obj_tpi;
static FakeVtObj *g_obj_gsi;
static FakeVtObj *g_obj_dbg;
static FakeVtObj *g_obj_namemap;
static FakeVtObj *g_obj_stream;

// Vtable sizes: must cover all slots the linker may call.
// Source: microsoft-pdb/langapi/include/pdb.h
static constexpr int kPdbVtableSlots = 64;     // PDB interface (32 defined + headroom)
static constexpr int kDbiVtableSlots = 64;     // DBI interface (57 defined + headroom)
static constexpr int kModVtableSlots = 64;     // Mod interface
static constexpr int kTpiVtableSlots = 32;     // TPI interface (23 defined)
static constexpr int kGsiVtableSlots = 16;     // GSI interface (11 defined)
static constexpr int kDbgVtableSlots = 16;     // Dbg interface
static constexpr int kNameMapVtableSlots = 20; // NameMap interface (15 defined)
static constexpr int kStreamVtableSlots = 12;  // Stream interface (9 defined)

// Vtables: arrays of 32-bit x86 function pointers - allocated from MAP_32BIT code page
static uint32_t *g_vt_pdb;
static uint32_t *g_vt_dbi;
static uint32_t *g_vt_mod;
static uint32_t *g_vt_tpi;
static uint32_t *g_vt_gsi;
static uint32_t *g_vt_dbg;
static uint32_t *g_vt_namemap;
static uint32_t *g_vt_stream;

// Legacy sentinel value for PDBOpenStreamEx C-style export - allocated from MAP_32BIT code page
static uint32_t *g_fakeStream_legacy;

// --- x86 machine code generation ---

static uint8_t *g_code_page;
static size_t g_code_pos;
static constexpr size_t CODE_PAGE_SIZE = 16384;

static uint8_t *codeAlloc(size_t n) {
	if (!g_code_page || g_code_pos + n > CODE_PAGE_SIZE) {
		DEBUG_LOG("mspdb: codeAlloc(%zu) failed: page=%p pos=%zu\n", n, g_code_page, g_code_pos);
		abort();
	}
	uint8_t *p = g_code_page + g_code_pos;
	g_code_pos += n;
	return p;
}

static uint32_t addr32(void *p) {
	return (uint32_t)(uintptr_t)p;
}

// Generate: mov eax, <retval>; ret <nargs*4>
// For __thiscall methods that return a constant value.
static uint32_t genRet(uint32_t retval, int nargs) {
	uint16_t pop = nargs * 4;
	size_t sz = 5 + (pop ? 3 : 1);
	uint8_t *s = codeAlloc(sz);
	uint8_t *p = s;
	*p++ = 0xB8;
	memcpy(p, &retval, 4);
	p += 4; // mov eax, retval
	if (pop) {
		*p++ = 0xC2;
		memcpy(p, &pop, 2);
	} // ret pop
	else {
		*p++ = 0xC3;
	} // ret
	return addr32(s);
}

// Generate: ret <nargs*4>  (void return)
static uint32_t genVoid(int nargs) {
	uint16_t pop = nargs * 4;
	size_t sz = pop ? 3 : 1;
	uint8_t *s = codeAlloc(sz);
	uint8_t *p = s;
	if (pop) {
		*p++ = 0xC2;
		memcpy(p, &pop, 2);
	} else {
		*p++ = 0xC3;
	}
	return addr32(s);
}

// Generate: mov eax,[esp+off]; test eax,eax; jz skip; mov dword [eax],val; skip: mov eax,1; ret pop
// For __thiscall methods that write a 32-bit value to an output pointer param.
// outArg: 0-based index of the output param among stack args (not counting this)
// NULL-safe: skips the write if the output pointer is NULL.
static uint32_t genOut(int outArg, uint32_t val, int nargs) {
	uint8_t off = (uint8_t)((outArg + 1) * 4); // +1 for return address
	uint16_t pop = nargs * 4;
	uint8_t *s = codeAlloc(28);
	uint8_t *p = s;
	// mov eax, [esp+off]
	*p++ = 0x8B;
	*p++ = 0x44;
	*p++ = 0x24;
	*p++ = off;
	// test eax, eax
	*p++ = 0x85;
	*p++ = 0xC0;
	// jz +6 (skip the mov dword ptr [eax], val)
	*p++ = 0x74;
	*p++ = 0x06;
	// mov dword ptr [eax], val
	*p++ = 0xC7;
	*p++ = 0x00;
	memcpy(p, &val, 4);
	p += 4;
	// mov eax, 1
	*p++ = 0xB8;
	*p++ = 0x01;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	// ret pop
	if (pop) {
		*p++ = 0xC2;
		memcpy(p, &pop, 2);
	} else {
		*p++ = 0xC3;
	}
	return addr32(s);
}

// Generate: mov eax,[esp+off]; mov byte [eax],0; xor eax,eax; ret pop
// For QueryLastError-style methods: write empty string to buffer, return 0.
static uint32_t genClearBuf(int bufArg, int nargs) {
	uint8_t off = (uint8_t)((bufArg + 1) * 4);
	uint16_t pop = nargs * 4;
	uint8_t *s = codeAlloc(16);
	uint8_t *p = s;
	// mov eax, [esp+off]
	*p++ = 0x8B;
	*p++ = 0x44;
	*p++ = 0x24;
	*p++ = off;
	// mov byte ptr [eax], 0
	*p++ = 0xC6;
	*p++ = 0x00;
	*p++ = 0x00;
	// xor eax, eax
	*p++ = 0x31;
	*p++ = 0xC0;
	// ret pop
	if (pop) {
		*p++ = 0xC2;
		memcpy(p, &pop, 2);
	} else {
		*p++ = 0xC3;
	}
	return addr32(s);
}

// Generate: int3 (trap for unimplemented methods, with index in AL for debugging)
static uint32_t genTrap(uint8_t idx) {
	uint8_t *s = codeAlloc(4);
	s[0] = 0xB0;
	s[1] = idx; // mov al, idx
	s[2] = 0xCC; // int3
	s[3] = 0xC3; // ret (fallthrough safety)
	return addr32(s);
}

// PDB version constants (VS2010 era - matches X360 linker)
static constexpr uint32_t PDB_INTV = 20091201;
static constexpr uint32_t PDB_IMPV = 20091201;

static bool g_vtables_ready = false;

static void initVtables() {
	if (g_vtables_ready)
		return;
	g_vtables_ready = true;

	// Allocate executable page for x86 stubs (MAP_32BIT = first 2GB)
	g_code_page = (uint8_t *)mmap(nullptr, CODE_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
								  MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (g_code_page == MAP_FAILED) {
		// Fallback without MAP_32BIT
		g_code_page = (uint8_t *)mmap(nullptr, CODE_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
									  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	if (g_code_page == MAP_FAILED) {
		DEBUG_LOG("mspdb: mmap for code page failed\n");
		abort();
	}
	if ((uintptr_t)g_code_page >= 0xFFFFFFFFULL) {
		DEBUG_LOG("mspdb: code page at %p not 32-bit addressable\n", g_code_page);
		abort();
	}
	g_code_pos = 0;

	// Allocate fake objects from MAP_32BIT page (must be <4GB for guest pointers)
	g_obj_pdb = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_dbi = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_mod = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_tpi = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_gsi = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_dbg = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_namemap = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));
	g_obj_stream = (FakeVtObj *)codeAlloc(sizeof(FakeVtObj));

	// Allocate vtable arrays from MAP_32BIT page
	g_vt_pdb = (uint32_t *)codeAlloc(kPdbVtableSlots * sizeof(uint32_t));
	g_vt_dbi = (uint32_t *)codeAlloc(kDbiVtableSlots * sizeof(uint32_t));
	g_vt_mod = (uint32_t *)codeAlloc(kModVtableSlots * sizeof(uint32_t));
	g_vt_tpi = (uint32_t *)codeAlloc(kTpiVtableSlots * sizeof(uint32_t));
	g_vt_gsi = (uint32_t *)codeAlloc(kGsiVtableSlots * sizeof(uint32_t));
	g_vt_dbg = (uint32_t *)codeAlloc(kDbgVtableSlots * sizeof(uint32_t));
	g_vt_namemap = (uint32_t *)codeAlloc(kNameMapVtableSlots * sizeof(uint32_t));
	g_vt_stream = (uint32_t *)codeAlloc(kStreamVtableSlots * sizeof(uint32_t));

	// Allocate legacy stream sentinel
	g_fakeStream_legacy = (uint32_t *)codeAlloc(sizeof(uint32_t));
	*g_fakeStream_legacy = 0;

	DEBUG_LOG("mspdb: code page at %p, objects: PDB=%p DBI=%p Mod=%p TPI=%p GSI=%p\n", g_code_page, g_obj_pdb,
			  g_obj_dbi, g_obj_mod, g_obj_tpi, g_obj_gsi);

	// Shorthand addresses for fake sub-objects
	uint32_t pPDB = addr32(g_obj_pdb);
	uint32_t pDBI = addr32(g_obj_dbi);
	uint32_t pMod = addr32(g_obj_mod);
	uint32_t pTPI = addr32(g_obj_tpi);
	uint32_t pGSI = addr32(g_obj_gsi);
	uint32_t pDbg = addr32(g_obj_dbg);
	uint32_t pNM = addr32(g_obj_namemap);
	uint32_t pStr = addr32(g_obj_stream);

	// --- PDB vtable (microsoft-pdb/langapi/include/pdb.h, slots 0-31) ---
	// Fill with traps first
	for (int i = 0; i < kPdbVtableSlots; i++)
		g_vt_pdb[i] = genTrap((uint8_t)i);
	//  0: QueryInterfaceVersion() -> INTV
	g_vt_pdb[0] = genRet(PDB_INTV, 0);
	//  1: QueryImplementationVersion() -> IMPV
	g_vt_pdb[1] = genRet(PDB_IMPV, 0);
	//  2: QueryLastError(char szError[]) -> EC
	g_vt_pdb[2] = genClearBuf(0, 1);
	//  3: QueryPDBName(char szPDB[]) -> char* (return the buffer with empty string)
	g_vt_pdb[3] = genClearBuf(0, 1); // sets buf[0]=0, returns 0 (NULL) but that's OK
	//  4: QuerySignature() -> SIG
	g_vt_pdb[4] = genRet(0, 0);
	//  5: QueryAge() -> AGE
	g_vt_pdb[5] = genRet(1, 0);
	//  6: CreateDBI(szTarget, DBI** ppdbi) -> BOOL  [2 args, out=arg1]
	g_vt_pdb[6] = genOut(1, pDBI, 2);
	//  7: OpenDBI(szTarget, szMode, DBI** ppdbi) -> BOOL  [3 args, out=arg2]
	g_vt_pdb[7] = genOut(2, pDBI, 3);
	//  8: OpenTpi(szMode, TPI** pptpi) -> BOOL  [2 args, out=arg1]
	g_vt_pdb[8] = genOut(1, pTPI, 2);
	//  9: OpenIpi(szMode, TPI** pptpi) -> BOOL  [2 args, out=arg1]
	g_vt_pdb[9] = genOut(1, pTPI, 2);
	// 10: Commit() -> BOOL
	g_vt_pdb[10] = genRet(1, 0);
	// 11: Close() -> BOOL
	g_vt_pdb[11] = genRet(1, 0);
	// 12: OpenStream(szStream, Stream** ppstream) -> BOOL [2 args, out=arg1]
	g_vt_pdb[12] = genOut(1, pStr, 2);
	// 13: GetEnumStreamNameMap(Enum**) -> BOOL
	g_vt_pdb[13] = genRet(0, 1); // return FALSE - no enumerator
	// 14: GetRawBytes(pfn) -> BOOL
	g_vt_pdb[14] = genRet(0, 1);
	// 15: QueryPdbImplementationVersion() -> IMPV
	g_vt_pdb[15] = genRet(PDB_IMPV, 0);
	// 16: OpenDBIEx(szTarget, szMode, DBI**, pfn) -> BOOL [4 args, out=arg2]
	g_vt_pdb[16] = genOut(2, pDBI, 4);
	// 17: CopyTo(szDst, filter, reserved) -> BOOL
	g_vt_pdb[17] = genRet(1, 3);
	// 18: OpenSrc(Src**) -> BOOL
	g_vt_pdb[18] = genRet(0, 1); // return FALSE
	// 19: QueryLastErrorExW(wszError, cchMax) -> EC
	g_vt_pdb[19] = genClearBuf(0, 2);
	// 20: QueryPDBNameExW(wszPDB, cchMax) -> wchar_t*
	// NOTE: linker's helper at 0x42EA4B only pushes 1 arg before calling this
	g_vt_pdb[20] = genClearBuf(0, 1);
	// 21: QuerySignature2(PSIG70) -> BOOL
	g_vt_pdb[21] = genRet(1, 1);
	// 22: CopyToW(szDst, filter, reserved) -> BOOL
	g_vt_pdb[22] = genRet(1, 3);
	// 23: fIsSZPDB() -> BOOL
	g_vt_pdb[23] = genRet(1, 0);
	// 24: OpenStreamW(szStream, Stream**) -> BOOL [2 args, out=arg1]
	g_vt_pdb[24] = genOut(1, pStr, 2);
	// 25: CopyToW2(szDst, filter, pfn, pvCtx) -> BOOL
	g_vt_pdb[25] = genRet(1, 4);
	// 26: OpenStreamEx(szStream, szMode, Stream**) -> BOOL [3 args, out=arg2]
	g_vt_pdb[26] = genOut(2, pStr, 3);
	// 27: RegisterPDBMapping(from, to) -> BOOL
	g_vt_pdb[27] = genRet(1, 2);
	// 28: EnablePrefetching() -> BOOL
	g_vt_pdb[28] = genRet(1, 0);
	// 29: FLazy() -> BOOL
	g_vt_pdb[29] = genRet(0, 0);
	// 30: FMinimal() -> BOOL
	g_vt_pdb[30] = genRet(0, 0);
	// 31: ResetGUID(pb, cb) -> BOOL
	g_vt_pdb[31] = genRet(1, 2);

	// --- DBI vtable (microsoft-pdb DBI interface, slots 0-63) ---
	for (int i = 0; i < kDbiVtableSlots; i++)
		g_vt_dbi[i] = genTrap((uint8_t)i);
	//  0: QueryImplementationVersion() -> IMPV
	g_vt_dbi[0] = genRet(PDB_IMPV, 0);
	//  1: QueryInterfaceVersion() -> INTV
	g_vt_dbi[1] = genRet(PDB_INTV, 0);
	//  2: OpenMod(szModule, szFile, Mod**) [3 args, out=arg2]
	g_vt_dbi[2] = genOut(2, pMod, 3);
	//  3: DeleteMod(szModule) -> BOOL
	g_vt_dbi[3] = genRet(1, 1);
	//  4: QueryNextMod(pmod, ppmodNext) -> BOOL [2 args, out=arg1 -> NULL]
	g_vt_dbi[4] = genOut(1, 0, 2); // *ppmodNext = NULL (end of list)
	//  5: OpenGlobals(GSI**) [1 arg, out=arg0]
	g_vt_dbi[5] = genOut(0, pGSI, 1);
	//  6: OpenPublics(GSI**) [1 arg, out=arg0]
	g_vt_dbi[6] = genOut(0, pGSI, 1);
	//  7: AddSec(isect, flags, off, cb) -> BOOL
	g_vt_dbi[7] = genRet(1, 4);
	//  8: QueryModFromAddr(6 args) -> BOOL
	g_vt_dbi[8] = genRet(0, 6);
	//  9: QuerySecMap(pb, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_dbi[9] = genOut(1, 0, 2);
	// 10: QueryFileInfo(pb, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_dbi[10] = genOut(1, 0, 2);
	// 11: DumpMods() -> void
	g_vt_dbi[11] = genVoid(0);
	// 12: DumpSecContribs() -> void
	g_vt_dbi[12] = genVoid(0);
	// 13: DumpSecMap() -> void
	g_vt_dbi[13] = genVoid(0);
	// 14: Close() -> BOOL
	g_vt_dbi[14] = genRet(1, 0);
	// 15: AddThunkMap(7 args) -> BOOL
	g_vt_dbi[15] = genRet(1, 7);
	// 16: AddPublic(szPublic, isect, off) -> BOOL
	g_vt_dbi[16] = genRet(1, 3);
	// 17: getEnumContrib(Enum**) -> BOOL
	g_vt_dbi[17] = genRet(0, 1);
	// 18: QueryTypeServer(itsm, TPI**) -> BOOL
	g_vt_dbi[18] = genRet(0, 2);
	// 19: QueryItsmForTi(ti, pitsm) -> BOOL
	g_vt_dbi[19] = genRet(0, 2);
	// 20: QueryNextItsm(itsm, inext) -> BOOL
	g_vt_dbi[20] = genRet(0, 2);
	// 21: QueryLazyTypes() -> BOOL
	g_vt_dbi[21] = genRet(0, 0);
	// 22: SetLazyTypes(fLazy) -> BOOL
	g_vt_dbi[22] = genRet(1, 1);
	// 23: FindTypeServers(pec, szError) -> BOOL
	g_vt_dbi[23] = genRet(1, 2);
	// 24: DumpTypeServers() -> void
	g_vt_dbi[24] = genVoid(0);
	// 25: OpenDbg(dbgtype, Dbg**) [2 args, out=arg1]
	g_vt_dbi[25] = genOut(1, pDbg, 2);
	// 26: QueryDbgTypes(pdbgtype, pcDbgtype) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_dbi[26] = genOut(1, 0, 2);
	// 27: QueryAddrForSec(6 args) -> BOOL
	g_vt_dbi[27] = genRet(0, 6);
	// 28: QueryAddrForSecEx(7 args) -> BOOL
	g_vt_dbi[28] = genRet(0, 7);
	// 29: QuerySupportsEC() -> BOOL
	g_vt_dbi[29] = genRet(0, 0);
	// 30: QueryPdb(PDB**) [1 arg, out=arg0]
	g_vt_dbi[30] = genOut(0, pPDB, 1);
	// 31: AddLinkInfo(pli) -> BOOL
	g_vt_dbi[31] = genRet(1, 1);
	// 32: QueryLinkInfo(pli, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_dbi[32] = genOut(1, 0, 2);
	// 33: QueryAge() const -> AGE
	g_vt_dbi[33] = genRet(1, 0);
	// 34: QueryHeader() const -> void*
	g_vt_dbi[34] = genRet(0, 0);
	// 35: FlushTypeServers() -> void
	g_vt_dbi[35] = genVoid(0);
	// 36: QueryTypeServerByPdb(szPdb, pitsm) -> BOOL
	g_vt_dbi[36] = genRet(0, 2);
	// 37: OpenModW(szModule, szFile, Mod**) [3 args, out=arg2]
	g_vt_dbi[37] = genOut(2, pMod, 3);
	// 38: DeleteModW(szModule) -> BOOL
	g_vt_dbi[38] = genRet(1, 1);
	// 39: AddPublicW(szPublic, isect, off, cvpsf) -> BOOL
	g_vt_dbi[39] = genRet(1, 4);
	// 40: QueryTypeServerByPdbW(szPdb, pitsm) -> BOOL
	g_vt_dbi[40] = genRet(0, 2);
	// 41: AddLinkInfoW(pli) -> BOOL
	g_vt_dbi[41] = genRet(1, 1);
	// 42: AddPublic2(szPublic, isect, off, cvpsf) -> BOOL
	g_vt_dbi[42] = genRet(1, 4);
	// 43: QueryMachineType() const -> USHORT
	g_vt_dbi[43] = genRet(0, 0);
	// 44: SetMachineType(wMachine) -> void
	g_vt_dbi[44] = genVoid(1);
	// 45: RemoveDataForRva(rva, cb) -> void
	g_vt_dbi[45] = genVoid(2);
	// 46: FStripped() -> BOOL
	g_vt_dbi[46] = genRet(0, 0);
	// 47: QueryModFromAddr2(7 args) -> BOOL
	g_vt_dbi[47] = genRet(0, 7);
	// 48: QueryNoOfMods(pcMods) -> BOOL [1 arg, out=arg0 -> 0]
	g_vt_dbi[48] = genOut(0, 0, 1);
	// 49: QueryMods(ppmodNext, cMods) -> BOOL
	g_vt_dbi[49] = genRet(1, 2);
	// 50: QueryImodFromAddr(7 args) -> BOOL
	g_vt_dbi[50] = genRet(0, 7);
	// 51: OpenModFromImod(imod, Mod**) [2 args]
	g_vt_dbi[51] = genRet(0, 2);
	// 52: QueryHeader2(cb, pb, pcbOut) -> BOOL [3 args, out=arg2 -> 0]
	g_vt_dbi[52] = genOut(2, 0, 3);
	// 53: FAddSourceMappingItem(3 args) -> BOOL
	g_vt_dbi[53] = genRet(1, 3);
	// 54: FSetPfnNotePdbUsed(pvCtx, pfn) -> BOOL
	g_vt_dbi[54] = genRet(1, 2);
	// 55: FCTypes() -> BOOL
	g_vt_dbi[55] = genRet(0, 0);
	// 56: QueryFileInfo2(pb, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_dbi[56] = genOut(1, 0, 2);
	// 57: FSetPfnQueryCallback(pvCtx, pfn) -> BOOL
	g_vt_dbi[57] = genRet(1, 2);
	// 58: FSetPfnNoteTypeMismatch(pvCtx, pfn) -> BOOL
	g_vt_dbi[58] = genRet(1, 2);
	// 59: FSetPfnTmdTypeFilter(pvCtx, pfn) -> BOOL
	g_vt_dbi[59] = genRet(1, 2);
	// 60: RemovePublic(szPublic) -> BOOL
	g_vt_dbi[60] = genRet(1, 1);
	// 61: getEnumContrib2(Enum**) -> BOOL
	g_vt_dbi[61] = genRet(0, 1);
	// 62: QueryModFromAddrEx(8 args) -> BOOL
	g_vt_dbi[62] = genRet(0, 8);
	// 63: QueryImodFromAddrEx(8 args) -> BOOL
	g_vt_dbi[63] = genRet(0, 8);

	// --- Mod vtable (microsoft-pdb Mod interface, slots 0-49) ---
	for (int i = 0; i < kModVtableSlots; i++)
		g_vt_mod[i] = genTrap((uint8_t)i);
	//  0: QueryInterfaceVersion() -> INTV
	g_vt_mod[0] = genRet(PDB_INTV, 0);
	//  1: QueryImplementationVersion() -> IMPV
	g_vt_mod[1] = genRet(PDB_IMPV, 0);
	//  2: AddTypes(pbTypes, cb) -> BOOL
	g_vt_mod[2] = genRet(1, 2);
	//  3: AddSymbols(pbSym, cb) -> BOOL
	g_vt_mod[3] = genRet(1, 2);
	//  4: AddPublic(szPublic, isect, off) -> BOOL
	g_vt_mod[4] = genRet(1, 3);
	//  5: AddLines(szSrc, isect, offCon, cbCon, doff, lineStart, pbCoff, cbCoff) -> BOOL
	g_vt_mod[5] = genRet(1, 8);
	//  6: AddSecContrib(isect, off, cb, dwCharacteristics) -> BOOL
	g_vt_mod[6] = genRet(1, 4);
	//  7: QueryCBName(pcb) -> BOOL [1 arg, out=arg0 -> 0]
	g_vt_mod[7] = genOut(0, 0, 1);
	//  8: QueryName(szName, pcb) -> BOOL
	g_vt_mod[8] = genClearBuf(0, 2);
	//  9: QuerySymbols(pbSym, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_mod[9] = genOut(1, 0, 2);
	// 10: QueryLines(pbLines, pcb) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_mod[10] = genOut(1, 0, 2);
	// 11: SetPvClient(pvClient) -> BOOL
	g_vt_mod[11] = genRet(1, 1);
	// 12: GetPvClient(ppvClient) -> BOOL
	g_vt_mod[12] = genOut(0, 0, 1);
	// 13: QueryFirstCodeSecContrib(4 args) -> BOOL
	g_vt_mod[13] = genRet(0, 4);
	// 14: QueryImod(pimod) -> BOOL [1 arg, out=arg0 -> 0]
	g_vt_mod[14] = genOut(0, 0, 1);
	// 15: QueryDBI(ppdbi) -> BOOL [1 arg, out=arg0]
	g_vt_mod[15] = genOut(0, pDBI, 1);
	// 16: Close() -> BOOL
	g_vt_mod[16] = genRet(1, 0);
	// 17: QueryCBFile(pcb) -> BOOL [1 arg, out=arg0 -> 0]
	g_vt_mod[17] = genOut(0, 0, 1);
	// 18: QueryFile(szFile, pcb) -> BOOL
	g_vt_mod[18] = genClearBuf(0, 2);
	// 19: QueryTpi(pptpi) -> BOOL [1 arg, out=arg0]
	g_vt_mod[19] = genOut(0, pTPI, 1);
	// 20: AddSecContribEx(isect, off, cb, dwChar, dwDataCrc, dwRelocCrc) -> BOOL
	g_vt_mod[20] = genRet(1, 6);
	// 21: QueryItsm(pitsm) -> BOOL [1 arg, out=arg0 -> 0]
	g_vt_mod[21] = genOut(0, 0, 1);
	// 22: QuerySrcFile(szFile, pcb) -> BOOL
	g_vt_mod[22] = genClearBuf(0, 2);
	// 23: QuerySupportsEC() -> BOOL
	g_vt_mod[23] = genRet(0, 0);
	// 24: QueryPdbFile(szFile, pcb) -> BOOL
	g_vt_mod[24] = genClearBuf(0, 2);
	// 25: ReplaceLines(pbLines, cb) -> BOOL
	g_vt_mod[25] = genRet(1, 2);
	// 26: GetEnumLines(EnumLines**) -> bool
	g_vt_mod[26] = genRet(0, 1);
	// 27: QueryLineFlags(pdwFlags) -> bool
	g_vt_mod[27] = genRet(0, 1);
	// 28: QueryFileNameInfo(5 args) -> bool
	g_vt_mod[28] = genRet(0, 5);
	// 29: AddPublicW(szPublic, isect, off, cvpsf) -> BOOL
	g_vt_mod[29] = genRet(1, 4);
	// 30: AddLinesW(szSrc, isect, offCon, cbCon, doff, lineStart, pbCoff, cbCoff) -> BOOL
	g_vt_mod[30] = genRet(1, 8);
	// 31: QueryNameW(szName, pcb) -> BOOL
	g_vt_mod[31] = genClearBuf(0, 2);
	// 32: QueryFileW(szFile, pcb) -> BOOL
	g_vt_mod[32] = genClearBuf(0, 2);
	// 33: QuerySrcFileW(szFile, pcb) -> BOOL
	g_vt_mod[33] = genClearBuf(0, 2);
	// 34: QueryPdbFileW(szFile, pcb) -> BOOL
	g_vt_mod[34] = genClearBuf(0, 2);
	// 35: AddPublic2(szPublic, isect, off, cvpsf) -> BOOL
	g_vt_mod[35] = genRet(1, 4);
	// 36: InsertLines(pbLines, cb) -> BOOL
	g_vt_mod[36] = genRet(1, 2);
	// 37: QueryLines2(cbLines, pbLines, pcbLines) -> BOOL [3 args, out=arg2 -> 0]
	g_vt_mod[37] = genOut(2, 0, 3);
	// 38-49: Various Query/Add methods -> return 0 or 1
	for (int i = 38; i <= 49; i++)
		g_vt_mod[i] = genRet(0, 3); // safe default: return FALSE, pop 3 args

	// --- TPI vtable (microsoft-pdb TPI interface, slots 0-22) ---
	for (int i = 0; i < kTpiVtableSlots; i++)
		g_vt_tpi[i] = genTrap((uint8_t)i);
	//  0: QueryInterfaceVersion() -> INTV
	g_vt_tpi[0] = genRet(PDB_INTV, 0);
	//  1: QueryImplementationVersion() -> IMPV
	g_vt_tpi[1] = genRet(PDB_IMPV, 0);
	//  2: QueryTi16ForCVRecord(pb, pti) -> BOOL
	g_vt_tpi[2] = genRet(0, 2);
	//  3: QueryCVRecordForTi16(ti, pb, pcb) -> BOOL
	g_vt_tpi[3] = genRet(0, 3);
	//  4: QueryPbCVRecordForTi16(ti, ppb) -> BOOL
	g_vt_tpi[4] = genRet(0, 2);
	//  5: QueryTi16Min() -> TI16
	g_vt_tpi[5] = genRet(0, 0);
	//  6: QueryTi16Mac() -> TI16
	g_vt_tpi[6] = genRet(0, 0);
	//  7: QueryCb() -> long
	g_vt_tpi[7] = genRet(0, 0);
	//  8: Close() -> BOOL
	g_vt_tpi[8] = genRet(1, 0);
	//  9: Commit() -> BOOL
	g_vt_tpi[9] = genRet(1, 0);
	// 10: QueryTi16ForUDT(sz, fCase, pti) -> BOOL
	g_vt_tpi[10] = genRet(0, 3);
	// 11: SupportQueryTiForUDT() -> BOOL
	g_vt_tpi[11] = genRet(0, 0);
	// 12: fIs16bitTypePool() -> BOOL
	g_vt_tpi[12] = genRet(0, 0);
	// 13: QueryTiForUDT(sz, fCase, pti) -> BOOL
	g_vt_tpi[13] = genRet(0, 3);
	// 14: QueryTiForCVRecord(pb, pti) -> BOOL
	g_vt_tpi[14] = genRet(0, 2);
	// 15: QueryCVRecordForTi(ti, pb, pcb) -> BOOL
	g_vt_tpi[15] = genRet(0, 3);
	// 16: QueryPbCVRecordForTi(ti, ppb) -> BOOL
	g_vt_tpi[16] = genRet(0, 2);
	// 17: QueryTiMin() -> TI
	g_vt_tpi[17] = genRet(0x1000, 0); // standard min TI
	// 18: QueryTiMac() -> TI
	g_vt_tpi[18] = genRet(0x1000, 0); // same = empty type pool
	// 19: AreTypesEqual(ti1, ti2) -> BOOL
	g_vt_tpi[19] = genRet(0, 2);
	// 20: IsTypeServed(ti) -> BOOL
	g_vt_tpi[20] = genRet(0, 1);
	// 21: QueryTiForUDTW(wcs, fCase, pti) -> BOOL
	g_vt_tpi[21] = genRet(0, 3);
	// 22: QueryModSrcLineForUDTDefn(4 args) -> BOOL
	g_vt_tpi[22] = genRet(0, 4);

	// --- GSI vtable (microsoft-pdb GSI interface, slots 0-10) ---
	for (int i = 0; i < kGsiVtableSlots; i++)
		g_vt_gsi[i] = genTrap((uint8_t)i);
	//  0: QueryInterfaceVersion() -> INTV
	g_vt_gsi[0] = genRet(PDB_INTV, 0);
	//  1: QueryImplementationVersion() -> IMPV
	g_vt_gsi[1] = genRet(PDB_IMPV, 0);
	//  2: NextSym(pbSym) -> BYTE* (return NULL = end)
	g_vt_gsi[2] = genRet(0, 1);
	//  3: HashSym(szName, pbSym) -> BYTE*
	g_vt_gsi[3] = genRet(0, 2);
	//  4: NearestSym(isect, off, pdisp) -> BYTE*
	g_vt_gsi[4] = genRet(0, 3);
	//  5: Close() -> BOOL
	g_vt_gsi[5] = genRet(1, 0);
	//  6: getEnumThunk(isect, off, ppenum) -> BOOL
	g_vt_gsi[6] = genRet(0, 3);
	//  7: OffForSym(pbSym) -> ulong
	g_vt_gsi[7] = genRet(0, 1);
	//  8: SymForOff(off) -> BYTE*
	g_vt_gsi[8] = genRet(0, 1);
	//  9: HashSymW(wcsName, pbSym) -> BYTE*
	g_vt_gsi[9] = genRet(0, 2);
	// 10: getEnumByAddr(ppEnum) -> BOOL
	g_vt_gsi[10] = genRet(0, 1);

	// --- Dbg vtable (microsoft-pdb Dbg interface, slots 0-10) ---
	for (int i = 0; i < kDbgVtableSlots; i++)
		g_vt_dbg[i] = genTrap((uint8_t)i);
	//  0: Close() -> BOOL
	g_vt_dbg[0] = genRet(1, 0);
	//  1: QuerySize() -> long
	g_vt_dbg[1] = genRet(0, 0);
	//  2: Reset() -> void
	g_vt_dbg[2] = genVoid(0);
	//  3: Skip(celt) -> BOOL
	g_vt_dbg[3] = genRet(1, 1);
	//  4: QueryNext(celt, rgelt) -> BOOL
	g_vt_dbg[4] = genRet(0, 2); // return FALSE = no more
	//  5: Find(pelt) -> BOOL
	g_vt_dbg[5] = genRet(0, 1);
	//  6: Clear() -> BOOL
	g_vt_dbg[6] = genRet(1, 0);
	//  7: Append(celt, rgelt) -> BOOL
	g_vt_dbg[7] = genRet(1, 2);
	//  8: ReplaceNext(celt, rgelt) -> BOOL
	g_vt_dbg[8] = genRet(1, 2);
	//  9: Clone(ppDbg) -> BOOL
	g_vt_dbg[9] = genRet(0, 1);
	// 10: QueryElementSize() -> long
	g_vt_dbg[10] = genRet(0, 0);

	// --- NameMap vtable (microsoft-pdb NameMap interface, slots 0-14) ---
	for (int i = 0; i < kNameMapVtableSlots; i++)
		g_vt_namemap[i] = genTrap((uint8_t)i);
	//  0: close() -> BOOL
	g_vt_namemap[0] = genRet(1, 0);
	//  1: reinitialize() -> BOOL
	g_vt_namemap[1] = genRet(1, 0);
	//  2: getNi(sz, pni) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_namemap[2] = genOut(1, 0, 2);
	//  3: getName(ni, psz) -> BOOL
	g_vt_namemap[3] = genRet(0, 2);
	//  4: getEnumNameMap(ppenum) -> BOOL
	g_vt_namemap[4] = genRet(0, 1);
	//  5: contains(sz, pni) -> BOOL
	g_vt_namemap[5] = genRet(0, 2);
	//  6: commit() -> BOOL
	g_vt_namemap[6] = genRet(1, 0);
	//  7: isValidNi(ni) -> BOOL
	g_vt_namemap[7] = genRet(0, 1);
	//  8: getNiW(sz, pni) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_namemap[8] = genOut(1, 0, 2);
	//  9: getNameW(ni, szName, pcch) -> BOOL
	g_vt_namemap[9] = genRet(0, 3);
	// 10: containsW(sz, pni) -> BOOL
	g_vt_namemap[10] = genRet(0, 2);
	// 11: containsUTF8(sz, pni) -> BOOL
	g_vt_namemap[11] = genRet(0, 2);
	// 12: getNiUTF8(sz, pni) -> BOOL [2 args, out=arg1 -> 0]
	g_vt_namemap[12] = genOut(1, 0, 2);
	// 13: getNameA(ni, psz) -> BOOL
	g_vt_namemap[13] = genRet(0, 2);
	// 14: getNameW2(ni, pwsz) -> BOOL
	g_vt_namemap[14] = genRet(0, 2);

	// --- Stream vtable (microsoft-pdb Stream interface, slots 0-8) ---
	for (int i = 0; i < kStreamVtableSlots; i++)
		g_vt_stream[i] = genTrap((uint8_t)i);
	//  0: QueryCb() -> long
	g_vt_stream[0] = genRet(0, 0);
	//  1: Read(off, pvBuf, pcbBuf) -> BOOL
	g_vt_stream[1] = genRet(1, 3);
	//  2: Write(off, pvBuf, cbBuf) -> BOOL
	g_vt_stream[2] = genRet(1, 3);
	//  3: Replace(pvBuf, cbBuf) -> BOOL
	g_vt_stream[3] = genRet(1, 2);
	//  4: Append(pvBuf, cbBuf) -> BOOL
	g_vt_stream[4] = genRet(1, 2);
	//  5: Delete() -> BOOL
	g_vt_stream[5] = genRet(1, 0);
	//  6: Release() -> BOOL
	g_vt_stream[6] = genRet(1, 0);
	//  7: Read2(off, pvBuf, cbBuf) -> BOOL
	g_vt_stream[7] = genRet(1, 3);
	//  8: Truncate(cb) -> BOOL
	g_vt_stream[8] = genRet(1, 1);

	// --- Wire up vtable pointers ---
	g_obj_pdb->vptr = addr32(g_vt_pdb);
	g_obj_dbi->vptr = addr32(g_vt_dbi);
	g_obj_mod->vptr = addr32(g_vt_mod);
	g_obj_tpi->vptr = addr32(g_vt_tpi);
	g_obj_gsi->vptr = addr32(g_vt_gsi);
	g_obj_dbg->vptr = addr32(g_vt_dbg);
	g_obj_namemap->vptr = addr32(g_vt_namemap);
	g_obj_stream->vptr = addr32(g_vt_stream);

	DEBUG_LOG("mspdb: fake vtables initialized, code used %zu/%zu bytes\n", g_code_pos, CODE_PAGE_SIZE);
}

static int openPDB(LONG *pec, void **ppPDB) {
	initVtables();
	if (pec)
		*(uint32_t *)pec = 0; // EC_OK
	if (ppPDB)
		*(uint32_t *)ppPDB = addr32(g_obj_pdb);
	return 1; // TRUE
}

namespace mspdb {

int CDECL PDB_Open2W(LPCWSTR wszPDB, LPCSTR szMode, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDB_Open2W(mode=%s)\n", szMode ? szMode : "(null)");
	return openPDB(pec, ppPDB);
}

int CDECL PDB_Open3W(LPCWSTR wszPDB, LPCSTR szMode, DWORD dwSig, void *pcsig70, DWORD dwAge, LONG *pec,
					  LPWSTR wszError, UINT cchErrMax, void **ppPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDB_Open3W(mode=%s)\n", szMode ? szMode : "(null)");
	return openPDB(pec, ppPDB);
}

int CDECL PDB_OpenValidate5(LPCWSTR wszPDB, LPCWSTR wszSearchPath, void *pvClient, void *pfnQueryCallback,
							void *pfnNoteCallback, DWORD dwUnused, LONG *pec, LPWSTR wszError, UINT cchErrMax,
							void **ppPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDB_OpenValidate5()\n");
	return openPDB(pec, ppPDB);
}

int CDECL PDBExportValidateInterface(DWORD intv) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDBExportValidateInterface(intv=%u)\n", intv);
	return 1; // TRUE - interface is valid
}

DWORD CDECL SigForPbCb(void *pb, DWORD cb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::SigForPbCb(pb=%p, cb=%u)\n", pb, cb);
	return 0;
}

LPCSTR CDECL SzCanonFilename(LPCSTR szFilename) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::SzCanonFilename(%s)\n", szFilename ? szFilename : "(null)");
	return szFilename;
}

// PDB management functions (C-style exports for supplementary linker module)

int CDECL PDBOpen2W_C(LPCWSTR wszPDB, LPCSTR szMode, LONG *pec, LPWSTR wszError, UINT cchErrMax, void **ppPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDBOpen2W_C(mode=%s)\n", szMode ? szMode : "(null)");
	return openPDB(pec, ppPDB);
}

int CDECL PDBOpenStreamEx(void *pPDB, LPCSTR szStream, DWORD dwFlags, void **ppStream) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDBOpenStreamEx(stream=%s)\n", szStream ? szStream : "(null)");
	initVtables();
	if (ppStream)
		*(uint32_t *)ppStream = addr32(g_fakeStream_legacy);
	return 1; // TRUE
}

int CDECL PDBCommit(void *pPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDBCommit()\n");
	return 1; // TRUE
}

int CDECL PDBClose(void *pPDB) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::PDBClose()\n");
	return 1; // TRUE
}

// NameMap

int CDECL NameMap_open(void *pPDB, int fWrite, void **ppNameMap) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("mspdb::NameMap_open(fWrite=%d)\n", fWrite);
	initVtables();
	if (ppNameMap)
		*(uint32_t *)ppNameMap = addr32(g_obj_namemap);
	return 1; // TRUE
}

// Stream functions

int CDECL StreamAppend(void *pStream, void *pvData, LONG cbData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamAppend(cb=%d)\n", cbData);
	return 1; // TRUE
}

LONG CDECL StreamQueryCb(void *pStream) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamQueryCb()\n");
	return 0; // stream is empty
}

int CDECL StreamRead(void *pStream, LONG off, void *pvData, LONG *pcbData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamRead(off=%d)\n", off);
	if (pcbData)
		*pcbData = 0;
	return 1; // TRUE
}

int CDECL StreamRelease(void *pStream) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamRelease()\n");
	return 1; // TRUE
}

int CDECL StreamReplace(void *pStream, void *pvData, LONG cbData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamReplace(cb=%d)\n", cbData);
	return 1; // TRUE
}

int CDECL StreamTruncate(void *pStream, LONG cbData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamTruncate(cb=%d)\n", cbData);
	return 1; // TRUE
}

int CDECL StreamWrite(void *pStream, LONG off, void *pvData, LONG cbData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("mspdb::StreamWrite(off=%d, cb=%d)\n", off, cbData);
	return 1; // TRUE
}

} // namespace mspdb

#include "mspdb_trampolines.h"

static void *resolveByName(const char *name) {
	// Decorated C++ names (not covered by mspdbThunkByName)
	if (strcmp(name, "?Open2W@PDB@@SAHPBGPBDPAJPAGIPAPAU1@@Z") == 0)
		return (void *)thunk_mspdb_PDB_Open2W;
	if (strcmp(name, "?Open3W@PDB@@SAHPBGPBDKPBU_GUID@@KPAJPAGIPAPAU1@@Z") == 0)
		return (void *)thunk_mspdb_PDB_Open3W;
	if (strcmp(name, "?OpenValidate5@PDB@@SAHPBG0PAXP6AP6AHXZ1W4POVC@@@ZPAJPAGIPAPAU1@@Z") == 0)
		return (void *)thunk_mspdb_PDB_OpenValidate5;
	if (strcmp(name, "?open@NameMap@@SAHPAUPDB@@HPAPAU1@@Z") == 0)
		return (void *)thunk_mspdb_NameMap_open;

	// Export name alias (DLL exports "PDBOpen2W", C function is PDBOpen2W_C)
	if (strcmp(name, "PDBOpen2W") == 0)
		return (void *)thunk_mspdb_PDBOpen2W_C;

	// C-style names: delegate to auto-generated lookup
	return mspdbThunkByName(name);
}

extern const wibo::ModuleStub lib_mspdb = {
	(const char *[]){
		"mspdbxx",
		"mspdb100",
		"mspdb80",
		nullptr,
	},
	resolveByName,
	nullptr,
};
