#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["clang==17.0.6"]
# ///
"""
Generate Windows ABI trampolines by scanning C++ prototypes using libclang.

This emits x86 trampolines for guest<->host calls.
"""

if __name__ == "__main__":
    import script_venv

    script_venv.bootstrap_venv(__file__)

import argparse
import ctypes
import os
import sys
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable, List, Optional

from clang.cindex import (
    Config,
    Cursor,
    CursorKind,
    Index,
    TranslationUnit,
    Type,
    TypeKind,
    conf,
)
from clang.cindex import (
    Type as CXType,
)

# Allow libclang path to be specified via environment variable
if "LIBCLANG_PATH" in os.environ:
    libclang_path = os.environ["LIBCLANG_PATH"]
    if os.path.isfile(libclang_path):
        Config.set_library_file(libclang_path)
    elif os.path.isdir(libclang_path):
        Config.set_library_path(libclang_path)
    else:
        sys.stderr.write(
            f"Warning: LIBCLANG_PATH={libclang_path} is not a file or directory\n"
        )


class CallingConv(IntEnum):
    """CXCallingConv enum values from clang-c/Index.h"""

    DEFAULT = 0
    C = 1
    X86_STDCALL = 2
    X86_FASTCALL = 3
    X86_THISCALL = 4
    X86_PASCAL = 5
    AAPCS = 6
    AAPCS_VFP = 7
    X86_REGCALL = 8
    INTELOCLBICC = 9
    WIN64 = 10
    X86_64_WIN64 = 11
    X86_64_SYSV = 12
    X86_VECTORCALL = 13
    SWIFT = 14
    PRESERVEMOST = 15
    PRESERVEALL = 16
    AARCH64_VECTORCALL = 17
    SWIFTASYNC = 18
    AARCH64_SVEPCS = 19
    M68K_RTD = 20
    INVALID = 100
    UNEXPOSED = 200


# Register the clang_getFunctionTypeCallingConv function
_get_calling_conv = conf.lib.clang_getFunctionTypeCallingConv
_get_calling_conv.argtypes = [CXType]
_get_calling_conv.restype = ctypes.c_int


def _get_function_calling_conv(func_type: CXType) -> CallingConv:
    """
    Get the calling convention of a function type.
    """
    return CallingConv(_get_calling_conv(func_type))


@dataclass
class ArgInfo:
    size: int
    slot_size: int
    primitive: bool
    sign_extended: bool
    type: Type


@dataclass
class FuncInfo:
    qualified_ns: str
    name: str
    mangled: str
    source_cc: CallingConv
    target_cc: CallingConv
    variadic: bool
    return_type: Type
    args: List[ArgInfo] = field(default_factory=list)


@dataclass
class TypedefInfo:
    name: str
    source_cc: CallingConv
    target_cc: CallingConv
    variadic: bool
    return_type: Type
    args: List[ArgInfo] = field(default_factory=list)


def parse_tu(
    headers: List[str], include_dirs: List[str], target: str
) -> TranslationUnit:
    # Construct a tiny TU that includes the requested headers
    tu_source = "\n".join([f'#include "{h}"' for h in headers]) + "\n"
    with tempfile.NamedTemporaryFile("w", suffix=".cpp") as tf:
        tf.write(tu_source)
        tf.flush()
        args = [
            "-x",
            "c++",
            "-std=c++17",
            "-target",
            target,
            "-DWIBO_CODEGEN=1",
        ] + [arg for inc in include_dirs for arg in ("-I", inc)]

        index = Index.create()
        tu = index.parse(
            tf.name, args=args, options=TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
        )
        for d in tu.diagnostics:
            if d.severity >= d.Warning:
                sys.stderr.write(str(d) + "\n")
        return tu


def _cursor_namespace(cursor: Cursor) -> List[str]:
    ns: List[str] = []
    c = cursor
    while c is not None and c.kind != CursorKind.TRANSLATION_UNIT:
        if c.kind == CursorKind.NAMESPACE and c.spelling:
            ns.append(c.spelling)
        c = c.semantic_parent
    return list(reversed(ns))


def _source_cc_from_annotations(func: Cursor) -> CallingConv:
    for child in func.get_children():
        if child.kind == CursorKind.ANNOTATE_ATTR:
            if child.spelling == "CC:fastcall":
                return CallingConv.X86_FASTCALL
            elif child.spelling == "CC:stdcall":
                return CallingConv.X86_STDCALL
            elif child.spelling == "CC:cdecl":
                return CallingConv.C
    return CallingConv.DEFAULT


def _is_handle_typedef(arg_type: CXType) -> bool:
    """Check if a type is a HANDLE-like typedef (HWND, HINSTANCE, etc.)."""
    t = arg_type
    # Trace through ELABORATED and TYPEDEF to find the original typedef name
    while t.kind == TypeKind.ELABORATED or t.kind == TypeKind.TYPEDEF:
        if t.kind == TypeKind.TYPEDEF:
            decl = t.get_declaration()
            name = decl.spelling
            # Windows HANDLE types conventionally start with 'H'
            if name and name.startswith("H") and name.isupper():
                return True
            t = decl.underlying_typedef_type
        elif t.kind == TypeKind.ELABORATED:
            named = t.get_named_type()
            if named is None:
                break
            t = named
        else:
            break
    return False


SIGNED_KINDS = [
    TypeKind.SCHAR,
    TypeKind.CHAR_S,
    TypeKind.SHORT,
    TypeKind.INT,
    TypeKind.LONG,
    TypeKind.LONGLONG,
    TypeKind.INT128,
]


def _collect_args(func_type: CXType) -> List[ArgInfo]:
    """Collect argument information for a function."""
    args: List[ArgInfo] = []
    for t in func_type.argument_types():
        size = t.get_size()
        canonical = t.get_canonical()

        # Determine if primitive (not struct/union)
        is_primitive = canonical.kind != TypeKind.RECORD

        # Determine if sign-extended
        # Sign-extend signed integers and HANDLE-like typedefs
        is_sign_extended = canonical in SIGNED_KINDS or _is_handle_typedef(t)

        # Calculate stack slot size
        if size <= 4:
            slot_size = 4
        elif size <= 8:
            slot_size = 8
        else:
            raise NotImplementedError(
                f"Argument size {size} not supported for function {func_type.spelling}"
            )

        args.append(
            ArgInfo(
                size=size,
                slot_size=slot_size,
                primitive=is_primitive,
                sign_extended=is_sign_extended,
                type=t,
            )
        )
    return args


def collect_functions(tu: TranslationUnit, ns_filter: Optional[str]) -> List[FuncInfo]:
    want_ns = ns_filter.split("::") if ns_filter else None
    out: dict[str, FuncInfo] = {}

    def visit(node: Cursor) -> None:
        if node.kind == CursorKind.FUNCTION_DECL:
            ns_parts = _cursor_namespace(node)
            if want_ns is not None and ns_parts != want_ns:
                return
            name = node.spelling
            if not name:
                return
            source_cc = _source_cc_from_annotations(node)
            if source_cc == CallingConv.DEFAULT:
                return  # No CC annotation; skip
            out[name] = FuncInfo(
                qualified_ns="::".join(ns_parts),
                name=name,
                mangled=node.mangled_name or name,
                source_cc=source_cc,
                target_cc=_get_function_calling_conv(node.type),
                variadic=node.type.is_function_variadic(),
                return_type=node.type.get_result(),
                args=_collect_args(node.type),
            )

        # Recurse into children
        if node.kind in (CursorKind.TRANSLATION_UNIT, CursorKind.NAMESPACE):
            for c in node.get_children():
                visit(c)

    if tu.cursor is not None:
        visit(tu.cursor)
    return sorted(out.values(), key=lambda f: f.name)


def _type_to_string(t: CXType) -> str:
    """Convert a CXType to a C type string."""
    spelling = t.spelling
    # Clean up common type spellings
    spelling = (
        spelling.replace("struct ", "").replace("union ", "").replace("enum ", "")
    )
    return spelling


def collect_typedefs(tu: TranslationUnit) -> List[TypedefInfo]:
    """Collect function pointer typedefs and type aliases from the translation unit."""
    out: dict[str, TypedefInfo] = {}

    def process_function_pointer_type(
        name: str, node: Cursor, func_type: CXType
    ) -> None:
        """Process a function pointer type and add it to the output."""
        if not name:
            return

        # Determine calling convention
        source_cc = _get_function_calling_conv(func_type)
        target_cc = _source_cc_from_annotations(node)
        if target_cc == CallingConv.DEFAULT:
            return  # No CC annotation; skip

        variadic = func_type.is_function_variadic()
        args = _collect_args(func_type)
        return_type = func_type.get_result()

        out[name] = TypedefInfo(
            name=name,
            source_cc=source_cc,
            target_cc=target_cc,
            variadic=variadic,
            return_type=return_type,
            args=args,
        )

    def visit(node: Cursor) -> None:
        if node.kind == CursorKind.TYPEDEF_DECL:
            name = node.spelling
            if not name:
                return
            underlying = node.underlying_typedef_type
            if underlying.kind == TypeKind.POINTER:
                pointee = underlying.get_pointee()
                if pointee.kind == TypeKind.FUNCTIONPROTO:
                    process_function_pointer_type(name, node, pointee)

        # Recurse into children
        if node.kind in (CursorKind.TRANSLATION_UNIT, CursorKind.NAMESPACE):
            for c in node.get_children():
                visit(c)

    if tu.cursor is not None:
        visit(tu.cursor)
    return sorted(out.values(), key=lambda t: t.name)


def emit_cc_thunk(f: FuncInfo | TypedefInfo, lines: List[str]):
    if isinstance(f, TypedefInfo):
        # Host-to-guest
        target = "[eax+4]"
        arg_off = 8
        align = 0
        host_to_guest = True
    elif isinstance(f, FuncInfo):
        # Guest-to-host
        target = f.mangled
        arg_off = 4
        align = 16
        host_to_guest = False

    if f.variadic:
        # Variadic functions are not yet supported for calling convention conversion.
        assert f.source_cc == CallingConv.C and f.target_cc == CallingConv.C, (
            "Variadic functions must be cdecl"
        )
        lines.append(f"\tjmp {target}")
        return

    # Compute argument stack offsets
    offsets: List[int] = []
    for arg in f.args:
        offsets.append(arg_off)
        arg_off += arg.slot_size

    reg_indices: List[int] = []
    if f.target_cc == CallingConv.X86_FASTCALL:
        # Store the first two non-record 4-byte args in ECX/EDX for GCC/Clang x86 fastcall
        if len(f.args) >= 1 and f.args[0].primitive and f.args[0].slot_size == 4:
            reg_indices.append(0)  # ECX
            if len(f.args) >= 2 and f.args[1].primitive and f.args[1].slot_size == 4:
                reg_indices.append(1)  # EDX
    elif f.target_cc == CallingConv.C or f.target_cc == CallingConv.X86_STDCALL:
        # No register args for cdecl or stdcall
        pass
    else:
        raise NotImplementedError(
            f"Unsupported target calling convention {f.target_cc.name} for function {f.name}"
        )

    # Bytes we will push for the call (exclude args passed in registers)
    stack_bytes = sum(
        arg.slot_size for i, arg in enumerate(f.args) if i not in reg_indices
    )

    # Get current TIB
    if host_to_guest:
        lines.append("\tmov ecx, gs:[currentThreadTeb@ntpoff]")
    else:
        lines.append("\tmov ecx, fs:[0x18]")

    # Swap fs and gs
    lines.append("\tmov ax, fs")
    lines.append("\tmov dx, word ptr [ecx+0xf98]")
    lines.append("\tmov word ptr [ecx+0xf98], ax")
    lines.append("\tmov fs, dx")
    lines.append("\tmov ax, gs")
    lines.append("\tmov dx, word ptr [ecx+0xf9a]")
    lines.append("\tmov word ptr [ecx+0xf9a], ax")
    lines.append("\tmov gs, dx")

    # Store guest stack pointer in eax for arg access
    if len(f.args) > 0 or host_to_guest:
        lines.append("\tmov eax, esp")

    # Swap stack pointer
    lines.append("\tpush ebp")
    lines.append("\tmov ebp, dword ptr [ecx+0xf9c]")
    lines.append("\tmov dword ptr [ecx+0xf9c], esp")
    lines.append("\tmov esp, ebp")

    # Allocate stack space for arguments
    if stack_bytes > 0:
        lines.append(f"\tsub esp, {stack_bytes}")

    # Align stack if needed (must be done after allocating args)
    if align > 0:
        lines.append(f"\tand esp, ~{align - 1}")

    # Copy args onto stack
    cur_off = 0
    for i, arg in enumerate(f.args):
        if i in reg_indices:
            continue
        base = offsets[i]
        for part_off in range(0, arg.slot_size, 4):
            lines.append(f"\tmov ecx, [eax+{base + part_off}]")
            lines.append(f"\tmov [esp+{cur_off + part_off}], ecx")
        cur_off += arg.slot_size

    # Load args into registers as needed
    if len(reg_indices) > 0:
        i = reg_indices[0]
        offset = offsets[i]
        lines.append(f"\tmov ecx, [eax+{offset}]")
    if len(reg_indices) > 1:
        i = reg_indices[1]
        offset = offsets[i]
        lines.append(f"\tmov edx, [eax+{offset}]")

    # Call into target
    lines.append(f"\tcall {target}")

    # Determine if we can clobber eax/edx
    if f.return_type.kind == TypeKind.RECORD:
        raise NotImplementedError(
            f"Struct return type not supported for function {f.name}"
        )
    return_size = f.return_type.get_size()
    save_eax = return_size > 0
    save_edx = return_size > 4
    if return_size > 8:
        raise NotImplementedError(
            f"Return size {return_size} not supported for function {f.name}"
        )

    # Restore segment registers
    if save_eax:
        lines.append("\tpush eax")
    if save_edx:
        lines.append("\tpush edx")
    if host_to_guest:
        lines.append("\tmov ecx, fs:[0x18]")
    else:
        lines.append("\tmov ecx, gs:[currentThreadTeb@ntpoff]")
    lines.append("\tmov ax, fs")
    lines.append("\tmov dx, word ptr [ecx+0xf98]")
    lines.append("\tmov word ptr [ecx+0xf98], ax")
    lines.append("\tmov fs, dx")
    lines.append("\tmov ax, gs")
    lines.append("\tmov dx, word ptr [ecx+0xf9a]")
    lines.append("\tmov word ptr [ecx+0xf9a], ax")
    lines.append("\tmov gs, dx")
    if save_edx:
        lines.append("\tpop edx")
    if save_eax:
        lines.append("\tpop eax")

    # Swap stack pointer
    lines.append("\tmov esp, ebp")  # Clean up arg space
    lines.append("\tmov ebp, dword ptr [ecx+0xf9c]")
    lines.append("\tmov dword ptr [ecx+0xf9c], esp")

    # Restore stack and frame pointer
    lines.append("\tleave")

    # Return to guest
    if f.source_cc == CallingConv.X86_STDCALL:
        ret_bytes = sum(arg.slot_size for arg in f.args)
    elif f.source_cc == CallingConv.C:
        ret_bytes = 0
    else:
        raise NotImplementedError(
            f"Unsupported source calling convention {f.source_cc.name} for function {f.name}"
        )
    if ret_bytes > 0:
        lines.append(f"\tret {ret_bytes}")
    else:
        lines.append("\tret")


def emit_guest_to_host_thunks(
    lines: List[str], dll: str, funcs: Iterable[FuncInfo]
) -> None:
    for f in funcs:
        thunk = f"thunk_{dll}_{f.name}"
        lines.append("")
        lines.append(
            f"# {f.qualified_ns}::{f.name} (source_cc={f.source_cc.name}, target_cc={f.target_cc.name}, variadic={f.variadic})"
        )
        for i, arg in enumerate(f.args):
            lines.append(
                f"\t# Arg {i} (slot_size={arg.slot_size}, primitive={arg.primitive}, sign_extended={arg.sign_extended})"
            )
        lines.append(f".globl {thunk}")
        lines.append(f".type {thunk}, @function")
        lines.append(f"{thunk}:")
        emit_cc_thunk(f, lines)
        lines.append(f".size {thunk}, .-{thunk}")


def emit_host_to_guest_thunks(
    lines: List[str], typedefs: Iterable[TypedefInfo]
) -> None:
    for f in typedefs:
        thunk = f"call_{f.name}"
        lines.append("")
        lines.append(
            f"# {f.name} (target_cc={f.target_cc.name}, variadic={f.variadic})"
        )
        for i, arg in enumerate(f.args):
            lines.append(
                f"\t# Arg {i} (slot_size={arg.slot_size}, primitive={arg.primitive}, sign_extended={arg.sign_extended})"
            )
        lines.append(f".globl {thunk}")
        lines.append(f".weak {thunk}")
        lines.append(f".type {thunk}, @function")
        lines.append(f"{thunk}:")
        emit_cc_thunk(f, lines)
        lines.append(f".size {thunk}, .-{thunk}")


def emit_header_mapping(
    dll: str, funcs: Iterable[FuncInfo], typedefs: Iterable[TypedefInfo]
) -> str:
    guard = f"WIBO_GEN_{dll.upper()}_THUNKS_H"
    lines: List[str] = []
    lines.append("/* Auto-generated; DO NOT EDIT. */")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append("#include <stddef.h>")
    lines.append("#include <string.h>")
    lines.append('#ifdef __cplusplus\nextern "C" {\n#endif')

    # Guest-to-host thunk functions
    for f in funcs:
        # Generate best-effort function prototype so that simple thunks can be called directly
        # in special cases (e.g. thunk_entry_stubBase)
        def _is_opaque(t: Type) -> bool:
            if (
                t.kind == TypeKind.RECORD
                or t.kind == TypeKind.ENUM
                or t.kind == TypeKind.FUNCTIONPROTO
                or t.kind == TypeKind.FUNCTIONNOPROTO
            ):
                return True
            return t.kind == TypeKind.POINTER and _is_opaque(
                t.get_pointee().get_canonical()
            )

        def _canonical_type_str(t: Type) -> str:
            c = t.get_canonical()
            if _is_opaque(c):
                return "void *"
            return c.spelling

        thunk = f"thunk_{dll}_{f.name}"
        args = []
        for i, arg in enumerate(f.args):
            type_str = _canonical_type_str(arg.type)
            args.append(f"{type_str} arg{i}")
        param_list = ", ".join(args)
        return_type = _canonical_type_str(f.return_type)
        if f.source_cc == CallingConv.X86_STDCALL:
            cc_attr = "__attribute__((stdcall))"
        elif f.source_cc == CallingConv.C:
            cc_attr = "__attribute__((cdecl))"
        else:
            raise NotImplementedError(
                f"Unsupported calling convention {f.source_cc.name} for function {f.name}"
            )
        lines.append(f"{cc_attr} {return_type} {thunk}({param_list});")

    # Host-to-guest thunk functions
    for td in typedefs:
        thunk = f"call_{td.name}"
        if td.variadic:
            continue

        params = [f"{td.name} fn"]
        for i, arg in enumerate(td.args):
            type_str = _type_to_string(arg.type)
            params.append(f"{type_str} arg{i}")

        param_list = ", ".join(params)
        return_type = _type_to_string(td.return_type)
        lines.append(f"{return_type} {thunk}({param_list});")

    lines.append("#ifdef __cplusplus\n}\n#endif")
    lines.append("")
    # name->address helper for resolveByName
    lines.append("static inline void *%sThunkByName(const char *name) {" % dll)
    for f in funcs:
        lines.append(
            f'\tif (strcmp(name, "{f.name}") == 0) return (void*)&thunk_{dll}_{f.name};'
        )
    lines.append("\treturn NULL;")
    lines.append("}")

    lines.append(f"#endif /* {guard} */\n")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True, help="DLL name, e.g. kernel32")
    ap.add_argument("--headers", nargs="+", required=True, help="Header files to scan")
    ap.add_argument(
        "--namespace", dest="ns", default=None, help="Namespace filter, e.g. kernel32"
    )
    ap.add_argument("--arch", choices=["x86"], default="x86")
    ap.add_argument(
        "--out-asm", type=Path, required=True, help="Output assembly file (.S)"
    )
    ap.add_argument(
        "--out-hdr", type=Path, required=True, help="Output header file (.h)"
    )
    ap.add_argument("-I", dest="incs", action="append", default=[])
    args = ap.parse_args()

    target = "i686-pc-linux-gnu" if args.arch == "x86" else "x86_64-pc-linux-gnu"
    tu = parse_tu(args.headers, args.incs, target)
    funcs = collect_functions(tu, args.ns)
    typedefs = collect_typedefs(tu)

    if not funcs and not typedefs:
        sys.stderr.write("No functions or typedefs found for generation.\n")
        return 1

    lines: List[str] = []
    lines.append("# Auto-generated thunks; DO NOT EDIT.")
    lines.append(".intel_syntax noprefix")
    lines.append('.section .note.GNU-stack, "", @progbits')
    lines.append(".text")

    emit_guest_to_host_thunks(lines, args.dll, funcs)
    emit_host_to_guest_thunks(lines, typedefs)

    asm = "\n".join(lines) + "\n"
    hdr = emit_header_mapping(args.dll, funcs, typedefs)

    args.out_asm.parent.mkdir(parents=True, exist_ok=True)
    args.out_hdr.parent.mkdir(parents=True, exist_ok=True)
    args.out_asm.write_text(asm)
    args.out_hdr.write_text(hdr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
