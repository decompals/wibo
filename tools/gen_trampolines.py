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
from enum import Enum, IntEnum
from pathlib import Path
from typing import Iterable, List, Optional

from clang.cindex import (
    Config,
    Cursor,
    CursorKind,
    Index,
    StorageClass,
    TranslationUnit,
    Type,
    TypeKind,
    conf,
)
from clang.cindex import Type as CXType

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


class Arch(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"


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


class ArgClass(str, Enum):
    INT = "int"
    MEMORY = "memory"


@dataclass
class ArgInfo:
    type: Type
    arg_class: ArgClass
    sign_extended: bool


@dataclass
class ArgPlacement:
    size: int
    slot_size: int
    stack_offset: Optional[int] = None
    register: Optional[str] = None

    def __init__(self, arg: ArgInfo, arch: Arch):
        self.size = arg.type.get_canonical().get_size()
        self.slot_size = _slot_size_for_arch(arg, arch)
        self.register = None
        self.stack_offset = None


@dataclass
class FuncInfo:
    qualified_ns: str
    name: str
    mangled: str
    source_cc: CallingConv
    target_cc: CallingConv
    variadic: bool
    return_type: ArgInfo
    args: List[ArgInfo] = field(default_factory=list)


@dataclass
class TypedefInfo:
    name: str
    source_cc: CallingConv
    target_cc: CallingConv
    variadic: bool
    return_type: ArgInfo
    args: List[ArgInfo] = field(default_factory=list)


@dataclass
class VarInfo:
    qualified_ns: str
    name: str


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


def _calculate_arg_info(t: Type) -> ArgInfo:
    canonical = t.get_canonical()

    # if canonical.kind == TypeKind.RECORD:
    #     arg_class = ArgClass.MEMORY
    # else:
    arg_class = ArgClass.INT

    if canonical.kind == TypeKind.POINTER:
        pointee = canonical.get_pointee()
        if pointee.kind == TypeKind.POINTER:
            print(f"Bugprone: Pointer to pointer ({_type_to_string(t)})")

    # Sign-extend signed integers and HANDLE-like typedefs
    is_sign_extended = canonical.kind in SIGNED_KINDS or _is_handle_typedef(t)

    return ArgInfo(
        arg_class=arg_class,
        sign_extended=is_sign_extended,
        type=t,
    )


def _collect_args(func_type: CXType) -> List[ArgInfo]:
    """Collect argument information for a function."""
    args: List[ArgInfo] = []
    for t in func_type.argument_types():
        args.append(_calculate_arg_info(t))
    return args


def _slot_size_for_arch(arg: ArgInfo, arch: Arch) -> int:
    """Return the slot size (in bytes) used to pass an argument on the given architecture."""
    canonical = arg.type.get_canonical()
    if canonical.kind == TypeKind.POINTER:
        return 8 if arch == Arch.X86_64 else 4
    size = canonical.get_size()
    if arch == Arch.X86:
        if size <= 4:
            return 4
        if size <= 8:
            return 8
    elif arch == Arch.X86_64:
        if size <= 8:
            return 8
    raise NotImplementedError(
        f"Argument size {size} not supported for architecture {arch.value}"
    )


@dataclass
class ArgLayout:
    args: List[ArgPlacement]
    stack_size: int


def compute_arg_layout(
    args: List[ArgInfo],
    cc: CallingConv,
    arch: Arch,
    stack_offset: int = 0,
    skip_args: int = 0,
) -> ArgLayout:
    """Compute how each argument is passed for the given calling convention and arch."""

    placements: List[ArgPlacement] = []
    stack_size = 0
    gpr_order: List[str] = []
    gpr_index = skip_args

    if arch == Arch.X86 and cc == CallingConv.X86_FASTCALL:
        gpr_order = ["ecx", "edx"]
    elif arch == Arch.X86_64 and cc == CallingConv.C:
        gpr_order = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    # Offset our stack based on number of extra arguments
    # We assume that every arg represented by skip_args fits in a register
    register_size = 8 if arch == Arch.X86_64 else 4
    consumed_stack = max(0, skip_args - len(gpr_order)) * register_size
    stack_offset += consumed_stack
    stack_size += consumed_stack

    def _push_stack(arg: ArgInfo) -> None:
        nonlocal stack_offset
        nonlocal stack_size
        placement = ArgPlacement(arg, arch)
        placement.stack_offset = stack_offset
        placements.append(placement)
        stack_offset += placement.slot_size
        stack_size += placement.slot_size

    def _push_register(arg: ArgInfo) -> None:
        nonlocal gpr_index
        placement = ArgPlacement(arg, arch)
        placement.register = gpr_order[gpr_index]
        placements.append(placement)
        gpr_index += 1

    # Special case for x86 fastcall: stop using registers if any spill onto the stack
    if arch == Arch.X86 and cc == CallingConv.X86_FASTCALL:
        stack_args_start = 0
        for i in range(min(len(gpr_order), len(args))):
            if gpr_index >= len(gpr_order):
                break
            arg = args[i]
            slot_size = _slot_size_for_arch(arg, arch)
            if arg.arg_class == ArgClass.INT and slot_size == 4:
                _push_register(arg)
                stack_args_start += 1
            else:
                break

        for i in range(stack_args_start, len(args)):
            _push_stack(args[i])
    else:
        for arg in args:
            slot_size = _slot_size_for_arch(arg, arch)
            if (
                arg.arg_class == ArgClass.INT
                and slot_size <= register_size
                and gpr_index < len(gpr_order)
            ):
                _push_register(arg)
            else:
                _push_stack(arg)

    return ArgLayout(args=placements, stack_size=stack_size)


def describe_arg_placement(placement: ArgPlacement) -> str:
    if placement.register is not None:
        return f"{placement.register}[{placement.slot_size}]"
    if placement.stack_offset is not None:
        return f"stack+{placement.stack_offset}[{placement.slot_size}]"
    raise ValueError(f"Unassigned placement {placement}")


def collect_functions(
    tu: TranslationUnit, ns_filter: Optional[str], arch: Arch
) -> List[FuncInfo]:
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
                return_type=_calculate_arg_info(node.type.get_result()),
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


def collect_typedefs(tu: TranslationUnit, arch: Arch) -> List[TypedefInfo]:
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

        out[name] = TypedefInfo(
            name=name,
            source_cc=source_cc,
            target_cc=target_cc,
            variadic=func_type.is_function_variadic(),
            return_type=_calculate_arg_info(func_type.get_result()),
            args=_collect_args(func_type),
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


def collect_variables(tu: TranslationUnit, ns_filter: Optional[str]) -> List[VarInfo]:
    """Collect extern variable declarations from the translation unit."""
    want_ns = ns_filter.split("::") if ns_filter else None
    out: dict[str, VarInfo] = {}

    def visit(node: Cursor) -> None:
        if node.kind == CursorKind.VAR_DECL:
            if node.storage_class != StorageClass.EXTERN or node.is_definition():
                return
            ns_parts = _cursor_namespace(node)
            if want_ns is not None and ns_parts != want_ns:
                return
            name = node.spelling
            if not name:
                return
            out[name] = VarInfo(
                qualified_ns="::".join(ns_parts),
                name=name,
            )

        if node.kind in (CursorKind.TRANSLATION_UNIT, CursorKind.NAMESPACE):
            for c in node.get_children():
                visit(c)

    if tu.cursor is not None:
        visit(tu.cursor)
    return sorted(out.values(), key=lambda v: v.name)


def emit_cc_thunk32(f: FuncInfo | TypedefInfo, lines: List[str]):
    if isinstance(f, TypedefInfo):
        # Host-to-guest
        call_target = "[eax+4]"
        align = 0
        host_to_guest = True
    elif isinstance(f, FuncInfo):
        # Guest-to-host
        call_target = f.mangled
        align = 16
        host_to_guest = False

    if f.variadic:
        # Variadic functions are not yet supported for calling convention conversion.
        assert f.source_cc == CallingConv.C and f.target_cc == CallingConv.C, (
            "Variadic functions must be cdecl"
        )
        lines.append(f"\tjmp {call_target}")
        return

    source_layout = compute_arg_layout(
        f.args,
        f.source_cc,
        Arch.X86,
        stack_offset=4,
        skip_args=1 if host_to_guest else 0,
    )
    target_layout = compute_arg_layout(f.args, f.target_cc, Arch.X86)

    # Get current TEB
    if host_to_guest:
        lines.append("\tmov ecx, gs:[currentThreadTeb@ntpoff]")
    else:
        lines.append("\tmov ecx, fs:[TEB_SELF]")

    # Swap fs and gs
    lines.append("\tmov ax, fs")
    lines.append("\tmov dx, word ptr [ecx+TEB_FS_SEL]")
    lines.append("\tmov word ptr [ecx+TEB_FS_SEL], ax")
    lines.append("\tmov fs, dx")
    lines.append("\tmov ax, gs")
    lines.append("\tmov dx, word ptr [ecx+TEB_GS_SEL]")
    lines.append("\tmov word ptr [ecx+TEB_GS_SEL], ax")
    lines.append("\tmov gs, dx")

    # Store guest stack pointer in eax for arg access
    if len(f.args) > 0 or host_to_guest:
        lines.append("\tmov eax, esp")

    # Swap stack pointer
    lines.append("\tpush ebp")
    lines.append("\tmov ebp, dword ptr [ecx+TEB_SP]")
    lines.append("\tmov dword ptr [ecx+TEB_SP], esp")
    lines.append("\tmov esp, ebp")

    # Allocate stack space for arguments
    if target_layout.stack_size > 0:
        lines.append(f"\tsub esp, {target_layout.stack_size}")

    # Align stack if needed (must be done after allocating args)
    if align > 0:
        lines.append(f"\tand esp, ~{align - 1}")

    # Copy args onto stack for the callee
    for idx, target in enumerate(target_layout.args):
        if target.stack_offset is None:
            continue

        source = source_layout.args[idx]
        if source.stack_offset is None:
            raise NotImplementedError(
                f"Source calling convention {f.source_cc.name} requires register argument {idx}; not implemented"
            )

        if source.slot_size != target.slot_size:
            raise NotImplementedError(
                f"Argument {idx} requires size conversion {source.slot_size}->{target.slot_size}; not implemented"
            )

        for off in range(0, target.slot_size, 4):
            lines.append(f"\tmov ecx, [eax+{source.stack_offset + off}]")
            lines.append(f"\tmov [esp+{target.stack_offset + off}], ecx")

    # Load args into registers as needed
    for idx, target in enumerate(target_layout.args):
        if target.register is None:
            continue

        source = source_layout.args[idx]
        if source.stack_offset is None:
            raise NotImplementedError(
                f"Source calling convention {f.source_cc.name} requires register argument {idx}; not implemented"
            )

        lines.append(f"\tmov {target.register}, [eax+{source.stack_offset}]")

    # Call into target
    lines.append(f"\tcall {call_target}")

    # Determine if we can clobber eax/edx
    if f.return_type.arg_class != ArgClass.INT:
        raise NotImplementedError(
            f"Unsupported return type class {f.return_type.arg_class.value} for function {f.name}"
        )
    return_size = f.return_type.type.get_size()
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
        lines.append("\tmov ecx, fs:[TEB_SELF]")
    else:
        lines.append("\tmov ecx, gs:[currentThreadTeb@ntpoff]")
    lines.append("\tmov ax, fs")
    lines.append("\tmov dx, word ptr [ecx+TEB_FS_SEL]")
    lines.append("\tmov word ptr [ecx+TEB_FS_SEL], ax")
    lines.append("\tmov fs, dx")
    lines.append("\tmov ax, gs")
    lines.append("\tmov dx, word ptr [ecx+TEB_GS_SEL]")
    lines.append("\tmov word ptr [ecx+TEB_GS_SEL], ax")
    lines.append("\tmov gs, dx")
    if save_edx:
        lines.append("\tpop edx")
    if save_eax:
        lines.append("\tpop eax")

    # Swap stack pointer
    lines.append("\tmov esp, ebp")  # Clean up arg space
    lines.append("\tmov ebp, dword ptr [ecx+TEB_SP]")
    lines.append("\tmov dword ptr [ecx+TEB_SP], esp")

    # Restore stack and frame pointer
    lines.append("\tleave")

    # Return to guest
    if f.source_cc == CallingConv.X86_STDCALL and source_layout.stack_size > 0:
        lines.append(f"\tret {source_layout.stack_size}")
    else:
        lines.append("\tret")


def _x64_register_by_slot_size(reg: str, slot_size: int) -> str:
    if slot_size == 8:
        return reg
    if reg in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]:
        if slot_size == 4:
            return f"e{reg[1:]}"
        elif slot_size == 2:
            return reg[1:]
        elif slot_size == 1:
            if reg in ["rax", "rbx", "rcx", "rdx"]:
                return f"{reg[1]}l"
            elif reg in ["rsi", "rdi"]:
                return f"{reg[1]}il"
            else:
                return f"{reg[1]}pl"
    if slot_size == 4:
        return f"{reg}d"
    if slot_size == 2:
        return f"{reg}w"
    if slot_size == 1:
        return f"{reg}b"
    raise NotImplementedError(f"Unsupported register {reg} for slot size {slot_size}")


def _x64_ptr_type_by_slot_size(slot_size) -> str:
    if slot_size == 4:
        return "dword ptr"
    elif slot_size == 8:
        return "qword ptr"
    else:
        raise ValueError(f"Unsupported slot size {slot_size}")


def emit_cc_thunk64(f: FuncInfo | TypedefInfo, lines: List[str]):
    if isinstance(f, TypedefInfo):
        # Host-to-guest
        call_target = "edi"
        align = 0
        host_to_guest = True
    elif isinstance(f, FuncInfo):
        # Guest-to-host
        call_target = f.mangled
        align = 16
        host_to_guest = False

    if f.variadic:
        # Variadic functions are not yet supported for calling convention conversion.
        assert f.source_cc == CallingConv.C and f.target_cc == CallingConv.C, (
            "Variadic functions must be cdecl"
        )
        lines.append(f"\tjmp {call_target}")
        return

    source_layout = compute_arg_layout(
        f.args,
        f.source_cc,
        Arch.X86_64 if host_to_guest else Arch.X86,
        stack_offset=24 if host_to_guest else 16,
        skip_args=1 if host_to_guest else 0,
    )
    target_layout = compute_arg_layout(
        f.args, f.target_cc, Arch.X86 if host_to_guest else Arch.X86_64
    )

    if host_to_guest:
        lines.append(".code64")

        # Save rbx and rbp
        lines.append("\tpush rbx")
        lines.append("\tpush rbp")

        # Stash host stack in r10
        lines.append("\tmov r10, rsp")

        # Get current TEB
        lines.append("\tmov rcx, fs:[currentThreadTeb@tpoff]")

        # Save FS base
        lines.append("\trdfsbase r9")
        lines.append("\tmov qword ptr [rcx+TEB_FSBASE], r9")

        # Save RSP and load guest stack
        lines.append("\tmov rbp, qword ptr [rcx+TEB_SP]")
        lines.append("\tmov qword ptr [rcx+TEB_SP], rsp")
        lines.append("\tmov rsp, rbp")

        # Allocate stack space for arguments
        if target_layout.stack_size > 0:
            lines.append(f"\tsub rsp, {target_layout.stack_size}")

        # Align stack if needed (must be done after allocating args)
        if align > 0:
            lines.append(f"\tand rsp, ~{align - 1}")

        # Transfer arguments
        for i, target in enumerate(target_layout.args):
            if target.stack_offset is None:
                raise NotImplementedError(f"Unexpected register argument {target}")

            source = source_layout.args[i]
            if source.stack_offset is not None:
                ptr_type = _x64_ptr_type_by_slot_size(source.slot_size)
                register = _x64_register_by_slot_size("rax", target.slot_size)
                lines.append(
                    f"\tmov {register}, {ptr_type} [r10+{source.stack_offset}]"
                )
                ptr_type = _x64_ptr_type_by_slot_size(target.slot_size)
                register = _x64_register_by_slot_size("rax", target.slot_size)
            elif source.register is not None:
                ptr_type = _x64_ptr_type_by_slot_size(target.slot_size)
                register = _x64_register_by_slot_size(source.register, target.slot_size)
            else:
                raise ValueError(f"Argument {i} is not a register or stack offset")
            lines.append(f"\tmov {ptr_type} [rsp+{target.stack_offset}], {register}")

        # Jump to 32-bit mode
        lines.append("\tLJMP32")

        # Setup FS selector
        lines.append("\tmov ax, word ptr [ecx+TEB_FS_SEL]")
        lines.append("\tmov fs, ax")

        # Call into target
        lines.append(f"\tcall {call_target}")

        # Get current TEB
        lines.append("\tmov ecx, fs:[TEB_SELF]")

        # Jump back to 64-bit
        lines.append("\tLJMP64")

        # Sign extend return value if necessary
        if f.return_type.sign_extended:
            lines.append("\tcdqe")

        # Restore FS base
        lines.append("\tmov r9, qword ptr [rcx+TEB_FSBASE]")
        lines.append("\twrfsbase r9")

        # Restore host stack
        lines.append("\tmov rsp, qword ptr [rcx+TEB_SP]")
        lines.append("\tmov qword ptr [rcx+TEB_SP], rbp")

        # Restore rbp, rbx and return
        lines.append("\tpop rbp")
        lines.append("\tpop rbx")
        lines.append("\tret")
    else:
        lines.append(".code32")

        # Save registers
        lines.append("\tpush ebp")
        lines.append("\tpush esi")
        lines.append("\tpush edi")

        # Get current TEB
        lines.append("\tmov ecx, fs:[TEB_SELF]")

        # Save fs segment
        lines.append("\tmov di, fs")
        lines.append("\tmov word ptr [ecx+TEB_FS_SEL], di")

        # Jump back to 64-bit
        lines.append("\tLJMP64")

        # Restore FS base
        lines.append("\tmov r9, qword ptr [rcx+TEB_FSBASE]")
        lines.append("\twrfsbase r9")

        # Stash guest stack in r10
        lines.append("\tmov r10, rsp")

        # Restore host stack
        lines.append("\tmov rbp, qword ptr [rcx+TEB_SP]")
        lines.append("\tmov qword ptr [rcx+TEB_SP], rsp")
        lines.append("\tmov rsp, rbp")

        # Allocate stack space for arguments
        if target_layout.stack_size > 0:
            lines.append(f"\tsub rsp, {target_layout.stack_size}")

        # Align stack if needed (must be done after allocating args)
        if align > 0:
            lines.append(f"\tand rsp, ~{align - 1}")

        # Transfer args
        for i, target in enumerate(target_layout.args):
            arg = f.args[i]
            source = source_layout.args[i]

            if target.stack_offset is not None:
                if source.stack_offset is not None:
                    ptr_type = _x64_ptr_type_by_slot_size(source.slot_size)
                    register = _x64_register_by_slot_size("rax", source.slot_size)
                    lines.append(
                        f"\tmov {register}, {ptr_type} [r10+{source.stack_offset}]"
                    )
                    ptr_type = _x64_ptr_type_by_slot_size(target.slot_size)
                    register = _x64_register_by_slot_size("rax", target.slot_size)
                elif source.register is not None:
                    ptr_type = _x64_ptr_type_by_slot_size(target.slot_size)
                    register = _x64_register_by_slot_size(
                        source.register, target.slot_size
                    )
                else:
                    raise ValueError(f"Argument {i} is not a register or stack offset")
                lines.append(
                    f"\tmov {ptr_type} [rsp+{target.stack_offset}], {register}"
                )
            elif target.register is not None:
                ptr_type = _x64_ptr_type_by_slot_size(source.slot_size)
                if source.slot_size == 4 and target.slot_size == 8:
                    if arg.sign_extended:
                        register = _x64_register_by_slot_size(
                            target.register, source.slot_size
                        )
                        lines.append(
                            f"\tmov {register}, {ptr_type} [r10+{source.stack_offset}]"
                        )
                        lines.append(f"\tmovsxd {target.register}, {register}")
                    else:
                        register = _x64_register_by_slot_size(
                            target.register, source.slot_size
                        )
                        lines.append(
                            f"\tmov {register}, {ptr_type} [r10+{source.stack_offset}]"
                        )
                elif source.slot_size == 8 and target.slot_size == 8:
                    lines.append(
                        f"\tmov {target.register}, {ptr_type} [r10+{source.stack_offset}]"
                    )
                else:
                    raise NotImplementedError(
                        f"Unsupported conversion from {source.slot_size} to {target.slot_size}"
                    )

        # Call into target
        lines.append(f"\tcall {call_target}")

        # Get current TEB
        lines.append("\tmov rcx, fs:[currentThreadTeb@tpoff]")

        # Restore host stack
        lines.append("\tmov rsp, qword ptr [rcx+TEB_SP]")
        lines.append("\tmov qword ptr [rcx+TEB_SP], rbp")

        # Jump to 32-bit mode
        lines.append("\tLJMP32")

        # Setup FS selector
        lines.append("\tmov di, word ptr [ecx+TEB_FS_SEL]")
        lines.append("\tmov fs, di")

        # Restore registers
        lines.append("\tpop edi")
        lines.append("\tpop esi")
        lines.append("\tpop ebp")

        # Return to guest
        if f.source_cc == CallingConv.X86_STDCALL and source_layout.stack_size > 0:
            lines.append(f"\tret {source_layout.stack_size}")
        else:
            lines.append("\tret")


def emit_cc_thunk(f: FuncInfo | TypedefInfo, lines: List[str], arch: Arch):
    if arch == Arch.X86_64:
        return emit_cc_thunk64(f, lines)
    elif arch == Arch.X86:
        return emit_cc_thunk32(f, lines)


def emit_guest_to_host_thunks(
    lines: List[str], dll: str, funcs: Iterable[FuncInfo], arch: Arch
) -> None:
    for f in funcs:
        thunk = f"thunk_{dll}_{f.name}"
        lines.append("")
        lines.append(
            f"# {f.qualified_ns}::{f.name} (source_cc={f.source_cc.name}, target_cc={f.target_cc.name}, variadic={f.variadic})"
        )
        source_layout = compute_arg_layout(f.args, f.source_cc, Arch.X86)
        target_layout = compute_arg_layout(f.args, f.target_cc, arch)
        for i, arg in enumerate(f.args):
            details: List[str] = []
            details.append(f"src={describe_arg_placement(source_layout.args[i])}")
            details.append(f"dst={describe_arg_placement(target_layout.args[i])}")
            details.append(f"class={arg.arg_class.value}")
            details.append(f"sign_extended={arg.sign_extended}")
            lines.append(f"\t# Arg {i} ({', '.join(details)})")
        lines.append(f".globl {thunk}")
        lines.append(f".type {thunk}, @function")
        lines.append(f"{thunk}:")
        emit_cc_thunk(f, lines, arch)
        lines.append(f".size {thunk}, .-{thunk}")


def emit_host_to_guest_thunks(
    lines: List[str], typedefs: Iterable[TypedefInfo], arch: Arch
) -> None:
    for f in typedefs:
        thunk = f"call_{f.name}"
        lines.append("")
        lines.append(
            f"# {f.name} (target_cc={f.target_cc.name}, variadic={f.variadic})"
        )
        source_layout = compute_arg_layout(f.args, f.source_cc, arch, skip_args=1)
        target_layout = compute_arg_layout(f.args, f.target_cc, Arch.X86)
        for i, arg in enumerate(f.args):
            details: List[str] = []
            details.append(f"src={describe_arg_placement(source_layout.args[i])}")
            details.append(f"dst={describe_arg_placement(target_layout.args[i])}")
            details.append(f"class={arg.arg_class.value}")
            details.append(f"sign_extended={arg.sign_extended}")
            lines.append(f"\t# Arg {i} ({', '.join(details)})")
        # details = []
        # details.append(f"class={f.return_type.arg_class.value}")
        # details.append(f"sign_extended={f.return_type.sign_extended}")
        # lines.append(f"\t# Ret ({', '.join(details)})")
        lines.append(f".weak {thunk}")
        lines.append(f".type {thunk}, @function")
        lines.append(f"{thunk}:")
        emit_cc_thunk(f, lines, arch)
        lines.append(f".size {thunk}, .-{thunk}")


def emit_header_mapping(
    dll: str,
    funcs: Iterable[FuncInfo],
    typedefs: Iterable[TypedefInfo],
    variables: Iterable[VarInfo],
    arch: Arch,
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
        return_type = _canonical_type_str(f.return_type.type)
        if arch == Arch.X86_64:
            cc_attr = ""
        elif f.source_cc == CallingConv.X86_STDCALL:
            cc_attr = "__attribute__((stdcall)) "
        elif f.source_cc == CallingConv.C:
            cc_attr = "__attribute__((cdecl)) "
        else:
            raise NotImplementedError(
                f"Unsupported calling convention {f.source_cc.name} for function {f.name}"
            )
        lines.append(f"{cc_attr}{return_type} {thunk}({param_list});")

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
        return_type = _type_to_string(td.return_type.type)
        lines.append(f"{return_type} {thunk}({param_list});")

    lines.append("#ifdef __cplusplus\n}\n#endif")
    lines.append("")
    # name->address helper for resolveByName
    lines.append("static inline void *%sThunkByName(const char *name) {" % dll)
    for f in funcs:
        lines.append(
            f'\tif (strcmp(name, "{f.name}") == 0) return (void*)&thunk_{dll}_{f.name};'
        )
    for v in variables:
        qualified = f"{v.qualified_ns}::{v.name}" if v.qualified_ns else v.name
        lines.append(
            f'\tif (strcmp(name, "{v.name}") == 0) return (void*)&{qualified};'
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
    ap.add_argument("--arch", choices=["x86", "x86_64"], default="x86")
    ap.add_argument(
        "--out-asm", type=Path, required=True, help="Output assembly file (.S)"
    )
    ap.add_argument(
        "--out-hdr", type=Path, required=True, help="Output header file (.h)"
    )
    ap.add_argument("-I", dest="incs", action="append", default=[])
    args = ap.parse_args()

    if args.arch == "x86":
        arch = Arch.X86
    elif args.arch == "x86_64":
        arch = Arch.X86_64
    else:
        raise ValueError(f"Unsupported architecture: {args.arch}")

    target = "i686-pc-linux-gnu" if args.arch == "x86" else "x86_64-pc-linux-gnu"
    tu = parse_tu(args.headers, args.incs, target)
    funcs = collect_functions(tu, args.ns, arch)
    typedefs = collect_typedefs(tu, arch)
    variables = collect_variables(tu, args.ns)

    if not funcs and not typedefs and not variables:
        sys.stderr.write("No functions, typedefs, or variables found for generation.\n")
        return 1

    lines: List[str] = []
    lines.append("# Auto-generated thunks; DO NOT EDIT.")
    lines.append('#include "macros.S"')
    lines.append('.section .note.GNU-stack, "", @progbits')
    lines.append(".text")

    emit_guest_to_host_thunks(lines, args.dll, funcs, arch)
    emit_host_to_guest_thunks(lines, typedefs, arch)

    asm = "\n".join(lines) + "\n"
    hdr = emit_header_mapping(args.dll, funcs, typedefs, variables, arch)

    args.out_asm.parent.mkdir(parents=True, exist_ok=True)
    args.out_hdr.parent.mkdir(parents=True, exist_ok=True)
    args.out_asm.write_text(asm)
    args.out_hdr.write_text(hdr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
