#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["clang==17.0.6"]
# ///
"""
Generate Windows ABI trampolines by scanning C++ prototypes using libclang.

This emits x86 trampolines for guest-to-host calls.
"""

if __name__ == "__main__":
    import script_venv

    script_venv.bootstrap_venv(__file__)

import argparse
import os
import sys
import tempfile

from clang.cindex import (
    Config,
    Cursor,
    CursorKind,
    Index,
    TranslationUnit,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

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


@dataclass
class FuncInfo:
    qualified_ns: str
    name: str
    mangled: str
    argc: int
    stdcall: bool


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


def _has_stdcall_annotation(func: Cursor) -> bool:
    for child in func.get_children():
        if child.kind == CursorKind.ANNOTATE_ATTR and child.spelling == "CC:stdcall":
            return True
    return False


def _arg_count(func: Cursor) -> int:
    return sum(1 for _ in func.type.argument_types())


def collect_functions(tu: TranslationUnit, ns_filter: Optional[str]) -> List[FuncInfo]:
    want_ns = ns_filter.split("::") if ns_filter else None
    out: dict[str, FuncInfo] = {}

    def visit(node: Cursor) -> None:
        if node.kind == CursorKind.FUNCTION_DECL:
            ns_parts = _cursor_namespace(node)
            if want_ns is not None and ns_parts != want_ns:
                return
            name = node.spelling or ""
            mangled = getattr(node, "mangled_name", None) or ""
            if not name or not mangled:
                return
            out[name] = FuncInfo(
                qualified_ns="::".join(ns_parts),
                name=name,
                mangled=mangled,
                argc=_arg_count(node),
                stdcall=_has_stdcall_annotation(node),
            )
        # Recurse into children where it makes sense
        if node.kind in (CursorKind.TRANSLATION_UNIT, CursorKind.NAMESPACE):
            for c in node.get_children():
                visit(c)

    visit(tu.cursor)
    return sorted(out.values(), key=lambda f: f.name)


def emit_x86_asm_trampolines(dll: str, funcs: Iterable[FuncInfo]) -> str:
    lines: List[str] = []
    lines.append("#\tAuto-generated trampolines; DO NOT EDIT.")
    lines.append(".section .note.GNU-stack, \"\", @progbits")
    lines.append(".text")
    for f in funcs:
        name = f.name
        mangled = f.mangled
        # Ensure ms_abi is encoded for stdcall function-pointer types to match GCC
        # mangled = mangled.replace("U7stdcall", "U7stdcallU6ms_abi")
        tramp = f"thunk_{dll}_{name}"
        lines.append("")
        lines.append(f".globl {tramp}")
        lines.append(f".type {tramp}, @function")
        lines.append(f"{tramp}:")
        argc = int(f.argc or 0)
        # Calculate number of stack args (fastcall uses ECX/EDX for first 2)
        stack_argc = max(0, argc - 2)
        stack_bytes = stack_argc * 4
        # Use frame pointer for clean alignment and argument access
        lines.append("\tpush %ebp")
        lines.append("\tmovl %esp, %ebp")
        # Align stack: we want ESP = 16n before the call,
        # so that after call pushes return address, callee sees ESP = 16n - 4
        # After pushing stack_bytes worth of args, we need ESP = 16n + stack_bytes
        if stack_bytes > 0:
            lines.append(f"\tleal -{stack_bytes}(%ebp), %esp")
            lines.append("\tandl $0xFFFFFFF0, %esp")
            lines.append(f"\taddl ${stack_bytes}, %esp")
        else:
            # No stack args, just align to 16n for the call
            lines.append("\tandl $0xFFFFFFF0, %esp")
        # Move first two args into ECX/EDX for fastcall
        if argc >= 1:
            lines.append("\tmovl 8(%ebp), %ecx")
        if argc >= 2:
            lines.append("\tmovl 12(%ebp), %edx")
        # Push remaining args (from last down to the 3rd) so layout matches fastcall
        for i in range(argc, 2, -1):
            off = 4 * (i + 1)  # +1 because EBP offset includes pushed EBP
            lines.append(f"\tpushl {off}(%ebp)")
        # Call into fastcall stub
        lines.append(f"\tcall {mangled}")
        # Restore stack and frame pointer
        lines.append("\tleave")
        # Return to guest
        argb = argc * 4
        if f.stdcall and argb:
            lines.append(f"\tret ${argb}")
        else:
            lines.append("\tret")
        lines.append(f".size {tramp}, . - {tramp}")
    return "\n".join(lines) + "\n"


def emit_header_mapping(dll: str, funcs: Iterable[FuncInfo]) -> str:
    guard = f"WIBO_GEN_{dll.upper()}_TRAMPOLINES_H"
    lines: List[str] = []
    lines.append("/* Auto-generated; DO NOT EDIT. */")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append("#include <stddef.h>")
    lines.append("#include <string.h>")
    lines.append('#ifdef __cplusplus\nextern "C" {\n#endif')
    for f in funcs:
        tramp = f"thunk_{dll}_{f.name}"
        lines.append(f"void {tramp}(void);")
    lines.append("#ifdef __cplusplus\n}\n#endif")
    lines.append("")
    # name->address helper for resolveByName
    lines.append("static inline void *%s_trampoline_by_name(const char *name) {" % dll)
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
    if not funcs:
        sys.stderr.write("No functions found for generation.\n")
        return 1

    asm = emit_x86_asm_trampolines(args.dll, funcs)
    hdr = emit_header_mapping(args.dll, funcs)

    args.out_asm.parent.mkdir(parents=True, exist_ok=True)
    args.out_hdr.parent.mkdir(parents=True, exist_ok=True)
    args.out_asm.write_text(asm)
    args.out_hdr.write_text(hdr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
