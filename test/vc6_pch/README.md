# VC6 automatic precompiled-header regression

VC6's `/YX /Fprepro.pch` writes a temporary file and calls
`MoveFileExW(temp, "repro.pch", MOVEFILE_COPY_ALLOWED)` to publish it.
Before the MoveFileEx shim, this aborts on a missing import.
Reuse also needs fixed-address `MapViewOfFileEx` views to reserve their address
range in the allocator. Otherwise VC6's subsequent top-down `VirtualAlloc`
can overwrite the restored PCH view. `test_createfilemapping.exe` checks that
fixed views reject overlapping allocations and remain intact.

Supply your own VC6 compiler; no proprietary compiler files are included.
Run with Wine first, then the newly built wibo:

```sh
WINEDEBUG=-all python3 test/vc6_pch/check.py \
  --runner /path/to/wine --compiler /path/to/CL.EXE --output /tmp/pch-wine
python3 test/vc6_pch/check.py \
  --runner build/debug/wibo --compiler /path/to/CL.EXE --output /tmp/pch-wibo
```

The check compiles without PCH, creates an automatic PCH, and recompiles with
that PCH. It requires the PCH's hash and modification time to remain unchanged
on reuse, and compares all three objects after excluding only the COFF
header timestamp. It retains the objects and command results in the output
directory so Wine and wibo output can also be compared.

`test_movefileex.exe` covers the API without requiring VC6. An optional first
argument names a writable directory on another volume to exercise cross-volume
copy, replacement, write-through and directory-move rejection. Run that variant
under Wine first, then wibo with the same destination. Delayed reboot operations
and link tracking are unsupported by the shim and return `ERROR_NOT_SUPPORTED`;
copy combined with delay and unknown flags return `ERROR_INVALID_PARAMETER`.
