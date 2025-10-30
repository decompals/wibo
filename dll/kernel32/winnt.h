#pragma once

#include "types.h"
#include "errhandlingapi.h"

namespace kernel32 {

void WINAPI RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);

} // namespace kernel32
