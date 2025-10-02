#pragma once

#include "common.h"
#include "errhandlingapi.h"

namespace kernel32 {

void WIN_FUNC RtlUnwind(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue);

} // namespace kernel32

