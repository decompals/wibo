#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __x86_64__
int tebThreadSetup(int entryNumber, TEB *teb);
#endif

#ifdef __cplusplus
}
#endif
