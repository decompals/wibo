#pragma once

#include "types.h"

#define USER_PRIVILEGE 3

#ifdef __cplusplus
extern "C" {
#endif

bool tebThreadSetup(TEB *teb);
bool tebThreadTeardown(TEB *teb);

#ifdef __cplusplus
}
#endif
