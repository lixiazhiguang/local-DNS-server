#pragma once

#include "cstdarg"
#include "cstdio"

void set_log_level(int num);
void LOG(int level, const char* fmt, ...);
