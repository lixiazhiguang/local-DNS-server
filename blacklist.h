#pragma once

#include <iostream>
#include <string>
#include <unordered_set>
#include "log.h"

unordered_set<string> black_set;

bool init_black_list(const char* black_file);
int in_black(const string& str);
