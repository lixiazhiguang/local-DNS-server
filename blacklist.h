#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>
#include "log.h"

using namespace std;

bool init_black_list(const char* black_file);
bool in_black(const string& str);
