#pragma once

#include <cstdio>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include "blacklist.h"
#include "log.h"

using namespace std;

/**
 * @param  url   URL of the website
 * @param  addr  IP of the website
 * @param  ttl   Time to live
 */
void add_record(const char* url, const char* addr, time_t ttl);

/**
 * Read prepared cache.txt
 * @return  bool  true: Success, false: Fail
 */
bool pre_cache(const char* cache_file);

/**
 * @param   url  URL to query
 * @param   ip   IP return
 * @return  -1:in blacklist, 0:no cached or expired, 1:ok
 */
int get_ip(const char* url, char* ip);
