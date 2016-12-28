#include <cstdio>
#include <cstring>
#include <ctime>
#include "blacklist.h"
#include "cache.h"

unordered_map<string, set<pair<string, time_t>>> url_ip_map;

time_t get_expire(int ttl) {
  if (ttl == 0) {
    return 0;
  }

  return time(NULL) + ttl;
}

int is_expired(int expire_time) {
  if (expire_time == 0) return 0;

  time_t now_time;
  now_time = time(NULL);
  if (now_time > expire_time) return 1;
  return 0;
}

void remove_expired(set<pair<string, time_t>>& url_set) {
  for (auto iter = url_set.begin(); iter != url_set.end(); ++iter) {
    if (is_expired(iter->second)) {
      url_set.erase(iter);
    }
  }
}

void add_record(const char* url, const char* addr, time_t ttl) {
  string url_s(url);
  string addr_s(addr);

  if (url_ip_map.count(url_s) != 0) {
    remove_expired(url_ip_map[url_s]);
    url_ip_map[url_s].insert({addr_s, get_expire(ttl) + ttl});
  } else {
    url_ip_map[url_s].insert({addr_s, get_expire(ttl) + ttl});
  }
}

bool pre_cache(const char* cache_file_name) {
  FILE* cache_file = fopen(cache_file_name, "r");
  if (!cache_file) {
    return false;
  }

  char url[65];
  char ip[16];
  while (fscanf(cache_file, "%s %s", ip, url) > 0) {
    LOG(2, "Pre-cache: add %s %s\n", url, ip);
    add_record(url, ip, 0);
  }

  return true;
}

int get_ip(const char* url, char* ip) {
  ip[0] = '\0';

  string url_s(url);

  if (in_black(url_s)) {
    return -1;
  }
  if (url_ip_map.count(url_s) == 0) {
    return 0;
  }

  auto ip_info = url_ip_map[url_s].begin();
  string ip_s = ip_info->first;
  time_t expire_time = ip_info->second;
  if (in_black(ip_s)) {
    return -1;
  }
  if (is_expired(expire_time)) {
    return 0;
  }

  strcpy(ip, ip_s.c_str());
  return 1;
}
