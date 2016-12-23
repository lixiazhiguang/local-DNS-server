#include "common_function.h"

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