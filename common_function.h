#pragma once

time_t get_expire(int ttl);
int is_expired(int expire_time);