#pragma once

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <arpa/inet.h>

struct DNS_header {
  uint16_t id;
  uint16_t tag;
  uint16_t num_ques;
  uint16_t num_answ;
  uint16_t num_serv;
  uint16_t num_RRs;
};

void set_log_level(int num);
void LOG(int level, const char* fmt, ...);
void VERBOSE(char *buf);
