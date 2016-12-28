#include <ctime>
#include <cstring>
#include "log.h"

int log_level = 1;

void set_log_level(int num) {
  if (0 <= num && num <= 3) {
    log_level = num;
  }

  LOG(1, "The log level is %d.\n", log_level);
}

void LOG(int level, const char* fmt, ...) {
  if (level > log_level) {
    return;
  }

  if (level < 3) {
    time_t utc_time = time(NULL);
    tm* local = localtime(&utc_time);
    char *loc_time = asctime(local);
    loc_time[strlen(loc_time) - 1] = '\0';
    printf("%s: ", loc_time);
  }

  va_list args;
	va_start(args, fmt);
  vprintf(fmt, args);
	va_end(args);
}

void VERBOSE(char *buf) {
  DNS_header req_header;
  memcpy(&req_header, buf, sizeof(req_header));
  LOG(3, "ID: %0.4x\n", req_header.id);
  uint16_t tag = req_header.tag;
  LOG(3, "QR: %0.1x\n", (tag>>15&0x1));
  LOG(3, "OPCODE: %0.2x\n", (tag>>10&0x1111));
  LOG(3, "AA: %0.1x\n", (tag>>9&0x1));
  LOG(3, "TC: %0.1x\n", (tag>>8&0x1));
  LOG(3, "RD: %0.1x\n", (tag>>7&0x1));
  LOG(3, "RA: %0.1x\n", (tag>>6&0x1));
  LOG(3, "Z: %0.1x\n", (tag>>4&0x11));
  LOG(3, "RCODE: %0.2x\n", (tag&0x1111));
  LOG(3, "QDCOUNT: %d\n", ntohs(req_header.num_ques));
  LOG(3, "ANCOUNT: %d\n", ntohs(req_header.num_answ));
  LOG(3, "NSCOUNT: %d\n", ntohs(req_header.num_serv));
  LOG(3, "ARCOUNT: %d\n\n", ntohs(req_header.num_RRs));
}
