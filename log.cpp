#include "log.h"

int log_level = 1;
char printf_buf[256];

void set_log_level(int num) {
  if (0 <= num && num <= 2) {
    log_level = num;
  }
  LOG(1, "The log level is %d.\n", log_level);
}

void LOG(int level, const char* fmt, ...) {
  if (level > log_level) {
    return;
  }

  va_list args;
	va_start(args, fmt);
  vsprintf(printf_buf, fmt, args);
  perror(printf_buf);
	va_end(args);
}
