#include <ctime>
#include <cstring>
#include "log.h"

int log_level = 1;

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

  time_t utc_time = time(NULL);
  tm* local = localtime(&utc_time);
  char *loc_time = asctime(local);
  loc_time[strlen(loc_time) - 1] = '\0';
  printf("%s: ", loc_time);

  va_list args;
	va_start(args, fmt);
  vprintf(fmt, args);
	va_end(args);
}
