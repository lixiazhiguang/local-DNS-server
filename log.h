#pragma once

int log_level = 1;

void set_log_level(int num) {
  if (0 <= num && num <= 2) {
    log_level = num;
  }
  LOG(1, "The log level is %d", log_level);
}

void LOG(int level, const char* fmt, ...) {
  if (level > log_level) {
    return;
  }

  char printf_buf[1024];
  va_list args;
	va_start(args, fmt);
  vsprintf(printf_buf, fmt, args);
	va_end(args);
	return sum;
}
