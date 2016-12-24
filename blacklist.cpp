#include "blacklist.h"

unordered_set<string> black_set;

bool init_black_list(const char* black_file) {
  ifstream in_file(string(black_file), ios::in);
  if (!in_file.is_open()) return false;

  string record;
  while (!in_file.eof() && getline(in_file, record)) {
    LOG(1, "Load black record: %s\n", record.c_str());
    black_set.insert(record);
  }

  in_file.close();
  return true;
}

bool in_black(const string& str) { return black_set.count(str); }
