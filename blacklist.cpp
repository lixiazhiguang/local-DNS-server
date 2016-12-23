#include "blacklist.h"

bool init_black_list(const char* black_file) {
  ifstream in(string(black_file), ios::in);
  if (!in.is_open()) return false;

  string record;
  while (!in.eof()) {
    in.getline(record, 65);
    LOG(1, "Load black record: %s\n", record.c_str());
    black_set.add(record);
  }

  in.close();
  return true;
}

bool in_black(const string& str) { return black_set.find(str); }