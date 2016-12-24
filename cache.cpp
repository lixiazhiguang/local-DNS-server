#include "cache.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include "blacklist.h"
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

void remove_expired(const set<string, time_t>& url_set) {
  for (auto iter = url_set.begin(); iter != url_set.end(); ++iter) {
    if (is_expired(iter->second)) {
      url_set.erase(iter);
    }
  }
}

void add_record(const char* url, const char* addr, time_t ttl) {
  string url_s(url);
  string addr_s(addr);

  if (url_ip_map.count(url_s) == 0) {
    remove_expired(url_ip_map[url_s]);
    url_set.insert({addr_s, get_expire(ttl) + ttl});
  } else {
    url_ip_map[url_s] =
        vector<string, time_t>(1, {addr_s, get_expire(ttl) + ttl});
  }
}

bool pre_cache(const char* cache_file) {
  FILE* cache_file = fopen(cache_file, "r");
  if (!cache_file) {
    return false;
  }

  char url[65];
  char ip[16];
  while (fscanf(cache_file, "%s %s", url, ip) > 0) {
    Log(2, "Pre-cache: add %s %s\n", url, ip);
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

  auto ip_info = url_ip_map[url_s].start();
  string ip_s = ip_info->first;
  time_t expire_time = ip_info->second;
  if (in_black(ip_s)) {
    return -1;
  }
  if (is_expired(expire_time)) {
    return 0;
  }

  ip = ip_s.c_str();
  return 1;
}

// typedef struct {
//   char url[MAX_RECORD][65];     // url字符串
//   int index[MAX_RECORD];        //对应url的ip在文件里的位置
//   int expire_time[MAX_RECORD];  //过期时间
// } record_index;            //索引

// typedef struct {
//   char addr[16];  // ip地址字符串
// } stru_record;    // ip记录

// typedef struct { char addr[16]; } char*;

// //向缓存文件里添加网址为url，地址为addr，生存时间为ttl的记录
// int add_record(char* url, char* addr, int ttl) {
//   FILE* cache_file;
//   //如果缓存不存在就尝试创建并初始化
//   if ((cache_file = fopen("cache.dat", "r+")) == NULL) {
//     if (debug_level >= 1) puts("Cache file no exist.");
//     if ((cache_file = fopen("cache.dat", "w+")) == NULL) {
//       puts("Can't create cache file.");
//       return 1;
//     }

//     ini_cache_file(cache_file);  //初始化
//     fseek(cache_file, 0, 0);     //文件指针复位
//   }

//   //读取计数
//   int n_record, max_record;
//   fread((void*)&n_record, sizeof(n_record), 1, cache_file);
//   fread((void*)&max_record, sizeof(max_record), 1, cache_file);

//   //读取索引
//   record_index record_index;
//   fread((void*)&record_index, sizeof(record_index), 1, cache_file);

//   int url_pos = -1;
//   int empty_pos =
//       -1;
//       //要把这个新纪录写入到的位置；第一个空闲位置。等于-1表示没找到可用的位置
//   int expired_pos = -1,
//       first_expire_pos =
//           -1;  //第一个超时的位置；还没超时的记录里第一个超时的记录的位置

//   //看是不是已经有这个url的记录了。如果有就在之前位置写
//   for (int i = 0; i < max_record; ++i) {
//     int expire_time = record_index.expire_time[i];
//     if (record_index.index[i] ==
//         -1) {  //保存第一个空闲位置，后面可能会把记录写到这里
//       if (empty_pos < 0) empty_pos = i;
//     } else if (strcmp(url, record_index.url[i]) == 0) {
//     //如果非空就比较url
//       url_pos = i;
//       break;
//     } else {
//       if (expire_time > 0) {
//         if (first_expire_pos < 0)
//           first_expire_pos = i;
//         else if (expire_time <
//                  record_index.expire_time[first_expire_pos])
//                  //找最早超时的记录
//           first_expire_pos = i;
//       }
//       if (is_expired(expire_time) == 1) {
//         expired_pos = i;
//         break;
//       }
//     }
//   }

//   //如果缓存里没这个url
//   if (url_pos < 0) {
//     if (expired_pos >= 0)  //有过期的就覆盖过期的
//     {
//       url_pos = expired_pos;
//       --n_record;  //有记录要被覆盖，先把这个变量-1，后面会再加1
//     } else if (empty_pos >= 0)  //没过期的写到空位置
//     {
//       url_pos = empty_pos;
//     } else if (first_expire_pos >= 0)  //没过期的没空位置就覆盖最早过期的
//     {
//       url_pos = first_expire_pos;
//       --n_record;  //有记录要被覆盖，先把这个变量-1，后面会再加1
//     }
//   } else
//     --n_record;

//   if (url_pos >= 0)  //找到了可写的地方才更新缓存文件，否则不改缓存文件
//   {
//     //更新索引
//     strcpy(record_index.url[url_pos], url);
//     record_index.index[url_pos] = url_pos;  //可以换个给ip选位置的算法
//     set_expire(&record_index.expire_time[url_pos], ttl);
//     fseek(cache_file, sizeof(int) + sizeof(int), 0);
//     fwrite(&record_index, sizeof(record_index), 1, cache_file);

//     //更新ip记录
//     record new_record;
//     strcpy(new_record.addr, addr);
//     fseek(cache_file,
//           sizeof(int) + sizeof(int) + sizeof(record_index) +
//               url_pos * sizeof(record),
//           0);
//     fwrite(&new_record, sizeof(record), 1, cache_file);

//     //更新计数
//     ++n_record;
//     fseek(cache_file, 0, 0);
//     fwrite(&n_record, sizeof(int), 1, cache_file);
//   }

//   fclose(cache_file);
//   return 0;
// }

//读取预先设置的缓存
// void read_pre_cache() {
//   FILE* pre_cache_file;
//   if ((pre_cache_file = fopen("cache.txt", "r")) == NULL) return;
//   char url[65], ip[16];
//   while (fscanf(pre_cache_file, "%s %s", url, ip) > 0) {
//     if (debug_level >= 1) printf("precache: add %s %s\n", url, ip);
//     add_record(url, ip, 0);
//   }
//   fclose(pre_cache_file);
// }

//删除pos位置的记录
// void delete_record(FILE* file, int pos) {
//   if (debug_level >= 1) puts("delete pos %d");

//   //更新计数
//   int n_r;
//   fseek(file, 0, 0);
//   fread(&n_r, sizeof(n_r), 1, file);
//   --n_r;
//   fseek(file, 0, 0);
//   fwrite(&n_r, sizeof(n_r), 1, file);

//   //读取旧索引
//   record_index record_index;
//   fseek(file, sizeof(int) + sizeof(int), 0);
//   fread(&record_index, sizeof(record_index), 1, file);

//   //更新索引
//   record_index.url[pos][0] = '\0';
//   record_index.index[pos] = -1;

//   //写回索引
//   fseek(file, sizeof(int) + sizeof(int), 0);
//   fwrite(&record_index, sizeof(record_index), 1, file);
// }

//返回的地址第一个字符为'n'：没缓存这个。'e'：过期了。'b'：黑名单
// ip_addr get_ip(char* query_url) {
//   ip_addr result;
//   result.addr[0] = '\0';

//   if (in_black(query_url, "\0") == 1) {
//     result.addr[0] = 'b';
//     return result;
//   }

//   FILE* cache_file;
//   if ((cache_file = fopen("cache.dat", "r+")) == NULL) {
//     if (debug_level >= 1) puts("Cache file no exist.");
//     result.addr[0] = 'n';

//     if ((cache_file = fopen("cache.dat", "w+")) != NULL) {
//       ini_cache_file(cache_file);  //初始化
//       fclose(cache_file);
//     } else
//       puts("Can't create cache file.");

//     return result;
//   }

//   //读取计数
//   int n_record, max_record;
//   fread(&n_record, sizeof(n_record), 1, cache_file);
//   fread(&max_record, sizeof(max_record), 1, cache_file);

//   //读取索引
//   record_index record_index;
//   fread(&record_index, sizeof(record_index), 1, cache_file);

//   //线性找url在索引的位置
//   int url_index = -1;
//   for (int i = 0; i < max_record; ++i) {
//     if (record_index.index[i] != -1) {
//       if (strcmp(query_url, record_index.url[i]) == 0) {
//         //检查是不是超时
//         if (is_expired(record_index.expire_time[i]) == 1) {
//           if (debug_level >= 1) puts("expired");
//           delete_record(cache_file, i);
//           result.addr[0] = 'e';
//         } else
//           url_index = i;
//         break;
//       }
//     }
//   }

//   if (url_index == -1)  //索引里没找到url并且并不是因为超时而没找到
//   {
//     if (result.addr[0] != 'e') result.addr[0] = 'n';
//   } else {
//     //根据索引读取ip记录
//     record this_record;
//     fseek(cache_file,
//           sizeof(int) + sizeof(int) + sizeof(record_index) +
//               url_index * sizeof(record),
//           0);
//     fread(&this_record, sizeof(this_record), 1, cache_file);

//     //检查ip是不是在黑名单
//     if (in_black(query_url, this_record.addr) == 1)
//       result.addr[0] = 'b';
//     else
//       strcpy(result.addr, this_record.addr);
//   }

//   fclose(cache_file);
//   return result;
//   }

//   //显示缓存文件里内容
//   void disp() {
//     FILE* file;
//     file = fopen("cache.dat", "r");
//     if (file == NULL)
//     {
//         puts("disp::no exist.");
//         return;
//     }

//     int a;
//     fread(&a, sizeof(int), 1, file);
//     printf("n_record:%d\n", a);
//     fread(&a, sizeof(int), 1, file);
//     printf("max_record:%d\n", a);

//     record_index record_index;
//     record record;

//     fread(&record_index, sizeof(record_index), 1, file);
//     for (int i = 0; i < a; ++i)
//     {
//         printf("%d:%d >%s<\n", i, record_index.index[i], record_index.url[i]);
//     }

//     for (int i = 0; i < a; ++i)
//     {
//         fread(&record, sizeof(record), 1, file);
//         printf("%d:>%s< %d\n", i, record.addr, record_index.expire_time[i]);
//     }

//     fclose(file);
// }
