#include <Windows.h>
#include <windows.h>
#include <winsock2.h>
#include <cprocess>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include "blacklist.h"
#include "cache.h"
#include "log.h"

#pragma comment(lib, "Ws2_32.lib")

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;

struct ID_info {
  uint16_t ID;              //原有ID
  sockaddr_in client_addr;  //请求者套接字地址
  time_t expire_time;
};

struct DNS_header {
  uint16_t id;
  uint16_t tag;
  uint16_t num_ques;
  uint16_t num_answ;
  uint16_t num_serv;
  uint16_t num_RRs;
};

unordered_map<uint16_t, ID_info> id_table;
unordered_set<uint16_t> id_pool;

const int PORT_NO = 53;     // local DNS port
const int BUF_SIZE = 1024;  //最大报文缓存大小

time_t get_expire(int ttl);
int is_expired(int expire_time);
void revc_req(const SOCKET& local_sock, const SOCKET& remote_sock,
              const sockaddr_in& remote_addr);
void recv_ans(const SOCKET& local_sock, const SOCKET& remote_sock);
