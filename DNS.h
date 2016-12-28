#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// typedef unsigned char uint8_t;
// typedef unsigned short uint16_t;
// typedef unsigned int uint32_t;

struct ID_info {
  uint16_t id_client;
  sockaddr_in client_addr;
};

const int PORT_NO = 53;     // local DNS port
const int BUF_SIZE = 1024;  //最大报文缓存大小

void init_id_pool();
void proc_url(const char* buf, char* dest);
time_t get_expire(int ttl);
int is_expired(int expire_time);
void recv_req(const int local_sock, const int remote_sock,
              const sockaddr_in& remote_addr);
void recv_ans(const int local_sock, const int remote_sock);
