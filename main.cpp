#include <pthread.h>
#include <sys/ioctl.h>
#include "DNS.h"
#include "blacklist.h"
#include "cache.h"

using namespace std;

char local_ip[16] = "0.0.0.0";
char root_dns_ip[16] = "192.168.43.1";
char cache_file[128] = "cache.txt";
char black_file[128] = "blacklist.txt";

int local_sock;
int remote_sock;

int min(int a, int b) { return a <= b ? a : b; }

/**
 * Resolve the program settings
 * -r set root DNS server id
 * -l set log level(default 1)
 * -c set cache file(default "cache.txt")
 * -b set blacklist file(default "blacklist.txt")
 * @method proc_args
 * @param  argc      argv nums
 * @param  argv      settings from system
 */
void proc_args(int argc, char* argv[]) {
  char status = (char)0;
  for (int i = 1; i < argc;) {
    if (argv[i][0] == '-') {
      status = argv[i++][1];
    } else {
      switch (status) {
        case 'r':
          strcpy(root_dns_ip, argv[i]);
          LOG(2, "Set root DNS server: %s.\n", root_dns_ip);
          break;
        case 'l':
          set_log_level(argv[i][0] - '0');
          break;
        case 'c':
          strcpy(cache_file, argv[i]);
          LOG(2, "Set cache file: %s.\n", cache_file);
          break;
        case 'b':
          strcpy(black_file, argv[i]);
          LOG(2, "Set black list file: %s.\n", black_file);
          break;
        default:
          break;
      }
      i++;
    }
  }
}

/**
 * The thread to receive response from root DNS sercver
 * @method recv_asw_thread
 * @param  args  (not use in this function)
 */
void* recv_asw_thread(void* args) {
  while (true) {
    recv_ans(local_sock, remote_sock);
  }
}

int main(int argc, char* argv[]) {
  // char url[64];
  // char ori_url[65] = ".www.baidu.com.";
  // ori_url[0] = 3;
  // ori_url[4] = 5;
  // ori_url[10] = 3;
  // ori_url[14] = 0;
  // proc_url(ori_url, url);
  // return 0;
  //
  proc_args(argc, argv);

  local_sock = socket(AF_INET, SOCK_DGRAM, 0);
  remote_sock = socket(AF_INET, SOCK_DGRAM, 0);

  int mode = 1;  // set unblock
  if (ioctl(local_sock, FIONBIO, &mode) == -1) {
    LOG(1, "Set local socket unblock mode false.\n");
    exit(1);
  }
  if (ioctl(remote_sock, FIONBIO, &mode) == -1) {
    LOG(1, "Set remote socket unblock mode false.\n");
    exit(1);
  }

  sockaddr_in local_addr;
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = inet_addr(local_ip);
  local_addr.sin_port = htons(PORT_NO);

  sockaddr_in remote_addr;
  memset(&remote_addr, 0, sizeof(remote_addr));
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = inet_addr(root_dns_ip);
  remote_addr.sin_port = htons(PORT_NO);

  int reuse = 1;  // set port reusable
  if (setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    LOG(1, "Set local ip reuse failed.\n");
    exit(1);
  }

  if (::bind(local_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) <
      0) {
    LOG(1, "Local socket bind failed.\n");
    exit(1);
  }

  if (!pre_cache(cache_file)) {
    LOG(1, "Load cache file failed.\n");
    exit(1);
  }
  if (!init_black_list(black_file)) {
    LOG(1, "Local blacklist file failed.\n");
    exit(1);
  }
  init_id_pool();

  // pthread_t tid;
  // if (pthread_create(&tid, NULL, recv_asw_thread, NULL) != 0) {
    // LOG(1, "Create thread fail.\n");
    // exit(1);
  // }

  while (true) {
    recv_req(local_sock, remote_sock, remote_addr);
    recv_ans(local_sock, remote_sock);
  }

  return 0;
}
