#include "DNS.h"

char root_dns_ip[16] = "";
char cache_file[128] = "cache.txt";
char black_file[128] = "blacklist.txt";

SOCKET local_sock;
SOCKET remote_sock;

int min(int a, int b) { return a <= b ? a : b; }

void proc_args(int argc, char* argv[]) {
  char status = (char)0;
  for (int i = 1; i < argc;) {
    if (argv[i][0] == '-') {
      status = argv[i][1];
      i++;
    } else {
      switch (status) {
        case 'r':
          strcpy(root_dns_ip, argv[i], min(16, sizeof(argv[i])));
          LOG(2, "Set root DNS server: %s.\n", root_dns_ip);
          break;
        case 'l':
          set_log_level(argv[i][0] - '0');
          break;
        case 'c':
          strcpy(cache_file, argv[i], min(128, sizeof(argv[i])));
          LOG(2, "Set cache file: %s.\n", cache_file);
          break;
        case 'b':
          strcpy(black_file, argv[i], min(128, sizeof(argv[i])));
          LOG(2, "Set black list file: %s.\n", black_file);
          break;
        default:
          break;
      }
    }
  }
}

void recv_asn_thread() {
  while (true) {
    recv_ans(local_sock, remote_sock);
  }
}

int main(int argc, char* argv[]) {
  proc_args(argc, argv);

  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
  local_sock = socket(AF_INET, SOCK_DGRAM, 0);
  remote_sock = socket(AF_INET, SOCK_DGRAM, 0);

  u_long mode = 1;  // set unblock
  if (ioctlsocket(local_sock, FIONBIO, &mode) == -1) {
    LOG(1, "Set local socket unblock mode false.");
    exit(1);
  }
  if (ioctlsocket(remote_sock, FIONBIO, &mode) == -1) {
    LOG(1, "Set remote socket unblock mode false.");
    exit(1);
  }

  sockaddr_in local_addr;
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  local_addr.sin_port = htons(PORT_NO);

  sockaddr_in remote_addr;
  memset(&remote_addr, 0, sizeof(remote_addr));
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = inet_addr(root_dns_ip);

  bool reuse = true;  // set port reusable
  setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  if (bind(local_sock, &local_addr, sizeof(local_addr)) < 0) {
    LOG(1, "Local socket bind fail.\n");
    exit(1);
  }

  if (!pre_cache(cache_file)) {
    LOG(1, "Load cache file failed.\n");
    exit(1);
  }
  if (init_black_list(black_file)) {
    LOG(1, "Local blacklist file failed.\n");
    exit(1);
  }

  if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)recv_asn_thread, NULL, 0,
                    NULL)) {
    LOG(1, "Create thread fail.\n");
  }

  while (true) {
    recv_req(local_sock, remote_sock, remote_addr);
  }
}
