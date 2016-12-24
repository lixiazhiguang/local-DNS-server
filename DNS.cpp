#include "DNS.h"

unordered_map<uint16_t, ID_info> id_table;
unordered_set<uint16_t> id_pool;

/**
 * Read url from buf to dest
 * @param  buf
 * @param  dest
 */
void proc_url(const char* buf, char* dest) {
  int len = strlen(buf);
  int j = 0;
  for (int i = 0; i < len;) {
    // buf[i] is a number
    if (0 < buf[i] && buf[i] <= 63) {
      int num = buf[i];
      for (int k = 1; k <= num; k++) {
        dest[j++] = buf[i++];
      }
    }

    if (buf[i] != 0) {
      dest[j++] = '.';
    }
  }
}

bool regis_id(const uint16_t id_client, uint16_t& id_server,
              const sockaddr_in& client_addr) {
  if (id_pool.empty()) {
    return false;
  }

  id_server = *(id_pool.begin());
  id_pool.erase(id_server);

  ID_info id_info;
  id_info.id_client = id_client;
  id_info.client_addr = client_addr;
  id_table[id_server] = id_info;

  LOG(2, "Store %d -> %d in ID table", id_server, id_client);

  return true;
}

bool proj_id(const uint16_t id_server, ID_info& id_info) {
  if (id_table.count(id_server) == 0) {
    return false;
  }
  id_info = id_table[id_server];
  return true;
}

void send_resp(const int local_sock, const sockaddr_in& client_addr,
               const char* req_buf, int len, const char* url, const char* ip) {
  LOG(2, "Cache read %s -> %s", url, ip);

  char resp_buf[BUF_SIZE];
  memcpy(resp_buf, req_buf, len);

  uint16_t tag = htons(0x8180);
  memcpy(resp_buf + 2, &tag, sizeof(uint16_t));

  uint16_t ancount = strcmp(ip, "0.0.0.0") == 0 ? htons(0x0000) : htons(0x0001);
  memcpy(resp_buf + 7, &ancount, sizeof(uint16_t));

  uint16_t name = htons(0xc00c);
  memcpy(resp_buf + len, &name, sizeof(uint16_t));
  len += sizeof(uint16_t);

  uint16_t type = htons(0x0001);
  memcpy(resp_buf + len, &type, sizeof(uint16_t));
  len += sizeof(uint16_t);

  uint16_t class_ = htons(0x0001);
  memcpy(resp_buf + len, &class_, sizeof(uint16_t));
  len += sizeof(uint16_t);

  uint32_t ttl = htons(0x7b);
  memcpy(resp_buf + len, &ttl, sizeof(uint32_t));
  len += sizeof(uint32_t);

  uint16_t rdlength = htons(0xc00c);
  memcpy(resp_buf + len, &rdlength, sizeof(uint16_t));
  len += sizeof(uint16_t);

  uint32_t rdata = (uint32_t)inet_addr(ip);
  memcpy(resp_buf + len, &rdata, sizeof(uint32_t));
  len += sizeof(uint32_t);

  sendto(local_sock, resp_buf, len, 0, (const sockaddr*)&client_addr,
         sizeof(client_addr));
}

void recv_req(const int local_sock, const int remote_sock,
              const sockaddr_in& remote_addr) {
  char req_buf[BUF_SIZE];
  memset(req_buf, 0, BUF_SIZE);

  sockaddr_in client_addr;
  socklen_t client_size = sizeof(client_addr);
  int len = recvfrom(local_sock, req_buf, BUF_SIZE, 0, (sockaddr*)&client_addr,
                     &client_size);

  if (len <= 0) {
    // LOG(2, "Receive invalid request from client.");
    return;
  }

  char ori_url[65];
  memcpy(ori_url, req_buf + sizeof(DNS_header), len);
  char url[65];
  proc_url(ori_url, url);
  LOG(2, "Client query %s\n.", url);

  char ip[16];
  int ret = get_ip(url, ip);
  if (ret == -1) {
    LOG(2, "%s is in blacklist.", url);
  } else if (ret == 0) {
    uint16_t id_client;
    memcpy(&id_client, req_buf, sizeof(uint16_t));  // record request ID

    uint16_t id_server;
    if (regis_id(id_client, id_server, client_addr)) {
      memcpy(req_buf, &id_server, sizeof(uint16_t));
      sendto(remote_sock, req_buf, len, 0, (const sockaddr*)&remote_addr,
             sizeof(remote_addr));
      LOG(2, "Send DNS req %s to root DNS server.n", url);
      // TODO: add multi thread here
    } else {
      LOG(2, "ID pool runs out!");
    }
  } else {
    send_resp(local_sock, client_addr, req_buf, len, url, ip);
  }
}

void proc_ans(char* ans_buf) {
  int qdcount = ntohs((uint16_t) * (ans_buf + 4));
  int ancount = ntohs((uint16_t) * (ans_buf + 6));

  if (ancount > 0) {
    LOG(2, "Reveive %d answer", ancount);
  }

  char* cur_ptr = ans_buf + 12;
  for (int i = 0; i < qdcount; i++) {
    // skip qname
    while (*cur_ptr > 0) {
      cur_ptr += *cur_ptr + 1;
    }
    cur_ptr += sizeof(char);      // skip last 0
    cur_ptr += sizeof(uint16_t);  // skip qtype
    cur_ptr += sizeof(uint16_t);  // skip qclass
  }

  for (int i = 0; i < ancount; i++) {
    if ((uint16_t)*cur_ptr == 0xc000) {
      cur_ptr += sizeof(uint16_t);
    } else {
      char url[65];
      proc_url(cur_ptr, url);
      // skip name
      while (*cur_ptr > 0) {
        cur_ptr += *cur_ptr + 1;
      }

      uint16_t type = ntohs((uint16_t)*cur_ptr);
      cur_ptr += sizeof(uint16_t);

      uint16_t class_ = ntohs((uint16_t)*cur_ptr);
      cur_ptr += sizeof(uint16_t);

      uint16_t ttl_h = ntohs((uint16_t)*cur_ptr);
      cur_ptr += sizeof(uint16_t);

      uint16_t ttl_l = ntohs((uint16_t)*cur_ptr);
      cur_ptr += sizeof(uint16_t);

      uint32_t ttl = ((uint32_t)ttl_h) << sizeof(uint16_t) | ttl_l;

      uint16_t rdlength = ntohs((uint16_t)*cur_ptr);
      cur_ptr += sizeof(uint16_t);

      if (type == uint16_t(1)) {
        uint8_t ip1, ip2, ip3, ip4;
        ip1 = (uint8_t)*cur_ptr++;
        ip2 = (uint8_t)*cur_ptr++;
        ip3 = (uint8_t)*cur_ptr++;
        ip4 = (uint8_t)*cur_ptr++;

        char ip[16];
        memset(ip, 0, sizeof(ip));
        sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        LOG(2, "Answer: %s -> %s", url, ip);

        add_record(url, ip, ttl);
      } else {
        cur_ptr += rdlength;
      }
    }
  }
}

void recv_ans(const int local_sock, const int remote_sock) {
  char ans_buf[BUF_SIZE];
  sockaddr_in server_addr;
  socklen_t server_size = sizeof(server_addr);
  int len = recvfrom(remote_sock, ans_buf, sizeof(ans_buf), 0,
                     (sockaddr*)&server_addr, &server_size);
  if (len <= 0) {
    // LOG(2, "Receive invalid answer from root DNS.");
    return;
  }

  proc_ans(ans_buf);

  uint16_t id_server;
  memcpy(&id_server, ans_buf, sizeof(uint16_t));

  ID_info id_info;
  if (!proj_id(id_server, id_info)) {
    LOG(2, "Cannot project id %d back.\n", id_server);
  }

  memcpy(ans_buf, &(id_info.id_client), sizeof(uint16_t));
  sendto(local_sock, ans_buf, len, 0, (const sockaddr*)&(id_info.client_addr),
         sizeof(id_info.client_addr));

  char ip[16];
}
