#include <Windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include "blacklist.h"
#include "local_manager.h"

#pragma comment(lib, "Ws2_32.lib")
#define BUFSIZE 1024  //最大报文缓存大小
#define PORT_NO 53    // 53端口号
//#define DEF_DNS_ADDRESS "10.3.9.4"
#define AMOUNT 16  //最大ID转换表大小
#define ID_EXPIRE_TIME 10
#define CACHE_EXPIRE 10

//设置过期时间。参数是要设置的记录指针和生存时间
void set_ID_expire(IDTransform* record, int ttl) {
  time_t now_time;
  now_time = time(NULL);
  record->expire_time = now_time + ttl;  //过期时间=现在时间+生存时间
}

//检查record是否超时
int is_ID_expired(IDTransform* record) {
  time_t now_time;
  now_time = time(NULL);
  if (record->expire_time > 0 &&
      now_time > record->expire_time)  // expire_time>0说明是有效记录
    return 1;
  return 0;
}

//函数：将请求ID转换为新的ID，并将信息写入ID转换表中
unsigned short RegisterNewID(unsigned short oID, SOCKADDR_IN temp,
                             bool ifdone) {
  int i = 0;
  for (i = 0; i != AMOUNT; ++i) {
    //找到已过期或已完成请求的ID位置覆盖
    if (is_ID_expired(&IDTransTable[i]) == 1 || IDTransTable[i].done == TRUE) {
      IDTransTable[i].oldID = oID;    //本来的id
      IDTransTable[i].client = temp;  //本来的sockaddr
      IDTransTable[i].done = ifdone;  //是否完成了请求
      set_ID_expire(&IDTransTable[i], ID_EXPIRE_TIME);
      ++IDcount;
      if (debug_level >= 1) printf("%d id in id buffer\n", IDcount);
      break;
    }
  }
  if (i == AMOUNT)  //没找到可写的地方
    return 0;
  return (unsigned short)i + 1;  //以表中下标作为新的ID
}

//从报文buf里读取url到dest里。格式类似3www5baidu3com0
void readurl(char* buf, char* dest) {
  int len = strlen(buf);
  int i = 0, j = 0, k = 0;
  while (i < len) {
    if (buf[i] > 0 && buf[i] <= 63)  //如果是个计数
    {
      for (j = buf[i], i++; j > 0;
           j--, i++, k++)  // j是计数是几，k是目标位置下标，i是报文里的下标
        dest[k] = buf[i];
    }

    if (buf[i] != 0)  //如果没结束就在dest里加个'.'
    {
      dest[k] = '.';
      k++;
    }
  }
  dest[k] = '\0';
}

void standard_print(char* buf, int length) {
  unsigned char tage;
  printf("receive len=%d: ", length);
  for (int i = 0; i < length; i++) {
    tage = (unsigned char)buf[i];
    printf("%02x ", tage);
  }
  printf("\n");
}
//从远端DNS接收报文并转发到本机
void receive_from_out() {
  char buf[BUFSIZE], url[65];
  int length = -1;
  int i, j, k;

  length =
      recvfrom(outside_sock, buf, sizeof(buf), 0, (struct sockaddr*)&client2,
               &len_client);  //接受外部DNS报文消息

  if (length > -1) {
    if (debug_level >= 2) standard_print(buf, length);

    unsigned short* pID = (unsigned short*)malloc(
        sizeof(unsigned short));  //以进程ID来作为DNS报文的一个随机标示符
    memcpy(pID, buf, sizeof(unsigned short));
    int id_index = (*pID) - 1;
    free(pID);

    unsigned short oID = IDTransTable[id_index].oldID;  //转换为客户端方向的ID
    memcpy(buf, &oID, sizeof(unsigned short));

    //从ID转换表中获取发出DNS请求者的信息
    --IDcount;
    if (debug_level >= 1) printf("%d id in id buffer\n", IDcount);
    IDTransTable[id_index].done = TRUE;
    client =
        IDTransTable[id_index].client;  //从表中找到此条DNS请求的客户端发送者

    int nquery = ntohs(*((unsigned short*)(buf + 4))),
        nresponse = ntohs(*((unsigned short*)(buf + 6)));  //问题个数；回答个数
    char* p = buf + 12;  //跳过DNS包头的指针
    ip_addr ip;
    int ip1, ip2, ip3, ip4;

    //读取每个问题里的查询url
    for (i = 0; i < nquery; ++i) {
      readurl(p, url);  //这么写url里只会记录最后一个问题的url
      while (*p > 0)    //读取标识符前的计数跳过这个url
        p += (*p) + 1;
      p += 5;  //跳过url后的信息，指向下一个报文
    }

    if (nresponse > 0 && debug_level >= 1) printf("receive outside %s\n", url);
    //分析回复
    //具体参考DNS回复报文格式
    for (j = 0; j < nresponse; ++j) {
      if ((unsigned char)*p == 0xc0)  //是指针就跳过
        p += 2;
      else {
        //根据计数跳过url
        while (*p > 0) p += (*p) + 1;
        ++p;  //指向后面的内容
      }
      unsigned short resp_type = ntohs(*(unsigned short*)p);  //回复类型
      p += 2;
      unsigned short resp_class = ntohs(*(unsigned short*)p);  //回复类
      p += 2;
      unsigned short high = ntohs(*(unsigned short*)p);  //生存时间高位
      p += 2;
      unsigned short low = ntohs(*(unsigned short*)p);  //生存时间低位
      p += 2;
      int ttl = (((int)high) << 16) | low;  //高低位组合成生存时间
      int datalen = ntohs(*(unsigned short*)p);  //后面数据长度
      p += 2;
      if (debug_level >= 2)
        printf("type %d class %d ttl %d\n", resp_type, resp_class, ttl);

      if (resp_type == 1)  //是A类型，回复的是url的ip
      {
        memset(ip.addr, 0, sizeof(ip.addr));
        //读取4个ip部分
        ip1 = (unsigned char)*p++;
        ip2 = (unsigned char)*p++;
        ip3 = (unsigned char)*p++;
        ip4 = (unsigned char)*p++;

        sprintf(ip.addr, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        if (debug_level >= 2) printf("ip %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);

        // 缓存从外部服务器中接受到的域名对应的IP
        add_record(url, ip.addr, CACHE_EXPIRE);
        break;
      } else
        p += datalen;  //直接跳过
    }

    //把buf转发至请求者处
    length =
        sendto(local_sock, buf, length, 0, (SOCKADDR*)&client, sizeof(client));
    // printf("send local %s -> ip %d.%d.%d.%d\n", url, ip1, ip2, ip3, ip4);
  }
}

//从本机读取DNS查询，从缓存读取或发送到外部DNS服务器查询
void receive_from_local() {
  char buf[BUFSIZE], url[65];
  memset(buf, 0, BUFSIZE);
  int length = -1;
  length = recvfrom(local_sock, buf, sizeof buf, 0, (struct sockaddr*)&client,
                    &len_client);  //接受本地dns请求报文
  if (length > 0) {
    char ori_url[65];
    // printf("Recieve %d bytes\n",len);
    memcpy(ori_url, &(buf[sizeof(DNS_HDR)]),
           length);         //获取请求报文中的域名表示
    readurl(ori_url, url);  //获取报文中域名
    if (debug_level >= 1) printf("local query %s\n", url);

    ip_addr ip = get_ip(url);  //从缓存中查找该域名对应的IP
    if (ip.addr[0] == 'n' ||
        ip.addr[0] == 'e')  //在缓存中未找到对应的IP或者该域名对应的IP已经过期
    {
      // printf("%s not in cache or expired\n", url);
      unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
      memcpy(pID, buf, sizeof(unsigned short));  //记录ID
      unsigned short nID =
          RegisterNewID(*pID, client, FALSE);  //储存ID和该发送方的地址client
      if (nID == 0) {
        if (debug_level >= 1) puts("Buffer full.");
      } else {
        if (debug_level >= 1) printf("send outside %s\n", url);
        memcpy(buf, &nID, sizeof(unsigned short));
        length = sendto(outside_sock, buf, length, 0,
                        (struct sockaddr*)&outside_name,
                        sizeof(outside_name));  //将该请求发送给外部服务器
      }
      free(pID);
    } else if (ip.addr[0] == 'b')  //查询的url或ip在黑名单里
    {
      //////////////////////////////////////////////
      if (debug_level >= 1) printf("%s in blacklist\n", url);
    } else {
      char sendbuf[BUFSIZE];
      if (debug_level >= 1) printf("cache read %s -> %s\n", url, ip.addr);

      memcpy(sendbuf, buf, length);  //拷贝请求报文
      unsigned short a = htons(0x8180);
      memcpy(&sendbuf[2], &a, sizeof(unsigned short));  //修改标志域

      if (strcmp(ip.addr, "0.0.0.0") == 0)  //判断是否需要屏蔽该域名的回答
        a = htons(0x0000);                  //屏蔽功能：将回答数置为0
      else
        a = htons(0x0001);  //服务器功能：将回答数置为1

      memcpy(&sendbuf[6], &a, sizeof(unsigned short));

      int curLen = 0;
      char answer[16];
      unsigned short Name = htons(0xc00c);  //域名指针（偏移量）
      memcpy(answer, &Name, sizeof(unsigned short));
      curLen += sizeof(unsigned short);

      unsigned short TypeA = htons(0x0001);  //类型
      memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
      curLen += sizeof(unsigned short);

      unsigned short ClassA = htons(0x0001);  //查询类
      memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
      curLen += sizeof(unsigned short);

      unsigned long timeLive = htonl(0x7b);  //生存时间
      memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
      curLen += sizeof(unsigned long);

      unsigned short IPLen = htons(0x0004);  //资源数据长度
      memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
      curLen += sizeof(unsigned short);

      unsigned long IP = (unsigned long)inet_addr(ip.addr);  //资源数据即IP
      memcpy(answer + curLen, &IP, sizeof(unsigned long));
      curLen += sizeof(unsigned long);
      curLen += length;
      memcpy(sendbuf + length, answer, sizeof(answer));
      length = sendto(local_sock, sendbuf, curLen, 0, (SOCKADDR*)&client,
                      sizeof(client));

      if (length < 0) perror("recv outside len < 0");

      char* p;
      p = sendbuf + length - 4;
      if (debug_level >= 1)
        printf("send local %s -> %u.%u.%u.%u\n", url, (unsigned char)*p,
               (unsigned char)*(p + 1), (unsigned char)*(p + 2),
               (unsigned char)*(p + 3));
    }
  }
}

//根据提供的参数设置打印调试信息级别和设置外部dns服务器地址
void proc_args(int argc, char* argv[]) {
  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] == '-') {
      if (argv[i][1] == 'd' && argv[i][2] == 'd')
        debug_level = 2;
      else
        debug_level = 1;
    } else {
      printf("set dns server:%s\n", argv[i]);
      strcpy(DNS_ADDRESS, argv[i]);
    }
  }

  printf("debug level %d\n", debug_level);
}

int main(int argc, char* argv[]) {
  proc_args(argc, argv);

  //初始化ID转换表
  for (int i = 0; i < AMOUNT; i++) {
    IDTransTable[i].oldID = 0;
    IDTransTable[i].done = TRUE;
    IDTransTable[i].expire_time = 0;
    memset(&(IDTransTable[i].client), 0, sizeof(SOCKADDR_IN));
  }

  WSAStartup(MAKEWORD(2, 2), &wsaData);           //初始化Winsock服务
  local_sock = socket(AF_INET, SOCK_DGRAM, 0);    //创建本地套接字
  outside_sock = socket(AF_INET, SOCK_DGRAM, 0);  //创建外部套接字

  int unblock = 1;
  ioctlsocket(outside_sock, FIONBIO,
              (u_long FAR*)&unblock);  //将外部套街口设置为非阻塞
  ioctlsocket(local_sock, FIONBIO,
              (u_long FAR*)&unblock);  //将本地套街口设置为非阻塞
  if (local_sock < 0) {
    if (debug_level >= 1) perror("create socket");
    exit(1);
  }

  local_name.sin_family = AF_INET;  // Address family AF_INET代表TCP/IP协议族
  local_name.sin_addr.s_addr = INADDR_ANY;  //本地任意 address
  local_name.sin_port = htons(PORT_NO);     // Port number.DNS is 53

  outside_name.sin_family = AF_INET;                      // Address family
  outside_name.sin_addr.s_addr = inet_addr(DNS_ADDRESS);  //外部DNS address
  outside_name.sin_port = htons(PORT_NO);                 // Port number

  int reuse = 1;
  setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse,
             sizeof(reuse));  //设置套接字的选项,避免出现本地端口被占用情况

  if (bind(local_sock, (struct sockaddr*)&local_name, sizeof(local_name)) <
      0)  //绑定该套接字到53端口
  {
    if (debug_level >= 1) perror("binding socket");
    exit(1);
  }
  len_client = sizeof client;

  read_pre_cache();  //读取cache文件

  for (;;) {
    receive_from_out();
    receive_from_local();
  }
}
