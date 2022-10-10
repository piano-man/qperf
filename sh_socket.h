#pragma once
#include <runtime/poll.h>
#include <runtime/tcp.h>
#include <runtime/udp.h>


udpconn_t *sh_socket() {
  udpconn_t *c;
  struct netaddr localAddr;
  localAddr.ip = 0;
  localAddr.port =  0;
  int ret = udp_listen(localAddr, &c);
  if (ret) return NULL;
  return c;
}




