// Minimal lwIP type stub for host-side tests: wireguard.h stores ip_addr_t by
// value but wireguard.c never dereferences its internals.
#ifndef FAKE_LWIP_IP_ADDR_H
#define FAKE_LWIP_IP_ADDR_H
#include "lwip/arch.h"
typedef struct ip4_addr { u32_t addr; } ip4_addr_t;
typedef struct ip_addr { u32_t addr; } ip_addr_t;
#endif
