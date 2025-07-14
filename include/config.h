#ifndef __CONFIG_H1__
#define __CONFIG_H1__

#include <rte_ether.h>

#define ENABLE_SEND 1
#define ENABLE_ARP 1
#define ENABLE_ICMP 1
#define ENABLE_ARP_REPLY 1
#define ENABLE_DEBUG 1
#define ENABLE_TIMER 1
#define ENABLE_RINGBUFFER 1
#define ENABLE_MULTHREAD 1
#define ENABLE_UDP_APP 1
#define ENABLE_TCP_APP 1
#define ENABLE_KNI_APP 1

#define NUM_MBUFS (4096 - 1)
#define BURST_SIZE 32
#define RING_SIZE 1024
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))

#if ENABLE_SEND
extern uint32_t gLocalIp;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
#endif

#if ENABLE_ARP_REPLY
extern uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];
#endif


#endif // __CONFIG_H__