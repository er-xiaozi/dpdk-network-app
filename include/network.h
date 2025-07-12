#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <rte_ethdev.h>

extern int gDpdkPortId;

void ng_init_port(struct rte_mempool *mbuf_pool);
void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr);

#endif // __NETWORK_H__