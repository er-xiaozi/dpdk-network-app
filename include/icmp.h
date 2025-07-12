#ifndef __ICMP_H__
#define __ICMP_H__

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>

uint16_t ng_checksum(const void *data, int count);
int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
                      uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb);
struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
                            uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb);

#endif // __ICMP_H__