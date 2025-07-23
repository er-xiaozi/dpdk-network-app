#ifndef __PKT_PROCESS_H__
#define __PKT_PROCESS_H__

#include <rte_mempool.h>
#include <rte_kni.h>
#include "config.h"
#include "globals.h"


void launch_processing_thread(struct rte_mempool *mbuf_pool);
void process_packets(struct rte_mempool *mbuf_pool);
int udp_process(struct rte_mbuf *udpmbuf);
int ng_tcp_process(struct rte_mbuf *tcpmbuf);
int udp_out(struct rte_mempool *mbuf_pool);
int ng_tcp_out(struct rte_mempool *mbuf_pool);
struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length);

#endif // __PKT_PROCESS_H__