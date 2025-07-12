#include "config.h"
#include "pkt_process.h"
#include "arp.h"
#include "icmp.h"
#include "udp_app.h"
#include "tcp_app.h"
#include "ring_buffer.h"
#include <rte_ethdev.h>
#include <arpa/inet.h>

#include "globals.h"


static int pkt_process(void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
		
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

#if ENABLE_ARP

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {

				struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
					struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

				/*
				struct in_addr addr;
				addr.s_addr = ahdr->arp_data.arp_tip;
				printf("arp ---> src: %s ", inet_ntoa(addr));

				addr.s_addr = gLocalIp;
				printf(" local: %s \n", inet_ntoa(addr));
				*/
				
				if (ahdr->arp_data.arp_tip == gLocalIp) {

					if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {

						//printf("arp --> request\n");

						struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, 
							ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

						//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
						//rte_pktmbuf_free(arpbuf);

						rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);

					} else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {

						//printf("arp --> reply\n");

						struct arp_table *table = arp_table_instance();

						uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
						if (hwaddr == NULL) {

							struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
							if (entry) {
								memset(entry, 0, sizeof(struct arp_entry));

								entry->ip = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								entry->type = 0;
								
								LL_ADD(entry, table->entries);
								table->count ++;
							}

						}
#if 0 //ENABLE_DEBUG
						struct arp_entry *iter;
						for (iter = table->entries; iter != NULL; iter = iter->next) {
					
							struct in_addr addr;
							addr.s_addr = iter->ip;

							print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
								
							printf(" ip: %s \n", inet_ntoa(addr));
					
						}
#endif
						rte_pktmbuf_free(mbufs[i]);
					}
				
					continue;
				} 
			}
#endif

			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				udp_process(mbufs[i]);
				
			}

#if ENABLE_TCP_APP

			if (iphdr->next_proto_id == IPPROTO_TCP) {
				printf("ng_tcp_process\n");
				ng_tcp_process(mbufs[i]);
				
			}

#endif

#if ENABLE_ICMP

			if (iphdr->next_proto_id == IPPROTO_ICMP) {

				struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

				
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("icmp ---> src: %s ", inet_ntoa(addr));

				
				if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

					addr.s_addr = iphdr->dst_addr;
					printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
				

					struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
						iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

					//rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
					//rte_pktmbuf_free(txbuf);
					rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1, NULL);

					rte_pktmbuf_free(mbufs[i]);
				}				

			}
#endif			
		}

#if ENABLE_UDP_APP

		udp_out(mbuf_pool);

#endif


#if ENABLE_TCP_APP

		ng_tcp_out(mbuf_pool);

#endif

	}

	return 0;
}


void launch_processing_thread(struct rte_mempool *mbuf_pool) {
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	printf("processing thresd lcore id : %d \n", lcore_id);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);
}

void process_packets(struct rte_mempool *mbuf_pool) {
    struct inout_ring *ring = ringInstance();
    
    // rx
    struct rte_mbuf *rx[BURST_SIZE];
    unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
    if (num_recvd > BURST_SIZE) {
        rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
    } else if (num_recvd > 0) {
        rte_ring_sp_enqueue_burst(ring->in, (void **)rx, num_recvd, NULL);
    }

    // tx
    struct rte_mbuf *tx[BURST_SIZE];
    unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
    if (nb_tx > 0) {
        rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

        unsigned i = 0;
        for (i = 0; i < nb_tx; i++) {
            rte_pktmbuf_free(tx[i]);
        }
    }
}




int udp_process(struct rte_mbuf *udpmbuf) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	
	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
		// 打印 lhost 链表中的所有 host 信息
		struct localhost *iter;
		for (iter = lhost; iter != NULL; iter = iter->next) {
			struct in_addr addr;
			addr.s_addr = iter->localip;
			printf("lhost entry: IP=%s, Port=%d, Proto=%d\n", 
				inet_ntoa(addr), ntohs(iter->localport), iter->protocol);
		}
		rte_pktmbuf_free(udpmbuf);
		printf("host not found\n");
		return -3;
	} 

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}

	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;

	
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len);

	ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
	if (ol->data == NULL) {

		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);

		return -2;

	}
	rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

	rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);

	return 0;
}




int ng_tcp_process(struct rte_mbuf *tcpmbuf) {
	//printf("tcp proccess \n");

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	

	// tcphdr, rte_ipv4_udptcp_cksum
	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	
#if 1 //
	if (cksum != tcpcksum) {
		printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
		return -1;
	}
#endif

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
		tcphdr->src_port, tcphdr->dst_port);
	if (stream == NULL) { 
		printf("TCP proccess :stream == NULL\n");
		return -2;
	}

	switch (stream->status) {

		case NG_TCP_STATUS_CLOSED: //client 
			break;
			
		case NG_TCP_STATUS_LISTEN: // server
			ng_tcp_handle_listen(stream, tcphdr, iphdr);
			printf("TCP proccess :NG_TCP_STATUS_LISTEN\n");
			break;

		case NG_TCP_STATUS_SYN_RCVD: // server
			ng_tcp_handle_syn_rcvd(stream, tcphdr);
			printf("TCP proccess :NG_TCP_STATUS_SYN_RCVD\n");
			break;

		case NG_TCP_STATUS_SYN_SENT: // client
			break;

		case NG_TCP_STATUS_ESTABLISHED: { // server | client

			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			
			ng_tcp_handle_established(stream, tcphdr, tcplen);
			
			break;
		}
		case NG_TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case NG_TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case NG_TCP_STATUS_CLOSING: // ~client
			break;
			
		case NG_TCP_STATUS_TIME_WAIT: // ~client
			break;

		case NG_TCP_STATUS_CLOSE_WAIT: // ~server
			ng_tcp_handle_close_wait(stream, tcphdr);
			break;
			
		case NG_TCP_STATUS_LAST_ACK:  // ~server
			ng_tcp_handle_last_ack(stream, tcphdr);
			break;

	}

	return 0;
}




// offload --> mbuf
int udp_out(struct rte_mempool *mbuf_pool) {

	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {

		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));

		 // 添加静态ARP条目------------------------------------------
    	uint8_t target_mac[RTE_ETHER_ADDR_LEN] = {0x00, 0x50, 0x56, 0xC0, 0x00, 0x08};
    	uint32_t target_ip = MAKE_IPV4_ADDR(192, 168, 141, 1);
    	add_static_arp_entry(target_ip, target_mac);
			
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {

			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				ol->sip, ol->dip);

			struct inout_ring *ring = ringInstance();
			printf("send arppkt \n");
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(host->sndbuf, ol);
			
		} else {

			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
				host->localmac, dstmac, ol->data, ol->length);

			
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);

		}
		

	}

	return 0;
}



// struct localhost , struct tcp_stream

int ng_tcp_out(struct rte_mempool *mbuf_pool) {

	struct ng_tcp_table *table = tcpInstance();
	
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		if (stream->sndbuf == NULL) continue; // listener

		struct ng_tcp_fragment *fragment = NULL;		
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;

		 // 添加静态ARP条目------------------------------------------
    	uint8_t target_mac[RTE_ETHER_ADDR_LEN] = {0x00, 0x50, 0x56, 0xC0, 0x00, 0x08};
    	uint32_t target_ip = MAKE_IPV4_ADDR(192, 168, 141, 1);
    	add_static_arp_entry(target_ip, target_mac);

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {

			printf("ng_tcp_out:ng_send_arp\n");
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				stream->dip, stream->sip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(stream->sndbuf, fragment);

		} else {

			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

			if (fragment->data != NULL)
				rte_free(fragment->data);
			
			rte_free(fragment);
		}

	}

	return 0;
}


struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
		data, total_len);

	return mbuf;

}