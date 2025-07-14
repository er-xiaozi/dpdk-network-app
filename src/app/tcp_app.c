#include "config.h"
#include "tcp_app.h"
#include "network.h"
#include "arp.h"
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_tcp.h>   // 添加 DPDK TCP 头文件
#include <rte_ip.h>    // 添加 DPDK IP 头文件
#include <pthread.h>
#include "globals.h"
#include "udp_app.h"
#include "ring_buffer.h"

// 原有TCP相关函数实现
// ng_encode_tcp_apppkt, ng_tcp_pkt,  ng_tcp_stream_search, 
// ng_tcp_stream_create, ng_tcp_handle_listen, ng_tcp_handle_syn_rcvd, ng_tcp_handle_established等


struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto
	struct ng_tcp_table *table = tcpInstance();
	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) { // established
		if (iter->sip == sip && iter->dip == dip && 
			iter->sport == sport && iter->dport == dport) {
			return iter;
		}
	}
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {
		if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) { // listen
			return iter;
		}
	}
	return NULL;
}

struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	// tcp --> status
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) return NULL;

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1; //unused

	// 
	stream->status = NG_TCP_STATUS_LISTEN;

	printf("ng_tcp_stream_create\n");
	//
	stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
	stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);
	
	// seq num
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	//struct ng_tcp_table *table = tcpInstance();
	//LL_ADD(stream, table->tcb_set);

	return stream;
}

int nlisten(int sockfd, __attribute__((unused)) int backlog) { //

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}

	return 0;
}


int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *apt = NULL;

		pthread_mutex_lock(&stream->mutex);
		while((apt = get_accept_tcb(stream->dport)) == NULL) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		} 
		pthread_mutex_unlock(&stream->mutex);

		apt->fd = get_fd_frombitmap();

		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

		return apt->fd;
	}

	return -1;
}


ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {

	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));

		fragment->dport = stream->sport;
		fragment->sport = stream->dport;

		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;

		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;


		fragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len+1);

		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;

		// int nb_snd = 0;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);

	}

	
	return length;
}

// recv 32
// recv 
ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	
	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;

		printf("rte_ring_mc_dequeue before\n");
		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		printf("rte_ring_mc_dequeue after\n");

		if (fragment->length > len) {

			rte_memcpy(buf, fragment->data, len);

			uint32_t i = 0;
			for(i = 0;i < fragment->length-len;i ++) {
				fragment->data[i] = fragment->data[len+i];
			}
			fragment->length = fragment->length-len;
			length = fragment->length;

			rte_ring_mp_enqueue(stream->rcvbuf, fragment);

		} else if (fragment->length == 0) {

			rte_free(fragment);
			return 0;
		
		} else {

			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;

			rte_free(fragment->data);
			fragment->data = NULL;

			rte_free(fragment);
			
		}

	}

	return length;
}



int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  {
		//stream --> listenfd
		if (stream->status == NG_TCP_STATUS_LISTEN) {

			struct ng_tcp_table *table = tcpInstance();
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
			LL_ADD(syn, table->tcb_set);


			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			struct in_addr addr;
			addr.s_addr = syn->sip;
			printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(tcphdr->src_port));

			
			addr.s_addr = syn->dip;
			printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

			fragment->seqnum = syn->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			syn->rcv_nxt = fragment->acknum;
			
			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			
			fragment->data = NULL;
			fragment->length = 0;

			rte_ring_mp_enqueue(syn->sndbuf, fragment);
			
			syn->status = NG_TCP_STATUS_SYN_RCVD;
		}

	}

	return 0;
}


int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {

			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (acknum == stream->snd_nxt + 1) {
				// 
			}

			stream->status = NG_TCP_STATUS_ESTABLISHED;

			// accept
			struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
			if (listener == NULL) {
				rte_exit(EXIT_FAILURE, "ng_tcp_stream_search failed\n");
			}

			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
			

		}

	}
	return 0;
}

int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	// recv buffer
	struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (rfragment == NULL) return -1;
	memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

	rfragment->dport = ntohs(tcphdr->dst_port);
	rfragment->sport = ntohs(tcphdr->src_port);

	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payloadlen = tcplen - hdrlen * 4; //
	if (payloadlen > 0) {
		
		uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

		rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
		if (rfragment->data == NULL) {
			rte_free(rfragment);
			return -1;
		}
		memset(rfragment->data, 0, payloadlen+1);

		rte_memcpy(rfragment->data, payload, payloadlen);
		rfragment->length = payloadlen;

	} else if (payloadlen == 0) {

		rfragment->length = 0;
		rfragment->data = NULL;

	}
	rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (ackfrag == NULL) return -1;
	memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

	ackfrag->dport = tcphdr->src_port;
	ackfrag->sport = tcphdr->dst_port;

	// remote
	
	printf("ng_tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
	

	ackfrag->acknum = stream->rcv_nxt;
	ackfrag->seqnum = stream->snd_nxt;

	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->windows = TCP_INITIAL_WINDOW;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->data = NULL;
	ackfrag->length = 0;
	
	rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

	return 0;
}

int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	} 
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) { //

		// recv buffer
#if 0
		struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (rfragment == NULL) return -1;
		memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

		rfragment->dport = ntohs(tcphdr->dst_port);
		rfragment->sport = ntohs(tcphdr->src_port);

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		if (payloadlen > 0) {
			
			uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

			rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
			if (rfragment->data == NULL) {
				rte_free(rfragment);
				return -1;
			}
			memset(rfragment->data, 0, payloadlen+1);

			rte_memcpy(rfragment->data, payload, payloadlen);
			rfragment->length = payloadlen;

			printf("tcp : %s\n", rfragment->data);
		}
		rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
#else

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

#endif


#if 0
		// ack pkt
		struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (ackfrag == NULL) return -1;
		memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

		ackfrag->dport = tcphdr->src_port;
		ackfrag->sport = tcphdr->dst_port;

		// remote
		
		printf("ng_tcp_handle_established: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
		
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		// local 
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		//ackfrag->

		ackfrag->acknum = stream->rcv_nxt;
		ackfrag->seqnum = stream->snd_nxt;

		ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
		ackfrag->windows = TCP_INITIAL_WINDOW;
		ackfrag->hdrlen_off = 0x50;
		ackfrag->data = NULL;
		ackfrag->length = 0;
		
		rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

#else

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);
		
#endif
		// echo pkt
#if 0
		struct ng_tcp_fragment *echofrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (echofrag == NULL) return -1;
		memset(echofrag, 0, sizeof(struct ng_tcp_fragment));

		echofrag->dport = tcphdr->src_port;
		echofrag->sport = tcphdr->dst_port;

		echofrag->acknum = stream->rcv_nxt;
		echofrag->seqnum = stream->snd_nxt;

		echofrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		echofrag->windows = TCP_INITIAL_WINDOW;
		echofrag->hdrlen_off = 0x50;

		uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

		echofrag->data = rte_malloc("unsigned char *", payloadlen, 0);
		if (echofrag->data == NULL) {
			rte_free(echofrag);
			return -1;
		}
		memset(echofrag->data, 0, payloadlen);

		rte_memcpy(echofrag->data, payload, payloadlen);
		echofrag->length = payloadlen;

		rte_ring_mp_enqueue(stream->sndbuf, echofrag);
#endif

	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

		stream->status = NG_TCP_STATUS_CLOSE_WAIT;

#if 0

		struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (rfragment == NULL) return -1;
		memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

		rfragment->dport = ntohs(tcphdr->dst_port);
		rfragment->sport = ntohs(tcphdr->src_port);

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;

		rfragment->length = 0;
		rfragment->data = NULL;
		
		rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
		
#else

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

#endif
		// send ack ptk
		stream->rcv_nxt = stream->rcv_nxt + 1;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);

	}

	return 0;
}

int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) { //

		if (stream->status == NG_TCP_STATUS_CLOSE_WAIT) {

			

		}

	}

	
	return 0;

}

int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_LAST_ACK) {

			stream->status = NG_TCP_STATUS_CLOSED;

			printf("ng_tcp_handle_last_ack\n");
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);

		}

	}

	return 0;
}



int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}


struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// mempool --> mbuf

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

	return mbuf;

}


#define BUFFER_SIZE	1024
// hook
static int tcp_server_entry(__attribute__((unused))  void *arg)  {

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	nlisten(listenfd, 10);

	while (1) {
		
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		char buff[BUFFER_SIZE] = {0};
		while (1) {

			int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
			if (n > 0) {
				printf("recv: %s\n", buff);
				nsend(connfd, buff, n, 0);

			} else if (n == 0) {

				nclose(connfd);
				break;
			} else { //nonblock

			}
		}

	}
	nclose(listenfd);
	

}



void launch_tcp_server(struct rte_mempool *mbuf_pool) {
#if ENABLE_TCP_APP
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	printf("TCP Server thread lcore id %d :\n", lcore_id);
    rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);
#endif
}