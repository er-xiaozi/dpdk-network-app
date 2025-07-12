#ifndef __TCP_APP_H__
#define __TCP_APP_H__

#include <rte_mempool.h>
#include <sys/socket.h> 
#include <rte_tcp.h>   // 添加 DPDK TCP 头文件
#include <rte_ip.h>    // 添加 DPDK IP 头文件
#include "globals.h"

// TCP流管理
struct ng_tcp_stream *ng_tcp_stream_search(uint32_t sip, uint32_t dip, 
                                         uint16_t sport, uint16_t dport);
struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip, uint32_t dip, 
                                         uint16_t sport, uint16_t dport);
 
// POSIX兼容API
//int nsocket(int domain, int type, int protocol);
//int nbind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int nlisten(int sockfd, int backlog);
int naccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t nsend(int sockfd, const void *buf, size_t len, int flags);
ssize_t nrecv(int sockfd, void *buf, size_t len, int flags);
//int nclose(int fd);
 
// TCP处理核心函数
int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
                        uint8_t *srcmac, uint8_t *dstmac, 
                        struct ng_tcp_fragment *fragment);
struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
                          uint8_t *srcmac, uint8_t *dstmac, 
                          struct ng_tcp_fragment *fragment);

 
// 状态处理函数
int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr);
int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen);
int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
 
// 辅助函数
int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen);
int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr);
 
// 服务器启动函数
void launch_tcp_server(struct rte_mempool *mbuf_pool);

#endif // __UDP_APP_H__