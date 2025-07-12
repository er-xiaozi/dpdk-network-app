#ifndef __UDP_APP_H__
#define __UDP_APP_H__

#include <rte_mempool.h>
#include <sys/socket.h> 

int nsocket(int domain, int type, int protocol);
int nbind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t nrecvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t nsendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen);
int nclose(int fd);

int ng_encode_udp_apppkt(
    uint8_t *msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport,
    uint8_t *srcmac, uint8_t *dstmac,
    unsigned char *data, uint16_t total_len
);
void launch_udp_server(struct rte_mempool *mbuf_pool);
int udp_server_entry(void *arg); 

#endif // __UDP_APP_H__