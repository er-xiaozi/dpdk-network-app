#include "globals.h"
#include "ring_buffer.h"
#include <string.h> // for memset

// 全局变量定义
#if ENABLE_SEND
uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 0, 115);
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
#endif

#if ENABLE_ARP_REPLY
uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#endif

uint8_t fd_table[MAX_FD_COUNT / 8] = {0}; 
int gDpdkPortId = 0;
unsigned lcore_id = 0; 
// 静态变量定义
struct ng_tcp_table *tInst = NULL;

struct localhost *lhost = NULL;

// 函数实现
struct ng_tcp_table *tcpInstance(void) {
    if (tInst == NULL) {
        tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
        memset(tInst, 0, sizeof(struct ng_tcp_table));
    }
    return tInst;
}
struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            return host;
        }
    }
    return NULL;
}


void* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}
	}
#if ENABLE_TCP_APP
	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}
#endif	
	return NULL;
}

int set_fd_frombitmap(int fd) {
	if (fd >= MAX_FD_COUNT) return -1;
	fd_table[fd/8] &= ~(0x1 << (fd % 8));
	return 0;
}

int get_fd_frombitmap(void) {
    int fd = DEFAULT_FD_NUM;
    for (; fd < MAX_FD_COUNT; fd++) {
        if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
            fd_table[fd/8] |= (0x1 << (fd % 8));  // 标记为已使用
            return fd;
        }
    }
    return -1;  // 无可用fd
}


struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {
	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for (apt = table->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}
	return NULL;
}
