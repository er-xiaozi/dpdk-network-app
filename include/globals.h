#ifndef GLOBALS_H
#define GLOBALS_H

#include "config.h"
#include <stdint.h>
#include <pthread.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_lcore.h>


// 全局配置常量
#define UDP_APP_RECV_BUFFER_SIZE 128
#define TCP_OPTION_LENGTH        10
#define TCP_MAX_SEQ              4294967295
#define TCP_INITIAL_WINDOW       14600
#define MAX_FD_COUNT	1024

#define DEFAULT_FD_NUM	3


// 链表操作宏
#define LL_ADD(item, list) do { \
    item->prev = NULL; \
    item->next = list; \
    if (list != NULL) list->prev = item; \
    list = item; \
} while (0)

#define LL_REMOVE(item, list) do { \
    if (item->prev != NULL) item->prev->next = item->next; \
    if (item->next != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL; \
} while (0)

// 全局变量声明（extern）
#if ENABLE_SEND
extern uint32_t gLocalIp;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
#endif

#if ENABLE_ARP_REPLY
extern uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];
#endif

extern uint8_t fd_table[]; 
extern struct inout_ring *rInst ;
extern struct ng_tcp_table *tInst;
extern int gDpdkPortId;
extern unsigned lcore_id;

// 数据结构定义
struct offload {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    int protocol;
    unsigned char *data;
    uint16_t length;
};

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;
    uint8_t protocol;
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;
    struct localhost *prev;
    struct localhost *next;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

typedef enum _NG_TCP_STATUS {
    NG_TCP_STATUS_CLOSED = 0,
    NG_TCP_STATUS_LISTEN,
    NG_TCP_STATUS_SYN_RCVD,
    NG_TCP_STATUS_SYN_SENT,
    NG_TCP_STATUS_ESTABLISHED,
    NG_TCP_STATUS_FIN_WAIT_1,
    NG_TCP_STATUS_FIN_WAIT_2,
    NG_TCP_STATUS_CLOSING,
    NG_TCP_STATUS_TIME_WAIT,
    NG_TCP_STATUS_CLOSE_WAIT,
    NG_TCP_STATUS_LAST_ACK
} NG_TCP_STATUS;

struct ng_tcp_stream {
    int fd;
    uint32_t dip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t dport;
    uint8_t protocol;
    uint16_t sport;
    uint32_t sip;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    NG_TCP_STATUS status;
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;
    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct ng_tcp_table {
    int count;
    struct ng_tcp_stream *tcb_set;
};

struct ng_tcp_fragment {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t hdrlen_off;
    uint8_t tcp_flags;
    uint16_t windows;
    uint16_t cksum;
    uint16_t tcp_urp;
    int optlen;
    uint32_t option[TCP_OPTION_LENGTH];
    unsigned char *data;
    uint32_t length;
};

// 函数声明
//struct inout_ring *ringInstance(void);
struct ng_tcp_table *tcpInstance(void);
struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto);
void* get_hostinfo_fromfd(int sockfd);
int set_fd_frombitmap(int fd);
int get_fd_frombitmap(void);
struct ng_tcp_stream *get_accept_tcb(uint16_t dport);

extern struct localhost *lhost;  // 全局主机链表头


#endif // GLOBALS_H