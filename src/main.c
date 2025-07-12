#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <stdio.h>
#include <arpa/inet.h>

#include "config.h"
#include "network.h"
#include "arp.h"
#include "icmp.h"
#include "udp_app.h"
#include "tcp_app.h"
#include "pkt_process.h"
#include "ring_buffer.h"
#include "timer.h"
#include "globals.h"


int main(int argc, char *argv[]) {
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
                                                          0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ng_init_port(mbuf_pool);
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

    // 初始化各模块
    init_ring_buffer();
    init_timer_subsystem(mbuf_pool);
    
    unsigned lcore_id = rte_lcore_id();
    printf("main thread lcore id : %d \n", lcore_id);
    // 启动处理线程
    launch_processing_thread(mbuf_pool);
    
    // 启动应用线程
    launch_udp_server(mbuf_pool);
    launch_tcp_server(mbuf_pool);

    while (1) {
        // 主循环处理收发包
        process_packets(mbuf_pool);
        
        // 定时器处理
        manage_timers();
    }
}