//#ifndef __NG_ARP_H__
//#define __NG_ARP_H__
#pragma once
#include <arpa/inet.h> 
#include <rte_ether.h>
#include <rte_malloc.h>
#include <netinet/in.h>
#include <rte_arp.h>
#include <pthread.h>
#include <rte_spinlock.h> //自旋锁
#include "globals.h"

#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1


struct arp_entry {

	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

	uint8_t type;
	// 

	struct arp_entry *next;
	struct arp_entry *prev;
	
};

struct arp_table {

	struct arp_entry *entries;
	int count;
    //pthread_spinlock_t spinlock;
};



static struct  arp_table *arpt = NULL;

static struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;

}


static uint8_t* ng_get_dst_macaddr(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries;iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}

	return NULL;
}


// 添加手动ARP条目
static int add_static_arp_entry(uint32_t ip, uint8_t *mac) {
    struct arp_table *table = arp_table_instance();
    if (!table) {
        printf("ARP table not initialized\n");
        return -1;
    }

    // 检查是否已存在
    struct arp_entry *iter;
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->ip == ip) {
            printf("ARP entry for %s already exists\n", inet_ntoa((struct in_addr){ip}));
            return 0;
        }
    }

    // 创建新条目
    struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
    if (!entry) {
        printf("Failed to allocate ARP entry\n");
        return -1;
    }

    memset(entry, 0, sizeof(struct arp_entry));
    entry->ip = ip;
    rte_memcpy(entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
    entry->type = 1;  // 标记为静态条目

    LL_ADD(entry, table->entries);
    table->count++;

    printf("Added static ARP entry: IP=%s, MAC=%02X-%02X-%02X-%02X-%02X-%02X\n",
           inet_ntoa((struct in_addr){ip}),
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return 0;
}



int ng_arp_entry_insert(uint32_t ip, uint8_t *mac) ;


struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);


//#endif


