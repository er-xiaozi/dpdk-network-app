
#include <rte_kni.h>
#include <rte_ethdev.h>  // 必须包含此头文件以使用 rte_eth_dev_info
#include "globals.h"
#include "network.h"    //print_ethaddr


struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool);