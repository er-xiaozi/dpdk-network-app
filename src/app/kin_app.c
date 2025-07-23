#include "kin_app.h"

// ifconfig vEth0 up down
int ng_config_network_if(uint16_t port_id, uint8_t if_up){
    if(!rte_eth_dev_is_valid_port(port_id)){
        return -EINVAL;
    }
    int ret = 0;
    if(if_up){
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else {
        rte_eth_dev_stop(port_id);
    }
    if(ret < 0){
        printf("vEth--->Failed to start port : %d", port_id);
    }
    return 0;
}
/*


struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool){
    struct rte_kni *kni_hanlder = NULL;
    struct rte_kni_conf conf;
    memset(&conf, 0, sizeof(conf));
    snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%d", gDpdkPortId);
    conf.group_id = gDpdkPortId;
    conf.mbuf_size = MAX_PACKET_SIZE;
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)&conf.mac_addr);
    rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);
    print_ethaddr("ng_alloc_kni: ",(struct rte_ether_addr *)conf.mac_addr);

    struct rte_kni_ops ops;
    memset(&ops, 0, sizeof(ops));
    ops.port_id = gDpdkPortId;
    ops.config_network_if = ng_config_network_if;


    // 获取已绑定网卡的信息
    //struct rte_eth_dev_info dev_info;
    //memset(&dev_info, 0, sizeof(dev_info));
    //rte_eth_dev_info_get(gDefaultArpMac, &dev_info);

    kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);
    if(!kni_hanlder){
        rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d", gDpdkPortId);
    }
    return kni_hanlder;
}
*/

struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {

	struct rte_kni *kni_hanlder = NULL;
	
	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", gDpdkPortId);
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = MAX_PACKET_SIZE;
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

	print_ethaddr("ng_alloc_kni: ", (struct rte_ether_addr *)conf.mac_addr);

/*
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	*/


	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = gDpdkPortId;
	ops.config_network_if = ng_config_network_if;
	

	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", gDpdkPortId);
	}
	
	return kni_hanlder;
}
