#include "config.h"
#include "ring_buffer.h"
#include <rte_ring.h>
#include <rte_malloc.h>

static struct inout_ring *rInst = NULL;

struct inout_ring *ringInstance(void) {
    if (rInst == NULL) {
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }
    return rInst;
}

void init_ring_buffer(void) {
    struct inout_ring *ring = ringInstance();
    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if (ring->in == NULL) {
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    if (ring->out == NULL) {
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
}