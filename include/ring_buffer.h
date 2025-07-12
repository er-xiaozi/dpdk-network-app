#ifndef __RING_BUFFER_H__
#define __RING_BUFFER_H__

#include <rte_ring.h>

struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};

struct inout_ring *ringInstance(void);
void init_ring_buffer(void);

#endif // __RING_BUFFER_H__