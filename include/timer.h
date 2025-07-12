#ifndef __TIMER_H__
#define __TIMER_H__

#include <rte_timer.h>

void init_timer_subsystem(struct rte_mempool *mbuf_pool);
void manage_timers(void);

#endif // __TIMER_H__