#ifndef __NVALLOC_UTIL__
#define __NVALLOC_UTIL__

#include <linux/atomic.h>
#include <linux/swait.h>
#include <linux/sched.h>

struct c_barrier {
	struct swait_queue_head wait;
	uint max;
	atomic_t counter;
	atomic_t generation;
	const char *name;
};

static inline void c_barrier_init(struct c_barrier *self, uint n,
				  const char *name)
{
	// pr_info("\tbarrier '%s' init %d\n", name, n);
	init_swait_queue_head(&self->wait);
	self->max = n;
	atomic_set(&self->counter, n);
	atomic_set(&self->generation, 0);
	self->name = name;
}

/// No threads are allowed to wait on this barrier for reinit!
static inline void c_barrier_reinit(struct c_barrier *self, uint n)
{
	// pr_info("\tbarrier '%s' reinit %d\n", self->name, n);
	BUG_ON(atomic_read(&self->counter) != self->max ||
	       swait_active(&self->wait));
	self->max = n;
	atomic_set(&self->counter, n);
	atomic_set(&self->generation, 0);
}

static inline void c_barrier_sync(struct c_barrier *self)
{
	int counter = atomic_fetch_dec(&self->counter);
	BUG_ON(counter <= 0);
	if (counter == 1) {
		// pr_info("\tbarrier '%s' wake %d\n", self->name,
		// 	raw_smp_processor_id());
		atomic_set(&self->counter, self->max);
		atomic_inc(&self->generation);
		swake_up_all(&self->wait);
	} else {
		int generation = atomic_read(&self->generation);
		// pr_info("\tbarrier '%s' wait %d\n", self->name,
		// 	raw_smp_processor_id());
		__swait_event(self->wait,
			      atomic_read(&self->generation) != generation);
	}
	// pr_info("\tbarrier '%s' continue %d\n", self->name,
	// 	raw_smp_processor_id());
}

#endif // __NVALLOC_UTIL__
