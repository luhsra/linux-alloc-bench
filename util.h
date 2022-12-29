#ifndef __NVALLOC_UTIL__
#define __NVALLOC_UTIL__

#include <linux/atomic.h>
#include <linux/swait.h>
#include <linux/sched.h>

/// PThread-like synchronization barrier
struct c_barrier {
	/// Waitqueue
	struct swait_queue_head wait;
	/// Number of threads
	uint max;
	/// Number of still running threads (wait decrements this)
	atomic_t counter;
	/// Generation, incremented when all threads are woken up
	atomic_t generation;
	/// Name of this barrier
	const char *name;
};

static inline void c_barrier_init(struct c_barrier *self, uint n,
				  const char *name)
{
	init_swait_queue_head(&self->wait);
	self->max = n;
	atomic_set(&self->counter, n);
	atomic_set(&self->generation, 0);
	self->name = name;
}

/// No threads are allowed to wait on this barrier for reinit!
static inline void c_barrier_reinit(struct c_barrier *self, uint n)
{
	int ret;
	preempt_disable();

	BUG_ON(swait_active(&self->wait));

	ret = atomic_cmpxchg(&self->counter, self->max, n);
	BUG_ON(ret != self->max); // no waiting threads!
	self->max = n;

	preempt_enable();
}

static inline void c_barrier_sync(struct c_barrier *self)
{
	int counter;
	preempt_disable();

	counter = atomic_fetch_dec(&self->counter);
	BUG_ON(counter <= 0);
	if (counter == 1) {
		atomic_set(&self->counter, self->max);
		atomic_inc(&self->generation);

		preempt_enable();
		swake_up_all(&self->wait);
	} else {
		int generation = atomic_read(&self->generation);

		preempt_enable();
		// Wait for wakeup
		swait_event_exclusive(self->wait,
				      atomic_read(&self->generation) !=
					      generation);
	}
}

#endif // __NVALLOC_UTIL__
