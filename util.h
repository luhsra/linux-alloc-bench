#ifndef __LLFREE_UTIL__
#define __LLFREE_UTIL__

#include <linux/jiffies.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/mmzone.h>

// Workaround for older kernel versions
#ifndef CACHELINE_PADDING
#define CACHELINE_PADDING(x) ZONE_PADDING(x)
#endif

/// PThread-like synchronization barrier
struct c_barrier {
	/// Number of still running threads (wait decrements this)
	atomic_t counter;
	/// Number of managed threads
	atomic_t threads;
	/// Cacheline padding -> no false sharing
	CACHELINE_PADDING(_pad);

	/// Completions (one active, one for reinit)
	struct completion comp[2];
	/// The currently active completion
	uint active;
	/// Name of this barrier
	const char *name;
};

static inline void c_barrier_init(struct c_barrier *self, uint n,
				  const char *name)
{
	init_completion(&self->comp[0]);
	init_completion(&self->comp[1]);
	atomic_set(&self->counter, n);
	atomic_set(&self->threads, n);
	self->active = 0;
	self->name = name;
}

/// No threads are allowed to wait on this barrier for reinit!
static inline void c_barrier_reinit(struct c_barrier *self, uint n)
{
	uint last = self->active;
	atomic_set(&self->threads, n);
	atomic_set(&self->counter, n);

	// Wakeup all currently sleeping threads
	self->active = (self->active + 1) % 2;
	reinit_completion(&self->comp[self->active]);

	complete_all(&self->comp[last]);
}

static inline void c_barrier_sync(struct c_barrier *self)
{
	int counter = atomic_fetch_dec(&self->counter);
	BUG_ON(counter <= 0);
	if (counter == 1) {
		uint last = self->active;
		self->active = (self->active + 1) % 2;
		atomic_set(&self->counter, atomic_read(&self->threads));
		reinit_completion(&self->comp[self->active]);

		complete_all(&self->comp[last]);
	} else {
		unsigned long timeout = wait_for_completion_timeout(
			&self->comp[self->active], msecs_to_jiffies(60000));
		if (timeout == 0) {
			pr_info("Barrier timeout: %s\n", self->name);
		}
	}
}

#endif // __LLFREE_UTIL__
