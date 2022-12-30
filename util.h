#ifndef __NVALLOC_UTIL__
#define __NVALLOC_UTIL__

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/mmzone.h>

/// PThread-like synchronization barrier
struct c_barrier {
	/// Number of still running threads (wait decrements this)
	atomic_t counter;
	/// Number of managed threads
	atomic_t threads;
	/// Cacheline padding -> no false sharing
	ZONE_PADDING(_pad);

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
		wait_for_completion(&self->comp[self->active]);
	}
}

#endif // __NVALLOC_UTIL__
