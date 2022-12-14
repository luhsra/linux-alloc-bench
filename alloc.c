#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#ifdef CONFIG_NVALLOC
#include <nvalloc.h>
#endif

#include "nanorand.h"
#include "util.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel Alloc Benchmark");
MODULE_AUTHOR("Lars Wrenger");

static atomic64_t curr_threads;
static u64 max_threads;

static DEFINE_PER_CPU(struct task_struct *, per_cpu_tasks);

struct c_barrier outer_barrier;
struct c_barrier inner_barrier;

enum alloc_bench {
	/// Allocate a large number of pages and free them in sequential order
	BENCH_BULK,
	/// Reallocate a single page and free it immediately over and over
	BENCH_REPEAT,
	/// Allocate a large number of pages and free them in random order
	BENCH_RAND,
	/// Allocate all of the memory of a zone and free half of it randomly.
	/// Then reallocate and measure fragmentation.
	BENCH_FRAG,
};

/// Benchmark args
struct alloc_config {
	/// Benchmark (see enum alloc_bench)
	enum alloc_bench bench;
	union {
		// bulk, repeat, rand
		struct {
			/// Array of thread counts
			u64 *threads;
			/// Len of threads array
			u64 threads_len;
			/// Number of allocations per thread
			u64 allocs;
		};
		// frag
		struct {
			/// NUMA node
			u64 node;
			/// Percentage to be reallocated per iteration
			u64 realloc_percentage;
		};
	};
	/// Number of repetitions
	u64 iterations;
	/// Size of the allocations
	u64 order;
};

static struct alloc_config alloc_config = { .bench = 0,
					    { .threads = NULL,
					      .threads_len = 0 },
					    .iterations = 0,
					    .allocs = 0,
					    .order = 0 };

static bool running = false;

struct thread_perf {
	u64 get;
	u64 put;
};
static DEFINE_PER_CPU(struct thread_perf, thread_perf);
/// Allocated pages per task
struct page ***allocated_pages = NULL;

struct perf {
	u64 get_min;
	u64 get_avg;
	u64 get_max;
	u64 put_min;
	u64 put_avg;
	u64 put_max;
	u16 *frag_buf;
};
static struct perf *measurements = NULL;

__maybe_unused static u64 cycles(void)
{
	u32 lo, hi;
	asm volatile("rdtsc" : "=eax"(lo), "=edx"(hi) :);
	return ((u64)lo) | ((u64)hi << 32);
};

__always_inline static gfp_t gfp_flags(int order)
{
	// return GFP_USER | (order ? __GFP_COMP : 0);
	return GFP_USER;
}

/// Alloc a number of pages at once and free them afterwards
static void bulk()
{
	u64 j;
	u64 timer;
	struct thread_perf *t_perf = this_cpu_ptr(&thread_perf);

	struct page **pages =
		vmalloc_array(alloc_config.allocs, sizeof(struct page *));
	BUG_ON(pages == NULL);

	// complete initialization
	pr_info("start bulk");
	c_barrier_sync(&inner_barrier);

	timer = ktime_get_ns();
	for (j = 0; j < alloc_config.allocs; j++) {
		pages[j] = alloc_pages(gfp_flags(alloc_config.order),
				       alloc_config.order);
		BUG_ON(pages[j] == NULL);
	}
	t_perf->get = (ktime_get_ns() - timer) / alloc_config.allocs;

	c_barrier_sync(&inner_barrier);

	timer = ktime_get_ns();
	for (j = 0; j < alloc_config.allocs; j++) {
		__free_pages(pages[j], alloc_config.order);
	}
	t_perf->put = (ktime_get_ns() - timer) / alloc_config.allocs;
	vfree(pages);
}

/// Alloc and free the same page
static void repeat()
{
	u64 j;
	u64 timer;

	struct thread_perf *t_perf = this_cpu_ptr(&thread_perf);

	struct page *page;

	// complete initialization
	c_barrier_sync(&inner_barrier);

	timer = ktime_get_ns();
	for (j = 0; j < alloc_config.allocs; j++) {
		page = alloc_pages(gfp_flags(alloc_config.order),
				   alloc_config.order);
		BUG_ON(page == NULL);
		__free_pages(page, alloc_config.order);
	}
	timer = (ktime_get_ns() - timer) / alloc_config.allocs;
	t_perf->get = timer;
	t_perf->put = timer;
}

/// Random free and realloc
static void rand(u64 task_id, u64 *rng)
{
	u64 timer;
	struct thread_perf *t_perf = this_cpu_ptr(&thread_perf);
	u64 threads = atomic64_read(&curr_threads);

	struct page **pages =
		vmalloc_array(alloc_config.allocs, sizeof(struct page *));
	BUG_ON(pages == NULL);

	for (u64 j = 0; j < alloc_config.allocs; j++) {
		pages[j] = alloc_pages(gfp_flags(alloc_config.order),
				       alloc_config.order);
		BUG_ON(pages[j] == NULL);
	}
	allocated_pages[task_id] = pages;

	// complete initialization
	c_barrier_sync(&inner_barrier);

	// shuffle between all threads
	if (task_id == 0) {
		pr_info("shuffle: a=%llu t=%llu\n", alloc_config.allocs,
			threads);
		for (u64 i = 0; i < alloc_config.allocs * threads; i++) {
			u64 j = nanorand_random_range(
				rng, 0, alloc_config.allocs * threads);
			struct page **cpu_a = allocated_pages[i % threads];
			struct page **cpu_b = allocated_pages[j % threads];
			BUG_ON(cpu_a == NULL || cpu_b == NULL);
			swap(cpu_a[i / threads], cpu_b[j / threads]);
		}
		pr_info("setup finished\n");
	}

	c_barrier_sync(&inner_barrier);

	timer = ktime_get_ns();
	for (u64 j = 0; j < alloc_config.allocs; j++) {
		__free_pages(pages[j], alloc_config.order);
	}
	timer = (ktime_get_ns() - timer) / alloc_config.allocs;
	t_perf->get = timer;
	t_perf->put = timer;

	this_cpu_write(allocated_pages, NULL);
	vfree(pages);
}

static u64 init_frag(u64 task_id)
{
	u64 threads = max_threads;
	int node = cpu_to_node(raw_smp_processor_id());
	struct zone *zone = &NODE_DATA(node)->node_zones[ZONE_NORMAL];
	struct page **pages;
	u64 free_pages;
	u64 num_allocs;

	BUG_ON(zone_is_empty(zone));

	// Approximation! Leave some for other operations...
	free_pages = zone->present_pages -
		     (threads * 10 * (1 << alloc_config.order));
	num_allocs = (free_pages / (1 << alloc_config.order)) / threads;
	num_allocs = num_allocs * 90 / 100;

	// Allocate almost all of the memory of this zone
	// Note: This array might be larger than MAX_ORDER
	pages = vmalloc_array(num_allocs, sizeof(struct page *));
	BUG_ON(pages == NULL);

	for (u64 j = 0; j < num_allocs; j++) {
		pages[j] = alloc_pages_node(
			node, gfp_flags(alloc_config.order) | __GFP_THISNODE,
			alloc_config.order);
		BUG_ON(pages[j] == NULL);
	}
	allocated_pages[task_id] = pages;

	c_barrier_sync(&outer_barrier);

	// shuffle between all threads
	if (task_id == 0) {
		u64 rng = 42;
		pr_info("shuffle: a=%llu t=%llu\n", num_allocs, threads);
		for (u64 i = 0; i < num_allocs * threads; i++) {
			u64 j = nanorand_random_range(&rng, 0,
						      num_allocs * threads);
			struct page **cpu_a = allocated_pages[i % threads];
			struct page **cpu_b = allocated_pages[j % threads];
			BUG_ON(cpu_a == NULL || cpu_b == NULL);
			swap(cpu_a[i / threads], cpu_b[j / threads]);
		}
		pr_info("setup finished\n");
	}

	c_barrier_sync(&outer_barrier);

	// free half of it
	for (u64 i = num_allocs / 2; i < num_allocs; i++) {
		__free_pages(pages[i], alloc_config.order);
	}

	return num_allocs / 2;
}

static void frag(u64 task_id, u64 *rng, u64 num_allocs)
{
	u64 num_reallocs = (num_allocs * alloc_config.realloc_percentage) / 100;
	int node = alloc_config.node;
	struct zone *zone = &NODE_DATA(node)->node_zones[ZONE_NORMAL];

	u64 rng_copy = *rng;

	struct page **pages = allocated_pages[task_id];
	BUG_ON(pages == NULL);

	// complete initialization
	c_barrier_sync(&inner_barrier);

	for (u64 j = 0; j < num_reallocs;) {
		u64 i = nanorand_random_range(rng, 0, num_allocs);
		if (pages[i] != NULL) {
			__free_pages(pages[i], alloc_config.order);
			pages[i] = NULL;
			j++;
		}
	}

	c_barrier_sync(&inner_barrier);

	// Draining to allow the kernel allocator to defragment its pages...
	// FIXME: This seems have no effect on the kernel -> it still does not defragment!
	drain_local_pages(zone);

	c_barrier_sync(&inner_barrier);

	for (u64 j = 0; j < num_reallocs;) {
		u64 i = nanorand_random_range(&rng_copy, 0, num_allocs);
		if (pages[i] == NULL) {
			pages[i] = alloc_pages_node(
				node,
				gfp_flags(alloc_config.order) | __GFP_THISNODE,
				alloc_config.order);
			BUG_ON(pages[i] == NULL);
			j++;
		}
	}
}

static int worker(void *data)
{
	u64 task_id = (u64)data;
	u64 num_allocs = 0;
	u64 cpu = raw_smp_processor_id();
	u64 thread_rng = task_id;

	pr_info("Worker t=%u c=%u bench %u\n", task_id, cpu,
		alloc_config.bench);

	if (alloc_config.bench == BENCH_FRAG) {
		num_allocs = init_frag(task_id);
	}

	for (;;) {
		u64 threads;

		c_barrier_sync(&outer_barrier);

		if (kthread_should_stop() || !running) {
			pr_info("Stopping worker %d\n", task_id);
			break;
		}
		threads = atomic64_read(&curr_threads);

		pr_info("Execute t=%d c=%d run=%d", task_id, cpu,
			task_id < threads);
		if (task_id < threads) {
			switch (alloc_config.bench) {
			case BENCH_BULK:
				bulk();
				break;
			case BENCH_REPEAT:
				repeat();
				break;
			case BENCH_RAND:
				rand(task_id, &thread_rng);
				break;
			case BENCH_FRAG:
				frag(task_id, &thread_rng, num_allocs);
				break;
			}
		}

		c_barrier_sync(&outer_barrier);
	}

	if (alloc_config.bench == BENCH_FRAG) {
		struct page **pages = allocated_pages[task_id];
		pr_info("uninit frag\n");
		for (u64 j = 0; j < num_allocs; j++) {
			__free_pages(pages[j], alloc_config.order);
		}
		vfree(pages);
		this_cpu_write(allocated_pages, NULL);
	}

	return 0;
}

#ifndef CONFIG_NVALLOC
// The parameter hp_pfn describes a huge page slot (512 pages).
// It must therefore be huge page aligned,
// pfn+512-1 must still be in the range of the zone.
static inline u16 count_free_pages_per_huge_page_slot(u64 hp_pfn)
{
	u64 free = 0;
	for (u64 pfn = hp_pfn; pfn < hp_pfn + HPAGE_PMD_NR; pfn++) {
		struct page *page;

		if (!pfn_valid(pfn)) {
			printk(KERN_WARNING "Invalid pfn: %lx\n", pfn);
			continue;
		}

		page = pfn_to_page(pfn);

		/* Only headpage is initialized to -1 */
		if (PageBuddy(page))
			free++;
		else if (page_count(page) == 0 && is_free_buddy_page(page))
			free++;
	}
	return free;
}

// from mm/page_alloc.c
static inline int pindex_to_order(unsigned int pindex)
{
	int order = pindex / MIGRATE_PCPTYPES;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pindex == NR_LOWORDER_PCP_LISTS)
		order = pageblock_order;
#else
	VM_BUG_ON(order > PAGE_ALLOC_COSTLY_ORDER);
#endif

	return order;
}

static void add_pcplist_pages(struct zone *zone, u16 *buf)
{
	u64 pfn_start = zone->zone_start_pfn;
	struct per_cpu_pages *pcp;
	unsigned long flags;
	preempt_disable(); /* only for !CONFIG_PREEMPT_RT */
	pcp = this_cpu_ptr(zone->per_cpu_pageset);
	spin_lock_irqsave(&pcp->lock, flags);

	for (int i = 0; i < NR_PCP_LISTS; i++) {
		int order = pindex_to_order(i);
		struct list_head *list = &pcp->lists[i];
		struct page *page;
		list_for_each_entry(page, list, pcp_list) {
			u64 pfn = page_to_pfn(page);
			u64 index = (pfn - pfn_start) / HPAGE_PMD_NR;
			/* Assume no order > hugepage order in pcp cache */
			buf[index] += (1 << order);
		}
	}

	spin_unlock_irqrestore(&pcp->lock, flags);
	preempt_enable();
}

static void get_huge_page_slots_info(struct zone *zone, u16 *buf)
{
	const u64 HMASK = ~(HPAGE_PMD_NR - 1);
	u64 pfn_start = zone->zone_start_pfn;
	u64 pfn_end = zone_end_pfn(zone);
	unsigned long flags;

	if (pfn_start % HPAGE_PMD_NR)
		pfn_start = (pfn_start + HPAGE_PMD_NR) & HMASK;
	if (pfn_end % HPAGE_PMD_NR)
		pfn_end &= HMASK;

	spin_lock_irqsave(&zone->lock, flags);
	for (u64 pfn = pfn_start; pfn < pfn_end; pfn += HPAGE_PMD_NR) {
		u16 free = count_free_pages_per_huge_page_slot(pfn);
		buf[(pfn - pfn_start) / HPAGE_PMD_NR] = free;
	}
	add_pcplist_pages(zone, buf);
	spin_unlock_irqrestore(&zone->lock, flags);
}
#else
static void for_each_huge_page(void *arg, u16 count)
{
	u16 **buf = arg;
	*((*buf)++) = count;
}
static void get_huge_page_slots_info(struct zone *zone, u16 *buf)
{
	u16 *local_buf = buf;
	nvalloc_for_each_huge_page(zone->nvalloc, for_each_huge_page,
				   &local_buf);
}
#endif

void iteration(u32 bench, u64 i, u64 iter)
{
	struct perf *p;
	u64 threads = bench == BENCH_FRAG ? max_threads :
					    alloc_config.threads[i];
	u64 time;

	atomic64_set(&curr_threads, threads);
	c_barrier_reinit(&inner_barrier, threads);

	pr_info("Start interation: %llu (%llu threads)\n", iter, threads);
	time = ktime_get_ns();
	c_barrier_sync(&outer_barrier);

	// Workers do their work...

	c_barrier_sync(&outer_barrier);
	time = ktime_get_ns() - time;
	pr_info("Finish iteration: %lld (%lld ns)\n", iter, time);

	p = &measurements[i * alloc_config.iterations + iter];
	p->get_min = 0;
	p->get_avg = 0;
	p->get_max = 0;
	p->put_min = 0;
	p->put_avg = 0;
	p->put_max = 0;
	if (alloc_config.bench != BENCH_FRAG) {
		p->get_min = (u64)-1;
		p->put_min = (u64)-1;
		for (u64 t = 0; t < threads; t++) {
			u64 get, put;
			struct thread_perf *t_perf =
				per_cpu_ptr(&thread_perf, t);
			BUG_ON(t_perf == NULL);

			get = t_perf->get;
			put = t_perf->put;

			p->get_min = min(p->get_min, get);
			p->get_avg += get;
			p->get_max = max(p->get_max, get);
			p->put_min = min(p->put_min, put);
			p->put_avg += put;
			p->put_max = max(p->put_max, put);
		}
		p->get_avg /= threads;
		p->put_avg /= threads;
	} else {
		struct zone *zone =
			&NODE_DATA(alloc_config.node)->node_zones[ZONE_NORMAL];

#ifndef CONFIG_NVALLOC
		p->get_avg = zone->free_area[9].nr_free +
			     2 * zone->free_area[10].nr_free;
#else
		p->get_avg = nvalloc_free_huge_count(zone->nvalloc);
#endif
		p->put_avg = zone_page_state(zone, NR_FREE_PAGES);
		get_huge_page_slots_info(zone, p->frag_buf);
	}
}

static void *out_start(struct seq_file *m, loff_t *pos)
{
	u64 threads_len =
		alloc_config.bench == BENCH_FRAG ? 1 : alloc_config.threads_len;

	if (*pos >= (threads_len * alloc_config.iterations))
		return NULL;
	return pos;
}

static void *out_next(struct seq_file *m, void *arg, loff_t *pos)
{
	u64 threads_len =
		alloc_config.bench == BENCH_FRAG ? 1 : alloc_config.threads_len;

	(*pos)++;
	if (*pos >= (threads_len * alloc_config.iterations))
		return NULL;
	return pos;
}

static void out_stop(struct seq_file *m, void *arg)
{
}

static int out_show_frag(struct seq_file *m, u64 iter)
{
	struct perf *p;
	BUG_ON(iter > alloc_config.iterations);

	if (iter == 0)
		seq_puts(m, "order,threads,iter,allocs,small,huge\n");

	p = &measurements[iter];
	seq_printf(m, "%llu,%llu,%lu,%llu,%llu,%llu\n", alloc_config.order,
		   max_threads, iter, alloc_config.realloc_percentage,
		   p->put_avg, p->get_avg);

	BUG_ON(seq_has_overflowed(m));

	return 0;
}

/// Outputs the measured data.
/// Note: `buf` is PAGE_SIZE large!
static int out_show(struct seq_file *m, void *arg)
{
	u64 off = *(loff_t *)arg;

	if (running || measurements == NULL)
		return -EINPROGRESS;

	if (alloc_config.bench == BENCH_FRAG) {
		return out_show_frag(m, off);
	} else {
		u64 iter = off % alloc_config.iterations;
		u64 idx = off / alloc_config.iterations;
		struct perf *p;
		u64 threads;

		BUG_ON(idx > alloc_config.threads_len);
		threads = alloc_config.threads[idx];

		if (iter == 0 && idx == 0)
			seq_puts(m, "order,x,iteration,allocs,get_min,get_avg,"
				    "get_max,put_min,put_avg,put_max\n");

		p = &measurements[idx * alloc_config.iterations + iter];
		seq_printf(m,
			   "%llu,%llu,%lu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
			   alloc_config.order, threads, iter,
			   alloc_config.allocs, p->get_min, p->get_avg,
			   p->get_max, p->put_min, p->put_avg, p->put_max);

		BUG_ON(seq_has_overflowed(m));
	}
	return 0;
}

static bool whitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *str_skip(const char *buf, const char *end, bool ws)
{
	BUG_ON(buf == NULL || end == NULL);
	for (; buf < end && whitespace(*buf) == ws; buf++)
		;
	return buf;
}

static const char *next_uint(const char *buf, const char *end, u64 *dst)
{
	char *next;
	BUG_ON(buf == NULL || end == NULL);
	buf = str_skip(buf, end, true);

	if (buf >= end)
		return NULL;

	*dst = simple_strtoull(buf, &next, 10);
	if (next <= buf)
		return NULL;

	return next;
}

// just parsing a list of integers...
static const char *next_uint_list(const char *buf, const char *end, u64 **list,
				  u64 *list_len)
{
	u64 *threads;
	u64 threads_len = 1;
	char buffer[24];
	u64 n = 0;
	u64 bi = 0;
	BUG_ON(buf == NULL || end == NULL || list == NULL || list_len == NULL);

	// skip whitespace
	buf = str_skip(buf, end, true);
	if (buf >= end)
		return NULL;

	// count number of thread counts
	for (const char *tmp = buf; tmp < end && !whitespace(*tmp); tmp++) {
		if (*tmp == ',') {
			threads_len += 1;
		}
	}
	if (threads_len == 0)
		return NULL;

	// parse ints
	threads = kmalloc_array(threads_len, sizeof(u64), GFP_KERNEL);
	BUG_ON(threads == NULL);
	for (; buf < end && !whitespace(*buf); buf++) {
		if (*buf == ',') {
			if (bi == 0) {
				kfree(threads);
				return NULL;
			}
			buffer[bi] = '\0';
			if (kstrtou64(buffer, 10, &threads[n]) < 0) {
				kfree(threads);
				return NULL;
			}

			n += 1;
			bi = 0;
		} else {
			buffer[bi] = *buf;
			bi++;

			if (bi >= 24) {
				kfree(threads);
				return NULL;
			}
		}
	}

	if (bi == 0) {
		kfree(threads);
		return NULL;
	}
	buffer[bi] = '\0';
	if (kstrtou64(buffer, 10, &threads[n]) < 0) {
		kfree(threads);
		return NULL;
	}

	*list = threads;
	*list_len = threads_len;
	return buf;
}

/// Parsing the cli args
static bool argparse(const char *buf, size_t len, struct alloc_config *args)
{
	enum alloc_bench bench;
	u64 *threads;
	u64 threads_len;
	u64 iterations;
	u64 allocs;
	u64 order;
	u64 node;
	u64 realloc_percentage;
	const char *end = buf + len;
	BUG_ON(buf == NULL || args == NULL);

	if (len == 0 || buf == NULL || args == NULL) {
		pr_err("usage: \n"
		       "\t(bulk|repeat|rand) <iterations> <allocs> <order> <threads>\n"
		       "\tfrag <iterations> <realloc_percentage> <order> <node>\n");
		return false;
	}

	if (strncmp(buf, "bulk", min(len, 4ul)) == 0) {
		bench = BENCH_BULK;
		buf += 4;
	} else if (strncmp(buf, "repeat", min(len, 6ul)) == 0) {
		bench = BENCH_REPEAT;
		buf += 6;
	} else if (strncmp(buf, "rand", min(len, 4ul)) == 0) {
		bench = BENCH_RAND;
		buf += 4;
	} else if (strncmp(buf, "frag", min(len, 4ul)) == 0) {
		bench = BENCH_FRAG;
		buf += 4;
	} else {
		pr_err("Invalid <bench>: %s\n", buf);
		return false;
	}

	if ((buf = next_uint(buf, end, &iterations)) == NULL ||
	    iterations == 0) {
		pr_err("Invalid <iterations>\n");
		return false;
	}
	if (bench != BENCH_FRAG) {
		if ((buf = next_uint(buf, end, &allocs)) == NULL) {
			pr_err("Invalid <allocs>\n");
			return false;
		}
	} else {
		if ((buf = next_uint(buf, end, &realloc_percentage)) == NULL ||
		    realloc_percentage == 0 || realloc_percentage > 100) {
			pr_err("Invalid <realloc_percentage>\n");
			return false;
		}
	}
	if ((buf = next_uint(buf, end, &order)) == NULL || order >= MAX_ORDER) {
		pr_err("Invalid <order>\n");
		return false;
	}
	if (bench != BENCH_FRAG) {
		if ((buf = next_uint_list(buf, end, &threads, &threads_len)) ==
		    NULL) {
			pr_err("Invalid <threads>\n");
			return false;
		}
	} else {
		if ((buf = next_uint(buf, end, &node)) == NULL ||
		    node > nr_online_nodes) {
			pr_err("Invalid <node>\n");
			return false;
		}
	}

	buf = str_skip(buf, end, true);
	if (buf != end)
		return false;

	args->bench = bench;
	if (bench != BENCH_FRAG) {
		if (args->threads)
			kfree(args->threads);
		args->threads = threads;
		args->threads_len = threads_len;
	} else {
		args->node = node;
		args->realloc_percentage = realloc_percentage;
	}
	args->iterations = iterations;
	args->allocs = allocs;
	args->order = order;
	return true;
}

int run_open(struct inode *inode, struct file *file)
{
	return 0;
}

ssize_t run_write(struct file *file, const char __user *buf, size_t len,
		  loff_t *pos)
{
	int cpu;
	const struct cpumask *mask = &__cpu_online_mask;
	u64 threads = 0;
	u64 threads_len = 1;
	char *kbuf;
	u64 previous_iterations = alloc_config.iterations;

	if (running)
		return -EINPROGRESS;

	// Copy buf to kernel
	if ((kbuf = kmalloc(len + 1, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	if (strncpy_from_user(kbuf, buf, len) <= 0) {
		kfree(kbuf);
		pr_err("user copy failed\n");
		return -EINVAL;
	}
	kbuf[len] = '\0';
	pr_info("args: %s\n", kbuf);

	if (!argparse(kbuf, len, &alloc_config)) {
		kfree(kbuf);
		pr_err("invalid args\n");
		return -EINVAL;
	}
	kfree(kbuf);

	running = true;

	max_threads = 0;
	if (alloc_config.bench != BENCH_FRAG) {
		// Retrieve max thread count
		threads_len = alloc_config.threads_len;
		for (u64 i = 0; i < threads_len; i++) {
			max_threads = max(alloc_config.threads[i], max_threads);
		}
	} else {
		// cpus of this node!
		int cpu;
		mask = cpumask_of_node(alloc_config.node);
		for_each_cpu(cpu, mask) {
			max_threads++;
		}
	}
	BUG_ON(max_threads > num_online_cpus());
	c_barrier_reinit(&outer_barrier, max_threads + 1);

	if (measurements) {
		for (u64 i = 0; i < previous_iterations; i++) {
			if (measurements[i].frag_buf) {
				vfree(measurements[i].frag_buf);
				measurements[i].frag_buf = NULL;
			}
		}
		kfree(measurements);
	}

	measurements = kmalloc_array(threads_len * alloc_config.iterations,
				     sizeof(struct perf), GFP_KERNEL);
	BUG_ON(measurements == NULL);

	if (alloc_config.bench == BENCH_FRAG) {
		int node = alloc_config.node;
		struct zone *zone = &NODE_DATA(node)->node_zones[ZONE_NORMAL];
		u64 hpslots = zone->spanned_pages / HPAGE_PMD_NR;

		for (u64 i = 0; i < alloc_config.iterations; i++) {
			measurements[i].frag_buf =
				vmalloc_array(hpslots, sizeof(u16));
			BUG_ON(measurements[i].frag_buf == NULL);
		}
	} else {
		// Reset ptrs (or does kmalloc_array zeroize?)
		for (u64 i = 0; i < threads_len * alloc_config.iterations;
		     i++) {
			measurements[i].frag_buf = NULL;
		}
	}

	// Initialize workers in advance
	pr_info("Initialize workers\n");
	for_each_cpu(cpu, mask) {
		struct task_struct **task;
		if (threads >= max_threads)
			break;
		task = per_cpu_ptr(&per_cpu_tasks, cpu);
		BUG_ON(task == NULL);
		*task = kthread_run_on_cpu(worker, (void *)threads, cpu,
					   "worker");
		BUG_ON(*task == NULL);
		threads++;
	}

	// Frag init
	if (alloc_config.bench == BENCH_FRAG) {
		c_barrier_sync(&outer_barrier); // shuffle
		c_barrier_sync(&outer_barrier); // free half
	}

	pr_info("Start iterating\n");
	for (u64 i = 0; i < threads_len; i++) {
		for (u64 iter = 0; iter < alloc_config.iterations; iter++) {
			iteration(alloc_config.bench, i, iter);
		}
	}

	pr_info("Cleanup\n");

	running = false;
	c_barrier_sync(&outer_barrier);

	pr_info("Finished\n");

	return len;
}

static ssize_t fragout_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	const u64 u16mask = sizeof(u16) - 1;
	unsigned long max_bytes;
	u64 global_index;
	u64 curr_iteration;
	u64 iter_index;

	struct zone *zone =
		&NODE_DATA(alloc_config.node)->node_zones[ZONE_NORMAL];
	u64 hpslots = zone->spanned_pages / HPAGE_PMD_NR;

	BUG_ON(alloc_config.bench != BENCH_FRAG);

	if (*ppos & u16mask || count & u16mask)
		return -EINVAL;
	if (!measurements || hpslots == 0)
		return 0;

	max_bytes = alloc_config.iterations * hpslots * sizeof(u16);
	if (*ppos >= max_bytes)
		return 0;

	global_index = *ppos / sizeof(u16);
	iter_index = global_index % hpslots;
	curr_iteration = global_index / hpslots;
	count = min_t(unsigned long, count, PAGE_SIZE);
	count = min_t(unsigned long, count,
		      (hpslots - iter_index) * sizeof(u16));

	BUG_ON(copy_to_user(buf,
			    &measurements[curr_iteration].frag_buf[iter_index],
			    count));

	*ppos += count;
	return count;
}

static const struct proc_ops fragout_ops = {
	/* .proc_lseek	= mem_lseek, */
	.proc_read = fragout_read,
};

static const struct seq_operations out_op = {
	.start = out_start,
	.next = out_next,
	.stop = out_stop,
	.show = out_show,
};

static const struct proc_ops run_ops = {
	.proc_open = run_open,
	.proc_write = run_write,
};

static struct proc_dir_entry *dir;
static struct proc_dir_entry *out;
static struct proc_dir_entry *fragout;
static struct proc_dir_entry *run;

static int alloc_init_module(void)
{
	pr_info("Init\n");

	if ((dir = proc_mkdir("alloc", NULL)) == NULL) {
		pr_err("Proc mkdir failed\n");
		return -ENOMEM;
	}
	if ((out = proc_create_seq("out", 0440, dir, &out_op)) == NULL) {
		pr_err("Proc mkdir failed\n");
		proc_remove(dir);
		return -ENOMEM;
	}
	if ((fragout = proc_create("fragout", 0440, dir, &fragout_ops)) ==
	    NULL) {
		pr_err("Proc mkdir failed\n");
		proc_remove(dir);
		proc_remove(out);
		return -ENOMEM;
	}
	if ((run = proc_create("run", 0220, dir, &run_ops)) == NULL) {
		pr_err("Proc mkdir failed\n");
		proc_remove(dir);
		proc_remove(out);
		proc_remove(fragout);
		return -ENOMEM;
	}

	c_barrier_init(&outer_barrier, num_present_cpus() + 1, "outer");
	c_barrier_init(&inner_barrier, 1, "inner");

	BUG_ON((allocated_pages = kmalloc_array(num_online_cpus(),
						sizeof(struct page *),
						GFP_KERNEL)) == NULL);

	return 0;
}

static void alloc_cleanup_module(void)
{
	pr_info("End\n");
	if (out)
		proc_remove(out);
	if (run)
		proc_remove(run);
	if (dir)
		proc_remove(dir);

	if (alloc_config.threads)
		kfree(alloc_config.threads);
	if (measurements)
		kfree(measurements);
	if (allocated_pages)
		kfree(allocated_pages);
}

module_init(alloc_init_module);
module_exit(alloc_cleanup_module);
