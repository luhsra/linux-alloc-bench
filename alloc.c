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

struct perf {
	u64 get_min;
	u64 get_avg;
	u64 get_max;
	u64 put_min;
	u64 put_avg;
	u64 put_max;
};
static struct perf *measurements = NULL;
static u64 out_index = 0;

static struct page ***rand_pages;

__maybe_unused static u64 cycles(void)
{
	u32 lo, hi;
	asm volatile("rdtsc" : "=eax"(lo), "=edx"(hi) :);
	return ((u64)lo) | ((u64)hi << 32);
};

__always_inline static gfp_t gfp_flags(int order)
{
	return GFP_USER | (order ? __GFP_COMP : 0);
}

/// Alloc a number of pages at once and free them afterwards
static void bulk()
{
	u64 j;
	u64 timer;
	struct thread_perf *t_perf = this_cpu_ptr(&thread_perf);

	struct page **pages = kmalloc_array(alloc_config.allocs,
					    sizeof(struct page *), GFP_KERNEL);
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
	kfree(pages);
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
static void rand(u64 *rng)
{
	u64 timer;
	struct thread_perf *t_perf = this_cpu_ptr(&thread_perf);
	u64 threads = atomic64_read(&curr_threads);

	struct page **pages = kmalloc_array(alloc_config.allocs,
					    sizeof(struct page *), GFP_KERNEL);
	BUG_ON(pages == NULL);

	for (u64 j = 0; j < alloc_config.allocs; j++) {
		pages[j] = alloc_pages(gfp_flags(alloc_config.order),
				       alloc_config.order);
		BUG_ON(pages[j] == NULL);
	}
	rand_pages[raw_smp_processor_id()] = pages;

	// complete initialization
	c_barrier_sync(&inner_barrier);

	// shuffle between all threads
	if (raw_smp_processor_id() == 0) {
		pr_info("shuffle: a=%llu t=%llu\n", alloc_config.allocs,
			threads);
		for (u64 i = 0; i < alloc_config.allocs * threads; i++) {
			u64 j = nanorand_random_range(
				rng, 0, alloc_config.allocs * threads);
			swap(rand_pages[i % threads][i / threads],
			     rand_pages[j % threads][j / threads]);
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

	kfree(pages);
}

static u64 init_frag()
{
	int cpu = raw_smp_processor_id();
	u64 threads = max_threads;
	int node = cpu_to_node(cpu);
	struct zone *zone = &NODE_DATA(node)->node_zones[ZONE_NORMAL];
	struct page **pages;

	// Approximation! Leave some for other operations...
	u64 free_pages = zone->present_pages -
			 (threads * 10 * (1 << alloc_config.order));
	u64 num_allocs = (free_pages / (1 << alloc_config.order)) / threads;
	num_allocs = num_allocs * 90 / 100;

	// Allocate almost all of the memory of this zone
	// Note: This array might be larger than MAX_ORDER
	pages = vmalloc_array(num_allocs, sizeof(struct page *));
	BUG_ON(pages == NULL);

	pr_info("init frag %d\n", cpu);

	for (u64 j = 0; j < num_allocs; j++) {
		pages[j] = alloc_pages_node(node, gfp_flags(alloc_config.order),
					    alloc_config.order);
		BUG_ON(pages[j] == NULL);
	}
	rand_pages[cpu] = pages;

	pr_info("alloc finished %d\n", cpu);
	c_barrier_sync(&outer_barrier);

	// shuffle between all threads
	if (cpu == 0) {
		u64 rng = 42;
		pr_info("shuffle: a=%llu t=%llu\n", num_allocs, threads);
		for (u64 i = 0; i < num_allocs * threads; i++) {
			u64 j = nanorand_random_range(&rng, 0,
						      num_allocs * threads);
			BUG_ON(i % threads >= threads ||
			       j % threads >= threads);
			BUG_ON(i / threads >= num_allocs ||
			       j / threads >= num_allocs);
			swap(rand_pages[i % threads][i / threads],
			     rand_pages[j % threads][j / threads]);
		}
		pr_info("setup finished\n");
	}
	return num_allocs;
}

static void frag(u64 *rng, u64 num_allocs)
{
	u64 cpu = raw_smp_processor_id();
	u64 num_reallocs = (num_allocs * alloc_config.realloc_percentage) / 100;

	int node = cpu_to_node(cpu);
	struct page **pages = rand_pages[cpu];

	// complete initialization
	c_barrier_sync(&inner_barrier);

	for (u64 j = 0; j < num_reallocs; j++) {
		u64 i = nanorand_random_range(rng, 0, num_allocs);
		__free_pages(pages[i], alloc_config.order);
		pages[i] = __alloc_pages_node(node,
					      gfp_flags(alloc_config.order),
					      alloc_config.order);
		BUG_ON(pages[i] == 0);
	}
}

static int worker(void *data)
{
	u64 task_id = (u64)data;
	u64 num_allocs = 0;
	u64 cpu = raw_smp_processor_id();
	u64 thread_rng = cpu;

	pr_info("Worker %u bench %u\n", smp_processor_id(), alloc_config.bench);

	if (alloc_config.bench == BENCH_FRAG) {
		num_allocs = init_frag();
	}

	for (;;) {
		u64 threads;

		c_barrier_sync(&outer_barrier);

		if (kthread_should_stop() || !running) {
			pr_info("Stopping worker %d\n", smp_processor_id());
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
				rand(&thread_rng);
				break;
			case BENCH_FRAG:
				frag(&thread_rng, num_allocs);
				break;
			}
		}

		c_barrier_sync(&outer_barrier);
	}

	if (alloc_config.bench == BENCH_FRAG) {
		pr_info("uninit frag\n");
		for (u64 j = 0; j < num_allocs; j++) {
			__free_pages(rand_pages[cpu][j], alloc_config.order);
		}
	}

	return 0;
}

/// Outputs the measured data.
/// Note: `buf` is PAGE_SIZE large!
static ssize_t out_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	struct perf *p;
	ssize_t len = 0;

	ssize_t max_out_index =
		alloc_config.bench != BENCH_FRAG ? alloc_config.threads_len : 1;
	u64 allocs = alloc_config.bench != BENCH_FRAG ?
			     alloc_config.allocs :
			     alloc_config.realloc_percentage;

	if (running || measurements == NULL)
		return -EINPROGRESS;

	if (out_index == 0) {
		len += sprintf(buf,
			       "alloc,x,iteration,allocs,get_min,get_avg,"
			       "get_max,put_min,put_avg,put_max,init,total\n");
	}

	for (ssize_t i = out_index; i < max_out_index; i++) {
		u64 threads = alloc_config.bench != BENCH_FRAG ?
				      alloc_config.threads[i] :
				      max_threads;

		// The output buffer has only the size of a PAGE.
		// If our output is larger we have to output it in multiple steps.
		if (len < PAGE_SIZE - alloc_config.iterations * 128) {
			for (ssize_t iter = 0; iter < alloc_config.iterations;
			     iter++) {
				p = &measurements[i * alloc_config.iterations +
						  iter];

				len += sprintf(
					buf + len,
					"Kernel,%llu,%lu,%llu,%llu,%llu,%llu,%llu,"
					"%llu,%llu,0,0\n",
					threads, iter, allocs, p->get_min,
					p->get_avg, p->get_max, p->put_min,
					p->put_avg, p->put_max);
			}
		} else {
			out_index = i;
			return len;
		}
	}
	out_index = 0;
	return len;
}

void iteration(u32 bench, u64 i, u64 iter)
{
	struct perf *p;
	u64 threads = max_threads;

	if (bench != BENCH_FRAG) {
		threads = alloc_config.threads[i];
	}

	atomic64_set(&curr_threads, threads);
	c_barrier_reinit(&inner_barrier, threads);

	pr_info("Start threads %llu\n", threads);
	c_barrier_sync(&outer_barrier);

	pr_info("Waiting for %llu workers...\n", threads);
	c_barrier_sync(&outer_barrier);
	pr_info("Finish iteration\n");

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
			struct thread_perf *t_perf =
				per_cpu_ptr(&thread_perf, t);
			u64 get, put;

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

		p->get_avg = zone->free_area[9].nr_free +
			     2 * zone->free_area[10].nr_free;
		p->put_avg = zone_page_state(zone, NR_FREE_PAGES);
	}
}

static bool whitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *str_skip(const char *buf, const char *end, bool ws)
{
	for (; buf < end && whitespace(*buf) == ws; buf++)
		;
	return buf;
}

static const char *next_uint(const char *buf, const char *end, u64 *dst)
{
	char *next;
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

	if (len == 0 || buf == NULL || args == NULL) {
		pr_err("usage: \n"
		       "\t(bulk|repeat|rand) <iterations> <allocs> <order> <threads>\n"
		       "\tfrag <iterations> <realloc_percentage> <order> <node>");
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
		pr_err("Invalid <bench>: %s", buf);
		return false;
	}

	if ((buf = next_uint(buf, end, &iterations)) == NULL ||
	    iterations == 0) {
		pr_err("Invalid <iterations>");
		return false;
	}
	if (bench != BENCH_FRAG) {
		if ((buf = next_uint(buf, end, &allocs)) == NULL) {
			pr_err("Invalid <allocs>");
			return false;
		}
	} else {
		if ((buf = next_uint(buf, end, &realloc_percentage)) == NULL ||
		    realloc_percentage == 0 || realloc_percentage > 100) {
			pr_err("Invalid <realloc_percentage>");
			return false;
		}
	}
	if ((buf = next_uint(buf, end, &order)) == NULL || order >= MAX_ORDER) {
		pr_err("Invalid <order>");
		return false;
	}
	if (bench != BENCH_FRAG) {
		if ((buf = next_uint_list(buf, end, &threads, &threads_len)) ==
		    NULL) {
			pr_err("Invalid <threads>");
			return false;
		}
	} else {
		if ((buf = next_uint(buf, end, &node)) == NULL ||
		    node > nr_online_nodes) {
			pr_err("Invalid <node>");
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

static ssize_t run_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t len)
{
	int cpu;
	const struct cpumask *mask = &__cpu_online_mask;
	u64 threads = 0;
	u64 threads_len = 1;

	if (running)
		return -EINPROGRESS;

	if (!argparse(buf, len, &alloc_config))
		return -EINVAL;

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
			max_threads += 1;
		}
	}
	BUG_ON(max_threads > num_online_cpus());
	c_barrier_reinit(&outer_barrier, max_threads + 1);

	if (measurements)
		kfree(measurements);

	measurements = kmalloc_array(threads_len * alloc_config.iterations,
				     sizeof(struct perf), GFP_KERNEL);

	// Initialize workers in advance
	for_each_cpu(cpu, mask) {
		struct task_struct **task;
		if (threads >= max_threads)
			break;
		task = per_cpu_ptr(&per_cpu_tasks, cpu);
		*task = kthread_run_on_cpu(worker, (void *)threads, cpu,
					   "worker");
		threads++;
	}

	// Frag init
	if (alloc_config.bench == BENCH_FRAG) {
		c_barrier_sync(&outer_barrier);
	}

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

static struct kobj_attribute out_attribute = __ATTR(out, 0444, out_show, NULL);
static struct kobj_attribute run_attribute = __ATTR(run, 0220, NULL, run_store);

static struct attribute *attrs[] = {
	&out_attribute.attr, &run_attribute.attr,
	NULL, /* need to NULL terminate the list of attributes */
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};
static struct kobject *output;

static int alloc_init_module(void)
{
	int retval;
	pr_info("Init\n");

	output = kobject_create_and_add(KBUILD_MODNAME, kernel_kobj);
	if (!output) {
		pr_err("KObj failed\n");
		return -ENOMEM;
	}

	retval = sysfs_create_group(output, &attr_group);
	if (retval) {
		pr_err("Sysfs failed\n");
		kobject_put(output);
	}

	rand_pages =
		kmalloc_array(num_present_cpus(), sizeof(void *), GFP_KERNEL);

	c_barrier_init(&outer_barrier, num_present_cpus() + 1, "outer");
	c_barrier_init(&inner_barrier, 1, "inner");

	return 0;
}

static void alloc_cleanup_module(void)
{
	pr_info("End\n");
	kobject_put(output);
	if (alloc_config.threads)
		kfree(alloc_config.threads);
	if (measurements)
		kfree(measurements);
	kfree(rand_pages);
}

module_init(alloc_init_module);
module_exit(alloc_cleanup_module);
