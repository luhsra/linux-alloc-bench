# Module for Benchmarking the Linux Allocator

This module contains multiple kernelspace benchmarks for the Linux allocator:

- `bulk`: Parallel allocation of a huge number of pages. In a second step, they are freed in parallel.
- `repeat`: Free and reallocate the same page over and over.
- `rand`: Allocates the available memory and reallocate a percentage randomly in parallel.
- `frag`: Similar to rand but measure fragmentation instead of runtime

## Usage

Building the module.

```bash
make LINUX_BUILD_DIR=../llfree-linux/build-llfree-vm LLVM=1
```

Load the benchmark module.

```bash
sudo insmod alloc.ko
```

Execute the `rand` benchmark on 1, 2 and 4 cores 4 times and allocate 1024 pages.

```bash
echo "bulk 4 1024 0 1,2,4" | sudo tee /proc/alloc/run
```

Read the results.

```bash
cat /proc/alloc/out
# For frag also
cat /proc/alloc/fragout
```

> FIXME: If the results are larger than 4K, this file has to be read multiple times.
