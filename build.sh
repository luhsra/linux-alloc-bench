make clean
mkdir -p build-llfree-vm
make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-llfree-vm LLVM=-14 -j50 && cp alloc.ko build-llfree-vm/alloc.keep
make clean
mkdir -p build-buddy-vm
make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-buddy-vm LLVM=-14 -j50 && cp alloc.ko build-buddy-vm/alloc.ko
mv build-llfree-vm/alloc.keep build-llfree-vm/alloc.ko

# make clean
# mkdir -p build-huge-vm
# make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-virtio-balloon-huge-pages-modified LLVM=-14 -j50 && cp alloc.ko build-huge-vm/alloc.ko
