make clean
mkdir -p build-llfree-vm
make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-llfree-vm LLVM=-16 -j`nproc` && cp alloc.ko build-llfree-vm/alloc.keep
make clean
mkdir -p build-buddy-vm
make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-buddy-vm LLVM=-16 -j`nproc` && cp alloc.ko build-buddy-vm/alloc.keep
make clean
mkdir -p build-buddy-huge
make LINUX_BUILD_DIR=../llfree-linux-ballooning/build-buddy-huge LLVM=-16 -j`nproc` && cp alloc.ko build-buddy-huge/alloc.keep

mv build-llfree-vm/alloc.keep build-llfree-vm/alloc.ko
mv build-buddy-vm/alloc.keep build-buddy-vm/alloc.ko
mv build-buddy-huge/alloc.keep build-buddy-huge/alloc.ko
