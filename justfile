[private]
@default:
    just --list --unsorted

build target dir=("../llfree-linux/" + target):
        make LINUX_BUILD_DIR={{dir}} LLVM=1 clean
        mkdir -p build-{{target}}
        make LINUX_BUILD_DIR={{dir}} LLVM=1 -j`nproc` && cp alloc.ko build-{{target}}/alloc.keep

b:
        just build buddy "../llfree-linux/build-buddy-vm"
        just build llfree "../llfree-linux/build-llfree-vm"
        # just build huge "../hyperalloc-linux/build-huge-vm"
        # just build llhyper "../hyperalloc-linux/build-llzero-vm"
        # just build llzero "../llzero-linux/build-llzero-vm"

        # rename all alloc.keep to alloc.ko
        find . -name "alloc.keep" -exec sh -c 'mv "$0" "${0%keep}ko"' {} \;
