LINUX_BUILD_DIR ?= $(PWD)/../llfree-linux-ballooning/build-llfree-vm
LINUX_SRC_DIR ?= $(LINUX_BUILD_DIR)/..

obj-m += alloc.o

all:
	ln -fs $(LINUX_SRC_DIR)/.clang-format .clang-format
	$(LINUX_SRC_DIR)/scripts/clang-tools/gen_compile_commands.py -d $(LINUX_BUILD_DIR)
	make -C $(LINUX_BUILD_DIR) M=$(PWD) modules

clean:
	make -C $(LINUX_BUILD_DIR) M=$(PWD) clean
	rm -f .clang-format compile_commands.json
