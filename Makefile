obj-m := bce_ttm.o
KERNEL_DIR := /usr/src/kernels/$(shell uname -r)/
OS := $(shell cat /etc/os-release|grep ^ID=|cut -d '=' -f 2)
ifeq ($(OS),ubuntu)
	KERNEL_DIR := /usr/src/linux-headers-$(shell uname -r)/
endif
ifeq ($(OS),debain)
	KERNEL_DIR := /usr/src/linux-headers-$(shell uname -r)/
endif
PWD := $(shell pwd)
#EXTRA_CFLAGS+=-D__GENKSYMS__
all:
	make -C $(KERNEL_DIR) M=$(PWD)
clean:
	rm *.o *.ko *.mod.c  Module.symvers modules.order
