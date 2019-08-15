obj-m := bce_ttm.o
KERNEL_DIR := /usr/src/kernels/$(shell uname -r)/
PWD := $(shell pwd)
#EXTRA_CFLAGS+=-D__GENKSYMS__
all:
	make -C $(KERNEL_DIR) M=$(PWD) 
clean:    
	rm *.o *.ko *.mod.c  Module.symvers modules.order
