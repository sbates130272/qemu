# Makefile for nvme_prp1_inject kernel module
KDIR := /lib/modules/$(shell uname -r)/build
obj-m += nvme_prp1_inject.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean



