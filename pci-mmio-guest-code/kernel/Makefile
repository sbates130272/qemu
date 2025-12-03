obj-m += nvme_vram_dmabuf.o
obj-m += nvme_prp1_inject.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


