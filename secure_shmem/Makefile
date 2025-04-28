obj-m := secshm.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	mkdir -p $(MODULEDIR)
	install secshm.ko $(MODULEDIR)

clean:
	make -C $(KDIR) M=$(PWD) clean

