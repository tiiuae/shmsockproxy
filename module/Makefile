#  Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
#  SPDX-License-Identifier: Apache-2.0

obj-m := kvm_ivshmem.o 
PWD   := $(shell pwd)

default:
	cp ../drivers/char/ivshmem/kvm_ivshmem.c .
	cp ../drivers/char/ivshmem/kvm_ivshmem.h .
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	mkdir -p $(MODULEDIR)
	install kvm_ivshmem.ko $(MODULEDIR)

clean:
	rm -f *.ko *.o kvm_ivshmem.mod.c Module.symvers
