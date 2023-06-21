obj-m += mod_firewall.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -o configure configure.c

clean:
	$(RM) -rf .*.cmd *.mod.c *.o *.ko .tmp*
