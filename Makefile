obj-m += selftest.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)/src modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/src clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD)/src modules_install
	depmod -a

.PHONY: all clean install 