# Try to find kernel headers in common locations
KVER ?= $(shell uname -r)
KDIR ?= $(shell [ -d "/usr/src/linux-headers-$(KVER)" ] && echo "/usr/src/linux-headers-$(KVER)" || \
               [ -d "/lib/modules/$(KVER)/build" ] && echo "/lib/modules/$(KVER)/build" || \
               echo "/usr/src/linux")

obj-m += selftest.o

all:
	@if [ ! -d "$(KDIR)" ]; then \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src clean

install:
	@if [ ! -d "$(KDIR)" ]; then \
		exit 1; \
	fi
	@if [ ! -d "/lib/modules/$(KVER)" ]; then \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(CURDIR)/src modules_install
	mkdir -p "/lib/modules/$(KVER)/updates"
	[ -f "/lib/modules/$(KVER)/modules.order" ] || touch "/lib/modules/$(KVER)/modules.order"
	[ -f "/lib/modules/$(KVER)/modules.builtin" ] || touch "/lib/modules/$(KVER)/modules.builtin"
	[ -f "/lib/modules/$(KVER)/modules.builtin.modinfo" ] || touch "/lib/modules/$(KVER)/modules.builtin.modinfo"
	depmod -a $(KVER)

.PHONY: all clean install 