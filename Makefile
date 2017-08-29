obj-m += main.o

UNAME = $(shell uname -r)

LINUX_BUILD ?= /lib/modules/$(UNAME)/build

all:
	make -C $(LINUX_BUILD) M=$(PWD) modules

clean:
	make -C $(LINUX_BUILD) M=$(PWD) clean
