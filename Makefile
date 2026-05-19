obj-m += rootkit_hidden_module.o
obj-m += rootkit_hidden_process.o
obj-m += detect_hidden_process_kmod.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all modules tools clean

all: modules tools

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools:
	$(CC) -std=c11 -O2 -Wall -Wextra -o detect_hidden_module detect_hidden_module.c
	$(CC) -std=c11 -O2 -Wall -Wextra -o detect_hidden_process detect_hidden_process.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) detect_hidden_module detect_hidden_process
