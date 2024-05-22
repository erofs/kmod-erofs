# SPDX-License-Identifier: GPL-2.0

ifneq ($(KERNELRELEASE),)
# Called from inline kernel build

ifdef CONFIG_EROFS_FS_XATTR
ccflags-y="-DCONFIG_EROFS_FS_XATTR"
endif

obj-$(CONFIG_EROFS_FS) += erofs.o
erofs-objs := super.o inode.o data.o namei.o dir.o
erofs-$(CONFIG_EROFS_FS_XATTR) += xattr.o
else
# Called from external kernel module build
KERNELRELEASE	?= $(shell uname -r)
KDIR	?= /lib/modules/${KERNELRELEASE}/build
MDIR	?= /lib/modules/${KERNELRELEASE}
PWD	:= $(shell pwd)

export CONFIG_EROFS_FS := m
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

endif
