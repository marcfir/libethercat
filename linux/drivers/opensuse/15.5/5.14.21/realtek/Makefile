# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Realtek network device drivers.
#

obj-$(CONFIG_8139CP) += 8139cp.o
obj-$(CONFIG_8139TOO) += 8139too.o
obj-$(CONFIG_ATP) += atp.o
r8169-ethercat-objs += r8169_main.o r8169_firmware.o r8169_phy_config.o
obj-$(CONFIG_R8169) += r8169-ethercat.o

EXTRA_CFLAGS=-I$(src)/../../../../../
KBUILD_EXTRA_SYMBOLS=$(src)/../../../../../Module.symvers
