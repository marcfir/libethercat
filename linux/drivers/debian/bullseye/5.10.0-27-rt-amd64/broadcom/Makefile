# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Broadcom network device drivers.
#

obj-m += tg3-ethercat.o

tg3-ethercat-objs := tg3.o

EXTRA_CFLAGS=-I$(src)/../../../../../
KBUILD_EXTRA_SYMBOLS=$(src)/../../../../../Module.symvers
