# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2018 Intel Corporation.
#
# Makefile for the Intel(R) 82575 PCI-Express ethernet driver
#

obj-$(CONFIG_IGB) += igb-ethercat.o

igb-ethercat-objs := igb_main.o igb_ethtool.o e1000_82575.o \
	    e1000_mac.o e1000_nvm.o e1000_phy.o e1000_mbx.o \
	    e1000_i210.o igb_ptp.o igb_hwmon.o

EXTRA_CFLAGS=-I$(ETHERCAT_DEVICE_BASE)
KBUILD_EXTRA_SYMBOLS=$(ETHERCAT_DEVICE_BASE)/Module.symvers
