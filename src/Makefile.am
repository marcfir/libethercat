ACLOCAL_AMFLAGS = -I m4

includedir = $(prefix)/include/libethercat

lib_LTLIBRARIES = libethercat.la

include_HEADERS = $(top_srcdir)/include/libethercat/common.h \
				  $(top_srcdir)/include/libethercat/config.h \
				  $(top_srcdir)/include/libethercat/datagram.h \
				  $(top_srcdir)/include/libethercat/pool.h \
				  $(top_srcdir)/include/libethercat/dc.h \
				  $(top_srcdir)/include/libethercat/ec.h \
				  $(top_srcdir)/include/libethercat/eeprom.h \
				  $(top_srcdir)/include/libethercat/error_codes.h \
				  $(top_srcdir)/include/libethercat/hw.h \
				  $(top_srcdir)/include/libethercat/mbx.h \
				  $(top_srcdir)/include/libethercat/async_loop.h \
				  $(top_srcdir)/include/libethercat/regs.h \
				  $(top_srcdir)/include/libethercat/slave.h \
				  $(top_srcdir)/include/libethercat/idx.h \
				  $(top_srcdir)/include/libethercat/mii.h

libethercat_la_SOURCES	= slave.c datagram.c pool.c async_loop.c ec.c \
						  hw.c mbx.c eeprom.c dc.c idx.c mii.c

if MBX_SUPPORT_EOE
include_HEADERS += $(top_srcdir)/include/libethercat/eoe.h
libethercat_la_SOURCES += eoe.c
endif

if MBX_SUPPORT_COE
include_HEADERS += $(top_srcdir)/include/libethercat/coe.h
libethercat_la_SOURCES += coe.c
libethercat_la_SOURCES += coe_master.c
endif

if MBX_SUPPORT_FOE
include_HEADERS += $(top_srcdir)/include/libethercat/foe.h
libethercat_la_SOURCES += foe.c
endif

if MBX_SUPPORT_SOE
include_HEADERS += $(top_srcdir)/include/libethercat/soe.h
libethercat_la_SOURCES += soe.c
endif

if BUILD_DEVICE_SOCK_RAW_LEGACY
include_HEADERS += $(top_srcdir)/include/libethercat/hw_sock_raw.h
libethercat_la_SOURCES += hw_sock_raw.c
endif

if BUILD_DEVICE_SOCK_RAW_MMAPED
include_HEADERS += $(top_srcdir)/include/libethercat/hw_sock_raw_mmaped.h
libethercat_la_SOURCES += hw_sock_raw_mmaped.c
endif

if BUILD_DEVICE_FILE
include_HEADERS += $(top_srcdir)/include/libethercat/hw_file.h
libethercat_la_SOURCES += hw_file.c
endif

if BUILD_DEVICE_BPF
include_HEADERS += $(top_srcdir)/include/libethercat/hw_bpf.h
libethercat_la_SOURCES += hw_bpf.c
endif

if BUILD_PIKEOS
include_HEADERS += $(top_srcdir)/include/libethercat/hw_pikeos.h
libethercat_la_SOURCES += hw_pikeos.c
endif

libethercat_la_CFLAGS	= -std=gnu99 -Wall -Werror -Wno-unused-const-variable -I$(top_srcdir)/include @LIBOSAL_CFLAGS@
libethercat_la_LDFLAGS	= -Wall -Werror -no-undefined @LIBOSAL_LIBS@
libethercat_la_LIBS     = @LIBOSAL_LIBS@

install-exec-hook: 
	find $(DESTDIR)$(libdir) -type f -name \*.la -delete


