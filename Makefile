#
# libpri: An implementation of Primary Rate ISDN
#
# Written by Mark Spencer <markster@linux-support.net>
#
# Copyright (C) 2001, Linux Support Services, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#
# Uncomment if you want libpri not send PROGRESS_INDICATOR w/ALERTING
#ALERTING=-DALERTING_NO_PROGRESS

CC=gcc
GREP=grep
AWK=awk
AR=ar
RANLIB=ranlib

OSARCH=$(shell uname -s)
PROC?=$(shell uname -m)

# SONAME version; should be changed on every ABI change
# please don't change it needlessly; it's perfectly fine to have a SONAME
# of 1.2 and a version of 1.4.x
SONAME:=1.4

STATIC_LIBRARY=libpri.a
DYNAMIC_LIBRARY:=libpri.so.$(SONAME)
STATIC_OBJS= \
	copy_string.o \
	pri.o \
	q921.o \
	prisched.o \
	q931.o \
	pri_aoc.o \
	pri_cc.o \
	pri_facility.o \
	asn1_primitive.o \
	rose.o \
	rose_address.o \
	rose_etsi_aoc.o \
	rose_etsi_cc.o \
	rose_etsi_diversion.o \
	rose_etsi_ect.o \
	rose_etsi_mwi.o \
	rose_other.o \
	rose_q931.o \
	rose_qsig_aoc.o \
	rose_qsig_cc.o \
	rose_qsig_ct.o \
	rose_qsig_diversion.o \
	rose_qsig_mwi.o \
	rose_qsig_name.o \
	version.o
DYNAMIC_OBJS= \
	$(STATIC_OBJS)
CFLAGS ?= -g
CFLAGS += $(CPPFLAGS)
CFLAGS += -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes -Wno-zero-length-bounds -Wno-stringop-overflow
CFLAGS += -fPIC $(ALERTING) $(LIBPRI_OPT) $(COVERAGE_CFLAGS)
INSTALL_PREFIX=$(DESTDIR)
INSTALL_BASE=/usr
libdir?=$(INSTALL_BASE)/lib
ifneq ($(findstring Darwin,$(OSARCH)),)
  SOFLAGS=$(LDFLAGS) -dynamic -bundle -Xlinker -macosx_version_min -Xlinker 10.4 -Xlinker -undefined -Xlinker dynamic_lookup -force_flat_namespace
  ifeq ($(shell /usr/bin/sw_vers -productVersion | cut -c1-4),10.6)
    SOFLAGS+=/usr/lib/bundle1.o
  endif
  LDCONFIG=/usr/bin/true
else
  SOFLAGS=$(LDFLAGS) -shared -Wl,-h$(DYNAMIC_LIBRARY) $(COVERAGE_LDFLAGS)
  LDCONFIG = /sbin/ldconfig
endif
ifneq (,$(findstring X$(OSARCH)X, XLinuxX XGNU/kFreeBSDX XGNUX))
LDCONFIG_FLAGS=-n
else
ifeq (${OSARCH},FreeBSD)
LDCONFIG_FLAGS=-m
CFLAGS += -I../zaptel -I../zapata
INSTALL_BASE=/usr/local
endif
endif
ifeq (${OSARCH},SunOS)
CFLAGS += -DSOLARIS -I../zaptel-solaris
LDCONFIG =
LDCONFIG_FLAGS = \# # Trick to comment out the period in the command below
#INSTALL_PREFIX = /opt/asterisk  # Uncomment out to install in standard Solaris location for 3rd party code
endif

UTILITIES= pridump pritest rosetest testprilib

export PRIVERSION

PRIVERSION:=$(shell GREP=$(GREP) AWK=$(AWK) build_tools/make_version .)

#The problem with sparc is the best stuff is in newer versions of gcc (post 3.0) only.
#This works for even old (2.96) versions of gcc and provides a small boost either way.
#A ultrasparc cpu is really v9 but the stock debian stable 3.0 gcc doesnt support it.
ifeq ($(PROC),sparc64)
PROC=ultrasparc
LIBPRI_OPT = -mtune=$(PROC) -O3 -pipe -fomit-frame-pointer -mcpu=v8
else
  ifneq ($(CODE_COVERAGE),)
    LIBPRI_OPT=
    COVERAGE_CFLAGS=-ftest-coverage -fprofile-arcs
    COVERAGE_LDFLAGS=-ftest-coverage -fprofile-arcs
  else
    LIBPRI_OPT=-O2
  endif
endif

ifeq ($(CPUARCH),i686)
CFLAGS += -m32
SOFLAGS += -m32
endif

all: $(STATIC_LIBRARY) $(DYNAMIC_LIBRARY) $(UTILITIES)

update:
	@if [ -d .svn ]; then \
		echo "Updating from Subversion..." ; \
		fromrev="`svn info | $(AWK) '/Revision: / {print $$2}'`"; \
		svn update | tee update.out; \
		torev="`svn info | $(AWK) '/Revision: / {print $$2}'`"; \
		echo "`date`  Updated from revision $${fromrev} to $${torev}." >> update.log; \
		rm -f .version; \
		if [ `grep -c ^C update.out` -gt 0 ]; then \
			echo ; echo "The following files have conflicts:" ; \
			grep ^C update.out | cut -b4- ; \
		fi ; \
		rm -f update.out; \
	else \
		echo "Not under version control";  \
	fi

install: $(STATIC_LIBRARY) $(DYNAMIC_LIBRARY)
	mkdir -p $(INSTALL_PREFIX)$(libdir)
	mkdir -p $(INSTALL_PREFIX)$(INSTALL_BASE)/include
ifneq (${OSARCH},SunOS)
	install -m 644 libpri.h $(INSTALL_PREFIX)$(INSTALL_BASE)/include
	install -m 755 $(DYNAMIC_LIBRARY) $(INSTALL_PREFIX)$(libdir)
	#if [ -x /usr/sbin/sestatus ] && ( /usr/sbin/sestatus | grep "SELinux status:" | grep -q "enabled"); then /sbin/restorecon -v $(INSTALL_PREFIX)$(libdir)/$(DYNAMIC_LIBRARY); fi
	( cd $(INSTALL_PREFIX)$(libdir) ; ln -sf $(DYNAMIC_LIBRARY) libpri.so)
	install -m 644 $(STATIC_LIBRARY) $(INSTALL_PREFIX)$(libdir)
	if test $$(id -u) = 0; then $(LDCONFIG) $(LDCONFIG_FLAGS) $(INSTALL_PREFIX)$(libdir); fi
else
	install -f $(INSTALL_PREFIX)$(INSTALL_BASE)/include -m 644 libpri.h
	install -f $(INSTALL_PREFIX)$(libdir) -m 755 $(DYNAMIC_LIBRARY)
	( cd $(INSTALL_PREFIX)$(libdir) ; ln -sf $(DYNAMIC_LIBRARY) libpri.so)
	install -f $(INSTALL_PREFIX)$(libdir) -m 644 $(STATIC_LIBRARY)
endif

uninstall:
	@echo "Removing Libpri"
	rm -f $(INSTALL_PREFIX)$(libdir)/$(STATIC_LIBRARY)
	rm -f $(INSTALL_PREFIX)$(libdir)/libpri.so
	rm -f $(INSTALL_PREFIX)$(libdir)/$(DYNAMIC_LIBRARY)
	rm -f $(INSTALL_PREFIX)$(INSTALL_BASE)/include/libpri.h

pritest: pritest.o $(STATIC_LIBRARY)
	$(CC) -o $@ $< $(STATIC_LIBRARY) $(CFLAGS)

testprilib.o: testprilib.c
	$(CC) $(CFLAGS) -D_REENTRANT -D_GNU_SOURCE $(MAKE_DEPS) -c -o $@ $<

testprilib: testprilib.o $(STATIC_LIBRARY)
	$(CC) -o $@ $< $(STATIC_LIBRARY) -lpthread $(CFLAGS)

pridump: pridump.o $(DYNAMIC_LIBRARY)
	$(CC) -o $@ $< -L. -lpri $(CFLAGS)

rosetest: rosetest.o $(STATIC_LIBRARY)
	$(CC) -o $@ $< $(STATIC_LIBRARY) $(CFLAGS)

MAKE_DEPS= -MD -MT $@ -MF .$(subst /,_,$@).d -MP

%.o: %.c
	$(CC) $(CFLAGS) $(MAKE_DEPS) -c -o $@ $<

%.lo: %.c
	$(CC) $(CFLAGS) $(MAKE_DEPS) -c -o $@ $<

$(STATIC_LIBRARY): $(STATIC_OBJS)
	$(AR) rcs $(STATIC_LIBRARY) $(STATIC_OBJS)
	$(RANLIB) $(STATIC_LIBRARY)

$(DYNAMIC_LIBRARY): $(DYNAMIC_OBJS)
	$(CC) $(SOFLAGS) -o $@ $(DYNAMIC_OBJS)
	$(LDCONFIG) $(LDCONFIG_FLAGS) .
	ln -sf $(DYNAMIC_LIBRARY) libpri.so

version.c: FORCE
	@build_tools/make_version_c > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

clean:
	rm -f *.o *.so *.lo
	rm -f $(STATIC_LIBRARY) $(DYNAMIC_LIBRARY)
	rm -f $(UTILITIES)
	rm -f .*.d

.PHONY:

FORCE:

ifneq ($(wildcard .*.d),)
   include .*.d
endif
