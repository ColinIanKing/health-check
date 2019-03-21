#
# Copyright (C) 2013-2019 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
VERSION=0.03.00
#
# Codename "Where have all my cycles gone?"
#

JSON_OUTPUT=y

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2

#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

LDFLAGS += -lpthread
ifeq ($(JSON_OUTPUT),y)
	LDFLAGS += -ljson-c
	CFLAGS += -DJSON_OUTPUT
endif
ifeq ($(FNOTIFY),y)
	CFLAGS += -DFNOTIFY
endif

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

OBJS =	list.o pid.o proc.o net.o syscall.o timeval.o \
	fnotify.o cpustat.o mem.o ctxt-switch.o health-check.o
ifeq ($(JSON_OUTPUT),y)
	OBJS += json.o
endif

health-check: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

health-check.8.gz: health-check.8
	gzip -c $< > $@

cpustat.o: cpustat.c list.h json.h cpustat.h timeval.h health-check.h

ctxt-switch.o: ctxt-switch.c list.h json.h ctxt-switch.h health-check.h

fnotify.o: fnotify.c fnotify.h list.h json.h proc.h health-check.h

health-check.o: health-check.c list.h json.h pid.h proc.h syscall.h timeval.h \
	fnotify.h cpustat.h mem.h net.h ctxt-switch.h

json.o: json.c json.h health-check.h

list.o: list.c list.h

mem.o: mem.c mem.h list.h health-check.h

net.o: net.c net.h list.h proc.h json.h health-check.h

pid.o: pid.c pid.h list.h proc.h

proc.o: proc.c list.h pid.h proc.h net.h health-check.h

syscall.o: syscall.c syscall.h proc.h json.h net.h mem.h \
	cpustat.h fnotify.h ctxt-switch.h health-check.h

timeval.o: timeval.c timeval.h

dist:
	rm -rf health-check-$(VERSION)
	mkdir health-check-$(VERSION)
	cp -rp Makefile *.c *.h scripts health-check.8 COPYING health-check-$(VERSION)
	tar -zcf health-check-$(VERSION).tar.gz health-check-$(VERSION)
	rm -rf health-check-$(VERSION)

clean:
	rm -f health-check health-check.o health-check.8.gz
	rm -f health-check-$(VERSION).tar.gz
	rm -f $(OBJS)

install: health-check health-check.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp health-check ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp health-check.8.gz ${DESTDIR}${MANDIR}
