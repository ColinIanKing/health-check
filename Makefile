VERSION=0.01.57
#
# Codename "Ravenous Bug Blaster"
#

JSON_OUTPUT=y

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'
LDFLAGS += -lpthread
ifeq ($(JSON_OUTPUT),y)
	LDFLAGS += -ljson	
	CFLAGS += -DJSON_OUTPUT
endif
ifeq ($(FNOTIFY),y)
	CFLAGS += -DFNOTIFY
endif

#CFLAGS += -DDEBUG_MALLOC

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

OBJS = alloc.o list.o pid.o proc.o net.o syscall.o timeval.o fnotify.o event.o cpustat.o mem.o ctxt-switch.o health-check.o
ifeq ($(JSON_OUTPUT),y)
	OBJS += json.o
endif

health-check: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

health-check.8.gz: health-check.8
	gzip -c $< > $@

alloc.o: alloc.c alloc.h

cpustat.o: cpustat.c list.h json.h cpustat.h timeval.h health-check.h

ctxt-switch.o: ctxt-switch.c list.h json.h ctxt-switch.h health-check.h

event.o: event.c list.h json.h event.h health-check.h

fnotify.o: fnotify.c fnotify.h list.h json.h proc.h health-check.h

health-check.o: health-check.c list.h json.h pid.h proc.h syscall.h timeval.h \
	fnotify.h event.h cpustat.h mem.h net.h ctxt-switch.h

json.o: json.c json.h health-check.h

list.o: list.c list.h

mem.o: mem.c mem.h list.h health-check.h

net.o: net.c net.h list.h proc.h json.h health-check.h

pid.o: pid.c pid.h list.h proc.h alloc.h

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
