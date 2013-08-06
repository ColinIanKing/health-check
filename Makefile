VERSION=0.01.16

JSON_OUTPUT=y

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'
LDFLAGS += -lpthread
ifeq ($(JSON_OUTPUT),y)
	LDFLAGS += -ljson	
	CFLAGS += -DJSON_OUTPUT
endif

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

OBJS = list.o pid.o proc.o net.o syscall.o timeval.o fnotify.o event.o cpustat.o mem.o health-check.o
ifeq ($(JSON_OUTPUT),y)
	OBJS += json.o
endif

health-check: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

health-check.8.gz: health-check.8
	gzip -c $< > $@

net.o: net.c net.h

json.o: json.c json.h health-check.h

cpustat.o: cpustat.c list.h cpustat.h health-check.h

event.o: event.c list.h event.h health-check.h

fnotify.o: fnotify.c fnotify.h list.h proc.h health-check.h

health-check.o: health-check.c list.h pid.h proc.h syscall.h timeval.h \
	fnotify.h event.h cpustat.h mem.h net.h

list.o: list.c list.h

mem.o: mem.c mem.h list.h health-check.h

pid.o: pid.c pid.h list.h proc.h

proc.o: proc.c list.h pid.h proc.h health-check.h

syscall.o: syscall.c syscall.h proc.h health-check.h

timeval.o: timeval.c

dist:
	git archive --format=tar --prefix="health-check-$(VERSION)/" V$(VERSION) | \
		gzip > health-check-$(VERSION).tar.gz

clean:
	rm -f health-check health-check.o health-check.8.gz
	rm -f health-check-$(VERSION).tar.gz
	rm -f $(OBJS)

install: health-check health-check.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp health-check ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp health-check.8.gz ${DESTDIR}${MANDIR}
