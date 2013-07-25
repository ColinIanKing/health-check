VERSION=0.01.04

CFLAGS += -g -Wall -Wextra -Werror -DVERSION='"$(VERSION)"'
LDFLAGS += -lpthread

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

OBJS = list.o pid.o proc.o syscall.o timeval.o fnotify.o event.o cpustat.o health-check.o

health-check: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

health-check.8.gz: health-check.8
	gzip -c $< > $@

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
