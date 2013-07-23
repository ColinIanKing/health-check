VERSION=0.01.02

CFLAGS += -g -Wall -DVERSION='"$(VERSION)"'
LDFLAGS += -lpthread

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

health-check: health-check.o
	$(CC) $(CFLAGS) $< -lm -o $@ $(LDFLAGS)

health-check.8.gz: health-check.8
	gzip -c $< > $@

dist:
	git archive --format=tar --prefix="health-check-$(VERSION)/" V$(VERSION) | \
		gzip > health-check-$(VERSION).tar.gz

clean:
	rm -f health-check health-check.o health-check.8.gz
	rm -f health-check-$(VERSION).tar.gz

install: health-check health-check.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp health-check ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp health-check.8.gz ${DESTDIR}${MANDIR}
