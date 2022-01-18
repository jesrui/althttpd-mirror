default: althttpd althttpsd 

VERSION_NUMBER ?= 2.0
VERSION_HASH ?= $(shell cut -c1-12 manifest.uuid)
VERSION_TIME ?= $(shell sed -n 2p manifest | cut -d' ' -f2)
ALTHTTPD_VERSION ?= "$(VERSION_NUMBER) [$(VERSION_HASH)] $(VERSION_TIME)"
CPPFLAGS += -DALTHTTPD_VERSION='$(ALTHTTPD_VERSION)'

manifest:
	@if which fossil > /dev/null; then \
		fossil update --nosync current; \
	else \
	  echo "fossil binary not found. Version hash/time might be incorrect."
	fi
manifest.uuid: manifest

althttpd:	althttpd.c manifest Makefile
	cc $(CPPFLAGS) -Os -Wall -Wextra -o althttpd althttpd.c

althttpsd:	althttpd.c manifest Makefile
	cc $(CPPFLAGS) -Os -Wall -Wextra -fPIC -o althttpsd -DENABLE_TLS althttpd.c -lssl -lcrypto

static-althttpd:	althttpd.c manifest Makefile
	cc $(CPPFLAGS) -Os -Wall -Wextra -static -o althttpd althttpd.c

static-althttpsd:	althttpd.c manifest Makefile
	cc $(CPPFLAGS) -Os -Wall -Wextra -static -fPIC -o althttpsd -DENABLE_TLS althttpd.c -lssl -lcrypto -lpthread -ldl

clean:	
	rm -f althttpd althttpsd
