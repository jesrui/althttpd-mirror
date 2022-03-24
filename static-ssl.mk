# 2022-02-16:
# This makefile is used by the author (drh) to build versions of
# althttpd that are statically linked against OpenSSL.  The resulting
# binaries power sqlite.org, fossil-scm.org, and other machines.
#
# This is not a general-purpose makefile.  But perhaps you can adapt
# it to your specific needs.
#

default: althttpd

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

OPENSSLDIR = /home/drh/fossil/release-build/compat/openssl
OPENSSLLIB = -L$(OPENSSLDIR) -lssl -lcrypto -ldl
CPPFLAGS += -I$(OPENSSLDIR)/include -DENABLE_TLS
CPPFLAGS += -Wall -Wextra
CFLAGS = -Os

althttpd:	althttpd.c manifest
	gcc $(CPPFLAGS) $(CFLAGS) -o althttpd althttpd.c $(OPENSSLLIB)

clean:	
	rm -f althttpd
