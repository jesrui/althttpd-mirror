default: althttpd althttpsd 

manifest: .fossil-settings/manifest
	fossil update --nosync current
manifest.uuid: manifest

VERSION_NUMBER := 0.9
althttpd.h: Makefile manifest.uuid
	@{ \
	echo "/* This file is generated. Edit at your own risk. */"; \
	echo '#define ALTHTTPD_VERSION_NUMBER "$(VERSION_NUMBER)"'; \
	vhash=`cut -c1-12 manifest.uuid`; \
	vtime=`awk '/^D /{print $$2}' manifest`; \
	echo "#define ALTHTTPD_VERSION_HASH \"[$${vhash}]\""; \
	echo "#define ALTHTTPD_VERSION_TIME \"$${vtime}\""; \
	echo '#define ALTHTTPD_VERSION ALTHTTPD_VERSION_HASH " " ALTHTTPD_VERSION_TIME'; \
	} > $@

althttpd:	althttpd.h althttpd.c
	cc -Os -Wall -Wextra -o althttpd althttpd.c

althttpsd: althttpd.h althttpd.c
	cc -DENABLE_TLS -Os -Wall -Wextra -fPIC -o althttpsd althttpd.c -lssl -lcrypto

clean:	
	rm -f althttpd althttpsd
