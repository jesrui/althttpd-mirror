default: althttpd althttpsd 

althttpd:	althttpd.c
	cc -Os -Wall -Wextra -o althttpd althttpd.c

althttpsd:	althttpd.c
	cc -Os -Wall -Wextra -fPIC -o althttpsd -DENABLE_TLS althttpd.c -lssl -lcrypto

clean:	
	rm -f althttpd althttpsd
