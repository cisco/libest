bin_PROGRAMS = estproxy
estproxy_SOURCES = estproxy.c ../util/utils.c ../util/simple_server.c 
AM_CFLAGS = -I../.. -I$(srcdir)/../../src/est -I$(SSL_CFLAGS) -g 
if FREEBSD 
DL=
else
DL=-ldl
endif

if DISABLE_PTHREAD
PTHREAD=
else
PTHREAD=-lpthread
endif

estproxy_LDFLAGS = -L../../src/est/.libs $(DL) $(PTHREAD) -lest -lssl -lcrypto

EXTRA_DIST = createRA.sh runproxy.sh estExampleCA.cnf
