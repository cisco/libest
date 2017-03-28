bin_PROGRAMS = estclient_simple
estclient_simple_includedir=$(includedir)/est
estclient_simple_SOURCES = estclient-simple.c ../util/utils.c 
AM_CFLAGS = -I../.. -I$(srcdir)/../../src/est -I$(SSL_CFLAGS) -g 
if FREEBSD 
DL=
else
DL=-ldl
endif
estclient_simple_LDFLAGS = -L../../src/est/.libs $(DL) -lest -lssl -lcrypto
