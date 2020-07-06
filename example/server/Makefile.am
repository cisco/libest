bin_PROGRAMS = estserver
estclient_includedir=$(includedir)/est
estserver_SOURCES = estserver.c ossl_srv.c ../util/utils.c ../util/simple_server.c ../util/jsmn.c
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

estserver_LDFLAGS = -L../../src/est/.libs $(DL) $(PTHREAD) -lest -lssl -lcrypto

EXTRA_DIST = ossl_srv.h apps.h createCA.sh createCA.bat ext.cnf ESTcommon.sh runserver.sh estExampleCA.cnf extExampleCA.cnf ESTcommon_masa.sh createMASA.sh masa.cnf masa_ExampleCA.cnf

