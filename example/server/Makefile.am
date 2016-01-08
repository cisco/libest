bin_PROGRAMS = estserver
estclient_includedir=$(includedir)/est
estserver_SOURCES = estserver.c ossl_srv.c ../util/utils.c ../util/simple_server.c 
AM_CFLAGS = -I../.. -I$(srcdir)/../../src/est

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

estserver_LDFLAGS = -L../../src/est/.libs -lest
estserver_DEPENDENCIES = ../../src/est/.libs/libest.*

EXTRA_DIST = ossl_srv.h apps.h createCA.sh ext.cnf ESTcommon.sh runserver.sh estExampleCA.cnf extExampleCA.cnf
