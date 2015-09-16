lib_LTLIBRARIES = libest.la
AM_CFLAGS = -I../.. 
libest_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libest_la_SOURCES = est.c est_client.c est_server.c est_server_http.c \
			est_proxy.c est_client_http.c est_ossl_util.c NonPosix.c
library_includedir=$(includedir)/est
library_include_HEADERS = est.h
EXTRA_DIST = est_locl.h est_ossl_util.h est_server.h est_server_http.h NonPosix.h
