lib_LTLIBRARIES = libest.la
AM_CFLAGS = -I$(SSL_CFLAGS) -I../.. 
libest_la_LDFLAGS = -version-info 1:0:0
libest_la_SOURCES = est.c est_client.c est_server.c est_server_http.c \
		    	est_proxy.c est_client_http.c est_ossl_util.c 
library_includedir=$(includedir)/est
library_include_HEADERS = est.h
EXTRA_DIST = est_locl.h est_ossl_util.h est_server.h est_server_http.h 
