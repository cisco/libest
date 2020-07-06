if ENABLE_CLIENT_ONLY 
lib_LTLIBRARIES = libest_client.la
AM_CFLAGS = -I$(SSL_CFLAGS) -I../.. -I$(SAFEC_CFLAGS) $(LIBCURL_CFLAGS)
libest_client_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libest_client_la_SOURCES = est.c est_client.c est_client_http.c est_ossl_util.c est_client_proxy.c jsmn.c \
                           multipart_parser.c

libest_client_la_LIBADD = $(SAFEC_LDFLAGS)
library_includedir=$(includedir)/est
library_include_HEADERS = est.h
EXTRA_DIST = est_locl.h est_ossl_util.h est_client_proxy.h est_sock_compat.h jsmn.h multipart_parser.h

else

lib_LTLIBRARIES = libest.la
AM_CFLAGS = -I$(SSL_CFLAGS) -I../.. -I$(SAFEC_CFLAGS) $(LIBCURL_CFLAGS)
libest_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libest_la_SOURCES = est.c est_client.c est_server.c est_server_http.c \
                    est_proxy.c est_client_http.c est_ossl_util.c \
                    est_client_proxy.c jsmn.c multipart_parser.c \
                    est_enhcd_cert_auth.c est_server_coap.c

libest_la_LIBADD = $(SAFEC_LDFLAGS)
library_includedir=$(includedir)/est
library_include_HEADERS = est.h
EXTRA_DIST = est_locl.h est_ossl_util.h est_server.h est_server_http.h est_client_proxy.h est_sock_compat.h \
             jsmn.h multipart_parser.h

endif