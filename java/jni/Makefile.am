if ENABLE_JNI
if JAVA_HOME_SET
lib_LTLIBRARIES = libciscojest.la
AM_CFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(SSL_CFLAGS) -I../.. -I$(srcdir)/../../src -I$(SAFEC_CFLAGS)/include
libciscojest_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libciscojest_la_SOURCES = client.c
#if ENABLE_CLIENT_ONLY
#libciscojest_la_LIBADD = ../../src/est/libest_client.la $(SAFEC_LDFLAGS)/libciscosafec.so
#else
#libciscojest_la_LIBADD = ../../src/est/libest.la $(SAFEC_LDFLAGS)/libciscosafec.so
#endif
if ENABLE_CLIENT_ONLY
  libciscojest_la_LIBADD = ../../src/est/libest_client.la 
else
  libciscojest_la_LIBADD = ../../src/est/libest.la
endif

library_includedir=$(includedir)/est
library_include_HEADERS = jest.h
#EXTRA_DIST = jest.h 
else
    $(warning JAVA_HOME is not set, JNI layer will not be built.)
endif
endif
