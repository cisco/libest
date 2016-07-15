if ENABLE_JNI
if JAVA_HOME_SET
lib_LTLIBRARIES = libjest.la
AM_CFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(SSL_CFLAGS) -I../.. -I$(srcdir)/../../src 
libjest_la_LDFLAGS = -release $(PACKAGE_VERSION) 
libjest_la_SOURCES = client.c
libjest_la_LIBADD = ../../src/est/libest.la 
library_includedir=$(includedir)/est
library_include_HEADERS = jest.h
#EXTRA_DIST = jest.h 
else
    $(warning JAVA_HOME is not set, JNI layer will not be built.)
endif
endif
