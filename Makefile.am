ACLOCAL_AMFLAGS = -I m4

if ENABLE_CLIENT_ONLY 
SUBDIRS = safe_c_stub src java/jni example/client example/client-simple example/client-brski
else 
SUBDIRS = safe_c_stub src java/jni example/client example/client-simple example/server example/proxy example/client-brski
endif

EXTRA_DIST = autogen.sh example/util LICENSE README.brski $(srcdir)/build.gradle $(srcdir)/example/build_examples.gradle
