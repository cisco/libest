ACLOCAL_AMFLAGS = -I m4

if ENABLE_JNI
libest_jni = java/jni
endif

if BUILTIN_LIBSAFEC
stub_safec_dir = safe_c_stub
endif

if ENABLE_EXAMPLES
if ENABLE_CLIENT_ONLY
examples = example/client example/client-simple example/client-brski
else
examples = example/client example/client-simple example/client-brski example/server example/proxy
endif
endif

SUBDIRS = $(stub_safec_dir) src $(libest_jni) $(examples)

EXTRA_DIST = autogen.sh example/util LICENSE README.brski $(srcdir)/build.gradle $(srcdir)/example/build_examples.gradle
