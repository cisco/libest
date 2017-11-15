dnl Process this file with autoconf to produce a configure script.
AC_INIT([libest],[2.1.0p],[libest-dev])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/est/est.c)
AC_CONFIG_SRCDIR(example/client/estclient.c)
AC_CONFIG_SRCDIR(example/client-simple/estclient-simple.c)
AC_CONFIG_SRCDIR(example/server/estserver.c)
AC_CONFIG_SRCDIR(example/proxy/estproxy.c)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT
AC_CANONICAL_HOST
case $host in
        *free*)    
	        OS_FREEBSD=true
    		AC_DEFINE([IS_FREEBSD],[1])
                AC_DEFINE([DISABLE_BACKTRACE],[1])
            	;;
esac
AC_MSG_CHECKING(Host OS is FreeBSD)
AM_CONDITIONAL([FREEBSD], [test x$OS_FREEBSD = xtrue])
AM_COND_IF([FREEBSD], AC_MSG_RESULT([FreeBSD is set]), AC_MSG_RESULT([FreeBSD not set]))
AM_COND_IF([FREEBSD], AC_MSG_RESULT([Skipping libdl check]),
		    AC_CHECK_LIB([dl], [dlopen], [],
				[AC_MSG_FAILURE([can't find libdl])]))
AC_ARG_ENABLE([jni], 
	       [AS_HELP_STRING([--enable-jni],
			       [Enable support for JNI library])],
		[jni_on=1],
		[jni_on=0])
AM_CONDITIONAL([ENABLE_JNI], [test x$jni_on = x1])
AM_COND_IF([ENABLE_JNI], 
	   AC_MSG_RESULT([JNI support enabled])
	   AC_DEFINE([ENABLE_JNI]),
	   AC_MSG_RESULT([JNI support is disabled]))
AM_CONDITIONAL([JAVA_HOME_SET], [test ! -z "$JAVA_HOME"]) 


AC_ARG_ENABLE([pthreads], 
	       [AS_HELP_STRING([--disable-pthreads],
			       [Disable support for pthreads])],
		[pthreads_on=1],
		[pthreads_on=0])
AM_CONDITIONAL([DISABLE_PTHREAD], [test x$pthreads_on = x1])
AM_COND_IF([DISABLE_PTHREAD], 
	   AC_MSG_RESULT([pthread support disabled])
	   AC_DEFINE([DISABLE_PTHREADS]), 
	   AC_MSG_RESULT([pthread support is enabled]))
AM_COND_IF([DISABLE_PTHREAD], [], 
	    [AC_CHECK_LIB([pthread], [pthread_create], [],
             [AC_MSG_FAILURE([can't find pthread lib])])])

AC_ARG_WITH([ssl-dir],
	    [AS_HELP_STRING([--with-ssl-dir],
		[location of OpenSSL install folder, defaults to /usr/local/ssl])],
	    [ssldir="$withval"],
	    [ssldir="/usr/local/ssl"])
AC_SUBST([SSL_CFLAGS], "$ssldir/include")
AC_SUBST([SSL_LDFLAGS], "$ssldir/lib")

CFLAGS="$CFLAGS -Wall -I$ssldir/include"
LDFLAGS="$LDFLAGS -L$ssldir/lib"
if test "$is_freebsd" = "1" ; then
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])]
	     [])
else
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openssl crypto lib])]
	     [-ldl])
fi
AC_CHECK_LIB([ssl], [SSL_CTX_new], [],
             [AC_MSG_FAILURE([can't find openssl ssl lib])])

# Conditionally include use of libcurl for client proxy support

AC_ARG_WITH([libcurl-dir],
 [AS_HELP_STRING([--with-libcurl-dir],
				 [enable support for client proxy using libcurl])],
 [libcurldir="$withval"],
 [with_libcurldir=no])

  AS_IF(
        [test "x$with_libcurldir" != xno],
        [[CFLAGS="$CFLAGS -I$libcurldir/include"]
         [LDFLAGS="$LDFLAGS -L$libcurldir/lib -lcurl"]
         AC_CHECK_LIB(
              [curl],
              [curl_easy_init],
			  [
               AC_DEFINE([HAVE_LIBCURL],[1],[Define if you have libcurl])
              ],
              [AC_MSG_FAILURE([--with-libcurl was given, but test for libcurl failed])]
             )
        ]
       )

# Conditionally include use of uriparser for URI path segment support

AC_ARG_WITH([uriparser-dir],
 [AS_HELP_STRING([--with-uriparser-dir],
				 [enable support for path segments using uriparser])],
 [uriparserdir="$withval"],
 [with_uriparserdir=no])
          
 dnl CFLAGS="$CFLAGS -Wall -I$uriparserdir/include"
 dnl CPPFLAGS="$CPPFLAGS -I$uriparser/include"
 dnl LDFLAGS="$LDFLAGS -L$uriparserdir/lib -luriparser"

  AS_IF(
        [test "x$with_uriparserdir" != xno],
        [[CFLAGS="$CFLAGS -Wall -I$uriparserdir/include"]
         [LDFLAGS="$LDFLAGS -L$uriparserdir/lib -luriparser"]
         AC_CHECK_LIB(
              [uriparser], 
              [uriParseUriA],
			  [
               AC_DEFINE([HAVE_URIPARSER],[1],[Define if you hve uriparser]) 
              ],
              [AC_MSG_FAILURE([--with-uriparser was given, but test for uriparser failed])]
             )
        ]
       )

SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)
safecdir="$SAFEC_STUB_DIR" 
AC_SUBST([SAFEC_DIR], "$safecdir")
AC_SUBST([SAFEC_CFLAGS], "$safecdir/include")
AC_SUBST([SAFEC_LDFLAGS], "$safecdir/lib")

CFLAGS="$CFLAGS -Wall -I$safecdir/include"
LDFLAGS="$LDFLAGS -L$safecdir/lib"
LIBS="$LIBS -lsafe_lib"

AC_PREFIX_DEFAULT([/usr/local/est])

cp confdefs.h est_config.h

AC_CONFIG_FILES([Makefile version safe_c_stub/Makefile safe_c_stub/lib/Makefile java/jni/Makefile src/Makefile src/est/Makefile example/client/Makefile example/client-simple/Makefile example/server/Makefile example/proxy/Makefile])
AC_OUTPUT
