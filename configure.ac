dnl Process this file with autoconf to produce a configure script.
AC_INIT([libest],[1.1.1p],[libest-dev])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/est/est.c)
AC_CONFIG_SRCDIR(example/client/estclient.c)
AC_CONFIG_SRCDIR(example/client-simple/estclient-simple.c)
AC_CONFIG_SRCDIR(example/server/estserver.c)
AC_CONFIG_SRCDIR(example/proxy/estproxy.c)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE

AC_PROG_CC
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

AC_PREFIX_DEFAULT([/usr/local/est])

cp confdefs.h est_config.h

AC_CONFIG_FILES([Makefile version java/jni/Makefile src/Makefile src/est/Makefile example/client/Makefile example/client-simple/Makefile example/server/Makefile example/proxy/Makefile])
AC_OUTPUT
