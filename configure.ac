dnl Process this file with autoconf to produce a configure script.
AC_INIT([libest],[3.2.0p],[libest-dev])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/est/est.c)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG
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
		[],
		[enable_jni="no"])
AM_CONDITIONAL([ENABLE_JNI], [test "$enable_jni" = "yes"])
AM_COND_IF([ENABLE_JNI], 
	   AC_MSG_RESULT([JNI support enabled])
	   AC_DEFINE([ENABLE_JNI]),
	   AC_MSG_RESULT([JNI support is disabled]))
AM_CONDITIONAL([JAVA_HOME_SET], [test ! -z "$JAVA_HOME"]) 

AC_ARG_ENABLE([client-only], 
	       [AS_HELP_STRING([--enable-client-only],
			       [Enable the building of only the client mode of libEST])],
		[],
		[enable_client_only="no"])
AM_CONDITIONAL([ENABLE_CLIENT_ONLY], [test "$enable_client_only" = "yes"])
AM_COND_IF([ENABLE_CLIENT_ONLY], 
	   AC_MSG_RESULT([Client only build enabled])
	   AC_DEFINE([ENABLE_CLIENT_ONLY]),
	   AC_MSG_RESULT([Client Only support is disabled]))

AC_ARG_ENABLE([brski], 
	       [AS_HELP_STRING([--enable-brski],
			       [Enable support for brski bootstrap functionality])],
		[],
		[enable_brski="no"])
AM_CONDITIONAL([ENABLE_BRSKI], [test "$enable_brski" = "yes"])
AM_COND_IF([ENABLE_BRSKI], 
	   AC_MSG_RESULT([BRSKI support is enabled])
	   AC_DEFINE([ENABLE_BRSKI]),
	   AC_MSG_RESULT([BRSKI support is disabled]))

AC_ARG_ENABLE([pthreads], 
	       [AS_HELP_STRING([--disable-pthreads],
			       [Disable support for pthreads])],
		[],
		[enable_pthreads="yes"])
AM_CONDITIONAL([DISABLE_PTHREAD], [test "$enable_pthreads" = "no"])
AM_COND_IF([DISABLE_PTHREAD], 
	   AC_MSG_RESULT([pthread support disabled])
	   AC_DEFINE([DISABLE_PTHREADS]), 
	   AC_MSG_RESULT([pthread support is enabled]))
AM_COND_IF([DISABLE_PTHREAD], [], 
	    [AC_CHECK_LIB([pthread], [pthread_create], [],
             [AC_MSG_FAILURE([can't find pthread lib])])])

AC_ARG_ENABLE([examples],
	       [AS_HELP_STRING([--disable-examples],
			       [Disable examples compilation])],
		[],
		[enable_examples="yes"])
AC_MSG_CHECKING(whether to build examples)
AM_CONDITIONAL([ENABLE_EXAMPLES], [test "$enable_examples" = "yes"])
AM_COND_IF([ENABLE_EXAMPLES], AC_MSG_RESULT([yes]), AC_MSG_RESULT([no]))

AC_ARG_WITH([ssl-dir],
	    [AS_HELP_STRING([--with-ssl-dir],
		[location of OpenSSL install folder, defaults to /usr/local/ssl])],
	    [],
	    [with_ssl_dir="/usr/local/ssl"])
AC_SUBST([SSL_CFLAGS], "$with_ssl_dir/include")
AC_SUBST([SSL_LDFLAGS], "$with_ssl_dir/lib")

CFLAGS="$CFLAGS -Wall -I$with_ssl_dir/include"
LDFLAGS="$LDFLAGS -L$with_ssl_dir/lib"
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

AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_reset], [], 
             [AC_DEFINE([HAVE_OLD_OPENSSL], [1], [Old OpenSSL is being used])
              AC_MSG_NOTICE([Old OpenSSL (Pre-1.1.0) is being used])] 
             [])
#AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_reset], [],
#             [AC_MSG_FAILURE([can't find openssl ssl lib])])


# Conditionally include use of libcurl for client proxy support

AC_ARG_WITH([libcurl-dir],
 [AS_HELP_STRING([--with-libcurl-dir],
				 [enable support for client proxy using libcurl])],
 [],
 [with_libcurl_dir=no])

  AS_IF(
        [test "$with_libcurl_dir" != "no"],
        [[CFLAGS="$CFLAGS -I$with_libcurl_dir/include"]
         [LDFLAGS="$LDFLAGS -L$with_libcurl_dir/lib -lcurl"]
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
 [],
 [with_uriparser_dir=no])
          
 dnl CFLAGS="$CFLAGS -Wall -I$uriparserdir/include"
 dnl CPPFLAGS="$CPPFLAGS -I$uriparser/include"
 dnl LDFLAGS="$LDFLAGS -L$uriparserdir/lib -luriparser"

  AS_IF(
        [test "$with_uriparser_dir" != "no"],
        [[CFLAGS="$CFLAGS -I$with_uriparser_dir/include"]
         [LDFLAGS="$LDFLAGS -L$with_uriparser_dir/lib -luriparser"]
         AC_CHECK_LIB(
              [uriparser], 
              [uriParseUriA],
			  [
               AC_DEFINE([HAVE_URIPARSER],[1],[Define if you have uriparser]) 
              ],
              [AC_MSG_FAILURE([--with-uriparser was given, but test for uriparser failed])]
             )
        ]
       )

# Conditionally include use of CoAP library for ESToCoAP support

AC_ARG_WITH([libcoap-dir],
 [AS_HELP_STRING([--with-libcoap-dir],
				 [enable support for ESToCoAP using libcoap library])],
 [],
 [with_libcoap_dir=no])

  AS_IF(
        [test "$with_libcoap_dir" != "no"],
        [[CFLAGS="$CFLAGS -I$with_libcoap_dir/include"]
         [LDFLAGS="$LDFLAGS -L$with_libcoap_dir/lib -lcoap-2-openssl"]
         AC_CHECK_LIB(
              [coap-2-openssl], 
              [coap_startup],
			  [
               AC_DEFINE([HAVE_LIBCOAP],[1],[Define if you have libcoap]) 
              ],
              [AC_MSG_FAILURE([--with-libcoapdir was given, but test for libcoap failed])]
             )
        ]
       )


SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)
# check for each of the possible safec options
AC_ARG_WITH(system-libsafec,
            AS_HELP_STRING([--with-system-libsafec],
                           [select to use libsafec installed in the system]),
            [with_system_libsafec="yes"],
            [with_system_libsafec="no"])

AC_ARG_WITH([safec-dir],
            [AS_HELP_STRING([--with-safec-dir=],
                            [location of SAFEC private installation])],
                            [safecdir="$withval"],
                            [safecdir="no"])    
            
AC_ARG_ENABLE(safec,
            [AS_HELP_STRING([--disable-safec],
                            [disable SAFEC use: **WARNING** this is not recommended])],
                            [disable_safec="yes"],
                            [disable_safec="no"]) 

AC_MSG_CHECKING(which libsafec to use)
if test "x$with_system_libsafec" = "xyes"; then

       AC_MSG_RESULT(system installation);
   
       PKG_CHECK_MODULES([libsafec], [libsafec])
       LIBS="$LIBS $libsafec_LIBS"
       CFLAGS="$CFLAGS $libsafec_CFLAGS"
       CPPFLAGS="$CPPFLAGS $libsafec_CFLAGS"

       AC_DEFINE([SYSTEM_LIBSAFEC],[1],[Define if using system installed SafeC]) 

else if test "x$safecdir" != "xno"; then

       # a local installation of safec has been specified
       AC_MSG_RESULT(private installation);

       AC_SUBST([SAFEC_DIR], "$safecdir")
       AC_SUBST([SAFEC_CFLAGS], "$safecdir/include")
       AC_SUBST([SAFEC_LDFLAGS], "$safecdir/lib")
       LDFLAGS="$LDFLAGS -L$safecdir/lib"

       # make sure it's there and linkable.
       AC_CHECK_LIB([ciscosafec], [memset_s], 
                    [], [AC_MSG_FAILURE([can't find CiscoSafeC lib])] [])

       AC_DEFINE([CISCO_LIBSAFEC],[1],[Define if using Cisco installed SafeC]) 

else if test "x$disable_safec" = "xyes"; then

       AC_MSG_RESULT(builtin);

       safecdir="$SAFEC_STUB_DIR"
       AC_SUBST([SAFEC_DIR], "$safecdir")
       AC_SUBST([SAFEC_CFLAGS], "$safecdir/include")
       AC_SUBST([SAFEC_LDFLAGS], "$safecdir/lib")
       LDFLAGS="$LDFLAGS -L$safecdir/lib"
       LIBS="$LIBS -lsafe_lib"

else 

       AC_MSG_RESULT();
       AC_MSG_FAILURE([No libsafec option specified. Must be one of: --with-system-libsafec, --with-safec-dir, --disable-safec])

fi 
fi
fi

AC_PREFIX_DEFAULT([/usr/local/est])

cp confdefs.h est_config.h

AC_CONFIG_FILES([Makefile version src/Makefile src/est/Makefile safe_c_stub/Makefile safe_c_stub/lib/Makefile java/jni/Makefile])

AM_CONDITIONAL([BUILTIN_LIBSAFEC], [test "x$disable_safec" = "xyes"])

AM_COND_IF([ENABLE_EXAMPLES],
           [
            AC_CONFIG_FILES([example/client/Makefile example/client-simple/Makefile example/client-brski/Makefile])
            AM_COND_IF([ENABLE_CLIENT_ONLY],
                       [],
                       [AC_CONFIG_FILES([example/server/Makefile example/proxy/Makefile])])
           ])

AC_OUTPUT
