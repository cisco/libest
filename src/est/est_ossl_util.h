/*------------------------------------------------------------------
 * est_ossl_util.h - Entry point definitions into the OpenSSL
 *                   interface for EST server operations. 
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#ifndef HEADER_EST_OSSL_UTIL_H 
#define HEADER_EST_OSSL_UTIL_H

/* Windows only option: Export local API functions for testing */
#ifdef WIN32
#ifdef DEVTEST
#ifdef DT_EXPORTS
#define LIBEST_TEST_API __declspec(dllexport)
#else
#define LIBEST_TEST_API __declspec(dllimport)
#endif /* DT_EXPORTS */
#else
#define LIBEST_TEST_API
#endif /* DEVTEST */
#else
#define LIBEST_TEST_API
#endif /* WIN32 */

#include "est.h"

int ossl_verify_cb(int ok, X509_STORE_CTX *ctx);
LIBEST_TEST_API void ossl_dump_ssl_errors(void);
EST_ERROR ossl_init_cert_store (X509_STORE *store,
                                unsigned char *raw1, int size1);

#endif
