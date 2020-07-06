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

/*
 * Indicate whether a pointer is to a cert or a csr
 */
typedef enum {
    EST_CERT = 1,
    EST_CSR
} EST_CERT_OR_CSR;

EST_ERROR est_get_subj_fld_from_cert (void *cert_csr,
                                      EST_CERT_OR_CSR cert_or_csr,
                                      char *name, int len);
int ossl_verify_cb(int ok, X509_STORE_CTX *ctx);
LIBEST_TEST_API void ossl_dump_ssl_errors(void);
EST_ERROR ossl_init_cert_store(X509_STORE *store,
                               unsigned char *raw1, int size1);

#endif
