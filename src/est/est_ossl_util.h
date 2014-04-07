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

#include "est.h"

int ossl_verify_cb(int ok, X509_STORE_CTX *ctx);
void ossl_dump_ssl_errors(void);
EST_ERROR ossl_init_cert_store (X509_STORE *store,
                                unsigned char *raw1, int size1);

#endif
