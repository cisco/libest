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

char *ossl_error_string(int err_code);
int ossl_verify_cb(int ok, X509_STORE_CTX *ctx);
void ossl_dump_ssl_errors(void);
EST_ERROR ossl_init_cert_store (X509_STORE *store,
                                unsigned char *raw1, int size1);
unsigned char *est_ossl_BIO_copy_data(BIO *out, int *data_lenp);
int X509_REQ_get_extension(X509_REQ *req, int nid, int lastpos, STACK_OF(X509_EXTENSION) **pexts, 
			   int delete_exts, int *pnid_deleted_exts);
unsigned char *ossl_get_csr_subject_alt_name (const X509_REQ *csr); 
unsigned char *ossl_get_cert_subject_alt_name(const X509 *cert);
unsigned char *ossl_get_extension_value (const X509_EXTENSION *ext);
int ossl_name_entries_inclusion (X509_NAME *name1, X509_NAME *name2);
EST_ERROR ossl_check_subjects_agree(const X509_REQ *csr, const X509 *cert);

#endif
