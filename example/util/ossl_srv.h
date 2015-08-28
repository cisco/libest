/*------------------------------------------------------------------
 * ossl_srv.h - Entry point definitions into the OpenSSL
 *              interface for EST server operations. 
 *
 * November, 2012
 *
 * Copyright (c) 2012 by cisco Systems, Inc.
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 *------------------------------------------------------------------
 */

// 2015-08-14 removed duplication of ossl_srv.{c,h}, moving them to example/util
// 2014-04-23 added read_cert_pkcs7

#ifndef HEADER_OSSL_SRV_H 
#define HEADER_OSSL_SRV_H 

BIO * read_cert_pkcs7(char *cert_file);
BIO * ossl_simple_enroll(const unsigned char *p10buf, int p10len, const char *configfile);

#endif
