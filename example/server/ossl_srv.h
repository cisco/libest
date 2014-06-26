/*------------------------------------------------------------------
 * ossl_srv.h - Entry point definitions into the OpenSSL
 *              interface for EST server operations. 
 *
 * November, 2012
 *
 * Copyright (c) 2012 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
// Copyright (c) Siemens AG, 2014
// 2014-04-23 added read_cert_pkcs7

#ifndef HEADER_OSSL_SRV_H 
#define HEADER_OSSL_SRV_H 

BIO * read_cert_pkcs7(char *cert_file);
BIO * ossl_simple_enroll(unsigned char *p10buf, int p10len);

#endif
