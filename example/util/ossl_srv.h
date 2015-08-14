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
#ifndef HEADER_OSSL_SRV_H 
#define HEADER_OSSL_SRV_H 

BIO * ossl_simple_enroll(unsigned char *p10buf, int p10len, char *configfile);

#endif
