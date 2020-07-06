/*------------------------------------------------------------------
 * utils.h - Generic functions used by all the example apps
 *
 * August, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#define MAX_UID_LEN 255
#define MAX_PWD_LEN 255

void ossl_dump_ssl_errors ();
int read_binary_file(char *filename, unsigned char **contents);
void write_binary_file(char *filename, unsigned char *contents, int len); 
void dumpbin(unsigned char *buf, int len);
EVP_PKEY *read_private_key(const char *key_file, pem_password_cb *cb);
EVP_PKEY *load_private_key (const unsigned char *key, int key_len, int format, pem_password_cb *cb);
#define load_clear_private_key_PEM(key) load_private_key((unsigned char*)(key),strlen(key),EST_FORMAT_PEM, NULL)
char *private_key_to_PEM (const EVP_PKEY* pkey, pem_password_cb *cb);
char *generate_private_EC_key (int curve_nid, pem_password_cb *cb);
char *generate_private_RSA_key (int key_size, pem_password_cb *cb);
#endif

