/*------------------------------------------------------------------
 * test_utils.h - General purpose utilities used by all the test code
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#ifndef WIN32
#define SLEEP(x) sleep(x)
#else
#define SLEEP(x) Sleep(x*1000)
#endif 

#define LOG_FUNC_NM \
    do { \
	printf("\nEnter function %s\n", __FUNCTION__); \
	fflush(stdout); \
    } while (0)

int read_binary_file(char *filename, unsigned char **contents);
int write_binary_file(char *filename, unsigned char *contents, int len);
int grep(char *filename, char *string); 
BIO *open_tcp_socket(char *ipaddr, char *port);
BIO *open_tcp_socket_ipv4(char *ipaddr, char *port);
EVP_PKEY *read_private_key(char *key_file);
EVP_PKEY *read_protected_private_key(const char *key_file, pem_password_cb *cb);
#endif


