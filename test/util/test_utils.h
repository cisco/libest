/*------------------------------------------------------------------
 * test_utils.h - General purpose utilities used by all the test code
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016, 2018 by cisco Systems, Inc.
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
int get_subj_fld_from_cert(void *cert_csr, int cert_or_csr, char *name,
                           int len);
int coap_mode_supported(char *cert_key_file, char *trusted_certs_file,
                        char *cacerts_file, int test_port);
int kill_process (pid_t pid, int max_time_msec, int time_to_sleep_msec);
int read_x509_cert_and_key_file(char *cert_file_path, char *pkey_file_path,
                                X509 **cert, EVP_PKEY **pkey);
#endif


