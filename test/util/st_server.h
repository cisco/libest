/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * August, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef ST_SERVER_H
#define ST_SERVER_H
void st_stop(void);
int st_start(int tcp_port,
	     char *certfile,
	     char *keyfile,
	     char *realm,
	     char *ca_chain_file,
	     char *trusted_certs_file,
	     char *ossl_conf_file,
	     int simulate_manual_enroll,
	     int enable_pop,
	     int ec_nid);
int st_start_nocacerts (int listen_port,
                        char *certfile,
                        char *keyfile,
                        char *realm,
                        char *ca_chain_file,
                        char *trusted_certs_file,
                        char *ossl_conf_file,
                        int simulate_manual_enroll,
                        int enable_pop,
                        int ec_nid);
int st_start_tls10(int tcp_port,
	     char *certfile,
	     char *keyfile,
	     char *realm,
	     char *ca_chain_file,
	     char *trusted_certs_file,
	     char *ossl_conf_file,
	     int simulate_manual_enroll,
	     int enable_pop,
	     int ec_nid);
int st_start_srp (int listen_port,
	          char *certfile,
	          char *keyfile,
	          char *realm,
	          char *ca_chain_file,
	          char *trusted_certs_file,
	          char *ossl_conf_file,
	          int enable_pop,
		  char *vfile);
int st_start_srp_tls10 (int listen_port,
                  char *certfile,
                  char *keyfile,
                  char *realm,
                  char *ca_chain_file,
                  char *trusted_certs_file,
                  char *ossl_conf_file,
                  int enable_pop,
                  char *vfile);
void st_enable_http_digest_auth();
void st_enable_http_basic_auth();
void st_enable_http_token_auth();
void st_enable_http_auth();
void st_set_token(char *value);
void st_enable_pop(void);
void st_disable_pop(void);
void st_enable_crl(void);
void st_disable_http_auth(void);
void st_disable_csr_cb();
void st_set_csrattrs(char *value);
void st_set_http_auth_optional();
void st_set_http_auth_required();
void st_enable_csrattr_enforce();
void st_set_read_timeout(int timeout);
void st_write_csr(int state);
void st_csr_filename(char *incoming_name);
#ifdef WIN32
void st_toggle_ipv6();
#endif

#endif

