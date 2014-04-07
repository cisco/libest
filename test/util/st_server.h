/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * August, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
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
void st_enable_http_digest_auth();
void st_enable_http_basic_auth();
void st_enable_pop(void);
void st_disable_pop(void);
void st_disable_http_auth(void);
void st_disable_csr_cb();
void st_set_csrattrs(char *value);
#endif

