/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * October, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef ST_PROXY_H
#define ST_PROXY_H
void st_proxy_stop();
int st_proxy_start(int listen_port,
	           char *certfile,
	           char *keyfile,
	           char *realm,
	           char *ca_chain_file,
	           char *trusted_certs_file,
		   char *userid,
		   char *password,
		   char *server,
		   int server_port,
	           int enable_pop,
	           int ec_nid);
void st_proxy_enable_pop(void);
void st_proxy_disable_pop(void);
void st_proxy_set_auth (EST_HTTP_AUTH_MODE auth_mode);
int st_proxy_http_disable (int disable);
void st_proxy_set_read_timeout (int timeout);
#endif

