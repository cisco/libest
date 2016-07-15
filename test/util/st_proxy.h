/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * October, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
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
int st_proxy_start_nocacerts(int listen_port,
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
int st_proxy_start_srp(int listen_port,
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
		   char *vfile);
int st_proxy_start_tls10 (int listen_port,
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
int st_proxy_start_srp_tls10 (int listen_port,
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
                    char *vfile);
int st_proxy_start_token (int listen_port,
                          char *certfile,
                          char *keyfile,
                          char *realm,
                          char *ca_chain_file,
                          char *trusted_certs_file,
                          char *userid,
                          char *password,
                          char *server,
                          int server_port,
                          int enable_pop);
void st_proxy_enable_pop(void);
void st_proxy_disable_pop(void);
void st_proxy_set_auth(EST_HTTP_AUTH_MODE auth_mode);

void st_proxy_enable_http_basic_auth();
void st_proxy_enable_http_digest_auth();
void st_proxy_enable_http_token_auth();
void st_proxy_set_srv_valid_token(char *value);
void st_proxy_set_clnt_token_cred(char *value);

int st_proxy_http_disable(int disable);
void st_proxy_set_http_auth_optional();
void st_proxy_set_http_auth_required();
void st_proxy_set_read_timeout(int timeout);
void st_proxy_disable_http_auth();
#endif

