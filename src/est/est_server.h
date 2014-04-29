/*------------------------------------------------------------------
 * est_server.h - Private declarations for EST server  
 *
 * May, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef HEADER_EST_SERVER_H 
#define HEADER_EST_SERVER_H 


/*
 * These prototypes are private to est_server.c and are
 * not part of the public API.
 */
void est_send_http_error(EST_CTX *ctx, void *http_ctx, int fail_code);
int est_enroll_auth(EST_CTX *ctx, void *http_ctx, SSL *ssl, int reenroll); 
int est_handle_cacerts(EST_CTX *ctx, void *http_ctx); 
int est_tls_uid_auth(EST_CTX *ctx, SSL *ssl, X509_REQ *req); 
X509_REQ * est_server_parse_csr(unsigned char *pkcs10, int pkcs10_len);
int est_server_check_csr(X509_REQ *req); 
EST_ERROR est_server_send_http_retry_after(EST_CTX *ctx, void *http_ctx, int delay);

#endif

