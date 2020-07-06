/*------------------------------------------------------------------
 * est_server.h - Private declarations for EST server  
 *
 * May, 2013
 *
 * Copyright (c) 2013, 2016, 2018 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef HEADER_EST_SERVER_H 
#define HEADER_EST_SERVER_H

/*
 * Indicate whether or not to bypass the base64 decode on a CSR parse
 */
typedef enum {
    EST_CSR_DECODE = 1,
    EST_CSR_DECODE_BYPASS
} EST_CSR_BASE64_DECODE;

/*
 * These prototypes are private to est_server.c and are
 * not part of the public API.
 */
void est_send_http_error(EST_CTX *ctx, void *http_ctx, int fail_code);
EST_AUTH_STATE est_enroll_auth(EST_CTX *ctx, void *http_ctx, SSL *ssl,
                               char *path_seg, EST_ENROLL_REQ_TYPE enroll_req, char *csr_buf,
                               int csr_buf_len, X509_REQ **csr_p);
int est_handle_cacerts (EST_CTX *ctx, unsigned char *ca_certs, int ca_certs_len,
                        void *http_ctx, char *path_seg);
int est_tls_uid_auth(EST_CTX *ctx, SSL *ssl, X509_REQ *req); 
X509_REQ * est_server_parse_csr(unsigned char *pkcs10, int pkcs10_len, EST_CSR_BASE64_DECODE base64_decode);
int est_server_check_csr(X509_REQ *req);
EST_ERROR est_server_send_http_retry_after(EST_CTX *ctx, void *http_ctx, int delay);

void est_invoke_endpoint_req_event_cb(EST_CTX *ctx, X509 *peer_cert, SSL *ssl,
                                      void *addr_info, const char *uri,
                                      EST_ENDPOINT_EVENT_TYPE event_type);

EST_ERROR est_invoke_enroll_req_event_cb(EST_CTX *ctx, SSL *ssl, X509 *peer_cert,
                                         unsigned char *csr_buf, int csr_len,
                                         void *addr_info, char *path_seg, EST_ENROLL_REQ_TYPE enroll_req);

EST_ERROR est_invoke_enroll_rsp_event_cb(EST_CTX *ctx, SSL *ssl, X509 *peer_cert,
                                         unsigned char *csr_buf, int csr_len,
                                         void *addr_info, char *path_seg, EST_ENROLL_REQ_TYPE enroll_req,
                                         unsigned char *returned_cert, int returned_cert_len,
                                         EST_ERROR rc);
#endif

