/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * October, 2013
 *
 * Copyright (c) 2013, 2016, 2018, 2019 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#ifndef ST_PROXY_H
#define ST_PROXY_H
#include "st_server.h"

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
int st_proxy_start_coap(int listen_port,
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
                        int no_cacert_rsp,
                        int ec_nid);
int st_proxy_start_coap_sessions(int listen_port,
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
                                 int no_cacert_rsp,
                                 int ec_nid,
                                 int max_sessions);
int st_proxy_start_events(int listen_port,
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
int st_proxy_start_coap_events(int listen_port,
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
int st_proxy_start_pathseg_coap(int listen_port,
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
                                int ec_nid,
                                char *path_seg);
int st_proxy_start_pathseg(int listen_port,
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
                           int ec_nid,
                           char *path_seg);
int st_proxy_coap_start_nocacerts(int listen_port,
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
int st_proxy_enable_enhcd_cert_auth(int nid, char *ah_pwd,
                                    EST_ECA_CSR_CHECK_FLAG csr_check_flag);
int st_proxy_enhcd_cert_auth_add_mfg_info(char *mfg_name,
                                          int mfg_subj_field_nid,
                                          unsigned char *truststore_buf,
                                          int truststore_buf_len);
int st_proxy_disable_enhcd_cert_auth(void);
int st_proxy_set_http_auth_cb(int (*cb)(EST_CTX *ctx,
                                        EST_HTTP_AUTH_HDR *ah,
                                        X509 *peer_cert,
                                        char *path_seg,
                                        void *app_data));

extern void st_proxy_set_est_event_callbacks(st_est_event_cb_table_t *event_cb_table_ptr);
extern void st_proxy_set_default_est_event_callbacks();
extern void st_proxy_disable_est_event_callbacks();

extern void st_proxy_set_dtls_handshake_timeout(int timeout);

EST_ERROR st_proxy_enable_performance_timers();
EST_ERROR st_proxy_disable_performance_timers();
#endif

