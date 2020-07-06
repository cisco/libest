/*------------------------------------------------------------------
 * st_server.h - Public API for simple single-threaded EST server
 *
 * August, 2013
 *
 * Copyright (c) 2013, 2016, 2018 by cisco Systems, Inc.
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
int st_start_crl(int listen_port,
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
int st_start_events(int tcp_port,
                    char *certfile,
                    char *keyfile,
                    char *realm,
                    char *ca_chain_file,
                    char *trusted_certs_file,
                    char *ossl_conf_file,
                    int simulate_manual_enroll,
                    int enable_pop,
                    int ec_nid);
int st_start_coap (int listen_port,
                   char *certfile,
                   char *keyfile,
                   char *realm,
                   char *ca_chain_file,
                   char *trusted_certs_file,
                   char *ossl_conf_file,
                   int simulate_manual_enroll,
                   int enable_pop,
                   int ec_nid);
int st_start_coap_sessions (int listen_port,
                            char *certfile,
                            char *keyfile,
                            char *realm,
                            char *ca_chain_file,
                            char *trusted_certs_file,
                            char *ossl_conf_file,
                            int simulate_manual_enroll,
                            int enable_pop,
                            int ec_nid,
                            int max_sessions);
int st_start_coap_events(int tcp_port,
                         char *certfile,
                         char *keyfile,
                         char *realm,
                         char *ca_chain_file,
                         char *trusted_certs_file,
                         char *ossl_conf_file,
                         int simulate_manual_enroll,
                         int enable_pop,
                         int ec_nid);
int st_start_coap_nocacerts(int tcp_port,
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
void st_enable_http_token_auth();
void st_enable_http_auth();
void st_set_token(char *value);
void st_enable_pop(void);
void st_disable_pop(void);
void st_enable_crl(void);
void st_disable_http_auth(void);
void st_disable_csr_cb();
void st_set_csrattrs(char *value);
void st_disable_cacerts_cb();
void st_null_cacerts_cb();
void st_set_http_auth_optional();
void st_set_http_auth_required();
void st_enable_csrattr_enforce();
void st_set_read_timeout(int timeout);
void st_write_csr(int state);
void st_csr_filename(char *incoming_name);
int st_set_brski_mode();
int st_set_brski_retry_mode(int enable_retry, int retry_delay, int retry_count);
int st_set_brski_nonce_mode(int send_nonce, int nonce_too_long,
                            int nonce_mismatch);
int st_set_brski_serial_num_mode(int send_serial_num, int serial_num_too_long,
                                 int serial_num_mismatch);
int st_set_brski_masa_credentials(char *masa_root_ca_file, char *masa_priv_key_file);
int st_enable_enhanced_cert_auth(int nid, char *ah_pwd,
                                 EST_ECA_CSR_CHECK_FLAG csr_check_flag);
int st_enhanced_cert_auth_add_mfg_info(char *mfg_name, int mfg_subj_field_nid,
                                       unsigned char *truststore_buf,
                                       int truststore_buf_len);
int st_disable_enhanced_cert_auth(void);
int st_server_set_http_auth_cb(int (*cb)(EST_CTX *ctx,
                                         EST_HTTP_AUTH_HDR *ah,
                                         X509 *peer_cert,
                                         char *path_seg,
                                         void *app_data));
void st_set_dtls_handshake_timeout(int timeout);


/*
 * Event notification callback testing infrastructure.
 */
typedef struct st_est_event_cb_table_ {

    /*
     * Specifies the address of the EST error event callback function
     * to register.
     */
    est_est_err_event_cb_t est_err_event_cb;

    /*
     * Specifies the address of the SSL protocol error event callback
     * function to register.
     */
    est_ssl_proto_err_event_cb_t ssl_proto_err_event_cb;

    /*
     * Specifies the address of the EST enroll request event callback
     * function to register.
     */
    est_enroll_req_event_cb_t enroll_req_event_cb;

    /*
     * Specifies the address of the EST enroll response event callback
     * function to register.
     */
    est_enroll_rsp_event_cb_t enroll_rsp_event_cb;

    /*
     * Specifies the address of the EST enroll authentication result event callback
     * function to register.
     */
    est_enroll_auth_result_event_cb_t enroll_auth_result_event_cb;

    /*
     * Specifies the address of the EST endpoint request event callback
     * function to register.
     */
    est_endpoint_req_event_cb_t endpoint_req_event_cb;

} st_est_event_cb_table_t;

extern void st_set_est_event_callbacks(st_est_event_cb_table_t *event_cb_table_ptr);
extern void st_set_default_est_event_callbacks();
extern void st_disable_est_event_callbacks();

#ifdef WIN32
void st_toggle_ipv6();
#endif

EST_ERROR st_server_enable_performance_timers();
EST_ERROR st_server_disable_performance_timers();

#endif

