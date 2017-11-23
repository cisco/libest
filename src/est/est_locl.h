/*------------------------------------------------------------------
 * est/est_locl.h - Private declarations for EST stack
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014, 2016, 2017 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */

#ifndef HEADER_EST_LOCL_H
#define HEADER_EST_LOCL_H
#include <openssl/srp.h>
#include "est_client_proxy.h"

/* Windows only option: Export local API functions for testing */
#ifdef WIN32
#ifdef DEVTEST
#ifdef DT_EXPORTS
#define LIBEST_TEST_API __declspec(dllexport) 
#else
#define LIBEST_TEST_API __declspec(dllimport) 
#endif /* DT_EXPORTS */ 
#else
#define LIBEST_TEST_API
#endif /* DEVTEST */ 
#else
#define LIBEST_TEST_API
#endif /* WIN32 */ 

#ifndef WIN32
#include "est_config.h"
#endif 
/*
 * Version identifiers.  These should be updated appropriately
 * for each release.
 */
#define EST_API_LEVEL       4  //Update this whenever there's a change to the public API
#define EST_VER_STRING      PACKAGE_STRING

#define EST_URI_PATH_PREFIX_MAX_LEN (16)
/* one segment for the possible CA path seg and one for the operation path */
#define EST_URI_MAX_LEN     (EST_URI_PATH_PREFIX_MAX_LEN+EST_MAX_PATH_SEGMENT_LEN+EST_MAX_PATH_SEGMENT_LEN)
#define EST_BODY_MAX_LEN    16384
#define EST_CA_MAX	    2000000
#define EST_TLS_UID_LEN     17
#define EST_RAW_CSR_LEN_MAX 8192

#define EST_MAX_CONTENT_LEN 8192

/* The retry-after values below are in seconds */
#define EST_RETRY_PERIOD_DEF	3600 
#define EST_RETRY_PERIOD_MIN	60 
#define EST_RETRY_PERIOD_MAX	3600*48 

#define EST_TLS_VERIFY_DEPTH	    7
/*
 * Cipher suite filter for OpenSSL
 */
#define EST_CIPHER_LIST             "ALL:!aNULL:!eNULL:!SSLv2:!EXPORT:!SRP"
#define EST_CIPHER_LIST_SRP_SERVER  "ALL:!eNULL:!SSLv2:!EXPORT:SRP"
#define EST_CIPHER_LIST_SRP_ONLY    "SRP:!aRSA:!aDSS"
#define EST_CIPHER_LIST_SRP_AUTH    "SRP"
/*
 * SRP
 */
#define EST_SRP_STRENGTH_MIN	    SRP_MINIMAL_N  /* from OpenSSL */
/*
 * HTTP
 */
#define EST_HTTP_STAT_202	    202 
#define EST_HTTP_STAT_204	    204 
#define EST_HTTP_STAT_400	    400 
#define EST_HTTP_STAT_401	    401
#define EST_HTTP_STAT_404	    404
#define EST_HTTP_STAT_423	    423

#define EST_HTTP_STAT_202_TXT	    "Accepted" 
#define EST_HTTP_STAT_204_TXT	    "No Content" 
#define EST_HTTP_STAT_400_TXT	    "Bad Request" 
#define EST_HTTP_STAT_401_TXT	    "Unauthorized" 
#define EST_HTTP_STAT_404_TXT	    "Not Found" 
#define EST_HTTP_STAT_423_TXT	    "Locked"

#define EST_HTTP_MAX_REASON_PHRASE  256
#define EST_HTTP_HDR_MAX            1024 
#define EST_HTTP_HDR_200            "HTTP/1.1 200 OK"
#define EST_HTTP_HDR_STAT_200       "Status: 200 OK"
#define EST_HTTP_HDR_202            "HTTP/1.1 202 " EST_HTTP_STAT_202_TXT
#define EST_HTTP_HDR_STAT_202       "Status: 202 "  EST_HTTP_STAT_202_TXT
#define EST_HTTP_HDR_204            "HTTP/1.1 204 " EST_HTTP_STAT_204_TXT
#define EST_HTTP_HDR_400            "HTTP/1.1 400 " EST_HTTP_STAT_400_TXT
#define EST_HTTP_HDR_401            "HTTP/1.1 401 " EST_HTTP_STAT_401_TXT
#define EST_HTTP_HDR_404            "HTTP/1.1 404 " EST_HTTP_STAT_404_TXT
#define EST_HTTP_HDR_423            "HTTP/1.1 423 " EST_HTTP_STAT_423_TXT
#define EST_HTTP_HDR_CT             "Content-Type"
#define EST_HTTP_HDR_CE             "Content-Transfer-Encoding"
#define EST_HTTP_HDR_CL             "Content-Length"
#define EST_HTTP_HDR_AUTH           "WWW-Authenticate"
#define EST_HTTP_HDR_RETRY_AFTER    "Retry-After"
#define EST_HTTP_HDR_EOL            "\r\n"

#define EST_HTTP_CT_PKCS7           "application/pkcs7-mime"
#define EST_HTTP_CT_PKCS7_CO        "application/pkcs7-mime; smime-type=certs-only"
#define EST_HTTP_CT_CSRATTRS        "application/csrattrs"
#define EST_HTTP_CE_BASE64          "base64"
#define EST_CSRATTRS_POP            "MAsGCSqGSIb3DQEJBw=="
#define EST_CSRATTRS_POP_LEN         20

#define EST_HTTP_HDR_EST_CLIENT     "Cisco EST client 2.0 with BRSKI"

#define EST_HTTP_REQ_DATA_MAX       4096
#define EST_HTTP_REQ_TERMINATOR_LEN 5
#define EST_HTTP_REQ_TOTAL_LEN      EST_HTTP_HDR_MAX+EST_HTTP_REQ_DATA_MAX+EST_HTTP_REQ_TERMINATOR_LEN

#define EST_MAX_MD5_DIGEST_STR_LEN  33  

/*
 * HTTP error responses
 */
#define EST_BODY_BAD_PKCS10     "Invalid or corrupted pkcs10 request.\n"
#define EST_BODY_UNAUTHORIZED   "The server was unable to authorize the request.\n"
#define EST_BODY_BAD_METH       "Invalid HTTP method used.  Either GET or POST required depending on the request type.\n"
#define EST_BODY_BAD_SSL        "An unknown TLS error has occured.\n"
#define EST_BODY_UNKNOWN_ERR    "An unknown error has occured.\n"
#define EST_BODY_NOT_FOUND      "Requested content is currently not available on the server.\n"


/*
 * URI definitions
 */
#define EST_GET_CACERTS         "cacerts"
#define EST_GET_CSRATTRS        "csrattrs"
#define EST_SIMPLE_ENROLL       "simpleenroll"
#define EST_SIMPLE_REENROLL     "simplereenroll"
#define WELL_KNOWN_SEGMENT      ".well-known"
#define WELL_KNOWN_SEGMENT_LEN  11
#define EST_SEGMENT             "est"
#define EST_SEGMENT_LEN         3
#define EST_PATH_PREFIX         "/"WELL_KNOWN_SEGMENT"/"EST_SEGMENT
#define EST_SIMPLE_ENROLL_URI   "/.well-known/est/simpleenroll"
#define EST_RE_ENROLL_URI       "/.well-known/est/simplereenroll"
#define EST_CSR_ATTRS_URI       "/.well-known/est/csrattrs"
#define EST_CACERTS_URI         "/.well-known/est/cacerts"
#define EST_KEYGEN_URI          "/.well-known/est/serverkeygen"

/*
 * BRSKI Support
 */
#define EST_BRSKI_GET_VOUCHER    "requestvoucher"
#define EST_BRSKI_VOUCHER_STATUS "voucher_status"
#define EST_BRSKI_ENROLL_STATUS  "enrollstatus"
#define EST_BRSKI_GET_VOUCHER_URI EST_PATH_PREFIX"/"EST_BRSKI_GET_VOUCHER
#define EST_BRSKI_VOUCHER_STATUS_URI EST_PATH_PREFIX"/"EST_BRSKI_VOUCHER_STATUS
#define EST_BRSKI_ENROLL_STATUS_URI EST_PATH_PREFIX"/"EST_BRSKI_ENROLL_STATUS

#define EST_BRSKI_CT_VREQ_SIGNED "application/pkcs7-mime; smime-type=voucher-request"
#define EST_BRSKI_CT_VREQ "application/json"
#define EST_BRSKI_CT_VRSP "application/voucher+cms"
#define EST_BRSKI_CT_STATUS "application/json"

#define BRSKI_ENABLED 1
#define EST_BRSKI_CLIENT_RETRY_MAX      60

/* The server retry-after values below are in seconds */
#define EST_BRSKI_RETRY_PERIOD_DEF	30 
#define EST_BRSKI_RETRY_PERIOD_MIN	1 
#define EST_BRSKI_RETRY_PERIOD_MAX	70


#define EST_BEARER_TOKEN_STR    "Bearer "

typedef enum {
    EST_AUTH_HDR_GOOD = 0,
    EST_AUTH_HDR_MISSING = 1,
    EST_AUTH_HDR_BAD = 2
} EST_HTTP_AUTH_HDR_RESULT;

typedef enum {
    EST_UNAUTHORIZED,
    EST_HTTP_AUTH,
    EST_HTTP_AUTH_PENDING,
    EST_CERT_AUTH,
    EST_SRP_AUTH,
} EST_AUTH_STATE;


typedef enum {
    EST_OP_SIMPLE_ENROLL,
    EST_OP_SIMPLE_REENROLL,
    EST_OP_CACERTS,
    EST_OP_CSRATTRS,
#if ENABLE_BRSKI
    EST_OP_BRSKI_REQ_VOUCHER,
    EST_OP_BRSKI_VOUCHER_STATUS,
    EST_OP_BRSKI_ENROLL_STATUS,
#endif    
    EST_OP_MAX
} EST_OPERATION;

typedef struct {
    EST_OPERATION op;
    char          *uri;
    char          *content_type;
    int           length;
} EST_OP_DEF;

#define INITIAL_PROXY_CLIENT_CTXS 8

typedef struct {
    unsigned long threadid;
    EST_CTX *client_ctx;
} CLIENT_CTX_LU_NODE_T;

typedef struct mg_context EST_MG_CONTEXT;

/*
 * This context is global for the EST instance, which could
 * be a client, server, or both (proxy).  It stores global
 * items such as the certificate chain used for peer
 * verification.
 */
struct est_ctx {
    EST_MODE est_mode;        /* operational mode of the instance: client or server */
    unsigned char   *ca_certs;
    int              local_cacerts_processing;
    int              ca_certs_len;
    unsigned char   *retrieved_ca_certs;
    int              retrieved_ca_certs_len;
    unsigned char   *enrolled_client_cert;
    int              enrolled_client_cert_len;
    unsigned char   *server_csrattrs;
    int              server_csrattrs_len;
    unsigned char   *retrieved_csrattrs;
    int              retrieved_csrattrs_len;
    X509_STORE      *trusted_certs_store;
    char realm[MAX_REALM+1];
    SSL_CTX         *ssl_ctx;
    int              enable_crl;

    char             token_error[MAX_TOKEN_ERROR+1];
    char             token_error_desc[MAX_TOKEN_ERROR_DESC+1];
    
    /*
     * Callbacks requried for server mode operation
     */
    int (*est_enroll_pkcs10_cb)(unsigned char *pkcs10, int p10_len, 
	                        unsigned char **pkcs7, int *cert_len,
				char *user_id, X509 *peer_cert,
                                char *path_seg, void *ex_data);
    int (*est_reenroll_pkcs10_cb)(unsigned char *pkcs10, int p10_len, 
	                          unsigned char **pkcs7, int *cert_len,
				  char *user_id, X509 *peer_cert,
                                  char *path_seg, void *ex_data);
    unsigned char *(*est_get_cacerts_cb)(int *cacerts_len, char *path_seg,
                                         void *ex_data);
    unsigned char *(*est_get_csr_cb)(int *csr_len, char *path_seg, X509 *peer_cert, void *ex_data);
    int (*est_http_auth_cb)(struct est_ctx *ctx, EST_HTTP_AUTH_HDR *ah, 
	                    X509 *peer_cert, char *path_seg, void *ex_data);

    /*
     * BRSKI based call backs
     */
    brski_voucher_req_cb est_brski_voucher_req_cb;
    brski_voucher_status_cb est_brski_voucher_status_cb;    
    brski_enroll_status_cb est_brski_enroll_status_cb;
    
    /*
     * Client mode configuration options
     */
    char est_server[EST_MAX_SERVERNAME_LEN+1];
    int est_port_num;
    char *uri_path_segment;
    X509 *client_cert;
    char *client_cert_ser_num;
    EVP_PKEY   *client_key;
    EST_HTTP_AUTH_CRED_RC (*auth_credentials_cb)(EST_HTTP_AUTH_HDR *auth_credentials);
    EST_HTTP_AUTH_MODE auth_mode;
    char userid[MAX_UIDPWD+1];
    char password[MAX_UIDPWD+1];
    char s_nonce[MAX_NONCE+1];
    char c_nonce[MAX_NONCE+1];
    SSL_SESSION *sess;
    int  read_timeout;
    int  (*manual_cert_verify_cb)(X509 *cur_cert, int openssl_cert_error);
    const EVP_MD *signing_digest;
    int  retry_after_delay;
    time_t retry_after_date;

    /* Client mode proxy configuration */
    int use_proxy;
    EST_CLIENT_PROXY_PROTO proxy_proto;
    char proxy_server[EST_MAX_SERVERNAME_LEN + 1];
    unsigned short int proxy_port;
    unsigned int proxy_auth;
    char proxy_username[MAX_UIDPWD+1];
    char proxy_password[MAX_UIDPWD+1];

    tcw_sock_t tcw_sock;
    int tcw_sock_connected;

    int est_client_initialized;
    
    /*
     * BRSKI mode
     */
    /* client */
    int              brski_mode;
    unsigned char   *brski_retrieved_voucher;
    int              brski_retrieved_voucher_len;
    unsigned char   *brski_retrieved_cacert;
    int              brski_retrieved_cacert_len;

    /* server */
    int brski_retry_period;  /* Number of seconds client should wait
                                to attempt voucher request */    
    
    /*
     * The following are used for server and/or proxy mode
     */
    EST_MG_CONTEXT *mg_ctx;
    int server_read_timeout;
    X509 *server_cert;
    EVP_PKEY *server_priv_key;
    int server_enable_pop; /* enable proof-of-possession check */
    int client_force_pop;  /* force proof-of-possession gen at the client */
    EST_HTTP_AUTH_REQUIRED require_http_auth;  
			   /* require http authentication of the client
			      even when TLS auth was performed */
    int csr_pop_present;  /* proof-of-possession already in csr attributes */
    int csr_pop_required; /* proof-of-possession required in enroll */
    SSL_CTX         *ssl_ctx_proxy;
    DH	            *dh_tmp;  //temp DH parms for TLS 
    int retry_period;  /* Number of seconds client should wait
			  to attempt re-enrolling a CSR */
    int ecdhe_nid;     /* Specifies the ECC curve to use for
			  ephemeral EC diffie-hellman */
    unsigned char *ca_chain_raw;
    int   ca_chain_raw_len;
    CLIENT_CTX_LU_NODE_T *client_ctx_array;
    void *ex_data;
    int enable_srp;
    int (*est_srp_username_cb)(SSL *s, int *ad, void *arg);

    int last_http_status;
    int enforce_csrattrs; /* Used to force the client to provide the CSR attrs in the CSR */
};

#define EST_MAX_ATTR_LEN    128 
/*
 * This is used to build a linked list of the attributes
 * present in the client's CSR.
 */
typedef struct est_oid_list {
    char		    oid[EST_MAX_ATTR_LEN];
    struct est_oid_list    *next;
} EST_OID_LIST;

/*
 * Index used to link the EST Ctx into the SSL structures
 */
int e_ctx_ssl_exdata_index;


LIBEST_TEST_API void est_log (EST_LOG_LEVEL lvl, char *format, ...);
LIBEST_TEST_API void est_log_backtrace (void);

#ifdef WIN32
#ifndef EST_LOG_INFO
#define EST_LOG_INFO(...) do { \
	est_log(EST_LOG_LVL_INFO, "\n***EST [INFO][%s:%d]--> ", \
	__FUNCTION__, __LINE__); \
	est_log(EST_LOG_LVL_INFO, __VA_ARGS__); \
} while (0)
#endif

#ifndef EST_LOG_WARN
#define EST_LOG_WARN(...) do { \
	est_log(EST_LOG_LVL_WARN, "\n***EST [WARNING][%s:%d]--> ", \
	__FUNCTION__, __LINE__); \
	est_log(EST_LOG_LVL_WARN, __VA_ARGS__); \
	est_log_backtrace(); \
} while (0)
#endif

#ifndef EST_LOG_ERR
#define EST_LOG_ERR(...) do { \
	est_log(EST_LOG_LVL_ERR, "\n***EST [ERROR][%s:%d]--> ", \
	__FUNCTION__, __LINE__); \
	est_log(EST_LOG_LVL_ERR, __VA_ARGS__); \
	est_log_backtrace(); \
} while (0)
#endif
#else
#ifndef EST_LOG_INFO
#define EST_LOG_INFO(format, args ...) do { \
        est_log(EST_LOG_LVL_INFO, "***EST [INFO][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
} while (0)
#endif

#ifndef EST_LOG_WARN
#define EST_LOG_WARN(format, args ...) do { \
        est_log(EST_LOG_LVL_WARN, "***EST [WARNING][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
        est_log_backtrace(); \
} while (0)
#endif

#ifndef EST_LOG_ERR
#define EST_LOG_ERR(format, args ...) do { \
        est_log(EST_LOG_LVL_ERR, "***EST [ERROR][%s:%d]--> " format "\n", \
                __func__, __LINE__, ##args); \
        est_log_backtrace(); \
} while (0)
#endif 
#endif /* WIN32 */

/*
 * Not every CRT library has an implementation of strndup.  For example,
 * Windows.  In this case we use an internal version that originally
 * came with the Mongoose version we used for HTTP server.
 */
#ifdef WIN32
#define STRNDUP mg_strndup
#else
#define STRNDUP strndup
#endif

/* From est.c */
char * est_get_tls_uid(SSL *ssl, int is_client);
LIBEST_TEST_API EST_ERROR est_load_ca_certs(EST_CTX *ctx, unsigned char *raw, int size);

LIBEST_TEST_API EST_ERROR est_load_trusted_certs(EST_CTX *ctx, unsigned char *certs, int certs_len);
void est_log(EST_LOG_LEVEL lvl, char *format, ...);
LIBEST_TEST_API void est_log_version(void);
void est_hex_to_str(char *dst, unsigned char *src, int len);
int est_base64_encode (const char *src, int actual_src_len, char *dst, int max_dst_len);
LIBEST_TEST_API int est_base64_decode(const char *src, char *dst, int max_len);

/* From est_server.c */
int est_http_request(EST_CTX *ctx, void *http_ctx,
                     char *method, char *uri,
                     char *body, int body_len, const char *ct);

/* From est_client.c */
LIBEST_TEST_API EST_ERROR est_client_connect(EST_CTX *ctx, SSL **ssl);
int est_client_send_enroll_request(EST_CTX *ctx, SSL *ssl, BUF_MEM *bptr,
                                   unsigned char *pkcs7, int *pkcs7_len,
				   int reenroll);
LIBEST_TEST_API void est_client_disconnect(EST_CTX *ctx, SSL **ssl);
LIBEST_TEST_API int est_client_set_cert_and_key(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key);
EST_ERROR est_client_set_uid_pw(EST_CTX *ctx, const char *uid, const char *pwd);

/* From est_client_http.c */
EST_ERROR est_io_get_response (EST_CTX *ctx, SSL *ssl, EST_OPERATION op,
                         unsigned char **buf, int *payload_len);

/* From est_proxy.c */
LIBEST_TEST_API EST_ERROR est_proxy_http_request(EST_CTX *ctx, void *http_ctx,
                           char *method, char *uri,
                           char *body, int body_len, const char *ct);
void proxy_cleanup(EST_CTX *p_ctx);
EST_ERROR est_asn1_parse_attributes(const char *p, int len, int *offset);
EST_ERROR est_is_challengePassword_present(const char *base64_ptr, int b64_len, int *offset);
EST_ERROR est_add_challengePassword(const char *base64_ptr, int b64_len, char **new_csr, int *pop_len);
LIBEST_TEST_API EST_ERROR est_proxy_retrieve_cacerts (EST_CTX *ctx, unsigned char **cacerts_rtn,
                                      int *cacerts_rtn_len);
EST_ERROR est_send_csrattr_data(EST_CTX *ctx, char *csr_data, int csr_len, void *http_ctx);
void cleanse_auth_credentials(EST_HTTP_AUTH_HDR *auth_cred);
EST_ERROR est_parse_uri (char *uri, EST_OPERATION *operation,
                         char **path_seg);
LIBEST_TEST_API EST_ERROR est_store_path_segment (EST_CTX *ctx, char *path_segment,
                                  int path_segment_len);
EST_OPERATION est_parse_operation (char *op_path);
int est_strcasecmp_s (char *s1, char *s2);

char *skip(char **buf, const char *delimiters);
char *skip_quoted(char **buf, const char *delimiters, const char *whitespace,
                  char quotechar);
size_t est_strcspn(const char * str1,const char * str2);
#endif
