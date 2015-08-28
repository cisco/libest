/*------------------------------------------------------------------
 * est/est.h - Public API for Enrollment over Secure Transport
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-07 added est_set_log_source() differentiating log prefixes for client/server/proxy
// 2015-08-07 simplified declaration of error codes and related strings, now less error-prone
// 2014-04-23 added EST_ERR_NO_CERT
// 2014-04-26 extended EST_SSL_READ_TIMEOUT_MAX

#ifndef HEADER_EST_H
#define HEADER_EST_H

#include "NonPosix.h"

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/srp.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define EST_MAX_FILE_LEN    (255)
#define EST_MAX_SERVERNAME_LEN    (255)
#define EST_PORTNUM_LEN          (sizeof(int))
#define EST_MAX_SERVERNAME_AND_PORT_LEN    (EST_MAX_SERVERNAME_LEN+EST_PORTNUM_LEN)
#define EST_MAX_CLIENT_CERT_LEN  (4096)

typedef enum {
    EST_SERVER,
    EST_CLIENT,
    EST_PROXY
} EST_MODE;


#define FOREACH_EST_ERROR(E) \
   E(EST_ERR_NO_CTX, "The EST_CTX* was not provided when invoking the function") \
   E(EST_ERR_NO_CSR, "The CSR was not provided when invoking the function") \
   E(EST_ERR_NO_CERT, "No valid X509 certificate was provided when invoking the function") \
   E(EST_ERR_NO_KEY, "The EVP_PKEY* was not provided when invoking the function") \
   E(EST_ERR_INVALID_PARAMETERS, "An invalid argument was provided to the function") \
   E(EST_ERR_LOAD_CACERTS, "The CA certificates provided were not loaded") \
   E(EST_ERR_LOAD_TRUST_CERTS, "The certificate chain of trusted certificates was not loaded") \
   E(EST_ERR_LOAD_CLIENT_CERT, "The certificate of the client could not be loaded") \
   E(EST_ERR_LOAD_CLIENT_PKEY, "The private key of the client could not be loaded") \
   E(EST_ERR_BAD_MODE, "An EST operation was attempted while using the wrong mode of operation.  The valid modes are client, server, and proxy.  Some EST operations may only be performed in certain modes.") \
   E(EST_ERR_BAD_PKCS10, "The PKCS10 CSR received from the client is invalid or corrupted") \
   E(EST_ERR_HTTP_WRITE, "An error occurred while writing the HTTP response on the socket") \
   E(EST_ERR_HTTP_UNSUPPORTED, "The EST server sent an unsupported HTTP status code in the response") \
   E(EST_ERR_HTTP_CANNOT_BUILD_HEADER, "The HTTP header could not be built correctly") \
   E(EST_ERR_HTTP_BAD_REQ, "The HTTP request was bad as reported by the server") \
   E(EST_ERR_HTTP_FORBIDDEN, "The HTTP request was refused") \
   E(EST_ERR_HTTP_NOT_FOUND, "The requested information is currently not found on the server") \
   E(EST_ERR_HTTP_NO_CONTENT, "The content requested is not available") \
   E(EST_ERR_BAD_CONTENT_TYPE, "The HTTP content type header in the request was invalid") \
   E(EST_ERR_BAD_CONTENT_LEN, "The HTTP content length header in the request specified a value that was too large") \
   E(EST_ERR_NO_SSL_CTX, "The application did not provide a valid SSL_CTX* reference to the API") \
   E(EST_ERR_AUTH_FAIL, "The EST server was unable to authenticate the EST client") \
   E(EST_ERR_AUTH_FAIL_TLSUID, "Authentication failure due to a missing/invalid challengePassword (TLS UID for PoP binding) in the CSR") \
   E(EST_ERR_AUTH_PENDING, "An HTTP authentication challenge was sent to the client and the response is yet to arrive") \
   E(EST_ERR_CA_ENROLL_FAIL, "The certificate authority was unable to sign the CSR") \
   E(EST_ERR_CA_ENROLL_RETRY, "The certificate authority has requested the client to retry the enroll request in the future, likely due to the CA not being configured for automatic enrollment") \
   E(EST_ERR_WRONG_METHOD, "An invalid HTTP method (GET/POST) was used for the given type of request") \
   E(EST_ERR_X509_SIGN, "An error occurred in the OpenSSL library while trying to sign the CSR") \
   E(EST_ERR_X509_VER, "An error occurred in the OpenSSL library while trying to set the version on the CSR") \
   E(EST_ERR_X509_CN, "An error occurred in the OpenSSL library while trying to set name entry in the CSR") \
   E(EST_ERR_X509_ATTR, "An error occurred in the OpenSSL library while trying to set the X509 attributes in the CSR") \
   E(EST_ERR_X509_PUBKEY, "An error occurred in the OpenSSL library while trying to set the public key in the CSR") \
   E(EST_ERR_MALLOC, "Unable to allocation malloc. This likely indicates a critical failure on the host system") \
   E(EST_ERR_SSL_WRITE, "An error occurred at the TLS layer while trying to write to the socket") \
   E(EST_ERR_SSL_READ, "An error occurred at the TLS layer while trying to read from the socket") \
   E(EST_ERR_SSL_NEW, "An error occurred in the OpenSSL library while trying to allocate the SSL* reference") \
   E(EST_ERR_SSL_CTX_NEW, "An error occurred in the OpenSSL library while trying to allocate or update the SSL context") \
   E(EST_ERR_SSL_CONNECT, "An error occurred in the OpenSSL library while trying to establish a TLS session with the server") \
   E(EST_ERR_SSL_CIPHER_LIST, "An error occurred in the OpenSSL library while trying to set or use the allowed TLS cipher suites") \
   E(EST_ERR_PEM_READ, "An error occurred in the OpenSSL library while trying to read the PEM encoded CSR. This may be due to a corrupted PKSC10") \
   E(EST_ERR_NULL_CALLBACK, "The application layer failed to provide the required callback function for the requested EST operation") \
   E(EST_ERR_IP_GETADDR, "Unable to resolve the server host name") \
   E(EST_ERR_IP_CONNECT, "Unable to connect to requested host/port") \
   E(EST_ERR_INVALID_SERVER_NAME, "The server name provided was invalid. It may not be NULL and it may not exceed the maximum server name length") \
   E(EST_ERR_INVALID_PORT_NUM, "The TCP port number provided was invalid. It must be greater than 0 and less than 65536") \
   E(EST_ERR_CLIENT_INVALID_KEY, "The private key must match the public key in the certificate") \
   E(EST_ERR_CLIENT_NOT_INITIALIZED, "The application attempted to use the libest API prior to invoking est_client_init()") \
   E(EST_ERR_ZERO_LENGTH_BUF, "The certificate received from the server had an invalid length") \
   E(EST_ERR_READ_BUFFER_TOO_SMALL, "The I/O buffer provided for reading data from the socket is not large enough to receive the response from the server") \
   E(EST_ERR_BUF_EXCEEDS_MAX_LEN, "The EST server sent a cacerts response that exceeded the maximum size allowed") \
   E(EST_ERR_NO_CERTIFICATE, "No certificate provided, e.g., an attempt was made to copy the certs from the context prior to the EST operation being performed") \
   E(EST_ERR_NO_CERTS_FOUND, "No certificates were found in the trusted certificate list provided") \
   E(EST_ERR_FQDN_MISMATCH, "The EST server name did not match the fully qualified domain name in the server certificate") \
   E(EST_ERR_SYSCALL, "The OpenSSL library reported a system call error when attempting to establish the TLS session") \
   E(EST_ERR_CSR_ALREADY_SIGNED, "The CSR provided already contained a signature. Libest requires the CSR to not be signed since libest is responsible for signing the CSR") \
   E(EST_ERR_CSR_ATTR_MISSING, "The CSR received from the EST client does not contain all the required CSR attributes") \
   E(EST_ERR_SUBJECT_MISMATCH, "The Subject or SubjectAltName fields of client CSR and certificate do not agree") \
   E(EST_ERR_INVALID_DIGEST, "An invalid digest type was requested") \
   E(EST_ERR_CACERT_VERIFICATION, "Validation of certificate chain or of certificate relative to chain has failed") \
   E(EST_ERR_INVALID_TOKEN, "An invalid authorization token was received") \
   E(EST_ERR_INVALID_RETRY_VALUE, "An invalid or missing retry-after was received from the server") \
   E(EST_ERR_BAD_PKCS7, "An invalid or corrupted PKCS7 structure was provided") \
   E(EST_ERR_BAD_X509, "An invalid or corrupted X509 certificate was provided") \
   E(EST_ERR_BAD_BASE64, "An invalid or corrupted CSR Attribute Base64 encoded string was provided") \
   E(EST_ERR_BAD_ASN1_HEX, "An invalid or corrupted CSR Attribute ASN1 hex string was provided") \
   E(EST_ERR_BAD_ASN1_STR, "An invalid CSR Attribute configuration string was provided") \
   E(EST_ERR_ASN1, "Internal ASN1 error") \
   E(EST_ERR_SRP_STRENGTH_LOW, "The SRP strength requested by the application was too small") \
   E(EST_ERR_SRP_USERID_BAD, "The SRP user ID was not accepted") \
   E(EST_ERR_SRP_PWD_BAD, "The SRP password was not accepted") \
   E(EST_ERR_CB_FAILED,  "The application layer call-back facility failed") \
   E(EST_ERR_AUTH_SRP, "TLS SRP-based authentication failed") \
   E(EST_ERR_AUTH_CERT, "TLS cert-based authentication failed") \
   E(EST_ERR_SOCKET, "TLS socket error") \
   E(EST_ERR_SOCKET_STOP, "TLS connection stopped") \
   E(EST_ERR_UNKNOWN, "Unknown error") // Last error in the enum definition. Should never be used

#define GENERATE_ENUM(ENUM,TEXT) ENUM,
#define GENERATE_STRING(ENUM,TEXT) #ENUM,

/*! @enum EST_ERROR
 *  @brief This enum is used to indicate error conditions to the application layer.
 *         Most of the libest functions return an error indication from this
 *         enumeration.  Applications should always check the returned error
 *         indication and gracefully handle errors.  When no error occurs, libest
 *         will return EST_ERR_NONE, which has the value zero.
 */

typedef enum {
    EST_ERR_NONE = 0, // No error occurred
    FOREACH_EST_ERROR(GENERATE_ENUM)
    EST_ERR_LAST
} EST_ERROR;
extern const char *EST_ERR_STRINGS[]; 
#define EST_ERR_NUM_TO_STR(x) EST_ERR_STRINGS[x] 

typedef enum {
    AUTH_NONE,
    AUTH_BASIC,
    AUTH_DIGEST,
    AUTH_TOKEN,
    AUTH_FAIL
} EST_HTTP_AUTH_MODE;

typedef enum {
    HTTP_AUTH_NOT_REQUIRED = 0,
    HTTP_AUTH_REQUIRED,
} EST_HTTP_AUTH_REQUIRED;

typedef enum {
    EST_CERT_FORMAT_PEM = 1,
    EST_CERT_FORMAT_DER,
    EST_CERT_FORMAT_MAX
} EST_CERT_FORMAT;

#define EST_FORMAT_PEM EST_CERT_FORMAT_PEM
#define EST_FORMAT_DER EST_CERT_FORMAT_DER
    
/*
 * This enum allows the logging to be filtered to the
 * desired detailed level.  This is not a bitmask filter.  If
 * adding a new logging level, the order should be
 * maintained based on the urgency of the log message.
 */
typedef enum {
    EST_LOG_LVL_ERR = 1,
    EST_LOG_LVL_WARN,
    EST_LOG_LVL_INFO
} EST_LOG_LEVEL;

#define MAX_REALM 255
#define MAX_NONCE 64
#define MAX_UIDPWD 30
#define MAX_NC 9
#define MAX_QOP 10
#define MAX_RESPONSE 64
#define MIN_CSRATTRS 4
#define MAX_CSRATTRS 1024
#define MIN_ASN1_CSRATTRS 2
#define MAX_CSRATTRS_WITHPOP 1035
#define MAX_TOKEN_ERROR (255)
#define MAX_TOKEN_ERROR_DESC (255)
#define MAX_AUTH_TOKEN_LEN (512) 

/*
 * The following values define the minimum, maximum, and default
 * values for the timeout value for the SSL read operations.
 * These values are used for both EST Client and Proxy operations.
 */
#define EST_SSL_READ_TIMEOUT_MIN 1
#define EST_SSL_READ_TIMEOUT_MAX 3600
#define EST_SSL_READ_TIMEOUT_DEF 10

/*! @struct EST_HTTP_AUTH_HDR
 *  @brief This structure is used to pass HTTP authentication parameters to
 *         the application.  libest does not contain a user database
 *         for authenticating users.  It is expected the application will
 *         perform the user authentication against an external authentication
 *         server such as Radius.  This structure allows the HTTP authentication
 *         credentials to be passed from the libest HTTP layer to
 *         the application.
 *  @var EST_HTTP_AUTH_HDR::mode
 *	Contains the HTTP authentication mode being used (Basic or Digest).
 *  @var EST_HTTP_AUTH_HDR::user
 *	Contains the user ID from the EST client to be authenticated.
 *  @var EST_HTTP_AUTH_HDR::pwd
 *	Contains the password from the EST client to be authenticated
 *	when HTTP basic authentication is used.
 *  @var EST_HTTP_AUTH_HDR::uri
 *	Contains the URI from the EST client for HTTP digest authentication.
 *  @var EST_HTTP_AUTH_HDR::cnonce
 *	Contains the nonce from the EST client for HTTP digest authentication.
 *  @var EST_HTTP_AUTH_HDR::qop
 *	Contains the operation from the EST client for HTTP digest authentication.
 *  @var EST_HTTP_AUTH_HDR::nc
 *	Contains the nonce count from the EST client for HTTP digest authentication.
 *  @var EST_HTTP_AUTH_HDR::nonce
 *	Contains the server nonce for HTTP digest authentication.
 *  @var EST_HTTP_AUTH_HDR::response
 *	Contains the client's digest value to verify.
 *  @var EST_HTTP_AUTH_HDR::auth_token
 *	Contains the client's token value to verify.
 */
typedef struct {
    EST_HTTP_AUTH_MODE mode;
    char *user;
    char *pwd;
    char *uri;
    char *cnonce;
    char *qop;
    char *nc;
    char *nonce;
    char *response;
    char *auth_token;
} EST_HTTP_AUTH_HDR;

/*
 * Defines the valid return codes that the application layer's auth credential
 * callback function can provide.
 */
typedef enum {
    EST_HTTP_AUTH_CRED_SUCCESS = 1,
    EST_HTTP_AUTH_CRED_NOT_AVAILABLE,
} EST_HTTP_AUTH_CRED_RC;
    
        
/*! @struct EST_CTX
 *  @brief This structure is used to maintain the state of EST operations
 *         on behalf of the application.  A single context can be used to
 *         represent a single instance of either an EST client, EST server,
 *         or EST proxy server.  None of the members on this structure
 *         are publically accessible.  Application should use the functions
 *         provided by the libest API to manage the context.  A context
 *         is created using one of: est_client_init(), est_server_init(),
 *         or est_proxy_init().  When the context is no longer needed,
 *         the application shoud invoke est_destroy() to release all memory
 *         associated with the context.  
 */
typedef struct est_ctx EST_CTX;


/*! @typedef auth_credentials_cb
 *  @brief This typedef defines the prototype of the callback function
 *         that is to reside in the application code.  The application
 *         can register this function callback using the est_client_set_auth_cred_cb()
 *         API function.  This callback is called by the EST client library
 *         when it requires HTTP authentication credentials.
 *         This callback function takes as input a pointer to a EST_HTTP_AUTH_HDR
 *         structure.  The callback function must look at the mode structure
 *         element to determine which type of credentials are required.  If the
 *         mode is set to AUTH_BASIC or AUTH_DIGEST, the callback function must
 *         supply the user and pwd values.  If the mode is set to AUTH_TOKEN, the
 *         the callback must supply the auth_token value.  The auth_token value
 *         must be a base64 encoded string representing the access token.
 */
typedef EST_HTTP_AUTH_CRED_RC (*auth_credentials_cb)(EST_HTTP_AUTH_HDR *auth_credentials);


/*
 * Begin the public API prototypes
 */
EST_ERROR est_enable_crl(EST_CTX *ctx);
EST_ERROR est_init_logger(EST_LOG_LEVEL lvl, void (*loggerfunc)(char *, va_list));
EST_ERROR est_set_log_source (EST_MODE source);
int est_get_api_level(void); 
const char * est_get_version(void); 
void est_enable_backtrace(int enable);
EST_ERROR est_set_ex_data(EST_CTX *ctx, void *ex_data);
void * est_get_ex_data(EST_CTX *ctx);
EST_CTX * est_server_init(unsigned char *ca_chain, int ca_chain_len,
                          unsigned char *cacerts_resp_chain, int cacerts_resp_chain_len,
			  EST_CERT_FORMAT cert_format,
                          char *http_realm, X509 *tls_cert,
                          EVP_PKEY *tls_key);
EST_CTX * est_proxy_init(unsigned char *ca_chain, int ca_chain_len,
                         unsigned char *cacerts_resp_chain, int cacerts_resp_chain_len,
			 EST_CERT_FORMAT cert_format,
                         char *http_realm, X509 *tls_cert,
                         EVP_PKEY *tls_key,
                         char *uid, char *pwd);
EST_ERROR est_destroy(EST_CTX *ctx);
EST_ERROR est_server_set_auth_mode(EST_CTX *ctx, EST_HTTP_AUTH_MODE amode);
char *est_server_generate_auth_digest(EST_HTTP_AUTH_HDR *ah, char *HA1);
EST_ERROR est_server_start(EST_CTX *ctx);
EST_ERROR est_server_stop(EST_CTX *ctx);
EST_ERROR est_server_enable_srp(EST_CTX *ctx, int (*cb)(SSL *s, int *ad, void *arg));
EST_ERROR est_server_enable_pop(EST_CTX *ctx);
EST_ERROR est_server_disable_pop(EST_CTX *ctx);
EST_ERROR est_server_handle_request(EST_CTX *ctx, int fd);
EST_ERROR est_server_set_dh_parms(EST_CTX *ctx, DH *dh);
EST_ERROR est_server_init_csrattrs(EST_CTX *ctx, char *csrattrs, int crsattrs_len);
EST_ERROR est_server_set_retry_period(EST_CTX *ctx, int seconds);
EST_ERROR est_server_set_ecdhe_curve(EST_CTX *ctx, int nid);
EST_ERROR est_server_enforce_csrattr(EST_CTX *ctx);
/*
 * EST proxy specific functions
 */
EST_ERROR est_proxy_start(EST_CTX *ctx);
EST_ERROR est_proxy_stop(EST_CTX *ctx);
EST_ERROR est_proxy_set_server(EST_CTX *ctx, const char *server, int port);
EST_ERROR est_proxy_set_auth_mode(EST_CTX *ctx, EST_HTTP_AUTH_MODE amode);
EST_ERROR est_proxy_set_read_timeout(EST_CTX *ctx, int timeout);
EST_ERROR est_proxy_set_auth_cred_cb(EST_CTX *ctx, auth_credentials_cb);

/*
 * The following functions are used by an EST client
 */
EST_CTX *est_client_init(unsigned char *ca_chain, int ca_chain_len,
                         EST_CERT_FORMAT cert_format,
                         int (*cert_verify_cb)(X509 *, int));
EST_ERROR est_client_set_auth(EST_CTX *ctx, const char *uid, const char *pwd,
                              X509 *client_cert, EVP_PKEY *private_key);
EST_ERROR est_client_set_auth_cred_cb(EST_CTX *ctx, auth_credentials_cb);
EST_ERROR est_client_set_server(EST_CTX *ctx, const char *server, int port);
EST_ERROR est_client_provision_cert(EST_CTX *ctx, char *cn, 
	                            int *pkcs7_len,
				    int *ca_cert_len,
                                    EVP_PKEY *new_public_key);
EST_ERROR est_client_enroll(EST_CTX *ctx, char *cn, int *pkcs7_len,
                            EVP_PKEY *new_public_key);
EST_ERROR est_client_enroll_csr(EST_CTX *ctx, X509_REQ *csr, int *pkcs7_len, EVP_PKEY *priv_key);
EST_ERROR est_client_reenroll(EST_CTX *ctx, X509 *cert, int *pkcs7_len, EVP_PKEY *priv_key);
EST_ERROR est_client_copy_enrolled_cert(EST_CTX *ctx, unsigned char *pkcs7);
EST_ERROR est_client_get_csrattrs(EST_CTX *ctx, unsigned char **csr_data, int *csr_len);
EST_ERROR est_client_get_cacerts(EST_CTX *ctx, int *ca_certs_len);
EST_ERROR est_client_copy_cacerts(EST_CTX *ctx, unsigned char *ca_certs);
EST_ERROR est_client_set_sign_digest(EST_CTX *ctx, int nid); 
EST_ERROR est_client_copy_retry_after(EST_CTX *ctx, int *retry_delay,
                                       time_t *retry_time);
EST_ERROR est_client_set_read_timeout(EST_CTX *ctx, int timeout);
EST_ERROR est_client_enable_basic_auth_hint(EST_CTX *ctx);
EST_ERROR est_client_force_pop(EST_CTX *ctx);
EST_ERROR est_client_unforce_pop(EST_CTX *ctx);
EST_ERROR est_client_enable_srp(EST_CTX *ctx, int strength, char *uid, char *pwd); 

/*
 * The following callback entry points must be set by the application
 * when acting as an EST server or proxy.
 */
EST_ERROR est_set_ca_enroll_cb(EST_CTX *ctx, EST_ERROR (*cb)(unsigned char * pkcs10, 
	                       int p10_len, unsigned char **pkcs7, int *pkcs7_len, 
			       char *user_id, X509 *peer_cert, void *ex_data));
EST_ERROR est_set_ca_reenroll_cb(EST_CTX *ctx, EST_ERROR (*cb)(unsigned char * pkcs10, 
	                         int p10_len, unsigned char **pkcs7, int *pkcs7_len, 
				 char *user_id, X509 *peer_cert, void *ex_data));
EST_ERROR est_set_csr_cb(EST_CTX * ctx, unsigned char *(*cb)(int *csr_len, void *ex_data));
EST_ERROR est_set_http_auth_cb(EST_CTX * ctx, int (*cb)(EST_CTX*, EST_HTTP_AUTH_HDR*, X509*, void*));

    
EST_ERROR est_set_http_auth_required(EST_CTX * ctx, EST_HTTP_AUTH_REQUIRED required);
EST_ERROR est_add_attributes_helper(X509_REQ *req, int nid, void *string, int chtype);
EST_ERROR est_get_attributes_helper(unsigned char **der_ptr, int *der_len, int *new_nid);
EST_ERROR est_decode_attributes_helper(char *csrattrs, int csrattrs_len, 
  				       unsigned char **der_ptr, int *der_len);

/*
 * The following are helper functions to deal with
 * the OpenSSL data types for certs, keys, etc.
 */
X509_REQ *est_read_x509_request(unsigned char *csr, int csr_len,
	                         EST_CERT_FORMAT csr_format);
EVP_PKEY *est_load_key(unsigned char *key, int key_len, int format);
int est_convert_p7b64_to_pem(unsigned char *certs_p7, int certs_len, unsigned char **pem);

/*
 * These are helper macros that an application can use
 * to initialize/de-initialize OpenSSL.  
 */
/*! @brief est_apps_startup() is used by an application to initialize 
    the OpenSSL library.  This should be called first prior to using
    any other functions in the libest API. This is a helper function which invokes
    CRYPTO_malloc_init(), ERR_load_crypto_strings(), OpenSSL_add_all_algorithms(),
    ENGINE_load_builtin_engines(), SSL_library_init(), and SSL_load_error_strings().
 
    @return void.
 */
#if (defined(__MINGW32__) || defined(_WIN32)) && !defined(__SYMBIAN32__)
#define est_apps_startup() \
    WSADATA wsaData; \
    int rc = WSAStartup(MAKEWORD(2, 2), &wsaData); \
    if (rc != 0) { \
        printf("WSAStartup could not find a usable Winsock DLL, error: %d\n", rc); \
	exit(1); \
    } \
    est_ssl_startup()
#else
#define est_apps_startup() est_ssl_startup()
#endif
#define est_ssl_startup() \
    do { CRYPTO_malloc_init(); \
         ERR_load_crypto_strings(); OpenSSL_add_all_algorithms(); \
         ENGINE_load_builtin_engines(); \
         SSL_library_init(); \
         SSL_load_error_strings(); } while (0)

/*! @brief est_apps_shutdown() is used by an application to de-initialize 
    the OpenSSL library.  This should be called to prevent memory
    leaks in the OpenSSL library.  This is a helper function which invokes
    CONF_modules_unload(), OBJ_cleanup(), EVP_cleanup(), ENGINE_cleanup(),
    CRYPTO_cleanup_all_ex_data(), ERR_remove_thread_state(), and
    ERR_free_strings().
 
    @return void.
 */
#if (defined(__MINGW32__) || defined(_WIN32)) && !defined(__SYMBIAN32__)
#define est_apps_shutdown() \
    (void)WSACleanup(); \
    est_ssl_shutdown()
#else
#define est_apps_shutdown() est_ssl_shutdown()
#endif
#define est_ssl_shutdown() \
    do { CONF_modules_unload(1); \
         OBJ_cleanup(); EVP_cleanup(); ENGINE_cleanup(); \
         CRYPTO_cleanup_all_ex_data(); ERR_remove_thread_state(NULL); \
         ERR_free_strings(); } while (0)

#ifdef __cplusplus
}
#endif

#endif

