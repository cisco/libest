/*------------------------------------------------------------------
 * us1060.c - Unit Tests for User Story 1060 - TLS SRP support 
 *
 * May, 2014
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 *------------------------------------------------------------------
 */

// 2015-08-11 split matrix test us1060_test0() into smaller chunks for better reporting
// 2015-08-11 corrected some assertions and comments on expected behavior

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <est.h>
#include <curl/curl.h>
#include "test_utils.h"
#include "curl_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define US1060_SERVER_PORT      31060
#define US1060_TLS_PORT		31061	
#define US1060_SERVER_IP	"127.0.0.1"	
#define US1060_UID	        "estuser"
#define US1060_PWD	        "estpwd"
#define US1060_CACERTS	        "CA/estCA/cacert.crt"
#define US1060_TRUST_CERTS      "CA/trustedcerts.crt"
#define US1060_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
#define US1060_VFILE		"US1060/passwd.srpv"


#define US1060_RSA_CERT         "US1060/cert-rsa.pem"
#define US1060_RSA_KEY          "US1060/key-rsa.pem"
#define US1060_RSA_CERT_BAD     "US1060/cert-rsa-fqdnfail.pem"
#define US1060_RSA_KEY_BAD      "US1060/key-rsa-fqdnfail.pem"

#define US1060_EXPLICIT_CERT	"US1060/explicit-cert.pem" 
#define US1060_EXPLICIT_KEY	"US1060/explicit-key.pem"
#define US1060_SELFSIGN_CERT	"US1060/selfsigned-cert.pem" 
#define US1060_SELFSIGN_KEY	"US1060/selfsigned-key.pem"

#define US1060_ENROLL_URL	"https://127.0.0.1:31060/.well-known/est/simpleenroll"
#define US1060_UIDPWD_GOOD	"estuser:estpwd"
#define US1060_UIDPWD_BAD	"estuser:xxx111222"
#define US1060_PKCS10_CT	"Content-Type: application/pkcs10" 

#define US1060_PROXY_ENROLL_URL	"https://127.0.0.1:41060/.well-known/est/simpleenroll"
#define US1060_PROXY_PORT	41060

#define US1060_PKCS10_REQ    "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"

static char *log_search_target = NULL;
static int search_target_found = 0;
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static SRP_VBASE *srpdb = NULL;


static EVP_PKEY * generate_private_key (void)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey;

    /*
     * create an RSA keypair and assign them to a PKEY and return it.
     */
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);    

    pkey = EVP_PKEY_new();
    if (pkey==NULL) {
        printf("\nError allocating PKEY structure for new key pair\n");
        return NULL;
    }
    if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
        printf("\nError assigning RSA key pair to PKEY structure\n");
        return NULL;
    }        
    
    RSA_free(rsa);
    BN_free(bn);
    
    return (pkey);
}

/*
 * This is a simple callback used to override the default
 * logging facility in libest.  We'll use this to look
 * for specific debug output.
 */
static void us1060_logger_stderr (char *format, va_list l) 
{
    char t_log[1024];

    flockfile(stderr);
    if (log_search_target) {
	vsnprintf(t_log, 1024, format, l);
	if (strstr(t_log, log_search_target)) {
	    search_target_found = 1;
	}
        fprintf(stderr, "%s", t_log);
    } else {
        vfprintf(stderr, format, l);
    }
    fflush(stderr);
    funlockfile(stderr);
}

static int us1060_start_server (char *cert, char *key, int no_http_auth, int enable_pop, int enable_srp)
{
    int rv;

    if (enable_srp) {
	rv = st_start_srp(US1060_SERVER_PORT, 
			  cert, key,
			  "US1060 test realm",
			  US1060_CACERTS,
			  US1060_TRUST_CERTS,
	                  "CA/estExampleCA.cnf",
		          enable_pop,
		          US1060_VFILE);
    } else {
	rv = st_start(US1060_SERVER_PORT, 
		      cert, key,
		      "US1060 test realm",
		      US1060_CACERTS,
		      US1060_TRUST_CERTS,
	              "CA/estExampleCA.cnf",
		      0,
		      enable_pop,
		      0);
    }

    if (no_http_auth) {
        st_disable_http_auth();
    }

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us1060_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, &us1060_logger_stderr);

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Start an instance of the proxy with SRP enabled
     */
    rv = st_proxy_start_srp(US1060_PROXY_PORT, 
			    US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY,
			    "US1060 proxy realm",
			    US1060_CACERTS,
			    US1060_TRUST_CERTS,
			    US1060_UID, 
			    US1060_PWD,
			    US1060_SERVER_IP,
			    US1060_SERVER_PORT,
			    0,
			    US1060_VFILE);

    /*
     * Read in the CA certificates
     * Used for client-side API testing
     */
    cacerts_len = read_binary_file(US1060_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    srpdb = SRP_VBASE_new(NULL);
    if (!srpdb) {
	printf("\nUnable allocate SRP verifier database.  Aborting!!!\n");
    }
    if (SRP_VBASE_init(srpdb, US1060_VFILE) != SRP_NO_ERROR) {
	printf("\nUnable initialize SRP verifier database.  Aborting!!!\n");
    }

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1060_destroy_suite (void)
{
    if (srpdb) {
	SRP_VBASE_free(srpdb);
    }

    st_stop();
    st_proxy_stop();
    free(cacerts);
    return 0;
}


typedef enum {
    SRP_OFF,
    SRP_ON
} server_srp_mode;

typedef enum {
    SRP_GOOD,
    SRP_BAD,
    SRP_NONE,
} client_srp_mode;

typedef enum {
    HTTP_OFF,
    HTTP_OPTIONAL,
    HTTP_REQUIRED
} server_http_mode;

typedef struct {
    char		*test_name;
    char		*curl_cert;
    char		*curl_key;
    char		*curl_http_auth;
    client_srp_mode	curl_srp; 
    server_http_mode	server_http; 
    server_srp_mode	server_srp; 
    int			expected_http_result;
} us1060_matrix;

/*
 * This is the unit test matrix for server-side SRP support.  Curl is 
 * used as the EST client.  Because of this PoP is disabled on the
 * server for all test cases.  We try to cover a variety of configurations
 * and potential scenarios.  The client side variations include:
 *
 * curl_cert:  The certificate curl uses, which may be NULL 
 * curl_key:   The key curl uses, which may be NULL 
 * curl_http_auth:  The HTTP auth credentials used by curl.
 * client_srp_mode: Either GOOD, BAD, NONE.  Determines which SRP credentials are used 
 *                  Curl.
 *
 * On the server side we configure the server using the following variations:
 *
 * server_http_mode:  HTTP auth is required, optional, or disabled.
 *                    (optional means it only occurs when TLS auth fails)
 * server_srp_mode:   SRP is either enabled or disabled on the server.
 *
 * expected_http_result:  This is the expected HTTP status code received on by Curl.
 *                        When SRP fails, this results in a failed TLS session.  Curl
 *                        returns a zero in this case since the HTTP layer can not
 *                        communicate.  If TLS succeeds, but HTTP auth fails, then
 *                        the server should return a HTTP 401 response to the client.
 *                        When enrollment succeeds, the server should send a 
 *                        HTTP 200 response.
 *  
 *
 */
#define FOREACH_MATRIX_ENTRY(M) \
    M(1, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_REQUIRED, SRP_ON, 200) \
    M(2, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_REQUIRED, SRP_ON, 0) \
    M(3, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON, 200) \
    M(4, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OPTIONAL, SRP_ON, 200) \
    M(5, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OPTIONAL, SRP_ON, 0) \
    M(6, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON, 200) \
    M(7, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OFF,      SRP_ON, 200) \
    M(8, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OFF,      SRP_ON, 0) \
    M(9, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON, 401) \
\
    M(11, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_REQUIRED, SRP_ON, 401) \
    M(12, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_REQUIRED, SRP_ON, 0) \
    M(13, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_REQUIRED, SRP_ON, 401) \
    M(14, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OPTIONAL, SRP_ON, 200) \
    M(15, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OPTIONAL, SRP_ON, 0) \
    M(16, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OPTIONAL, SRP_ON, 401) \
    M(17, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OFF,      SRP_ON, 200) \
    M(18, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OFF,      SRP_ON, 0) \
    M(19, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OFF,      SRP_ON, 401) \
\
    M(21, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_REQUIRED, SRP_OFF, 0) \
    M(22, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_REQUIRED, SRP_OFF, 0) \
    M(23, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 200) \
    M(24, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OPTIONAL, SRP_OFF, 0) \
    M(25, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OPTIONAL, SRP_OFF, 0) \
    M(26, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200) \
    M(27, NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OFF,      SRP_OFF, 0) \
    M(28, NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OFF,      SRP_OFF, 0) \
    M(29, NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 401) \
\
    M(31, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_REQUIRED, SRP_OFF, 0) \
    M(32, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_REQUIRED, SRP_OFF, 0) \
    M(33, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 401) \
    M(34, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OPTIONAL, SRP_OFF, 0) \
    M(35, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OPTIONAL, SRP_OFF, 0) \
    M(36, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 401) \
    M(37, NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OFF,      SRP_OFF, 0) \
    M(38, NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OFF,      SRP_OFF, 0) \
    M(39, NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OFF,      SRP_OFF, 401) \
\
    M(40, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON,  200) \
    M(41, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_ON,  401) \
    M(42, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON,  200) \
    M(43, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_ON,  200) \
    M(44, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON,  200) \
    M(45, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_ON,  200) \
    M(46, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 200) \
    M(47, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_OFF, 401) \
    M(48, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200) \
    M(49, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200) \
    M(50, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 200) \
    M(51, US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_OFF, 200) \
\
    M(60, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON,  0) \
    M(61, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_ON,  0) \
    M(62, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON,  0) \
    M(63, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_ON,  0) \
    M(64, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON,  0) \
    M(65, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_ON,  0) \
    M(66, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 0) \
    M(67, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_OFF, 0) \
    M(68, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 0) \
    M(69, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 0) \
    M(70, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 0) \
    M(71, US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_OFF, 0)

#define GENERATE_ENTRY(N,C,K,HP,SP,HM,SM,R) {#N,C,K,HP,SP,HM,SM,R},
static us1060_matrix test_matrix[] = {
  FOREACH_MATRIX_ENTRY(GENERATE_ENTRY)
};

/*
 * This is our worker for each entry in the test matrix above.
 * We read the configuration from the entry, configure the
 * server and client as needed, and attempt a simple enroll
 * using Curl as the client.
 */
static void us1060_test_matrix_item () 
{
    int rv;
    static int i=0; // not the test number, but the index of the entry in the table above

    /*
     * Stop the server and restart it to make sure 
     * it's in the correct mode.
     */
    st_stop();
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, test_matrix[i].server_srp == SRP_ON);
    CU_ASSERT_FATAL(rv == 0);

    /*
     * Set the server HTTP auth configuration
     */
    switch (test_matrix[i].server_http) {
    case HTTP_OFF:
	st_disable_http_auth();
        break;
    case HTTP_OPTIONAL:
	st_enable_http_auth();
	st_set_http_auth_optional();
        break;
    case HTTP_REQUIRED:
	st_enable_http_auth();
	st_set_http_auth_required();
        break;
    }

    switch (test_matrix[i].curl_srp) {
    case SRP_GOOD:
	rv = curl_http_post_srp(US1060_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
				test_matrix[i].curl_http_auth, NULL, CURLAUTH_BASIC, 
				NULL, "srp_user", "srp_pwd", NULL, NULL);
	break;
    case SRP_BAD:
	rv = curl_http_post_srp(US1060_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
				test_matrix[i].curl_http_auth, NULL, CURLAUTH_BASIC, 
				NULL, "srp_user", "boguspwd", NULL, NULL);
	break;
    case SRP_NONE:
	/*
	 * Some of the SRP disabled test cases use a client
	 * certificate.
	 */
	if (test_matrix[i].curl_cert) {
	    rv = curl_http_post_certuid(US1060_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
					test_matrix[i].curl_http_auth, 
					test_matrix[i].curl_cert, test_matrix[i].curl_key,  
					US1060_CACERTS, NULL);
	} else {
	    rv = curl_http_post(US1060_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
				test_matrix[i].curl_http_auth, US1060_CACERTS, CURLAUTH_BASIC, 
				NULL, NULL, NULL);
	}
	break;
    }    
    CU_ASSERT_NM_EQ(test_matrix[i].test_name, rv, test_matrix[i].expected_http_result);
    if (rv != test_matrix[i].expected_http_result) {
	printf("\nMatrix test %s failed with rv = %d\n", test_matrix[i].test_name, (int)rv);
	fflush(stdout);
    }

    i++; // prepare index for next test in row
}

#define DECLARE_TEST(N,C,K,HP,SP,HM,SM,R) static void us1060_test##N(void) { \
	LOG_FUNC_NM; \
	return us1060_test_matrix_item(/*N*/); \
}
FOREACH_MATRIX_ENTRY(DECLARE_TEST)

/*
 * This struct is used to hack the use of API to
 * increase code coverage of the unit tests.
 * If est_ctx in est_locl.h changes, this may need
 * to be adjusted.  We're interested in accessing the
 * ssl_ctx member of an EST_CTX.
 */
struct est_dumb_ctx {
    EST_MODE est_mode;        /* operational mode of the instance: client or server */
    unsigned char   *dummy1;
    int              dummy2;
    unsigned char   *dummy3;
    int              dummy4;
    unsigned char   *dummy5;
    int              dummy6;
    unsigned char   *dummy7;
    int              dummy8;
    unsigned char   *dummy9;
    int              dummy10;
    X509_STORE      *dummy11;
    char             dummy12[MAX_REALM+1];
    SSL_CTX         *ssl_ctx;
};

static void us1060_easy_provision (int use_srp, int use_ta, char *cipher_suite, int port, int expected_rv)
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;
    int ca_certs_len = 0;
    unsigned char *new_cert = NULL;
    struct est_dumb_ctx *ed;

    /*
     * Create a client context 
     */
    if (use_ta) {
	ectx = est_client_init(cacerts, cacerts_len, 
	                       EST_CERT_FORMAT_PEM,
		               NULL);
    } else {
	ectx = est_client_init(NULL, 0, 
	                       EST_CERT_FORMAT_PEM,
		               NULL);
    }
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060_UID, US1060_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060_SERVER_IP, port);

    if (use_srp) {
	rv = est_client_enable_srp(ectx, 1024, US1060_UID, US1060_PWD); 
    }

    if (cipher_suite) {
	/*
	 * This is not an approved use of the EST API.  We do this
	 * here only to increase code coverage for testing
	 * purposes only.  If you are looking at this code as
	 * an example of how to use the EST API, do not do this!
	 */
	ed = (struct est_dumb_ctx*)ectx;
	rv = SSL_CTX_set_cipher_list(ed->ssl_ctx, cipher_suite); 
	CU_ASSERT(rv == 1);
    }

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_provision_cert(ectx, "US1060_TEST1xx", &pkcs7_len, &ca_certs_len, new_key);
    CU_ASSERT(rv == expected_rv);
    if (rv != expected_rv) {
	printf("Expected rv was %d, rv returned was %d\n", expected_rv, rv);
    }
    EVP_PKEY_free(new_key);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
	new_cert = (unsigned char *)malloc(pkcs7_len);
	CU_ASSERT(new_cert != NULL);
	rv = est_client_copy_enrolled_cert(ectx, new_cert);
	CU_ASSERT(rv == EST_ERR_NONE);
        if (new_cert) free(new_cert);
    } else {
        est_destroy(ectx);
	return;
    }

    /*
     * Retrieve a copy of the new CA certs
     */
    if (rv == EST_ERR_NONE) {
	new_cert = (unsigned char *)malloc(ca_certs_len);
	CU_ASSERT(new_cert != NULL);
	rv = est_client_copy_cacerts(ectx, new_cert);
	CU_ASSERT(rv == EST_ERR_NONE);
        if (new_cert) free(new_cert);
    } else {
        est_destroy(ectx);
	return;
    }

    /*
     * Cleanup
     */
    est_destroy(ectx);
}

/*
 * Simple "happy path" test case using the easy provision
 * API with SRP disabled.
 */
static void us1060_test100 ()
{
    LOG_FUNC_NM;

    st_stop();
    us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, 1);

    us1060_easy_provision(0, 1, NULL, US1060_SERVER_PORT, EST_ERR_NONE);
}

/*
 * Simple "happy path" test case using the easy provision
 * API with SRP enabled.  Note, this is also testing
 * TLS session resumption along with SRP since the easy
 * provision implicitly uses TLS session resumption.
 */
static void us1060_test101 ()
{
    LOG_FUNC_NM;

    us1060_easy_provision(1, 1, NULL, US1060_SERVER_PORT, EST_ERR_NONE);
}

/*
 * This test will enable a just the SRP-RSA-AES-128-CBC-SHA
 * cipher suite, which forces the server to send a certificate
 * to the client while SRP is used.  The FQDN check should occur
 * and succeed.
 */
static void us1060_test102 ()
{
    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    us1060_start_server(US1060_RSA_CERT, US1060_RSA_KEY, 0, 0, 1);

    us1060_easy_provision(1, 1, "SRP-RSA-AES-128-CBC-SHA", US1060_SERVER_PORT, EST_ERR_NONE);
}

/*
 * This test will enable a just the SRP-RSA-AES-128-CBC-SHA
 * cipher suite, which forces the server to send a certificate
 * to the client while SRP is used.  Unlike test #102, we'll
 * use a server cert with a mismatched FQDN.  This will
 * ensure the FQDN check still occurs when SRP is used.
 */
static void us1060_test103 ()
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;
    struct est_dumb_ctx *ed;

    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    us1060_start_server(US1060_RSA_CERT_BAD, US1060_RSA_KEY_BAD, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060_UID, US1060_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060_SERVER_IP, US1060_SERVER_PORT);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060_UID, US1060_PWD); 

    /*
     * This is not an approved use of the EST API.  We do this
     * here only to increase code coverage for testing
     * purposes only.  If you are looking at this code as
     * an example of how to use the EST API, do not do this!
     */
    ed = (struct est_dumb_ctx*)ectx;
    rv = SSL_CTX_set_cipher_list(ed->ssl_ctx, "SRP-RSA-AES-128-CBC-SHA"); 
    CU_ASSERT(rv == 1);

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060_TEST103", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_FQDN_MISMATCH);

    /*
     * Cleanup
     */
    EVP_PKEY_free(new_key);
    est_destroy(ectx);
}

/*
 * This test will initialize EST w/o a trust anchor,
 * enable SRP, and perform a simpleenroll. 
 * This should succeed since SRP doesn't require a
 * trust anchor.
 */
static void us1060_test104 ()
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;

    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060_UID, US1060_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060_SERVER_IP, US1060_SERVER_PORT);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060_UID, US1060_PWD); 

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060_TEST104", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    EVP_PKEY_free(new_key);
    est_destroy(ectx);
}

/*
 * This test will enable a just the SRP-RSA-AES-128-CBC-SHA
 * cipher suite, which forces the server to send a certificate
 * to the client while SRP is used.  Similar to #104, we'll
 * omit configuring the trust anchor on the client context.
 * This should cause the TLS session to fail since the
 * server cert can not be verified without a trust anchor. 
 */
static void us1060_test105 ()
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;
    struct est_dumb_ctx *ed;

    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    us1060_start_server(US1060_RSA_CERT, US1060_RSA_KEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060_UID, US1060_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060_SERVER_IP, US1060_SERVER_PORT);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060_UID, US1060_PWD); 

    /*
     * This is not an approved use of the EST API.  We do this
     * here only to increase code coverage for testing
     * purposes only.  If you are looking at this code as
     * an example of how to use the EST API, do not do this!
     */
    ed = (struct est_dumb_ctx*)ectx;
    rv = SSL_CTX_set_cipher_list(ed->ssl_ctx, "SRP-RSA-AES-128-CBC-SHA"); 
    CU_ASSERT(rv == 1);

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060_TEST105", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_AUTH_CERT);

    /*
     * Cleanup
     */
    EVP_PKEY_free(new_key);
    est_destroy(ectx);
}

/*
 * This test does a simple enroll with SRP using a
 * non-default value for the SRP strength.
 */
static void us1060_test106 ()
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;

    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060_UID, US1060_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060_SERVER_IP, US1060_SERVER_PORT);

    /*
     * Enable SRP on the client
     * Use a strength below the minimum
     */
    rv = est_client_enable_srp(ectx, 1023, US1060_UID, US1060_PWD); 
    CU_ASSERT(rv == EST_ERR_SRP_STRENGTH_LOW);

    /*
     * Enable SRP on the client
     * Use a strength slightly larger than the N value in passwd.srpv
     */
    rv = est_client_enable_srp(ectx, 1537, US1060_UID, US1060_PWD); 
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060_TEST106a", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_AUTH_SRP);

    /*
     * Enable SRP on the client
     * Use a strength the same size as the N value in passwd.srpv
     */
    rv = est_client_enable_srp(ectx, 1536, US1060_UID, US1060_PWD); 
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060_TEST106b", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    EVP_PKEY_free(new_key);
    est_destroy(ectx);
}

/*
 * This is called by OpenSSL when the SRP username is
 * needed during the TLS handshake.
 */
static int us1060_srp_cb (SSL *s, int *ad, void *arg) 
{
    char *login = SSL_get_srp_username(s);
    SRP_user_pwd *user;

    if (!login) return (-1);

    printf("SRP username = %s\n", login);

    user = SRP_VBASE_get_by_user(srpdb, login); 

    if (user == NULL) {
	printf("User %s doesn't exist in SRP database\n", login);
	return SSL3_AL_FATAL;
    }

    /*
     * Get the SRP parameters for the user from the verifier database.
     * Provide these parameters to TLS to complete the handshake
     */
    if (SSL_set_srp_server_param(s, user->N, user->g, user->s, user->v, user->info) < 0) {
	*ad = SSL_AD_INTERNAL_ERROR;
	return SSL3_AL_FATAL;
    }
		
    printf("SRP parameters set: username = \"%s\" info=\"%s\" \n", login, user->info);

    user = NULL;
    login = NULL;
    fflush(stdout);
    return SSL_ERROR_NONE;
}


/*
 * This starts a minimal TLS server that only does a
 * handshake and then closes the connection.  This is
 * strictly used to test TLS session negotiation
 * behavior with EST.
 */
static void us1060_start_tls_server (char *cipherstring)
{
    BIO *conn;
    BIO *listener;
    BIO *berr;
    char h_p[25];
    SSL *ssl;
    SSL_CTX *ssl_ctx = NULL;
    int nid, rv;
    EC_KEY *ecdh = NULL;

    berr = BIO_new_fp(stderr, BIO_NOCLOSE);

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
	printf("Failed to create SSL context\n");
	ERR_print_errors(berr);
	return;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, US1060_RSA_CERT) != 1) {
	printf("Failed to load server certificate\n");
	ERR_print_errors(berr);
	return;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, US1060_RSA_KEY, SSL_FILETYPE_PEM) != 1) {
	printf("Failed to load server private key\n");
	ERR_print_errors(berr);
	return;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 |
	                         SSL_OP_NO_SSLv3 |
				 SSL_OP_NO_TLSv1 |
                                 SSL_OP_SINGLE_ECDH_USE | 
				 SSL_OP_SINGLE_DH_USE |
			         SSL_OP_NO_TICKET);

    nid = OBJ_sn2nid("prime256v1");
    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
	printf("Failed to retrieve ECDH curve\n");
	ERR_print_errors(berr);
	return;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (SSL_CTX_set_cipher_list(ssl_ctx, cipherstring) != 1) {
	printf("Failed to set server cipher list\n");
	ERR_print_errors(berr);
	return;
    }
    SSL_CTX_set_srp_username_callback(ssl_ctx, us1060_srp_cb);

    sprintf(h_p, "%s:%d", US1060_SERVER_IP, US1060_TLS_PORT);
    listener = BIO_new_accept(h_p);
    if (listener == NULL) {
	printf("IP connection failed\n");
	return;
    }
    BIO_set_bind_mode(listener, BIO_BIND_REUSEADDR);

    /*
     * The first call to do_accept binds the socket
     */
    if (BIO_do_accept(listener) <= 0) {
	printf("TCP bind failed\n");
	BIO_free_all(listener);
	return;
    }

    /*
     * The second call to do_accept waits for a new
     * connection request on the listener.
     * Note that we are in blocking mode for this socket
     */
    if (BIO_do_accept(listener) <= 0) {
	printf("TCP accept failed\n");
	BIO_free_all(listener);
	return;
    }
    conn = BIO_pop(listener);

    ssl = SSL_new(ssl_ctx);
    SSL_set_bio(ssl, conn, conn);
    /*
     * Now that we have everything ready, let's start waiting for
     * a client to contact us.  Normally we might using a pthread
     * or some other construct to avoid blocking on the main 
     * thread while waiting for an incoming connection.  This
     * code is simply a contrived example, we will wait on the
     * main thread for an incoming connection.
     */
    rv = SSL_accept(ssl);
    if (rv <= 0) {
	printf("\nFailed to complete TLS handshake %d\n", rv);
	ERR_print_errors(berr);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    BIO_free(berr);
    (void)BIO_reset(listener);
    BIO_free_all(listener);
    pthread_exit(0);
}

static void* US1060_master_tls_thread (void *arg)
{
    char *c_suite = (char *)arg;
    /*
     * We'll start the server using an SRP cipher suite
     * that requires an RSA certificate.  The client will
     * not have a trust anchor configured, which should
     * result in a failed TLS handshake.
     */
    us1060_start_tls_server(c_suite);
    return NULL;
}

/*
 * This test starts a TLS server with only the SRP RSA
 * suites enabled.  It then configures EST client for SRP
 * mode w/o a trust anchor configured.  A TLS handshake is attempted
 * and should fail due to a cipher mismatch.  This ensures the
 * EST client is not offering SRP RSA cipher suites when it
 * doesn't have a trust anchor configured.
 */
static void us1060_test107 ()
{
    pthread_t thread;
    char *c_suite;

    LOG_FUNC_NM;

    /*
     * Start the dummy TLS server using SRP with
     * RSA authentication.
     */
    c_suite = "SRP-RSA-AES-256-CBC-SHA";
    pthread_create(&thread, NULL, US1060_master_tls_thread, c_suite);

    /*
     * Attempt to provision a cert w/o using a
     * trust anchor.  We should see an SSL connection error.
     */
    us1060_easy_provision(1, 0, NULL, US1060_TLS_PORT, EST_ERR_SSL_CIPHER_LIST);


    /*
     * Poor man's thread synchronization
     */
    sleep(2);

    /*
     * Start the dummy TLS server again using SRP with
     * NULL authentication.
     */
    c_suite = "SRP-AES-128-CBC-SHA";
    pthread_create(&thread, NULL, US1060_master_tls_thread, c_suite);

    /*
     * Attempt to provision a cert w/o using a trust anchor.
     * We should see an SSL read error.
     * The dummy TLS server doesn't actually send any data,
     * but the TLS handshake should succeed.
     */
    us1060_easy_provision(1, 0, NULL, US1060_TLS_PORT, EST_ERR_SSL_READ);
}

/*
 * This test case is verifies the happy path when EST
 * proxy is configured in SRP mode.  The client will attempt
 * to use SRP.  The connection between the proxy and
 * server does not use SRP.  We perform a simple enroll
 * operation.
 */
static void us1060_test200 ()
{
    long rv;

    LOG_FUNC_NM;

    /*
     * Restart the EST server with SRP disabled
     */
    st_stop();
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0, 0);
    CU_ASSERT(rv == 0);

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
	                    US1060_UIDPWD_GOOD, NULL, CURLAUTH_BASIC, 
			    NULL, "srp_user", "srp_pwd", NULL, NULL);
    /* 
     * Since we passed in a valid SRP userID/password,
     * we expect the server to respond with success
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test case is verifies the simple enroll fails
 * when the EST client provides a bad SRP password.
 * The connection between the proxy and server does not 
 * use SRP. 
 */
static void us1060_test201 ()
{
    long rv;

    LOG_FUNC_NM;

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
	                    US1060_UIDPWD_GOOD, NULL, CURLAUTH_BASIC, 
			    NULL, "srp_user", "boguspwd", NULL, NULL);
    CU_ASSERT(rv == 0);
}

/*
 * This test case is verifies the simple enroll fails
 * when the EST client provides a bad HTTP password
 * and SRP is used.  The connection between the proxy 
 * and server does not use SRP. 
 */
static void us1060_test202 ()
{
    long rv;

    LOG_FUNC_NM;

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
	                    US1060_UIDPWD_BAD, NULL, CURLAUTH_BASIC, 
			    NULL, "srp_user", "srp_pwd", NULL, NULL);
    CU_ASSERT(rv == 401);
}

/*
 * This test case is verifies the simple enroll works
 * when the EST client provides no HTTP password 
 * and SRP is used.  The connection between the proxy 
 * and server does not use SRP.  HTTP auth is disabled
 * on the proxy.
 */
static void us1060_test203 ()
{
    long rv;

    LOG_FUNC_NM;

    st_proxy_http_disable(1);

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT, US1060_PKCS10_REQ, 
	                    NULL, NULL, CURLAUTH_NONE, 
			    NULL, "srp_user", "srp_pwd", NULL, NULL);
    CU_ASSERT(rv == 200);
}



int us1060_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us1060_tls_srp", 
	                  us1060_init_suite, 
			  us1060_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* 
    * Add the tests to the suite 
    *
    * ********************IMPORTANT*********************
    * Do not change the order of these tests.
    * Some of the tests stop the EST server and restart
    * it using different certs.  If you change the order
    * then false negatives may occur.
    * **************************************************
    *
    */
   if (
#define ADD_TEST(N,C,K,HP,SP,HM,SM,R) \
       (NULL == CU_add_test(pSuite, "TLS-SRP server: matrix entry "#N, us1060_test##N)) ||  
       FOREACH_MATRIX_ENTRY(ADD_TEST)
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP disable ", us1060_test100)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP enable ", us1060_test101)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP w/cert ", us1060_test102)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP FQDN fail ", us1060_test103)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: no TA", us1060_test104)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: no TA w/cert", us1060_test105)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: SRP strengths", us1060_test106)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: SRP suites", us1060_test107)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll w/SRP", us1060_test200)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll bad SRP pwd", us1060_test201)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll bad HTTP pwd", us1060_test202)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll w/o HTTP auth", us1060_test203)))  
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}


