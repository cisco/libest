/*------------------------------------------------------------------
 * us1060c.c - Unit Tests for User Story 1060 - TLS SRP support (client)
 *
 * May, 2014
 *
 * Copyright (c) 2014-2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#endif
#include <est.h>
#include "test_utils.h"
#include "st_server.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define US1060C_SERVER_PORT   31062
#define US1060C_TLS_PORT      31063	
#define US1060C_SERVER_IP     "127.0.0.1"	
#define US1060C_UID           "estuser"
#define US1060C_PWD	      "estpwd"

/* Cert/Key files + SRP password file */
#ifdef WIN32
#define US1060C_CACERTS         ".\\CA\\estCA\\cacert.crt"
#define US1060C_TRUST_CERTS     ".\\CA\\trustedcerts.crt"
#define US1060C_SERVER_CERTKEY  ".\\CA\\estCA\\private\\estservercertandkey.pem"
#define US1060C_RSA_CERT        ".\\US1060\\cert-rsa.pem"
#define US1060C_RSA_KEY         ".\\US1060\\key-rsa.pem"
#define US1060C_RSA_CERT_BAD    ".\\US1060\\cert-rsa-fqdnfail.pem"
#define US1060C_RSA_KEY_BAD     ".\\US1060\\key-rsa-fqdnfail.pem"
#define US1060C_VFILE           ".\\US1060\\passwd.srpv"
#else
#define US1060C_CACERTS         "./CA/estCA/cacert.crt"
#define US1060C_TRUST_CERTS     "./CA/trustedcerts.crt"
#define US1060C_SERVER_CERTKEY  "./CA/estCA/private/estservercertandkey.pem"
#define US1060C_RSA_CERT        "./US1060/cert-rsa.pem"
#define US1060C_RSA_KEY         "./US1060/key-rsa.pem"
#define US1060C_RSA_CERT_BAD    "./US1060/cert-rsa-fqdnfail.pem"
#define US1060C_RSA_KEY_BAD     "./US1060/key-rsa-fqdnfail.pem"
#define US1060C_VFILE           "./US1060/passwd.srpv"
#endif

#define US1060C_PKCS10_REQ    "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"

/* Macro definitions */
#ifdef WIN32
#define SLEEP(x) Sleep(x*1000)
CRITICAL_SECTION logger_critical_section;
#else
#define SLEEP(x) sleep(x)
#endif

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
    RSA_generate_key_ex(rsa, 2048, bn, NULL);    

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
static void us1060c_logger_stderr (char *format, va_list l) 
{
    char t_log[1024];
#ifndef WIN32
    flockfile(stderr);
#else
    EnterCriticalSection(&logger_critical_section);
#endif 
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
#ifndef WIN32
    funlockfile(stderr);
#else
    LeaveCriticalSection(&logger_critical_section);
#endif 
}

static int us1060c_start_server (char *cert, char *key, int no_http_auth, int enable_pop, int enable_srp)
{
    int rv;

    if (enable_srp) {
	rv = st_start_srp(US1060C_SERVER_PORT, 
			  cert, key,
			  "US1060 test realm",
			  US1060C_CACERTS,
			  US1060C_TRUST_CERTS,
	                  "CA/estExampleCA.cnf",
		          enable_pop,
		          US1060C_VFILE);
    } else {
	rv = st_start(US1060C_SERVER_PORT, 
		      cert, key,
		      "US1060 test realm",
		      US1060C_CACERTS,
		      US1060C_TRUST_CERTS,
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
static int us1060c_init_suite (void)
{
    int rv;

#ifdef WIN32
    /* Initialize critical section on Windows*/
    InitializeCriticalSection(&logger_critical_section);
#endif

    est_init_logger(EST_LOG_LVL_INFO, &us1060c_logger_stderr);

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us1060c_start_server(US1060C_SERVER_CERTKEY, US1060C_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Read in the CA certificates
     * Used for client-side API testing
     */
    cacerts_len = read_binary_file(US1060C_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    srpdb = SRP_VBASE_new(NULL);
    if (!srpdb) {
	printf("\nUnable allocate SRP verifier database.  Aborting!!!\n");
    }
    if (SRP_VBASE_init(srpdb, US1060C_VFILE) != SRP_NO_ERROR) {
	printf("\nUnable initialize SRP verifier database.  Aborting!!!\n");
    }

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1060c_destroy_suite (void)
{
    if (srpdb) {
	SRP_VBASE_free(srpdb);
    }

    st_stop();
    free(cacerts);
    return 0;
}


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
    int              dummy_for_path_segs;
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

static void us1060c_easy_provision (int use_srp, int use_ta, char *cipher_suite, int port, int expected_rv)
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
    rv = est_client_set_auth(ectx, US1060C_UID, US1060C_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060C_SERVER_IP, port, NULL);

    if (use_srp) {
	rv = est_client_enable_srp(ectx, 1024, US1060C_UID, US1060C_PWD); 
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
    rv = est_client_provision_cert(ectx, "US1060C_TEST1xx", &pkcs7_len, &ca_certs_len, new_key);
    CU_ASSERT(rv == expected_rv);
    if (rv != expected_rv) {
	printf("\nExpected rv was %d, rv returned was %d", expected_rv, rv);
    }
    EVP_PKEY_free(new_key);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
	new_cert = malloc(pkcs7_len);
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
	new_cert = malloc(ca_certs_len);
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
static void us1060c_test100 (void)
{
    LOG_FUNC_NM;

    st_stop();
    SLEEP(2);
    us1060c_start_server(US1060C_SERVER_CERTKEY, US1060C_SERVER_CERTKEY, 0, 0, 1);

    us1060c_easy_provision(0, 1, NULL, US1060C_SERVER_PORT, EST_ERR_NONE);
}

/*
 * Simple "happy path" test case using the easy provision
 * API with SRP enabled.  Note, this is also testing
 * TLS session resumption along with SRP since the easy
 * provision implicitly uses TLS session resumption.
 */
static void us1060c_test101 (void)
{
    LOG_FUNC_NM;

    us1060c_easy_provision(1, 1, NULL, US1060C_SERVER_PORT, EST_ERR_NONE);
}

/*
 * This test will enable a just the SRP-RSA-AES-128-CBC-SHA
 * cipher suite, which forces the server to send a certificate
 * to the client while SRP is used.  The FQDN check should occur
 * and succeed.
 */
static void us1060c_test102 (void)
{
    LOG_FUNC_NM;

    /*
     * We need to restart the EST server using an RSA key
     * None of the SRP cipher suites support ECDSA
     */
    st_stop();
    SLEEP(2);
    us1060c_start_server(US1060C_RSA_CERT, US1060C_RSA_KEY, 0, 0, 1);

    us1060c_easy_provision(1, 1, "SRP-RSA-AES-128-CBC-SHA", US1060C_SERVER_PORT, EST_ERR_NONE);
}

/*
 * This test will enable a just the SRP-RSA-AES-128-CBC-SHA
 * cipher suite, which forces the server to send a certificate
 * to the client while SRP is used.  Unlike test #102, we'll
 * use a server cert with a mismatched FQDN.  This will
 * ensure the FQDN check still occurs when SRP is used.
 */
static void us1060c_test103 (void)
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
    SLEEP(2);
    us1060c_start_server(US1060C_RSA_CERT_BAD, US1060C_RSA_KEY_BAD, 0, 0, 1);

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
    rv = est_client_set_auth(ectx, US1060C_UID, US1060C_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060C_SERVER_IP, US1060C_SERVER_PORT, NULL);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060C_UID, US1060C_PWD); 

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
    rv = est_client_enroll(ectx, "US1060C_TEST103", &pkcs7_len, new_key);
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
static void us1060c_test104 (void)
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
    SLEEP(2);
    us1060c_start_server(US1060C_SERVER_CERTKEY, US1060C_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060C_UID, US1060C_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060C_SERVER_IP, US1060C_SERVER_PORT, NULL);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060C_UID, US1060C_PWD); 

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060C_TEST104", &pkcs7_len, new_key);
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
static void us1060c_test105 (void)
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
    SLEEP(2);
    us1060c_start_server(US1060C_RSA_CERT, US1060C_RSA_KEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060C_UID, US1060C_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060C_SERVER_IP, US1060C_SERVER_PORT, NULL);

    /*
     * Enable SRP on the client
     */
    rv = est_client_enable_srp(ectx, 1024, US1060C_UID, US1060C_PWD); 

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
    rv = est_client_enroll(ectx, "US1060C_TEST105", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);

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
static void us1060c_test106 (void)
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
    SLEEP(2);
    rv = us1060c_start_server(US1060C_SERVER_CERTKEY, US1060C_SERVER_CERTKEY, 0, 0, 1);

    /*
     * Create a client context 
     */
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1060C_UID, US1060C_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1060C_SERVER_IP, US1060C_SERVER_PORT, NULL);

    /*
     * Enable SRP on the client
     * Use a strength below the minimum
     */
    rv = est_client_enable_srp(ectx, 1023, US1060C_UID, US1060C_PWD); 
    CU_ASSERT(rv == EST_ERR_SRP_STRENGTH_LOW);

    /*
     * Enable SRP on the client
     * Use a strength slightly larger then the N value in passwd.srpv
     */
    rv = est_client_enable_srp(ectx, 1537, US1060C_UID, US1060C_PWD); 
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060C_TEST106a", &pkcs7_len, new_key);
    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);

    /*
     * Enable SRP on the client
     * Use a strength the same size as the N value in passwd.srpv
     */
    rv = est_client_enable_srp(ectx, 1536, US1060C_UID, US1060C_PWD); 
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_enroll(ectx, "US1060C_TEST106b", &pkcs7_len, new_key);
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

    user = SRP_VBASE_get1_by_user(srpdb, login);

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
        SRP_user_pwd_free(user);
	return SSL3_AL_FATAL;
    }
		
    printf("SRP parameters set: username = \"%s\" info=\"%s\" \n", login, user->info);

    user = NULL;
    login = NULL;
    fflush(stdout);
    SRP_user_pwd_free(user);
    return SSL_ERROR_NONE;
}


/*
 * This starts a minimal TLS server that only does a
 * handshake and then closes the connection.  This is
 * strictly used to test TLS session negotiation
 * behavior with EST.
 */
static void us1060c_start_tls_server (char *cipherstring)
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

#ifdef HAVE_OLD_OPENSSL        
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ssl_ctx = SSL_CTX_new(TLS_server_method());
#endif            
    if (!ssl_ctx) {
	printf("Failed to create SSL context\n");
	ERR_print_errors(berr);
	return;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, US1060C_RSA_CERT) != 1) {
	printf("Failed to load server certificate\n");
	ERR_print_errors(berr);
	return;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, US1060C_RSA_KEY, SSL_FILETYPE_PEM) != 1) {
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

    sprintf(h_p, "%s:%d", US1060C_SERVER_IP, US1060C_TLS_PORT);
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
#ifdef WIN32
    SLEEP(2);
#endif 
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    BIO_free(berr);
    (void)BIO_reset(listener);
    BIO_free_all(listener);
#ifndef WIN32
    pthread_exit(0);
#else
    ExitThread(0); 
#endif
}

#ifndef WIN32
static void* US1060c_master_tls_thread (void *arg)
#else
DWORD WINAPI US1060c_master_tls_thread(void *arg)
#endif 
{
    char *c_suite = (char *)arg;
    /*
     * We'll start the server using an SRP cipher suite
     * that requires an RSA certificate.  The client will
     * not have a trust anchor configured, which should
     * result in a failed TLS handshake.
     */
    us1060c_start_tls_server(c_suite);
#ifndef WIN32
    return NULL;
#else
    return 0;
#endif
}

/*
 * This test starts a TLS server with only the SRP RSA
 * suites enabled.  It then configures EST client for SRP
 * mode w/o a trust anchor configured.  A TLS handshake is attempted
 * and should fail due to a cipher mismatch.  This ensures the
 * EST client is not offering SRP RSA cipher suites when it
 * doesn't have a trust anchor configured.
 */
static void us1060c_test107 (void)
{
#ifndef WIN32
    pthread_t thread;
#else
    HANDLE mThread_1;
    HANDLE mThread_2;
    DWORD mThreadID_1;
    DWORD mThreadID_2;
#endif 
    char *c_suite;

    LOG_FUNC_NM;

    /*
     * Start the dummy TLS server using SRP with
     * RSA authentication.
     */
    c_suite = "SRP-RSA-AES-256-CBC-SHA";
#ifndef WIN32
    pthread_create(&thread, NULL, US1060c_master_tls_thread, c_suite);
#else
    mThread_1 = CreateThread(NULL, 0, US1060c_master_tls_thread, c_suite, 0, &mThreadID_1);
#endif

    /*
     * Attempt to provision a cert w/o using a
     * trust anchor.  We should see an SSL connection error.
     */
    us1060c_easy_provision(1, 0, NULL, US1060C_TLS_PORT, EST_ERR_SSL_CONNECT);


    /*
     * Poor man's thread synchronization
     */
    SLEEP(2);

    /*
     * Start the dummy TLS server again using SRP with
     * NULL authentication.
     */
    c_suite = "SRP-AES-128-CBC-SHA";
#ifndef WIN32
    pthread_create(&thread, NULL, US1060c_master_tls_thread, c_suite);
#else
    mThread_2 = CreateThread(NULL, 0, US1060c_master_tls_thread, c_suite, 0, &mThreadID_2);
#endif 

    /*
     * Attempt to provision a cert w/o using a
     * trust anchor.  We should see an HTTP Not Found error.
     * The dummy TLS server doesn't actually send any data,
     * but the TLS handshake should succeed.
     */
    us1060c_easy_provision(1, 0, NULL, US1060C_TLS_PORT, EST_ERR_HTTP_NOT_FOUND);
}

int us1060c_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us1060c_tls_srp (client)", 
	                  us1060c_init_suite, 
			  us1060c_destroy_suite);
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
   if ((NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP disable ", us1060c_test100)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP enable ", us1060c_test101)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP w/cert ", us1060c_test102)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: easy SRP FQDN fail ", us1060c_test103)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: no TA", us1060c_test104)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: no TA w/cert", us1060c_test105)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: SRP strengths", us1060c_test106)) ||  
       (NULL == CU_add_test(pSuite, "TLS-SRP client: SRP suites", us1060c_test107)))
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}

