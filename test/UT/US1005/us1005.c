/*------------------------------------------------------------------
 * us1005.c - Unit Tests for User Story 1005 - Client easy provision
 *
 * November, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
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

#ifdef WIN32
static CRITICAL_SECTION logger_critical_section;
#endif 

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US1005_SERVER_PORT      31005
#define US1005_SERVER_IP    "127.0.0.1" 
#define US1005_UID          "estuser"
#define US1005_PWD          "estpwd"
#ifndef WIN32
#define US1005_CACERTS          "CA/estCA/cacert.crt"
#define US1005_TRUST_CERTS      "CA/trustedcerts.crt"
#define US1005_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
#define US1005_CLIENT_KEY       "US1005/implicit-key.pem"
#define US1005_CLIENT_CERT      "US1005/implicit-cert.pem"
#else
#define US1005_CACERTS          "CA\\estCA\\cacert.crt"
#define US1005_TRUST_CERTS      "CA\\trustedcerts.crt"
#define US1005_SERVER_CERTKEY   "CA\\estCA\\private\\estservercertandkey.pem"
#define US1005_CLIENT_KEY       "US1005\\implicit-key.pem"
#define US1005_CLIENT_CERT      "US1005\\implicit-cert.pem"
#endif 
#define US1005_CSR_NOPOP        "MBQGBysGAQEBARYGCWCGSAFlAwQCAg==\0"

static char *log_search_target = NULL;
static int search_target_found = 0;
/*
 * This is a simple callback used to override the default
 * logging facility in libest.  We'll use this to look
 * for specific debug output.
 */
static void us1005_logger_stderr (char *format, va_list l)
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

static void us1005_clean (void)
{
}

static int us1005_start_server (int manual_enroll, int nid, int no_http_auth,
                                int enable_pop)
{
    int rv;

    rv = st_start(US1005_SERVER_PORT,
                  US1005_SERVER_CERTKEY,
                  US1005_SERVER_CERTKEY,
                  "US1005 test realm",
                  US1005_CACERTS,
                  US1005_TRUST_CERTS,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  enable_pop,
                  nid);

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
static int us1005_init_suite (void)
{
    int rv;

#ifdef WIN32
    /* Initialize critical section on Windows*/
    InitializeCriticalSection(&logger_critical_section);
#endif 

    est_init_logger(EST_LOG_LVL_INFO, &us1005_logger_stderr);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1005_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us1005_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1005_start_server(0, 0, 0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1005_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

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
    if (pkey == NULL) {
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
 * This function performs the easy provision operation using
 * a UID/PWD to identify the client to the server.  This
 * is used for a variety of test cases in this module.
 */
static void us1005_easy_provision (char *cn, char *server, int ba_hint,
                                   int use_cert)
{
    EST_CTX *ectx;
    EVP_PKEY *new_key;
    int rv;
    int pkcs7_len = 0;
    int ca_certs_len = 0;
    unsigned char *new_cert = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    X509 *cert = NULL;
    BIO *in;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    if (use_cert) {
        /*
         * Read in the private key
         */
        key_len = read_binary_file(US1005_CLIENT_KEY, &key_raw);
        CU_ASSERT(key_len > 0);
        key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
        CU_ASSERT(key != NULL);
        free(key_raw);

        /*
         * Read in the old cert
         */
        cert_len = read_binary_file(US1005_CLIENT_CERT, &cert_raw);
        CU_ASSERT(cert_len > 0);
        in = BIO_new_mem_buf(cert_raw, cert_len);
        CU_ASSERT(in != NULL);
        if (!in)
            return;
        cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
        CU_ASSERT(cert != NULL);
        if (!cert)
            return;
        BIO_free_all(in);
        free(cert_raw);
    }

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1005_UID, US1005_PWD, cert, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    if (ba_hint) {
        rv = est_client_enable_basic_auth_hint(ectx);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US1005_SERVER_PORT, NULL);

    /*
     * generate a new private key
     */
    new_key = generate_private_key();
    CU_ASSERT(new_key != NULL);

    /*
     * Attempt to provision a new cert
     */
    rv = est_client_provision_cert(ectx, cn, &pkcs7_len, &ca_certs_len,
        new_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    EVP_PKEY_free(new_key);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (new_cert)
            free(new_cert);
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
        if (new_cert)
            free(new_cert);
    } else {
        est_destroy(ectx);
        return;
    }

    EVP_PKEY_free(key);
    X509_free(cert);

    /*
     * Cleanup
     */
    est_destroy(ectx);
}

/*
 * Easy provision - HTTP basic auth, no client cert
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test1 (void)
{
    LOG_FUNC_NM
    ;

    us1005_easy_provision("TC1005-1", US1005_SERVER_IP, 0, 0);
}

/*
 * Easy provision - with HTTP basic auth hint enabled, no client cert
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test2 (void)
{
    LOG_FUNC_NM
    ;

    us1005_easy_provision("TC1005-2", US1005_SERVER_IP, 1, 0);
}

/*
 * Easy provision - client cert with HTTP basic auth enabled
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test3 (void)
{
    LOG_FUNC_NM
    ;

    us1005_easy_provision("TC1005-3", US1005_SERVER_IP, 0, 1);
}

/*
 * Easy provision - client cert with HTTP basic auth hint enabled
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test4 (void)
{
    LOG_FUNC_NM
    ;

    us1005_easy_provision("TC1005-4", US1005_SERVER_IP, 1, 1);
}

/*
 * Null pointers test
 */
static void us1005_test5 (void)
{
    int p7len = 0;
    int calen = 0;
    EVP_PKEY *key;
    int rv;
    EST_CTX *ectx;

    LOG_FUNC_NM
    ;

    /*
     * Create a valid context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US1005_UID, US1005_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US1005_SERVER_IP, US1005_SERVER_PORT, NULL);

    /*
     * Create a valid key pair
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Try with a NULL context
     */
    rv = est_client_provision_cert(NULL, "TEST2", &p7len, &calen, key);
    CU_ASSERT(rv == EST_ERR_NO_CTX);

    /*
     * Try with a NULL p7 length
     */
    rv = est_client_provision_cert(ectx, "TEST2", NULL, &calen, key);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);

    /*
     * Try with a NULL cacerts length
     */
    rv = est_client_provision_cert(ectx, "TEST2", &p7len, NULL, key);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);

    /*
     * Try with a NULL key
     */
    rv = est_client_provision_cert(ectx, "TEST2", &p7len, &calen, NULL);
    CU_ASSERT(rv == EST_ERR_NO_KEY);

    EVP_PKEY_free(key);
    est_destroy(ectx);
}

/*
 *  Enable pop on server, enable CSR attributes on server w/o challengePassword OID
 */
static void us1005_test6 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP enabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 1);

    /*
     * Set the CSR attributes to a value that doesn't include challengePassword OID
     */
    st_set_csrattrs(US1005_CSR_NOPOP);

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Client will include challengePassword in CSR\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-6", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

/*
 *  Disable pop on server, enable CSR attributes on server w/o challengePassword OID
 */
static void us1005_test7 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP disabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 0);

    /*
     * Set the CSR attributes to a value that doesn't include challengePassword OID
     */
    st_set_csrattrs(US1005_CSR_NOPOP);

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Cert request does not contain PoP\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-7", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

/*
 *  Enable pop on server, enable CSR attributes on server w/ challengePassword OID
 */
static void us1005_test8 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP enabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 1);

    /*
     * Set the CSR attributes to the default value, which includes challengePassword OID
     */
    st_set_csrattrs(NULL);

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Client will include challengePassword in CSR\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-8", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

/*
 *  Disable pop on server, enable CSR attributes on server w/challengePassword OID
 */
static void us1005_test9 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP disabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 0);

    /*
     * Set the CSR attributes to the default value, which includes challengePassword OID
     */
    st_set_csrattrs(NULL);

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Client will include challengePassword in CSR\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-9", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

/*
 *  Enable pop on server, disable CSR attributes on server
 */
static void us1005_test10 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP enabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 1);

    /*
     * Set the CSR attributes to the default value, which includes challengePassword OID
     */
    st_set_csrattrs(NULL);
    st_disable_csr_cb();

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Client will include challengePassword in CSR\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-10", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

/*
 *  Disable pop on server, disable CSR attributes on server
 */
static void us1005_test11 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with PoP disabled
     */
    st_stop();
    us1005_start_server(0, 0, 0, 0);

    /*
     * Set the CSR attributes to the default value, which includes challengePassword OID
     */
    st_set_csrattrs(NULL);
    st_disable_csr_cb();

    /*
     * We will search the debugs for the appropriate output
     * to confirm the PoP behavior is working as desired.
     */
    log_search_target = "Cert request does not contain PoP\0";
    search_target_found = 0;

    /*
     * Provision a new cert
     */
    us1005_easy_provision("TC1005-11", US1005_SERVER_IP, 0, 0);

    CU_ASSERT(search_target_found == 1);

    /*
     * Set the CSR attributes back to default value
     */
    st_set_csrattrs(NULL);
}

//
// The next two test caes repeate tests 3 & 4 but with
// HTTP auth disabled on the server.
//

/*
 * Easy provision - client cert with HTTP basic auth disabled
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test93 (void)
{
    LOG_FUNC_NM
    ;

    /*
     * Restart the server with HTTP auth disabled
     */
    st_stop();
    us1005_start_server(0, 0, 1, 0);

    us1005_easy_provision("TC1005-93", US1005_SERVER_IP, 0, 1);
}

/*
 * Easy provision - client cert with HTTP basic auth hint enabled
 *
 * This is a basic test to perform a a full trusted enroll
 * sequence of /cacerts, /csrattrs, and /simpleenroll using a
 * user ID and password to identify the client to the server.
 * No identity certificate is used by the client.
 */
static void us1005_test94 (void)
{
    LOG_FUNC_NM
    ;

    us1005_easy_provision("TC1005-94", US1005_SERVER_IP, 1, 1);
}

int us1005_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1005_client_easy_provision",
            us1005_init_suite,
            us1005_destroy_suite);
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
    if ((NULL == CU_add_test(pSuite, "Easy provision - no cert", us1005_test1)) ||
        (NULL == CU_add_test(pSuite, "Easy provision - no cert HTTP BA hint", us1005_test2)) ||
        (NULL == CU_add_test(pSuite, "Easy provision - w/cert", us1005_test3)) ||
        (NULL == CU_add_test(pSuite, "Easy provision - w/cert HTTP BA hint", us1005_test4)) ||
        (NULL == CU_add_test(pSuite, "Null pointers", us1005_test5)) ||
        (NULL == CU_add_test(pSuite, "Enable PoP - no challengePassword", us1005_test6)) ||
        (NULL == CU_add_test(pSuite, "Disable PoP - no challengePassword", us1005_test7)) ||
        (NULL == CU_add_test(pSuite, "Enable PoP - w/challengePassword", us1005_test8)) ||
        (NULL == CU_add_test(pSuite, "Disable PoP - w/challengePassword", us1005_test9)) ||
        (NULL == CU_add_test(pSuite, "Enable PoP - CSR disabled", us1005_test10)) ||
        (NULL == CU_add_test(pSuite, "Disable PoP - CSR disabled", us1005_test11)) ||
        (NULL == CU_add_test(pSuite, "Easy provision - w/cert no server auth", us1005_test93)) ||
        (NULL == CU_add_test(pSuite, "Easy provision - w/cert HTTP BA hint no server auth", us1005_test94)))
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

