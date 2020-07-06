/*------------------------------------------------------------------
 * us3496.c - Unit Tests URI path segment extension support 
 *
 * March, 2016
 *
 * Copyright (c) 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <est.h>
#include <curl/curl.h>
#include "curl_utils.h"
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif
#include "../../util/test_utils.h"
#include "st_server.h"

#include "../../src/est/est_locl.h"

extern char tst_srvr_path_seg_enroll[];
extern char tst_srvr_path_seg_auth[];

static int path_segment_support;

/*
 * max command line length when generating system commands
 */
#define EST_UT_MAX_CMD_LEN 256

/*
 * The CA certificate used to verify the EST server.  Grab it from the server's directory
 */
/* #define CLIENT_UT_CACERT "../../example/server/estCA/cacert.crt" */
#define CLIENT_UT_CACERT "CA/estCA/cacert.crt"
#define CLIENT_UT_PUBKEY "./est_client_ut_keypair"

#define US3496_SERVER_PORT   29496
#define US3496_SERVER_IP    "127.0.0.1"	
#define US3496_UIDPWD_GOOD   "estuser:estpwd"
#define US3496_UID           "estuser"
#define US3496_PWD           "estpwd"
#ifndef WIN32
#define US3496_CACERTS	    "CA/estCA/cacert.crt"
#define US3496_TRUST_CERTS   "CA/trustedcerts.crt"
#define US3496_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#else
#define US3496_CACERTS	    "CA\\estCA\\cacert.crt"
#define US3496_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US3496_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"

static CRITICAL_SECTION logger_critical_section;  
static void us3496_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}
#endif

#define US3496_ENROLL_URL_BA "https://127.0.0.1:29496/.well-known/est/cacerts-somestring/simpleenroll"
#define US3496_PKCS10_CT	    "Content-Type: application/pkcs10" 

#define US3496_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error);

static void us3496_clean (void)
{
}

static int us3496_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US3496_SERVER_PORT, 
	          US3496_SERVER_CERTKEY,
	          US3496_SERVER_CERTKEY,
	          "US3496 test realm",
	          US3496_CACERTS,
	          US3496_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  manual_enroll,
		  0,
		  nid);
    
    SLEEP(1);
    return rv;
}

static int path_seg_supported(void) {

    EST_CTX *ectx;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    free(cacerts);
    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT, "test_segment");

    if (ectx) est_destroy(ectx);

    if (rc == EST_ERR_NONE) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}


/*
 * This routine is called when CUnit initializes this test
 * suite. 
 * 1. Generate the keypair to be used for this EST Client UT suite
 */
static int us3496_init_suite (void)
{
    int rv = 0;
   
    char cmd[EST_UT_MAX_CMD_LEN];    
    printf("Starting EST Client/Proxy path segment unit tests.\n");

    /*
     * check to see if path segment support has been compiled in
     */
    if (!path_segment_support) {
        printf("URI Path Segment is not supported in this build of EST.  Rebuild using --with-uriparser-dir \n");
        return 0;
    }
    
    /*
     * gen the keypair to be used for EST Client testing
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "openssl ecparam -name prime256v1 -genkey -out %s", CLIENT_UT_PUBKEY);
    printf("%s\n", cmd);
    
    rv = system(cmd);

    /*
     * start the server for the tests that need to talk to a server
     */
    us3496_clean();    
    /*
     * Start an instance of the EST server
     */
    rv = us3496_start_server(0, 0);
    SLEEP(2);
    
    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us3496_destroy_suite (void)
{
    
    st_stop();    
    return 0;
}

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
{
    BIO *bio_err;
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;
    
    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
           __FUNCTION__, openssl_cert_error,
           X509_verify_cert_error_string(openssl_cert_error));
    
    printf("Failing Cert:\n");
    X509_print_fp(stdout,cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
#ifdef HAVE_OLD_OPENSSL    
    X509_get0_signature((ASN1_BIT_STRING **)&cur_cert_sig,
                        (X509_ALGOR **)&cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, (X509_ALGOR *)cur_cert_sig_alg,
                         (ASN1_BIT_STRING *)cur_cert_sig);
#else    
    X509_get0_signature(&cur_cert_sig, &cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, cur_cert_sig_alg, cur_cert_sig);
#endif    

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
    }    

    BIO_free(bio_err);
    
    return approve;
}
    


/*
 * This test case tests the set server with valid parameters,
 * NO path segment
 */
static void us3496_test1 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT, NULL);    
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down path segment that is valid
 */
static void us3496_test2 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "somestring");
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down path segment that contains 2 segments, should fail
 */
static void us3496_test3 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "somestring1/somestring2");

    CU_ASSERT(rc == EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * all valid characters
 */
#define PATH_SEG_ALL_VALID_CHARS "@%50%44%42ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-._~!$&'()*+,;="
static void us3496_test4 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                             PATH_SEG_ALL_VALID_CHARS);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down path segment that is invalid. invalid character.
 */
static void us3496_test5 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "someinvalid<string");
    CU_ASSERT(rc == EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down path segment that is too long (129)
 */
#define path_segment_too_long "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
static void us3496_test6 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               path_segment_too_long);
    CU_ASSERT(rc == EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down a path segment that is equal to an operation (cacerts)
 */
static void us3496_test7 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "cacerts");
    CU_ASSERT(rc == EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down a path segment that contains an operation (cacerts),
 * in this case it's at the front of the string
 */
static void us3496_test8 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "cacerts-server");
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down a path segment that is the empty string.
 * This should fail.
 */
static void us3496_test9 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               "");
    CU_ASSERT(rc == EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down a path segment that contains a ':'.
 * This should pass.
 */
static void us3496_test10 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT, "-._~:@!$&'()*+,;=");    
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/*
 * pass down path segment that is too long (129)
 */
#define path_segment_max "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
static void us3496_test11 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    rc = est_client_set_server(ectx, US3496_SERVER_IP, US3496_SERVER_PORT,
                               path_segment_max);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us3496_add_suite (void)
{
    CU_ErrorCode CU_error;
    
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us3496_client_proxy_path_seg", 
	                  us3496_init_suite, 
			  us3496_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }
   
#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us3496_logger_stderr);
#endif

   /*
    * check to see if path segment support has been compiled in
    */
   if (!path_seg_supported()) {
       printf("URI Path Segment is not supported in this build of EST.  Rebuild using --with-uriparser-dir= \n");
       path_segment_support = 0;
       return 0;
   }
   path_segment_support = 1; 
   
   if (path_segment_support) {
       
       /* add the tests to the suite */
       /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
       if (
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, no path segment", us3496_test1)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, valid path segment", us3496_test2)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, multi segment path segment", us3496_test3)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, valid path segment - all valid chars", us3496_test4)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, invalid path segment", us3496_test5)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment too long", us3496_test6)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment equals operation string", us3496_test7)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment contains operation string", us3496_test8)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment is the empty string", us3496_test9)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment contains a colon", us3496_test10)) ||
           (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters, path segment is the max length", us3496_test11))
           ) {
           CU_error = CU_get_error();
           printf("%d\n", CU_error);
           
           CU_cleanup_registry();
           printf("%s\n", CU_get_error_msg());
           return CU_get_error();
       }
   }
   

   return CUE_SUCCESS;
#endif
}


