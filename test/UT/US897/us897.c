/*------------------------------------------------------------------
 * us897.c - Unit Tests for User Story 897 - Client CACerts 
 *
 * June, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif 
#include <est.h>
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif
#include "../../util/test_utils.h"
#include "st_server.h"

/*
 * max command line length when generating system commands
 */
#define EST_UT_MAX_CMD_LEN 256
#define EST_CA_MAX	    200000
/*
 * The CA certificate used to verify the EST server.  Grab it from the server's directory
 */
/* #define CLIENT_UT_CACERT "../../example/server/estCA/cacert.crt" */
#define US897_SERVER_PORT   29897
#define CLIENT_UT_PUBKEY "./est_client_ut_keypair"
#define US897_SERVER_IP	    "127.0.0.1"	
#define US897_UID	    "estuser"
#define US897_PWD	    "estpwd"

#ifndef WIN32
#define CLIENT_UT_CACERT "CA/estCA/cacert.crt"
#define US897_CACERTS	    "CA/estCA/cacert.crt"
#define US897_TRUST_CERTS   "CA/trustedcerts.crt"
#define US897_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US897_CACERTS_SINGLE_CHAIN_MULT_CERTS "US897/singlechain_10certs_trusted.crt"
#define US897_CACERTS_SINGLE_CHAIN_MULT_CERTS_ONE_MISSING "US897/singlechain_9certs_missingcert.crt"
#define US897_CACERTS_SINGLE_CHAIN_EXPIRED "US897/singlechain_expired.crt"
#define US897_CACERTS_MULTI_CHAIN_CRLS "US897/trustedCHain10RevokedDepth6Implicit10andcacert.crt"
#else
#define CLIENT_UT_CACERT "CA\\estCA/cacert.crt"
#define US897_CACERTS	    "CA\\estCA\\cacert.crt"
#define US897_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US897_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US897_CACERTS_SINGLE_CHAIN_MULT_CERTS "US897\\singlechain_10certs_trusted.crt"
#define US897_CACERTS_SINGLE_CHAIN_MULT_CERTS_ONE_MISSING "US897\\singlechain_9certs_missingcert.crt"
#define US897_CACERTS_SINGLE_CHAIN_EXPIRED "US897\\singlechain_expired.crt"
#define US897_CACERTS_MULTI_CHAIN_CRLS "US897\\trustedCHain10RevokedDepth6Implicit10andcacert.crt"
#endif 

static void us897_clean (void)
{
}

static int us897_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
	          US897_CACERTS,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  manual_enroll,
		  0,
		  nid);
    
    SLEEP(1);
    return rv;
}


/*
 * This routine is called when CUnit initializes this test
 * suite. 
 * 1. Generate the keypair to be used for this EST Client UT suite
 */
static int us897_init_suite (void)
{
    int rv = 0;
    
    char cmd[EST_UT_MAX_CMD_LEN];    
    printf("Starting EST Client unit tests. PDB\n");

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
    us897_clean();    
    /*
     * Start an instance of the EST server
     */
    rv = us897_start_server(0, 0);
    SLEEP(2);
    
    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us897_destroy_suite (void)
{
    
    st_stop();    
    return 0;
}

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify(X509 *cur_cert, int openssl_cert_error)
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
 * This test case initializes an EST client context
 * using local CA certs, no client cert, and a valid public key,
 * no userid and password.
 */
static void us897_test1 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc;
    EVP_PKEY *priv_key;
    
    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }
    
    est_init_logger(EST_LOG_LVL_INFO, NULL);    
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
                             
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
 * This test case initializes an EST client context
 * using no local CA certs.  This is expected to be a successful initialization
 * since the local CA trust anchor certs are not mandatory.
 */
static void us897_test2 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
	printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }
    
    ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

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
 * This test case initializes an EST client context
 * using a local CA cert, no client cert,
 * and a valid public key, no userid and password.
 */
static void us897_test3 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
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

#if 0
/*
 * This test case initializes an EST client context
 * using explicit CA certs, no client cert, and a valid public key,
 * no userid and password.
 */
static void us897_test3 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc;
    EVP_PKEY *priv_key;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
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
#endif


/*
 * This test case initializes an EST client context
 * using explict CA certs, no client cert, a public key,
 * and a userid and password.
 */
static void us897_test6 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "USER", "PASSWORD", NULL, priv_key);
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
 * This test case initializes an EST client context
 * using explict CA certs, no client cert, a public key,
 * and a userid and NO password.
 */
static void us897_test7 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "USER", NULL, NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_INVALID_PARAMETERS);

    if (ectx) {
        est_destroy(ectx);
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, NULL, "PASSWORD", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_INVALID_PARAMETERS);
    
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
 * This test case tests the set server with valid parameters
 */
static void us897_test9 (void) 
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

    rc = est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);    
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
 * This test case tests the set server with invalid parameters
 */
static void us897_test10 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    char *server_name_too_long = "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890"\
        "12345678901234567890123456789012345678901234567890123456";
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

    /*
     * Null server name
     */
    rc = est_client_set_server(ectx, NULL, US897_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_INVALID_SERVER_NAME);

    /*
     * server too long
     */
    rc = est_client_set_server(ectx, server_name_too_long, US897_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_INVALID_SERVER_NAME);

    /*
     *  port num less than 0
     */
    rc = est_client_set_server(ectx, US897_SERVER_IP, -1, NULL);
    CU_ASSERT(rc == EST_ERR_INVALID_PORT_NUM);

    /*
     * port num greater than max
     */
    rc = est_client_set_server(ectx, US897_SERVER_IP, 65536, NULL);
    CU_ASSERT(rc == EST_ERR_INVALID_PORT_NUM);

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
 * This test case tests the Get CACerts request
 *
 */
static void us897_test11 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;

    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;
    EVP_PKEY *priv_key;

    SLEEP(1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);
    
    rc = est_client_copy_cacerts(ectx, retrieved_cacerts);
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);

    /*
     * make sure that the context is no longer valid and the EST client is
     * back to the uninitialized state
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);
    CU_ASSERT(rc == EST_ERR_CLIENT_NOT_INITIALIZED);

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
 * This test case tests the Get CACerts request with invalid input parameters
 *
 */
static void us897_test12 (void) 
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
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, NULL);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rc == EST_ERR_INVALID_PARAMETERS);
    
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
 * This test case tests the CA cert response verification function.  It will
 * verify a CAcert response containing a single certificate
 */
static void us897_test13 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    

    /*
     * Stop the existing server.  Need to ensure that the server
     * is using a specific CA cert chain.
     */
    st_stop();
    SLEEP(2);

    /*
     * Spin up a new instance of the EST server
     * using a CA cert chain that contains just one cert
     */
    rc = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
	          US897_CACERTS,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  0, 0, 0);

    CU_ASSERT(rc == 0);
    if (rc) return;
    SLEEP(1);

    /*
     * Read in thestartup  CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);
    
    rc = est_client_copy_cacerts(ectx, retrieved_cacerts);
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
 * This test case tests the CA cert response verification function.  It will
 * verify a CAcert response containing a single chain with multiple certs
 */
static void us897_test14 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    

    /*
     * Stop the existing server.  Need to ensure that the server
     * is using a specific CA cert chain.
     */
    st_stop();
    SLEEP(2);

    /*
     * Spin up a new instance of the EST server
     * using a CA cert chain that contains just one cert
     */
    rc = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
                  US897_CACERTS_SINGLE_CHAIN_MULT_CERTS,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  0, 0, 0);

    CU_ASSERT(rc == 0);
    if (rc) return;
    SLEEP(1);

    /*
     * Read in thestartup  CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);
    
    rc = est_client_copy_cacerts(ectx, retrieved_cacerts);
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
 * This test case tests the CA cert response verification function.  It will
 * verify a CAcert response containing a single chain with multiple certs and
 * a missing cert in the chain.  
 */
static void us897_test15 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    

    /*
     * Stop the existing server.  Need to ensure that the server
     * is using a specific CA cert chain.
     */
    st_stop();
    SLEEP(2);

    /*
     * Spin up a new instance of the EST server
     * using a CA cert chain that contains just one cert
     */
    rc = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
                  US897_CACERTS_SINGLE_CHAIN_MULT_CERTS_ONE_MISSING,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  0, 0, 0);

    CU_ASSERT(rc == 0);
    if (rc) return;
    SLEEP(1);

    /*
     * Read in thestartup  CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_CACERT_VERIFICATION);
    CU_ASSERT(retrieved_cacerts_len == 0);

    if (retrieved_cacerts_len) {
        /*
         * Shouldn't be in here, but if we are, malloc and call
         */
        retrieved_cacerts = malloc(retrieved_cacerts_len);
        rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

        /*
         * est should fail indicating that there's no cert to provide
         */
         CU_ASSERT(rc == EST_ERR_NO_CERTIFICATE);
    }    
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
 * This test case tests the CA cert response verification function.  It will
 * verify a CAcert response containing a single chain with multiple certs 
 * with the intermediate cert expired.
 */
static void us897_test16 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    

    /*
     * Stop the existing server.  Need to ensure that the server
     * is using a specific CA cert chain.
     */
    st_stop();
    SLEEP(2);

    /*
     * Spin up a new instance of the EST server
     * using a CA cert chain that contains just one cert
     */
    rc = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
                  US897_CACERTS_SINGLE_CHAIN_EXPIRED,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  0, 0, 0);

    CU_ASSERT(rc == 0);
    if (rc) return;
    SLEEP(1);

    /*
     * Read in thestartup  CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_CACERT_VERIFICATION);
    CU_ASSERT(retrieved_cacerts_len == 0);

    if (retrieved_cacerts_len) {
        /*
         * Shouldn't be in here, but if we are, malloc and call
         */
        retrieved_cacerts = malloc(retrieved_cacerts_len);
        rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

        /*
         * est should fail indicating that there's no cert to provide
         */
         CU_ASSERT(rc == EST_ERR_NO_CERTIFICATE);
    }    
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
 * This test case tests the CA cert response verification function.  It will
 * verify a CAcert response containing a multiple chains with multiple certs and
 * a CRL block.  The CRLs should be ignored.  
 */
static void us897_test17 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    

    /*
     * Stop the existing server.  Need to ensure that the server
     * is using a specific CA cert chain.
     */
    st_stop();
    SLEEP(2);

    /*
     * Spin up a new instance of the EST server
     * using a CA cert chain that contains just one cert
     */
    rc = st_start(US897_SERVER_PORT, 
	          US897_SERVER_CERTKEY,
	          US897_SERVER_CERTKEY,
	          "US897 test realm",
                  US897_CACERTS_MULTI_CHAIN_CRLS,
	          US897_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  0, 0, 0);

    CU_ASSERT(rc == 0);
    if (rc) return;
    SLEEP(1);

    /*
     * Read in the startup CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    if (retrieved_cacerts_len) {
        /*
         * Shouldn't be in here, but if we are, malloc and call
         */
        retrieved_cacerts = malloc(retrieved_cacerts_len);
        rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

        /*
         * est should fail indicating that there's no cert to provide
         */
         CU_ASSERT(rc == EST_ERR_NONE);
    }    
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
 * This test case tests the SSL read set timeout API.
 * The setting of the min, the max, a value in between, and a value
 * beyond the max.
 */
static void us897_test18 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    unsigned char *retrieved_cacerts = NULL;
    int  retrieved_cacerts_len = 0;    
  
    /*
     * Read in the startup CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

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
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US897_SERVER_IP, US897_SERVER_PORT, NULL);

    rc = est_client_set_read_timeout(ectx, EST_SSL_READ_TIMEOUT_MIN);
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_set_read_timeout(ectx, EST_SSL_READ_TIMEOUT_MAX);
    CU_ASSERT(rc == EST_ERR_NONE);
    rc = est_client_set_read_timeout(ectx, EST_SSL_READ_TIMEOUT_MAX+1);
    CU_ASSERT(rc == EST_ERR_INVALID_PARAMETERS);
    rc = est_client_set_read_timeout(ectx, 2);
    CU_ASSERT(rc == EST_ERR_NONE);

    /* Now proceed on with a GET /cacerts to verify that nothing gets broken */
    
    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);

    /*
     * should be successful, and should have obtained a valid length
     * for the size of the CA certs buffer
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    if (retrieved_cacerts_len) {
        /*
         * Shouldn't be in here, but if we are, malloc and call
         */
        retrieved_cacerts = malloc(retrieved_cacerts_len);
        rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

        /*
         * est should fail indicating that there's no cert to provide
         */
         CU_ASSERT(rc == EST_ERR_NONE);
    }    
    
    /*
     * output the retrieved ca certs and compare to what they should be
     */    
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);    
    }
    free(retrieved_cacerts);
    
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
int us897_add_suite (void)
{
    CU_ErrorCode CU_error;
    
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us897_client_cacerts", 
	                  us897_init_suite, 
			  us897_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
   if ((NULL == CU_add_test(pSuite, "EST Client Init: local CA, private key ", us897_test1))  ||
       (NULL == CU_add_test(pSuite, "EST Client Init: no local CA", us897_test2)) ||
       (NULL == CU_add_test(pSuite, "EST Client Init: local CA, explicit CA, private key", us897_test3)) ||
/*        (NULL == CU_add_test(pSuite, "EST Client Init: local CA, explicit CA, client CA, private key", us897_test4)) || */
       (NULL == CU_add_test(pSuite, "EST Client Init: local CA, userid/password", us897_test6)) ||
       (NULL == CU_add_test(pSuite, "EST Client Init: local CA, userid/no password", us897_test7)) ||
/*        (NULL == CU_add_test(pSuite, "EST Client Init: local CA, no userid/password", us897_test8)) || */
       (NULL == CU_add_test(pSuite, "EST Client Set Server: correct parameters", us897_test9)) ||
       (NULL == CU_add_test(pSuite, "EST Client Set Server: no parameters", us897_test10)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: ca_cert valid parameters", us897_test11)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: missing ca_cert pointers", us897_test12)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: verify chain-simple chain-success", us897_test13)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: verify chain-multiple certs-success", us897_test14)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: verify chain-broken chain-fail", us897_test15)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: verify chain-bad date-fail", us897_test16)) ||
       (NULL == CU_add_test(pSuite, "EST Client CA Certs: verify chain-multiple chains-success", us897_test17)) ||
       (NULL == CU_add_test(pSuite, "EST Client SSL read timeout API", us897_test18))
       ) 
   {
      CU_error = CU_get_error();
      printf("%d\n", CU_error);
   
      CU_cleanup_registry();
      printf("%s\n", CU_get_error_msg());
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}


