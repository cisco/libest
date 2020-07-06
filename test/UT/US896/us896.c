/*------------------------------------------------------------------
 * us896.c - Unit Tests for User Story 896 - Client CSR Attributes
 *
 * November, 2013
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
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include "st_server.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#ifndef WIN32
#define CLIENT_UT_CACERT "CA/estCA/cacert.crt"
#define US896_CACERTS       "CA/estCA/cacert.crt"
#define US896_TRUST_CERTS   "CA/trustedcerts.crt"
#define US896_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#else 
#define CLIENT_UT_CACERT "CA\\estCA\\cacert.crt"
#define US896_CACERTS       "CA\\estCA\\cacert.crt"
#define US896_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US896_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#endif 

#define CLIENT_UT_PUBKEY "./est_client_ut_keypair"
#define US896_SERVER_PORT   29896
#define US896_SERVER_IP     "127.0.0.1" 
#define TEST_SHORT_ATTR "M==\0"
#define TEST_LONG_ATTR "MIIENzCCA54GA4g3AjGCA5UGA4g3AwYDiDcEEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTASZTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDAxMjM0NTY3ODkwEmUxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAwMTIzNDU2Nzg5MBJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMDEyMzQ1Njc4OTATUVBhcnNlIFNFVCBhcyAyLjk5OS4yIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MAYJYIZIAWUDBAICBgkrJAMDAggBAQswawYDiDcBMWQTYlBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEgMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwYWIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTEyMzQ1BgcrBgEBAQEWBgcrBgEBAQEW\0"
#define TEST_CORRUPT_ATTR1 "MHwwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOIExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYJKoZIhvcNAQkH\0"
#define TEST_CORRUPT_ATTR2 "MIHTMIGBBgOINwIxegEB/wICAP8GA4g3AwYDiDcECgECEhAxMjM0NTY3ODkwQUJDREVGExRQYXJzZSBTRVQgYXMgMi45OTkuMhQFM12345TIzNDUUBTEyMzQ1FgUxMjM0NRoFMTIzNDUcFAAAADEAAAAyAAAAMwAAADQAAAA1HgoAMQAyADMANAA1BglghkgBZQMEAgIGCSskAwMCCAEBCzAiBgOINwExGxMZUGFyc2UgU0VUIGFzIDIuOTk5LjEgZGF0YQYHKwYBAQEBFgYHKwYBAQEBFgEBAA==\0"

#define EST_UT_MAX_CMD_LEN 255

static void us896_clean(void) {
}

static int us896_start_server(int manual_enroll, int nid) {
    int rv;

    rv = st_start(US896_SERVER_PORT,
    US896_SERVER_CERTKEY,
    US896_SERVER_CERTKEY, "US896 test realm",
    US896_CACERTS,
    US896_TRUST_CERTS, "CA/estExampleCA.cnf", manual_enroll, 0, nid);

    SLEEP(1);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us896_init_suite(void) {
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    printf("Starting EST Server CSR attributes unit tests.\n");

    /*
     * gen the keypair to be used for EST Client testing
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
            "openssl ecparam -name prime256v1 -genkey -out %s",
            CLIENT_UT_PUBKEY);
    printf("%s\n", cmd);

    rv = system(cmd);

    /*
     * start the server for the tests that need to talk to a server
     */
    us896_clean();

    /*
     * Start an instance of the EST server 
     */
    rv = us896_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us896_destroy_suite(void) {
    st_stop();
    SLEEP(2);
    return 0;
}

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify(X509 *cur_cert, int openssl_cert_error) {
    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;    

    /*
     * Print out the specifics of this cert
     */
    printf(
            "%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
            __FUNCTION__, openssl_cert_error,
            X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
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
 * Test1 - exercise the est_client_get_csrattrs() API.
 */
static void us896_test1(void) {
    int rc;
    unsigned char *csr_data;
    int csr_len;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, NULL, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, &csr_data, NULL);
    CU_ASSERT(rc != EST_ERR_NONE);

}

/*
 * Test2 - exercise the response  variations triggered
 *         by est_client_get_csrattrs()
 */
static void us896_test2(void) {
    EST_CTX *ctx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    unsigned char *retrieved_cacerts = NULL;
    int retrieved_cacerts_len = 0;
    EVP_PKEY *priv_key;

    SLEEP(1);

    LOG_FUNC_NM
    ;

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

    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
            client_manual_cert_verify);
    CU_ASSERT(ctx != NULL);

    rc = est_client_set_auth(ctx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ctx, US896_SERVER_IP, US896_SERVER_PORT, NULL);

    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ctx, &retrieved_cacerts_len);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);

    rc = est_client_copy_cacerts(ctx, retrieved_cacerts);

    /*
     * output the retrieved ca certs and compare to what they should be
     */
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);
    }
    free(retrieved_cacerts);

    /* 
     * All of these are negative tests and require that code in the
     * EST server is modified such that it will allow bad/corrupted
     * attributes to be initialized so they can be sent to the client.
     */
#ifdef NEGATIVE_UNIT_TEST
    unsigned char *csr_data;
    int csr_len;

    /* clear callback */
    if (est_set_csr_cb(ectx, NULL)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }

    rc = est_server_init_csrattrs(ectx, TEST_CORRUPT_ATTR1, strlen(TEST_CORRUPT_ATTR1));
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);
    CU_ASSERT(csr_len == 0);
    CU_ASSERT(csr_data == NULL);

    rc = est_server_init_csrattrs(ectx, TEST_CORRUPT_ATTR2, strlen(TEST_CORRUPT_ATTR2));
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);
    CU_ASSERT(csr_len == 0);
    CU_ASSERT(csr_data == NULL);

    rc = est_server_init_csrattrs(ectx, TEST_SHORT_ATTR, strlen(TEST_SHORT_ATTR));
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);
    CU_ASSERT(csr_len == 0);
    CU_ASSERT(csr_data == NULL);

    rc = est_server_init_csrattrs(ectx, TEST_LONG_ATTR, strlen(TEST_LONG_ATTR));
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_get_csrattrs(ctx, &csr_data, &csr_len);
    CU_ASSERT(rc != EST_ERR_NONE);
    CU_ASSERT(csr_len == 0);
    CU_ASSERT(csr_data == NULL);

#endif

    if (ctx) {
        est_destroy(ctx);
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
int us896_add_suite(void) {
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us896_client_csrattrs",
            us896_init_suite,
            us896_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "CSR Client Attributes API1", us896_test1)) ||
            (NULL == CU_add_test(pSuite, "CSR Client Attributes API2 ", us896_test2)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}


