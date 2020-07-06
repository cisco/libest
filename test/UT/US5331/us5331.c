/*------------------------------------------------------------------
 * us5331.c - Unit Tests for User Story 5331 - Test DTLS handshake
 *            timeout API
 *
 * April, 2019
 *
 * Copyright (c) 2019 by cisco Systems, Inc.
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

#define EST_UT_MAX_CMD_LEN       512
#define US5331_SERVER_IP         "127.0.0.1"
#define US5331_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5331_CACERTS       "CA/estCA/cacert.crt"
#define US5331_EXPLICIT_CERT "US5331/cert-RA.pem" 
#define US5331_EXPLICIT_KEY  "US5331/key-RA.pem"
#define US5331_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5331_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5331_HUGE_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugesudichain.crt"
#define US5331_HUGE_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugeSUDI.pem"
#define US5331_HUGER_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugersudichain.crt"
#define US5331_HUGER_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugerSUDI.pem"
#define US5331_MIDSIZE_CSR "US5331/midsize.csr"
#else
#define US5331_CACERTS       "CA\\estCA\\cacert.crt"
#define US5331_EXPLICIT_CERT "US5331\\cert-RA.pem" 
#define US5331_EXPLICIT_KEY  "US5331\\key-RA.pem"
#define US5331_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5331_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5331_HUGE_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugesudichain.crt"
#define US5331_HUGE_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugeSUDI.pem"
#define US5331_HUGER_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugersudichain.crt"
#define US5331_HUGER_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugerSUDI.pem"
#define US5331_MIDSIZE_CSR "US5331\\midsize.csr"
#endif

#define US5331_ATTR_TEST  "MHEGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBgUrgQQAIgYDVQQDBggqhkjOPQQDAg==\0"

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

/* CU_pSuite coap_sanity_psuite = NULL; */

/*
 * Used to start server in CoAP mode
 */
#define US5331_SERVER_PORT      29001
/*
 * Used to test the CoAP init API function
 */
#define US5331_API_TEST_PORT     29002


static void us5331_clean (void)
{
}

static int us5331_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5331_SERVER_PORT,
                       US5331_SERVER_CERT_AND_KEY,
                       US5331_SERVER_CERT_AND_KEY,
                       "US5331 test realm",
                       US5331_CACERTS,
                       US5331_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
    }

    st_set_default_est_event_callbacks();
    
    return rv;

}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5331_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5331_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us5331_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5331_start_server(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5331_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}


/*
 * Test the DTLS handshake API function,
 * est_server_set_dtls_handshake_timeout()
 */
static void us5331_test1 (void)
{
    EST_CTX *ectx;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;

    unsigned char *trustcerts = NULL;
    int trustcerts_len = 0;

    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    EST_ERROR est_rc;
    
    LOG_FUNC_NM;
    
    /*
     * Need to get a valid EST context in server mode.  To do that, need
     * to call est_server_init().  To do that, need to set up a bunch of
     * parameters to be passed in.
     */

    /*
     * The server's ID certificate.
     */
    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, US5331_SERVER_CERT_AND_KEY) <= 0) {
        printf("Unable to read server certificate file %s\n",
               US5331_SERVER_CERT_AND_KEY);
        return;
    }    
    /*
     * Read the file, which is expected to be PEM encoded.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
        printf("Error while reading PEM encoded server certificate file %s\n",
               US5331_SERVER_CERT_AND_KEY);
        return;
    }
    BIO_free(certin);

    /*
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyin, US5331_SERVER_CERT_AND_KEY) <= 0) {
        printf("Unable to read server private key file %s\n",
               US5331_SERVER_CERT_AND_KEY);
        return;
    }
    /*
     * Read in the private key file, which is expected to be a PEM
     * encoded private key.
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
        printf("Error while reading PEM encoded private key file %s\n",
               US5331_SERVER_CERT_AND_KEY);
        return;
    }
    BIO_free(keyin);
    
    /*
     * CA certs to use as the trust store
     */
    trustcerts_len = read_binary_file(US5331_TRUSTED_CERT, &trustcerts);
    if (trustcerts_len <= 0) {
        printf("Trusted certs file %s could not be read\n",
               US5331_TRUSTED_CERT);
        return;
    }

    /*
     * Read in the CA certs to use as response to /cacerts responses
     */
    cacerts_len = read_binary_file(US5331_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        printf("CA chain file %s file could not be read\n", US5331_CACERTS);
        return;
    }

    /*
     * Initialize the library and get an EST context
     */
    ectx = est_server_init(trustcerts, trustcerts_len, cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM, "estrealm", x, priv_key);
    if (!ectx) {
        printf("Unable to initialize EST context.  Aborting!!!\n");
        return;
    }

    /*
     * AND finally, test the dtls handshake timeout API
     *
     * No context
     */
    est_rc = est_server_set_dtls_handshake_timeout(NULL, EST_DTLS_HANDSHAKE_TIMEOUT_MIN);

    CU_ASSERT(est_rc == EST_ERR_NO_CTX);
    if (est_rc != EST_ERR_NO_CTX) {
        printf("Failed to detect no EST context passed in\n");
    }

    /*
     * A valid timeout value
     */
    est_rc = est_server_set_dtls_handshake_timeout(ectx, EST_DTLS_HANDSHAKE_TIMEOUT_MIN);

    CU_ASSERT(est_rc == EST_ERR_NONE);
    if (est_rc != EST_ERR_NONE) {
        printf("Failed to set the minimum dtls handshake timeout\n");
    }

    /*
     * maximum dtls handshake timeout 
     */
    est_rc = est_server_set_dtls_handshake_timeout(ectx, EST_DTLS_HANDSHAKE_TIMEOUT_MAX);

    CU_ASSERT(est_rc == EST_ERR_NONE);
    if (est_rc != EST_ERR_NONE) {
        printf("Failed set the maximum dtls handshake timeout\n");
    }
    
    /*
     * maximum +1 dtls handshake timeout 
     */
    est_rc = est_server_set_dtls_handshake_timeout(ectx, EST_DTLS_HANDSHAKE_TIMEOUT_MAX+1);

    CU_ASSERT(est_rc == EST_ERR_INVALID_PARAMETERS);
    if (est_rc != EST_ERR_INVALID_PARAMETERS) {
        printf("Failed to catch the max+1 dtls handshake timeout value\n");
    }

    /*
     * Turn it off by passing in a 0(default)
     */
    est_rc = est_server_set_dtls_handshake_timeout(ectx, EST_DTLS_HANDSHAKE_TIMEOUT_DEF);

    CU_ASSERT(est_rc == EST_ERR_NONE);
    if (est_rc != EST_ERR_NONE) {
        printf("Failed to reset dtls handshake timeout value\n");
    }
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5331_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5331_SERVER_CERT_AND_KEY, US5331_TRUSTED_CERT,
                             US5331_CACERTS, US5331_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5331_DTLS_handshake_timeout_API",
            us5331_init_suite,
            us5331_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "Test dtls handshake API", us5331_test1)) 
            ) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}

