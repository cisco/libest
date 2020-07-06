/*------------------------------------------------------------------
 * us5230.c - Unit Tests for User Story 5230 - CSR Attrs - Server
 *                                             in CoAP mode
 *
 * October, 2018
 *
 * Copyright (c) 2018 by Cisco Systems, Inc.
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
#define US5230_SERVER_IP         "127.0.0.1"
#define US5230_CSR_NOPOP         "MBQGBysGAQEBARYGCWCGSAFlAwQCAg==\0"
#define US5230_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5230_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5230_CACERTS       "CA/estCA/cacert.crt"
#define US5230_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5230_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5230_HUGE_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugesudichain.crt"
#define US5230_HUGE_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugeSUDI.pem"
#define US5230_HUGER_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugersudichain.crt"
#define US5230_HUGER_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugerSUDI.pem"
#define US5230_COAP_CLIENT_EMU_PATH "../util/"
#else
#define US5230_CACERTS       "CA\\estCA\\cacert.crt"
#define US5230_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5230_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5230_HUGE_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugesudichain.crt"
#define US5230_HUGE_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugeSUDI.pem"
#define US5230_HUGER_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugersudichain.crt"
#define US5230_HUGER_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugerSUDI.pem"
#define US5230_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

#define US5230_ATTR_TEST        "MHEGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBgUrgQQAIgYDVQQDBggqhkjOPQQDAg==\0"

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

static int csr_cb_called = 0;
extern EST_CTX *ectx;
static char *attrs;

/*
 * Used to start server in CoAP mode
 */
#define US5230_SERVER_PORT      29001
/*
 * Used to test the CoAP init API function
 */
#define US5230_API_TEST_PORT     29002

/*
 * From us1159.c
 */
static unsigned char * handle_csrattrs_request (int *csr_len,
                                                char *path_seg,
                                                X509 *peer_cert,
                                                void *app_data)
{
    unsigned char *csr_data;

    csr_cb_called = 1;

    *csr_len = strlen(attrs);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *)csr_data, attrs, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static int us5230_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5230_SERVER_PORT,
                       US5230_SERVER_CERT_AND_KEY,
                       US5230_SERVER_CERT_AND_KEY,
                       "US5230 test realm",
                       US5230_CACERTS,
                       US5230_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    rv = est_set_csr_cb(ectx, &handle_csrattrs_request);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set csr callback function on st_server\n");
    }
    return rv;

}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5230_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    attrs = US5230_ATTR_TEST;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5230_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5230_start_server(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5230_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Test /att (csrattrs) over coap in server mode
 * when the csr attrs cb is set and the csr attrs
 * are not locally stored. Then, test
 * that the attrs have not been saved locally with
 * the cb disabled.
 */
static void us5230_test1 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
    csr_cb_called = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5230_CSSL_NOT_SET_MSG);
        return;
    }
    
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5230_COAP_CLIENT_EMU_PATH, US5230_COAP_CLIENT_EMU,
             US5230_SERVER_PORT, US5230_SERVER_CERT_AND_KEY,
             US5230_SERVER_CERT_AND_KEY, US5230_CACERTS);
    if (strnlen(cmd,EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);
    CU_ASSERT(!rv);
    CU_ASSERT(csr_cb_called);

    /*
     * Now test that the csr attrs have not been locally stored
     * and that the cb is not called
     */

    /* ensure csr_cb is null */
    st_disable_csr_cb();

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5230_COAP_CLIENT_EMU_PATH, US5230_COAP_CLIENT_EMU,
             US5230_SERVER_PORT, US5230_SERVER_CERT_AND_KEY,
             US5230_SERVER_CERT_AND_KEY, US5230_CACERTS);
    if (strnlen(cmd,EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    /* 
     * since there is no cb set and no locally stored csr attrs, this should
     * fail and the cb should not have been called
     */
    csr_cb_called = 0;
    rv = system(cmd);
    CU_ASSERT(rv);
    CU_ASSERT(!csr_cb_called);

    /*
     * set the cb back to the handler function made for this test suite
     */
    rv = est_set_csr_cb(ectx, &handle_csrattrs_request);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set csr callback function on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);
}


/*
 * Test /att (csrattrs) over coap in server mode
 * when the csr attrs are set in the est context
 * but the callback function is not set
 */
static void us5230_test2 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
    csr_cb_called = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5230_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * initialize the csr attrs locally
     */
    rv = est_server_init_csrattrs(ectx, attrs, strlen(attrs));
    if (rv != EST_ERR_NONE) {
        printf("Failed to init csr attrs on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);

    /* ensure csr_cb is null */
    st_disable_csr_cb();
    
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5230_COAP_CLIENT_EMU_PATH, US5230_COAP_CLIENT_EMU,
             US5230_SERVER_PORT, US5230_SERVER_CERT_AND_KEY,
             US5230_SERVER_CERT_AND_KEY, US5230_CACERTS);
    if (strnlen(cmd,EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);
    CU_ASSERT(!rv);
    CU_ASSERT(!csr_cb_called);

    /*
     * set the cb back to the handler function made for this test suite
     */
    rv = est_set_csr_cb(ectx, &handle_csrattrs_request);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set csr callback function on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * set the locally configured attrs back to null
     * just as they are at the initialization of this suite
     */
    rv = est_server_init_csrattrs(ectx, NULL, 0);
    if (rv != EST_ERR_NONE) {
        printf("Failed to init csr attrs on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5230_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5230_SERVER_CERT_AND_KEY, US5230_TRUSTED_CERT,
                             US5230_CACERTS, US5230_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5230_CoAP_server_csr_attrs",
            us5230_init_suite,
            us5230_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "Test /att request cb", us5230_test1)) ||
           (NULL == CU_add_test(pSuite, "Test /att request no cb", us5230_test2))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }
     
    return CUE_SUCCESS;
#endif
}

