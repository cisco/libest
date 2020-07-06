/*------------------------------------------------------------------
 * us5237.c - Unit Tests for User Story 5237 - CACerts - Server
 *                                             in CoAP mode
 *
 * November, 2018
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
#define US5237_SERVER_IP         "127.0.0.1"
#define US5237_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5237_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5237_CACERTS       "CA/estCA/cacert.crt"
#define US5237_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5237_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5237_HUGE_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugesudichain.crt"
#define US5237_HUGE_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugeSUDI.pem"
#define US5237_HUGER_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugersudichain.crt"
#define US5237_HUGER_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugerSUDI.pem"
#define US5237_COAP_CLIENT_EMU_PATH "../util/"
#else
#define US5237_CACERTS       "CA\\estCA\\cacert.crt"
#define US5237_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5237_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5237_HUGE_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugesudichain.crt"
#define US5237_HUGE_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugeSUDI.pem"
#define US5237_HUGER_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugersudichain.crt"
#define US5237_HUGER_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugerSUDI.pem"
#define US5237_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

static int cacerts_cb_called = 0;
extern EST_CTX *ectx;

/*
 * Used to start server in CoAP mode
 */
#define US5237_SERVER_PORT      29001
/*
 * Used to test the CoAP init API function
 */
#define US5237_API_TEST_PORT     29002

/*
 * Set the cacerts cb flag to signify that we have
 * gone into the cb function, and return null certs
 * to test the EST_ERR_HTTP_NO_CONTENT path in the
 * est_server_handle_cacerts function in the est lib
 */
static unsigned char * handle_cacerts_request (int *cacerts_len,
                                               char *path_seg,
                                               void *app_data)
{
    cacerts_cb_called = 1;
    return NULL;
}

static int us5237_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5237_SERVER_PORT,
                       US5237_SERVER_CERT_AND_KEY,
                       US5237_SERVER_CERT_AND_KEY,
                       "US5237 test realm",
                       US5237_CACERTS,
                       US5237_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    rv = est_set_cacerts_cb(ectx, &handle_cacerts_request);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set cacerts callback function on st_server\n");
    }
    return rv;

}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5237_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5237_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5237_start_server(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5237_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Test that /crts (cacerts) over coap in server mode
 * uses the cb function set during server initialization.
 * Then ensure that the server returns locally configured
 * certs after the cb function is set to null.
 */
static void us5237_test1 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
    cacerts_cb_called = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5237_CSSL_NOT_SET_MSG);
        return;
    }
    
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "GET_CACERTS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5237_COAP_CLIENT_EMU_PATH, US5237_COAP_CLIENT_EMU,
             US5237_SERVER_PORT, US5237_SERVER_CERT_AND_KEY,
             US5237_SERVER_CERT_AND_KEY, US5237_CACERTS);
    if (strnlen(cmd,EST_UT_MAX_CMD_LEN) >= EST_UT_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    /*
     * the cb should be called and return null,
     * causing an EST_ERR_HTTP_NO_CONTENT error
     */
    rv = system(cmd);
    CU_ASSERT(rv);
    CU_ASSERT(cacerts_cb_called);

    cacerts_cb_called = 0;

    /*
     * Now set the cb to null so that the server will respond with
     * locally configured certs
     */
    rv = est_set_cacerts_cb(ectx, NULL);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set cacerts callback function on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * the cb should not have been called and the certs
     * should have come back valid
     */
    rv = system(cmd);
    CU_ASSERT(!rv);
    CU_ASSERT(!cacerts_cb_called);

    /*
     * return the cb to the original cb function for this suite
     */
    rv = est_set_cacerts_cb(ectx, &handle_cacerts_request);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set cacerts callback function on st_server\n");
    }
    CU_ASSERT(rv == EST_ERR_NONE);

}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5237_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5237_SERVER_CERT_AND_KEY, US5237_TRUSTED_CERT,
                             US5237_CACERTS, US5237_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5237_CoAP_server_cacerts_cb",
            us5237_init_suite,
            us5237_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "Test /crts request cb", us5237_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }
     
    return CUE_SUCCESS;
#endif
}
