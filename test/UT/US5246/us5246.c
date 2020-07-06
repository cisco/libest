/*------------------------------------------------------------------
 * us5246.c - Unit Tests for User Story 5246 - Test CoAP Content
 *                                             Format (media type)
 *                                             & Accept Option
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
#define US5246_SERVER_IP         "127.0.0.1"
#define US5246_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5246_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5246_CACERTS       "CA/estCA/cacert.crt"
#define US5246_CLIENT_CACERTS "CA/coap_emu_certs/coapcacert.crt"
#define US5246_CLIENT_CERT   "CA/coap_emu_certs/coap_client.pem"
#define US5246_CLIENT_KEY    "CA/coap_emu_certs/coap_client.key"
#define US5246_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5246_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5246_COAP_CLIENT_EMU_PATH "../util/"
#else
#define US5246_CACERTS       "CA\\estCA\\cacert.crt"
#define US5246_CLIENT_CACERTS "CA\\coap_emu_certs\\coapcacert.crt"
#define US5246_CLIENT_CERT   "CA\\coap_emu_certs\\coap_client.pem"
#define US5246_CLIENT_KEY    "CA\\coap_emu_certs\\coap_client.key"
#define US5246_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5246_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5246_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;


/*
 * Used to start server in CoAP mode
 */
#define US5246_SERVER_PORT      29003
/*
 * Used to test the CoAP init API function
 */
#define US5246_API_TEST_PORT     29004

static int us5246_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5246_SERVER_PORT,
                       US5246_SERVER_CERT_AND_KEY,
                       US5246_SERVER_CERT_AND_KEY,
                       "US5246 test realm",
                       US5246_CACERTS,
                       US5246_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
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
static int us5246_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5246_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5246_start_server(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5246_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Test the CoAP Content Format media type
 * by running the CONTENT_FORMAT cmd on the
 * coap emulator. This will run a /sen
 * request with the specified content format
 * of "application/pkcs7-mime+skg," which is
 * incorrect for a /sen request and should fail.
 * The CONTENT_FORMAT command will pass
 * because the /sen request failed appropriately.
 */
static void us5246_test1 (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    /* Record the test start */
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5246_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out EST client emulator command */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test CONTENT_FORMAT --port %d "
                 "--string %s --cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 "application/pkcs7-mime+skg",
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should pass, because the /sen call should fail */
    CU_ASSERT(!rv);
}

/*
 * Test the CoAP Content Format media type
 * by running the CONTENT_FORMAT cmd on the
 * coap emulator. This will run a /sen
 * request with the specified content format
 * of "application/pkcs10" which is
 * correct for a /sen request and should not fail.
 * Because the /sen request should pass, the
 * CONTENT_FORMAT call should fail, appropriately.
 */
static void us5246_test2 (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    /* Record the test start */
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5246_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out EST client emulator command */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test CONTENT_FORMAT --port %d "
                 "--string %s --cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 "application/pkcs10",
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should fail, because the /sen call should pass */
    CU_ASSERT(rv);
}

/*
 * Test the CoAP Content Format accept option
 * by running the ACCEPT cmd on the
 * coap emulator. This will run a /sen
 * request with the specified accept option
 * of "application/pkcs10" which is
 * incorrect for a /sen request and should fail.
 * The ACCEPT command will pass
 * because the /sen request failed appropriately.
 */
static void us5246_test3 (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    /* Record the test start */
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5246_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out EST client emulator command */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test ACCEPT --port %d "
                 "--string %s --cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 "application/pkcs10",
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should pass, because the /sen call should fail */
    CU_ASSERT(!rv);
}

/*
 * Test the CoAP Content Format accept option
 * by running the ACCEPT cmd on the
 * coap emulator. This will run a /sen
 * request with the specified content format
 * of "application/pkcs7-mime+certs" which is
 * correct for a /sen request and should not fail.
 * Because the /sen request should pass, the
 * ACCEPT call should fail, appropriately.
 */
static void us5246_test4 (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    /* Record the test start */
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5246_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out EST client emulator command */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test ACCEPT --port %d "
                 "--string %s --cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 "application/pkcs7-mime+certs",
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should fail, because the /sen call should pass */
    CU_ASSERT(rv);
}


/* 
 * Regular /sen, /sren, /crts, and /att calls
 * to make sure that the default content format
 * media types and accept option types do not fail.
 */
static void us5246_test5 (void)
{
    int rv = 0;
    char cmd[EST_UT_MAX_CMD_LEN];

    /* Record the test start */
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5246_CSSL_NOT_SET_MSG);
        return;
    }

    /* SIMPLE_ENROLL */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test SIMPLE_ENROLL --port %d "
                 "--cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should not fail */
    CU_ASSERT(!rv);

    /* SIMPLE_REENROLL */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test SIMPLE_REENROLL --port %d "
                 "--cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should not fail */
    CU_ASSERT(!rv);

    /* GET_CACERTS */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test GET_CACERTS --port %d "
                 "--cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should not fail */
    CU_ASSERT(!rv);

    /* CSR_ATTRS */
    sprintf(cmd, "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s "
                 "--test CSR_ATTRS --port %d "
                 "--cacert %s --cert %s --key %s "
                 "--debug",
                 cssl_emulator_path, cssl_emulator_path,
                 US5246_COAP_CLIENT_EMU_PATH, US5246_COAP_CLIENT_EMU,
                 US5246_SERVER_PORT,
                 US5246_CACERTS,
                 US5246_SERVER_CERT_AND_KEY,
                 US5246_SERVER_CERT_AND_KEY);

    rv = system(cmd);
    /* should not fail */
    CU_ASSERT(!rv);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5246_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5246_SERVER_CERT_AND_KEY, US5246_TRUSTED_CERT,
                             US5246_CACERTS, US5246_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5246_CoAP_content_format_accept",
            us5246_init_suite,
            us5246_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "CoAP Content Format- incorrect", us5246_test1)) ||
            (NULL == CU_add_test(pSuite, "CoAP Content Format- correct", us5246_test2)) ||
            (NULL == CU_add_test(pSuite, "CoAP Accept Option- incorrect", us5246_test3)) ||
            (NULL == CU_add_test(pSuite, "CoAP Accept Option- correct", us5246_test4)) ||
            (NULL == CU_add_test(pSuite, "CoAP Calls Pass", us5246_test5))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }
     
    return CUE_SUCCESS;
#endif
}
