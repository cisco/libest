/*------------------------------------------------------------------
 * us5213.c - Unit Tests for User Story 5213 - Add Proxy over CoAP
 *                                             mode Simple Reenroll
 *                                             and GetCACerts
 *
 * October 2018
 *
 * Copyright (c) 2018 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>

#ifndef WIN32

#include <unistd.h>
#include <sys/stat.h>

#endif

#include <est.h>
#include "test_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

/*
 * Used to test the CoAP init API function
 */
#define US5213_API_TEST_PORT         25003

#define US5213_TCP_SERVER_PORT       25213
#define US5213_UDP_PROXY_PORT        25215
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5213_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5213_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5213_CACERTS           "CA/estCA/cacert.crt"
#define US5213_CLIENT_CACERTS    "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5213_TRUSTED_CERTS     "CA/trustedcerts.crt"
#define US5213_SERVER_CERTKEY    "CA/estCA/private/estservercertandkey.pem"
#define US5213_PROXY_CERTKEY     "CA/estCA/private/proxy-certandkey.pem"
#define US5213_CLIENT_CERTKEY    "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5213_CA_CNF            "CA/estExampleCA.cnf"
#define US5213_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5213_CACERTS           "CA\\estCA\\cacert.crt"
#define US5213_CLIENT_CACERTS    "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5213_TRUSTED_CERTS     "CA\\trustedcerts.crt"
#define US5213_SERVER_CERTKEY    "CA\\estCA\\private\\estservercertandkey.pem"
#define US5213_PROXY_CERTKEY     "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5213_CLIENT_CERTKEY    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5213_CA_CNF            "CA\\estExampleCA.cnf"
#define US5213_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

static int us5213_start_server_and_proxy(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5213_TCP_SERVER_PORT,
                       US5213_SERVER_CERTKEY,
                       US5213_SERVER_CERTKEY,
                       "US5213 test realm",
                       US5213_CACERTS,
                       US5213_TRUSTED_CERTS,
                       US5213_CA_CNF,
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return rv;
    }


    /*
     * Next we start an EST proxy using CoAP acting as an RA
     */
    rv = st_proxy_start_coap(US5213_UDP_PROXY_PORT,
                             US5213_PROXY_CERTKEY,
                             US5213_PROXY_CERTKEY,
                             "US5213 test realm",
                             US5213_CACERTS,
                             US5213_TRUSTED_CERTS,
                             "estuser",
                             "estpwd",
                             "127.0.0.1",
                             US5213_TCP_SERVER_PORT,
                             0,
                             0,
                             nid); 
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }

    /*HTTP authentication is not required with CoAP*/
    st_set_http_auth_optional();
    
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5213_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5213_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST proxy and server
     * with automatic enrollment enabled.
     */
    rv = us5213_start_server_and_proxy(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5213_destroy_suite(void)
{
    st_stop();
    st_proxy_stop();
    if (cacerts) free(cacerts);
    return 0;
}

/*
 * This function performs a basic simple reenroll using
 * CoAP to identify the client through an EST over
 * CoAP proxy to an EST over HTTP server.
 */
static void us5213_test1(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5213_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_REENROLL --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5213_COAP_CLIENT_EMU_PATH, US5213_COAP_CLIENT_EMU,
             US5213_UDP_PROXY_PORT, US5213_CLIENT_CERTKEY,
             US5213_CLIENT_CERTKEY, US5213_CLIENT_CACERTS);
    if (strnlen(cmd,EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);

    CU_ASSERT(rv == 0);
    
    return;
}

/*
 * Test /cacerts (crts) over coap in proxy mode.
 */
static void us5213_test2(void)
{
    char cmd[EST_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5213_CSSL_NOT_SET_MSG);
        return;
    }
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s"
              " --test GET_CACERTS --port %d "
              " --key %s --cert %s --cacert %s --debug",
              cssl_emulator_path, cssl_emulator_path,
              US5213_COAP_CLIENT_EMU_PATH, US5213_COAP_CLIENT_EMU,
              US5213_UDP_PROXY_PORT, US5213_CLIENT_CERTKEY,
              US5213_CLIENT_CERTKEY, US5213_CLIENT_CACERTS);

    /* 
     * test that getcacerts in proxy over coap works
     * when the proxy has cacerts locally configured
     */
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * stop the coap proxy that is currently running so
     * we can start a proxy over coap that does not have
     * cacerts locally configured
     */
    st_proxy_stop();

    /* start a proxy over coap with cacerts disabled */
    rv = st_proxy_coap_start_nocacerts(US5213_UDP_PROXY_PORT,
                             US5213_PROXY_CERTKEY,
                             US5213_PROXY_CERTKEY,
                             "US5213 test realm",
                             NULL,
                             US5213_TRUSTED_CERTS,
                             "estuser",
                             "estpwd",
                             "127.0.0.1",
                             US5213_TCP_SERVER_PORT,
                             0,
                             0); 
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return;
    }
    CU_ASSERT(rv == 0);

     /*
      * Build the est client over coap emulator command and issue it
      */
     snprintf(cmd, EST_MAX_CMD_LEN,
              "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s"
              " --test GET_CACERTS --port %d "
              " --key %s --cert %s --cacert %s --debug",
              cssl_emulator_path, cssl_emulator_path,
              US5213_COAP_CLIENT_EMU_PATH, US5213_COAP_CLIENT_EMU,
              US5213_UDP_PROXY_PORT, US5213_CLIENT_CERTKEY,
              US5213_CLIENT_CERTKEY, US5213_CLIENT_CACERTS);

     /* 
      * test that getcacerts in proxy over coap works
      * when the proxy does NOT have cacerts locally configured
      */
     rv = system(cmd);
     CU_ASSERT(rv == 0);

     /*
      * Check that the proxy now holds the certs locally and will
      * not reach out to the server to retrieve the certs again
      */

     st_stop();

     /*
      * Build the est client over coap emulator command and issue it
      */
     snprintf(cmd, EST_MAX_CMD_LEN,
              "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s"
              " --test GET_CACERTS --port %d "
              " --key %s --cert %s --cacert %s --debug",
              cssl_emulator_path, cssl_emulator_path,
              US5213_COAP_CLIENT_EMU_PATH, US5213_COAP_CLIENT_EMU,
              US5213_UDP_PROXY_PORT, US5213_CLIENT_CERTKEY,
              US5213_CLIENT_CERTKEY, US5213_CLIENT_CACERTS);

     /* 
      * test that getcacerts in proxy over coap works
      * when the proxy has cacerts locally stored
      * and does not have an upstream server to get the
      * certs from
      */
     rv = system(cmd);
     CU_ASSERT(rv == 0);

    /*
     * start up a server (http) again to be used by the test suite
     */
     rv = st_start(US5213_TCP_SERVER_PORT,
                       US5213_SERVER_CERTKEY,
                       US5213_SERVER_CERTKEY,
                       "US5213 test realm",
                       US5213_CACERTS,
                       US5213_TRUSTED_CERTS,
                       US5213_CA_CNF,
                       0,
                       0,
                       0);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
    }
    CU_ASSERT(rv == 0);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5213_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5213_PROXY_CERTKEY, US5213_TRUSTED_CERTS,
                             US5213_CACERTS, US5213_UDP_PROXY_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5213_sren_crts_coap_proxy",
                          us5213_init_suite,
                          us5213_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {
    
        /* add the tests to the suite */
             
        if ((NULL == CU_add_test(pSuite, "Proxy CoAP Simple Reenroll",
                                 us5213_test1)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }

        if ((NULL == CU_add_test(pSuite, "Proxy CoAP Get CA Certs",
                                 us5213_test2)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }
    }
    
    return CUE_SUCCESS;
#endif
}
