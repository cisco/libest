/*------------------------------------------------------------------
 * us5226.c - Unit Tests for User Story 5226 - Proxy over CoAP
 *                                             mode CSR Attrs
 *
 * November 2018
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
#define US5226_API_TEST_PORT         25003

#define US5226_TCP_SERVER_PORT       25226
#define US5226_UDP_PROXY_PORT        25215
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5226_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5226_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5226_CACERTS           "CA/estCA/cacert.crt"
#define US5226_CLIENT_CACERTS    "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5226_TRUSTED_CERTS     "CA/trustedcerts.crt"
#define US5226_SERVER_CERTKEY    "CA/estCA/private/estservercertandkey.pem"
#define US5226_PROXY_CERTKEY     "CA/estCA/private/proxy-certandkey.pem"
#define US5226_CLIENT_CERTKEY    "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5226_CA_CNF            "CA/estExampleCA.cnf"
#define US5226_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5226_CACERTS           "CA\\estCA\\cacert.crt"
#define US5226_CLIENT_CACERTS    "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5226_TRUSTED_CERTS     "CA\\trustedcerts.crt"
#define US5226_SERVER_CERTKEY    "CA\\estCA\\private\\estservercertandkey.pem"
#define US5226_PROXY_CERTKEY     "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5226_CLIENT_CERTKEY    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5226_CA_CNF            "CA\\estExampleCA.cnf"
#define US5226_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

static int us5226_start_server_and_proxy(int manual_enroll, int nid)
{
    int rv;

    /*
     * start an EST server (HTTP) acting as the CA
     */
    rv = st_start(US5226_TCP_SERVER_PORT,
                       US5226_SERVER_CERTKEY,
                       US5226_SERVER_CERTKEY,
                       "US5226 test realm",
                       US5226_CACERTS,
                       US5226_TRUSTED_CERTS,
                       US5226_CA_CNF,
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return rv;
    }


    /*
     * start an EST proxy (CoAP) acting as an RA
     */
    rv = st_proxy_start_coap(US5226_UDP_PROXY_PORT,
                             US5226_PROXY_CERTKEY,
                             US5226_PROXY_CERTKEY,
                             "US5226 test realm",
                             US5226_CACERTS,
                             US5226_TRUSTED_CERTS,
                             "estuser",
                             "estpwd",
                             "127.0.0.1",
                             US5226_TCP_SERVER_PORT,
                             0,
                             0,
                             nid); 
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }

    st_set_default_est_event_callbacks();
    
    /*HTTP authentication is not required with CoAP*/
    st_set_http_auth_optional();
    
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5226_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5226_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST proxy and server
     * with automatic enrollment enabled.
     */
    rv = us5226_start_server_and_proxy(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5226_destroy_suite(void)
{
    st_stop();
    st_proxy_stop();
    if (cacerts) free(cacerts);
    return 0;
}

/*
 * This function performs a csr attrs call using
 * CoAP from the client through an EST over
 * CoAP proxy to an EST over HTTP server.
 */
static void us5226_test1(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5226_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5226_COAP_CLIENT_EMU_PATH, US5226_COAP_CLIENT_EMU,
             US5226_UDP_PROXY_PORT, US5226_CLIENT_CERTKEY,
             US5226_CLIENT_CERTKEY, US5226_CLIENT_CACERTS);
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
 * Test /csrattrs (att) over coap in proxy mode
 * when the upstream server is disabled (should fail)
 */
static void us5226_test2(void)
{
    char cmd[EST_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5226_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Disable the upstream server
     */
    st_stop();

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5226_COAP_CLIENT_EMU_PATH, US5226_COAP_CLIENT_EMU,
             US5226_UDP_PROXY_PORT, US5226_CLIENT_CERTKEY,
             US5226_CLIENT_CERTKEY, US5226_CLIENT_CACERTS);
    if (strnlen(cmd,EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

     /* 
      * The proxy should return an EST_ERR_HTTP_NO_CONTENT error
      * and this call should fail
      */
     rv = system(cmd);
     CU_ASSERT(rv);

    /*
     * start up a server (http) again to be used by the test suite
     */
    rv = st_start(US5226_TCP_SERVER_PORT,
                       US5226_SERVER_CERTKEY,
                       US5226_SERVER_CERTKEY,
                       "US5226 test realm",
                       US5226_CACERTS,
                       US5226_TRUSTED_CERTS,
                       US5226_CA_CNF,
                       0,
                       0,
                       0);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return;
    }
    CU_ASSERT(rv == 0);
}

/*
 * Test /csrattrs (att) over coap in proxy mode
 * when pop is disabled on the proxy (should pass)
 */
static void us5226_test3(void)
{
    char cmd[EST_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5226_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Disable pop on the proxy
     */
    st_proxy_disable_pop();

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "CSR_ATTRS --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5226_COAP_CLIENT_EMU_PATH, US5226_COAP_CLIENT_EMU,
             US5226_UDP_PROXY_PORT, US5226_CLIENT_CERTKEY,
             US5226_CLIENT_CERTKEY, US5226_CLIENT_CACERTS);
    if (strnlen(cmd,EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

     rv = system(cmd);
     CU_ASSERT(!rv);

     /*
      * reenable pop on the proxy
      */
     st_proxy_enable_pop();

}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5226_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5226_PROXY_CERTKEY, US5226_TRUSTED_CERTS,
                             US5226_CACERTS, US5226_UDP_PROXY_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5226_csr_attrs_coap_proxy",
                          us5226_init_suite,
                          us5226_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {
    
        /* add the tests to the suite */
             
        if ((NULL == CU_add_test(pSuite, "Proxy CoAP CSR Attrs",
                                 us5226_test1)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }

        if ((NULL == CU_add_test(pSuite, "Proxy CoAP CSR Attrs- no server",
                                 us5226_test2)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }

        if ((NULL == CU_add_test(pSuite, "Proxy CoAP CSR Attrs- no pop",
                                us5226_test3)))
        {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }
    
    return CUE_SUCCESS;
#endif
}
