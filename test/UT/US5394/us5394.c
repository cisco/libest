/*------------------------------------------------------------------
 * us5394.c - Unit Tests for User Story 5394 - CoAP Server Side
 *                                             Keygen Proxy Mode
 * 
 * July 2019
 *
 * Copyright (c) 2018-2019 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>

#ifndef WIN32

#include <sys/stat.h>
#include <unistd.h>

#endif

#include <est.h>
#include <openssl/ssl.h>

#include "st_proxy.h"
#include "st_server.h"
#include "test_utils.h"

#ifdef HAVE_CUNIT
#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#endif

/*
 * Used to test the CoAP init API function
 */
#define US5394_API_TEST_PORT 25002

#define US5394_TCP_SERVER_PORT 25394
#define US5394_UDP_PROXY_PORT 25186
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5394_COAP_CLIENT_EMU "est_coap_client.py"
#define US5394_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"

#ifndef WIN32
#define US5394_CACERTS "CA/estCA/cacert.crt"
#define US5394_CLIENT_CACERTS "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5394_SERVER_ENHCD_CERT_CACERTS "CA/mfgCAs/sudiCA/cacert.crt"
#define US5394_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5394_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5394_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5394_CLIENT_CERTKEY "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5394_CA_CNF "CA/estExampleCA.cnf"
#define US5394_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5394_CACERTS "CA\\estCA\\cacert.crt"
#define US5394_CLIENT_CACERTS "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5394_SERVER_ENHCD_CERT_CACERTS "CA\\mfgCAs\\sudiCA\\cacert.crt"
#define US5394_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5394_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5394_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5394_CLIENT_CERTKEY                                                  \
    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5394_CA_CNF "CA\\estExampleCA.cnf"
#define US5394_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static unsigned char *server_enhcd_cert_cacert = NULL;
static int server_enhcd_cert_cacert_len = 0;
static int auth_cb_called = 0;
static int expected_auth_result = 0;
static char temp_dir[MAX_FILENAME_LEN];
static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int us5394_server_process_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
                                      X509 *peer_cert, char *path_seg,
                                      void *app_data)
{
    int user_valid = 0;

    if (path_seg) {
        printf("\n %s: Path segment in the authenticate callback is: %s\n",
               __FUNCTION__, path_seg);
    }
    printf("Auth Callback: Checking Credentials\n");
    auth_cb_called = 1;
    switch (ah->mode) {
    case AUTH_BASIC:
        /*
         * this is where we might hook into a Radius server
         * or some external database to authenticate a
         * userID/password.  But for this example code,
         * we just hard-code a local user for testing
         * the CiscoEST API.
         */
        if (!strcmp(ah->user, "127.0.0.1") && !strcmp(ah->pwd, "cisco")) {
            /* The user is valid */
            user_valid = 1;
        }
        break;
    case AUTH_DIGEST:
    case AUTH_TOKEN:
    case AUTH_FAIL:
    case AUTH_NONE:
    default:
        break;
    }
    CU_ASSERT(user_valid == expected_auth_result);
    return user_valid;
}
static int us5394_start_server_and_proxy(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5394_TCP_SERVER_PORT, US5394_SERVER_CERTKEY,
                  US5394_SERVER_CERTKEY, "US5394 test realm", US5394_CACERTS,
                  US5394_TRUSTED_CERTS, US5394_CA_CNF, manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return rv;
    }

    /*
     * Next we start an EST proxy using CoAP acting as an RA
     */
    rv = st_proxy_start_coap(
        US5394_UDP_PROXY_PORT, US5394_PROXY_CERTKEY, US5394_PROXY_CERTKEY,
        "US5394 test realm", US5394_CACERTS, US5394_TRUSTED_CERTS, "estuser",
        "estpwd", "127.0.0.1", US5394_TCP_SERVER_PORT, 0, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }

    /*HTTP authentication is not required with CoAP*/
    st_set_http_auth_optional();

    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5394_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
    }

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5394_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5394_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }
    server_enhcd_cert_cacert_len = read_binary_file(
        US5394_SERVER_ENHCD_CERT_CACERTS, &server_enhcd_cert_cacert);
    if (server_enhcd_cert_cacert_len <= 0) {
        return 1;
    }

    /* Build out temp directory */
#ifdef WIN32
    snprintf(temp_dir, MAX_FILENAME_LEN, "%s\\", getenv("TEMP"));
#else
    snprintf(temp_dir, MAX_FILENAME_LEN, "/tmp/");
#endif

    /*
     * Start an instance of the EST proxy and server
     * with automatic enrollment enabled.
     */
    rv = us5394_start_server_and_proxy(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5394_destroy_suite(void)
{
    st_stop();
    st_proxy_stop();
    if (server_enhcd_cert_cacert)
        free(server_enhcd_cert_cacert);
    if (cacerts)
        free(cacerts);
    return 0;
}

/*
 * This function performs a basic server keygen using
 * CoAP to identify the client through an EST over
 * CoAP proxy to an EST over HTTP server.
 */
static void us5394_test1(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5394_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SERVER_KEYGEN --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5394_COAP_CLIENT_EMU_PATH, US5394_COAP_CLIENT_EMU,
             US5394_UDP_PROXY_PORT, US5394_CLIENT_CERTKEY,
             US5394_CLIENT_CERTKEY, US5394_CLIENT_CACERTS);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);

    CU_ASSERT(rv == 0);

    return;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5394_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5394_PROXY_CERTKEY, US5394_TRUSTED_CERTS,
                             US5394_CACERTS, US5394_UDP_PROXY_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5394_skg_coap_proxy", us5394_init_suite,
                          us5394_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL ==
             CU_add_test(pSuite, "Server Keygen Proxy mode using CoAP", us5394_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
