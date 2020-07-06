/*------------------------------------------------------------------
 * us5184.c - Unit Tests for User Story 5184 - Add Proxy over CoAP
 *                                             mode Simple Enroll
 *
 * September 2018
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
#define US5184_API_TEST_PORT 25002

#define US5184_TCP_SERVER_PORT 25184
#define US5184_UDP_PROXY_PORT 25186
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5184_COAP_CLIENT_EMU "est_coap_client.py"
#define US5184_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"

#ifndef WIN32
#define US5184_CACERTS "CA/estCA/cacert.crt"
#define US5184_CLIENT_CACERTS "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5184_SERVER_ENHCD_CERT_CACERTS "CA/mfgCAs/sudiCA/cacert.crt"
#define US5184_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5184_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5184_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5184_CLIENT_CERTKEY "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5184_CA_CNF "CA/estExampleCA.cnf"
#define US5184_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5184_CACERTS "CA\\estCA\\cacert.crt"
#define US5184_CLIENT_CACERTS "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5184_SERVER_ENHCD_CERT_CACERTS "CA\\mfgCAs\\sudiCA\\cacert.crt"
#define US5184_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5184_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5184_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5184_CLIENT_CERTKEY                                                  \
    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5184_CA_CNF "CA\\estExampleCA.cnf"
#define US5184_COAP_CLIENT_EMU_PATH "python ..\\util\\"
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
static int us5184_server_process_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
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
    CU_ASSERT(user_valid == expected_auth_result)
    return user_valid;
}
static int us5184_start_server_and_proxy(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5184_TCP_SERVER_PORT, US5184_SERVER_CERTKEY,
                  US5184_SERVER_CERTKEY, "US5184 test realm", US5184_CACERTS,
                  US5184_TRUSTED_CERTS, US5184_CA_CNF, manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return rv;
    }

    /*
     * Next we start an EST proxy using CoAP acting as an RA
     */
    rv = st_proxy_start_coap(
        US5184_UDP_PROXY_PORT, US5184_PROXY_CERTKEY, US5184_PROXY_CERTKEY,
        "US5184 test realm", US5184_CACERTS, US5184_TRUSTED_CERTS, "estuser",
        "estpwd", "127.0.0.1", US5184_TCP_SERVER_PORT, 0, 0, nid);
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
    rv = st_proxy_set_http_auth_cb(us5184_server_process_auth);
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
static int us5184_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5184_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }
    server_enhcd_cert_cacert_len = read_binary_file(
        US5184_SERVER_ENHCD_CERT_CACERTS, &server_enhcd_cert_cacert);
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
    rv = us5184_start_server_and_proxy(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5184_destroy_suite(void)
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
 * Test the CoAP Initialization API function,
 * est_proxy_coap_init_start()
 */
static void us5184_test1(void)
{
    EST_CTX *ectx;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;
    int coap_rc;

    unsigned char *trustcerts = NULL;
    int trustcerts_len = 0;

    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    LOG_FUNC_NM;

    /*
     * Set up the EST library in server mode.  This requires a number
     * of values to be passed to est_server_init(). Use server
     * mode to test that est_proxy_coap_init_start() returns
     * EST_ERR_BAD_MODE since it should only be called in proxy mode.
     */

    /*
     * The server's ID certificate.
     */
    certin = BIO_new(BIO_s_file());
    if (certin == NULL) {
        printf("Unable to create certin BIO\n");
        return;
    }
    if (BIO_read_filename(certin, US5184_SERVER_CERTKEY) <= 0) {
        printf("Unable to read server certificate file %s\n",
               US5184_SERVER_CERTKEY);
        BIO_free(certin);
        return;
    }
    /*
     * Read the file, which is expected to be PEM encoded.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
        printf("Error while reading PEM encoded server certificate file %s\n",
               US5184_SERVER_CERTKEY);
        BIO_free(certin);
        return;
    }
    BIO_free(certin);

    /*
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file());
    if (keyin == NULL) {
        printf("Unable to create keyin BIO\n");
        X509_free(x);
        return;
    }
    if (BIO_read_filename(keyin, US5184_SERVER_CERTKEY) <= 0) {
        printf("Unable to read server private key file %s\n",
               US5184_SERVER_CERTKEY);
        BIO_free(keyin);
        X509_free(x);
        return;
    }
    /*
     * Read in the private key file, which is expected to be a PEM
     * encoded private key.
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
        printf("Error while reading PEM encoded private key file %s\n",
               US5184_SERVER_CERTKEY);
        BIO_free(keyin);
        X509_free(x);
        return;
    }
    BIO_free(keyin);

    /*
     * CA certs to use as the trust store
     */
    trustcerts_len = read_binary_file(US5184_TRUSTED_CERTS, &trustcerts);
    if (trustcerts_len <= 0) {
        printf("Trusted certs file %s could not be read\n",
               US5184_TRUSTED_CERTS);
        EVP_PKEY_free(priv_key);
        X509_free(x);
        return;
    }

    /*
     * Read in the CA certs to use as response to /cacerts responses
     */
    cacerts_len = read_binary_file(US5184_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        printf("CA chain file %s file could not be read\n", US5184_CACERTS);
        X509_free(x);
        EVP_PKEY_free(priv_key);
        free(trustcerts);
        return;
    }

    /*
     * Initialize the library and get an EST context
     */
    ectx = est_server_init(trustcerts, trustcerts_len, cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM, "estrealm", x, priv_key);
    if (!ectx) {
        printf("Unable to initialize EST context.  Aborting!!!\n");
        X509_free(x);
        EVP_PKEY_free(priv_key);
        free(trustcerts);
        free(cacerts);
        return;
    }
    X509_free(x);
    EVP_PKEY_free(priv_key);
    free(trustcerts);
    free(cacerts);

    /*
     * Now test est_proxy_coap_init_start()
     *
     * No context
     */
    coap_rc = est_proxy_coap_init_start(NULL, US5184_API_TEST_PORT);
    CU_ASSERT(coap_rc == EST_ERR_NO_CTX);
    if (coap_rc != EST_ERR_NO_CTX) {
        printf("Failed to detect no EST context passed in\n");
    }

    /*
     * Server context
     */
    coap_rc = est_proxy_coap_init_start(ectx, US5184_API_TEST_PORT);
    CU_ASSERT(coap_rc == EST_ERR_BAD_MODE);
    if (coap_rc != EST_ERR_BAD_MODE) {
        printf("Failed to detect incorrect est context mode\n");
    }

    /*
     * est_proxy_coap_init_start() calls est_server_coap_init_start(),
     * which is tested in us5052.c for invalid port numbers
     */
    /* destroy context */
    if (ectx)
        est_destroy(ectx);
}

/*
 * This function performs a basic simple enroll using
 * CoAP to identify the client through an EST over
 * CoAP proxy to an EST over HTTP server.
 */
static void us5184_test2(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5184_CSSL_NOT_SET_MSG);
        return;
    }

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5184_COAP_CLIENT_EMU_PATH, US5184_COAP_CLIENT_EMU,
             US5184_UDP_PROXY_PORT, US5184_CLIENT_CERTKEY,
             US5184_CLIENT_CERTKEY, US5184_CLIENT_CACERTS);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);

    CU_ASSERT(rv == 0);

    return;
}

/*
 * This function performs a basic simple enroll using
 * Enhanced Cert Authentication with CoAP to identify
 * the client through an EST over CoAP proxy to an EST
 * over HTTP server.
 */
static void us5184_test3(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5184_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5184_est_tc1.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5184_COAP_CLIENT_EMU_PATH, US5184_COAP_CLIENT_EMU,
             US5184_UDP_PROXY_PORT, US5184_CLIENT_CERTKEY,
             US5184_CLIENT_CERTKEY, US5184_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Proxy
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5184_COAP_CLIENT_EMU_PATH, US5184_COAP_CLIENT_EMU,
             US5184_UDP_PROXY_PORT, US5184_CLIENT_CERTKEY,
             US5184_CLIENT_CERTKEY, US5184_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Proxy
     * This enable sets the password to BadPass. This will cause the request
     * to not succeed since the credentials for
     * the authentication callback are set to
     * User: "/CN=127.0.0.1" Pass: "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, "BadPass",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    auth_cb_called = 0;
    expected_auth_result = 0;
    system(cmd);
    CU_ASSERT(auth_cb_called);

/*
 * Cleanup
 */
cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the Proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5184_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5184_PROXY_CERTKEY, US5184_TRUSTED_CERTS,
                             US5184_CACERTS, US5184_UDP_PROXY_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5184_sen_coap_proxy", us5184_init_suite,
                          us5184_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL ==
             CU_add_test(pSuite, "Proxy CoAP init API", us5184_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL ==
             CU_add_test(pSuite, "Proxy CoAP Simple Enroll", us5184_test2))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL == CU_add_test(pSuite, "Proxy CoAP Sen- Enhanced Cert Auth",
                                 us5184_test3))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
