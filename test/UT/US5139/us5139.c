/*------------------------------------------------------------------
 * us5139.c - Unit Tests for User Story 5139 - Add Enhanced Cert Auth
 *                                             mode feature
 *
 * July 2018
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

#include "st_proxy.h"
#include "st_server.h"
#include "test_utils.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#endif

#define US5139_TCP_SERVER_PORT 25139
#define US5139_TCP_PROXY_PORT 25141
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5139_SERVER_IP "127.0.0.1"
#define US5139_COAP_CLIENT_EMU "est_coap_client.py"
#define US5139_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"
#define US5139_HTTP_SERVER_ERR_MSG                                             \
    "The test failed to start the HTTP endpoint server"

#ifndef WIN32
#define US5139_CACERTS "CA/estCA/cacert.crt"
#define US5139_CLIENT_CACERTS "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5139_SERVER_ENHCD_CERT_CACERTS "CA/mfgCAs/sudiCA/cacert.crt"
#define US5139_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5139_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5139_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5139_CLIENT_CERTKEY "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5139_CA_CNF "CA/estExampleCA.cnf"
#define US5139_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5139_CACERTS "CA\\estCA\\cacert.crt"
#define US5139_CLIENT_CACERTS "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5139_SERVER_ENHCD_CERT_CACERTS "CA\\mfgCAs\\sudiCA\\cacert.crt"
#define US5139_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5139_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5139_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5139_CLIENT_CERTKEY                                                  \
    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5139_CA_CNF "CA\\estExampleCA.cnf"
#define US5139_COAP_CLIENT_EMU_PATH "python ..\\util\\"
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
static int us5139_server_process_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
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

static int us5139_start_proxy(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST proxy actging as an RA
     */
    rv = st_proxy_start_coap(
        US5139_TCP_PROXY_PORT, US5139_PROXY_CERTKEY, US5139_PROXY_CERTKEY,
        "US5139 test realm", US5139_CACERTS, US5139_TRUSTED_CERTS, "estuser",
        "estpwd", "127.0.0.1", US5139_TCP_SERVER_PORT, 0, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5139_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }
    return rv;
}

static int us5139_start_coap_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start_coap(US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
                       US5139_SERVER_CERTKEY, "US5139 test realm",
                       US5139_CACERTS, US5139_TRUSTED_CERTS, US5139_CA_CNF,
                       manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_server_set_http_auth_cb(us5139_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }
    return rv;
}

static int us5139_start_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST server acting as the CA
     */
    rv = st_start(US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
                  US5139_SERVER_CERTKEY, "US5139 test realm", US5139_CACERTS,
                  US5139_TRUSTED_CERTS, US5139_CA_CNF, manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }

    /*
     * Remove auth callback for HTTP server
     */
    rv = st_server_set_http_auth_cb(NULL);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5139_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5139_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }
    server_enhcd_cert_cacert_len = read_binary_file(
        US5139_SERVER_ENHCD_CERT_CACERTS, &server_enhcd_cert_cacert);
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
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5139_start_coap_server(0, 0);
    if (rv == EST_ERR_NONE) {
        rv = us5139_start_proxy(0, 0);
    }
    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5139_destroy_suite(void)
{
    st_stop();
    st_proxy_stop();
    free(server_enhcd_cert_cacert);
    free(cacerts);
    return 0;
}

/*
 * TC5981: This function performs a basic simple enroll using
 * Enhanced Cert Authentication with CoAP to identify the client to the server.
 */
static void us5139_test1(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_enable_enhanced_cert_auth(NID_serialNumber, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc1.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, "cisco",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to BadPass. This will cause the request
     * to not succeed since the credentials for
     * the authentication callback are set to
     * User: "/CN=127.0.0.1" Pass: "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, "BadPass",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
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
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5989: This function performs a basic simple enroll using enhanced cert auth
 * through a proxy.
 */
static void us5139_test1p(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }
    st_stop();
    if (us5139_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5139_HTTP_SERVER_ERR_MSG);
        return;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc1p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to BadPass. This will cause the request
     * to not succeed since the credentials for
     * the authentication callback are set to
     * User: "/CN=127.0.0.1" Pass: "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "BadPass",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
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
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5980: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * non-Enhanced Cert certificate. This simple enroll request will fail since
 * the server will use the local PKI domain auth credentials which are not
 * provided in the peer cert.
 */
static void us5139_test2(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_enable_enhanced_cert_auth(NID_serialNumber, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 0;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc2.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(!auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, "cisco",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 0;
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(!auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5988: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy and through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * non-Enhanced Cert certificate. This simple enroll request will fail since
 * the proxy will use the local PKI domain auth credentials which are not
 * provided in the peer cert.
 */
static void us5139_test2p(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    if (us5139_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5139_HTTP_SERVER_ERR_MSG);
        return;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 0;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc2p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(!auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 0;
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(!auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5979: This function tests the use of Enhanced Cert Auth with no
 * manufacturers registered during a simple enroll request to an EST over CoAP
 * server
 *
 * This test enables Enhanced Cert Auth and then attempts perform simple enroll
 * requests using certificates from multiple CAs. This simple enroll request
 * will succeed since Enhanced Certificate Athentication assumes that all valid
 * certificates are a part of the local PKI domain when no manufacturers are
 * registered and the local PKI domain subject field was provided in the cert.
 */

static void us5139_test3(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server with the password set to
     * NULL meaning that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc3.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s > "
             "%s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "cisco",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }

    auth_cb_called = 0;
    expected_auth_result = 1;
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5987: This function tests the use of Enhanced Cert Auth with no
 * manufacturers registered during a simple enroll request to an EST over CoAP
 * proxy and through to an EST server
 *
 * This test enables Enhanced Cert Auth and then attempts perform simple enroll
 * requests using certificates from multiple CAs. This simple enroll request
 * will succeed since Enhanced Certificate Athentication assumes that all valid
 * certificates are a part of the local PKI domain when no manufacturers are
 * registered and the local PKI domain subject field was provided in the cert.
 */

static void us5139_test3p(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    if (us5139_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5139_HTTP_SERVER_ERR_MSG);
        return;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the proxy with the password set to
     * NULL meaning that it will be set to the default password "cisco"
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
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc3p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s > "
             "%s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
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
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_CLIENT_CERTKEY,
             US5139_CLIENT_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5982: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * non-registered manufacturer certificate. This simple enroll request will
 * succeed since the server will use the local PKI domain auth credentials
 * which are provided by the cert.
 */
static void us5139_test4(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_serialNumber,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc4.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "cisco",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_serialNumber,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_SERVER_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC5990: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy and through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * non-registered manufacturer certificate. This simple enroll request will
 * succeed since the proxy will use the local PKI domain auth credentials
 * which are provided by the cert.
 */
static void us5139_test4p(void)
{
    int rv;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5139_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    if (us5139_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5139_HTTP_SERVER_ERR_MSG);
        return;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the proxy.
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
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_serialNumber,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5139_est_tc4p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("Cisco", NID_serialNumber,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    auth_cb_called = 0;
    expected_auth_result = 1;
    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             ">> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5139_COAP_CLIENT_EMU_PATH, US5139_COAP_CLIENT_EMU,
             US5139_TCP_PROXY_PORT, US5139_SERVER_CERTKEY,
             US5139_SERVER_CERTKEY, US5139_CLIENT_CACERTS, coap_client_logs);
    if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    system(cmd);
    CU_ASSERT(auth_cb_called);

    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:

    /*
     * Disable Enhanced Cert Auth Mode on the proxy
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
int us5139_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5139_SERVER_CERTKEY, US5139_TRUSTED_CERTS,
                             US5139_CACERTS, US5139_TCP_SERVER_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5139_coap_enhanced_cert_auth_mode",
                          us5139_init_suite, us5139_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {
        /* add the tests to the suite */
        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5981: Server Enhcd Cert 1 Mfg Success Mfg cert",
                         us5139_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL ==
             CU_add_test(
                 pSuite,
                 "TC5980: Server Enhcd Cert Auth 1 Mfg Fail local PKI cert",
                 us5139_test2))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5979: Server Enhcd Cert Auth No Mfg Success",
                         us5139_test3))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5982: Enhcd Cert Auth 1 Mfg Success local PKI cert",
                         us5139_test4))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5989: Proxy Enhcd Cert 1 Mfg Success Mfg cert",
                         us5139_test1p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL ==
             CU_add_test(
                 pSuite,
                 "TC5988: Proxy Enhcd Cert Auth 1 Mfg Fail local PKI cert",
                 us5139_test2p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL == CU_add_test(pSuite,
                                 "TC5987: Proxy Enhcd Cert Auth No Mfg Success",
                                 us5139_test3p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }

        if ((NULL == CU_add_test(pSuite,
                                 "TC5990: Proxy Enhcd Cert Auth 1 "
                                 "Mfg Success local PKI cert",
                                 us5139_test4p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
