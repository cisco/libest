/*------------------------------------------------------------------
 * us5244.c - Unit Tests for User Story 5244 - Extend Enhanced Cert
 *                                             Auth mode feature
 * Dec 2018
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

#define US5244_TCP_SERVER_PORT 25244
/*
 * Must have at least one port between server and proxy since libcoap will
 * internally take that port
 */
#define US5244_TCP_PROXY_PORT 25246
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5244_SERVER_IP "127.0.0.1"
#define US5244_COAP_CLIENT_EMU "est_coap_client.py"
#define US5244_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"
#define US5244_HTTP_SERVER_ERR_MSG                                             \
    "The test failed to start the HTTP endpoint server"
#define NUM_MFGS 4

#ifndef WIN32
#define US5244_CACERTS "CA/estCA/cacert.crt"
#define US5244_CLIENT1_CACERTS "CA/mfgCAs/trustedcertswithmfg0chain.crt"
#define US5244_CLIENT2_CACERTS "CA/mfgCAs/trustedcertswithmfg1chain.crt"
#define US5244_CLIENT3_CACERTS "CA/mfgCAs/trustedcertswithmfg2chain.crt"
#define US5244_CLIENT4_CACERTS "CA/mfgCAs/trustedcertswithmfg3chain.crt"
#define US5244_CLIENT5_CACERTS "CA/mfgCAs/trustedcertswithmfg4chain.crt"
#define US5244_SERVER_TESTMFG1_CACERTS "CA/mfgCAs/TestMfgCA0/cacert.crt"
#define US5244_SERVER_TESTMFG2_CACERTS "CA/mfgCAs/TestMfgCA1/cacert.crt"
#define US5244_SERVER_TESTMFG3_CACERTS "CA/mfgCAs/TestMfgCA2/cacert.crt"
#define US5244_SERVER_TESTMFG4_CACERTS "CA/mfgCAs/TestMfgCA3/cacert.crt"
#define US5244_SERVER_TESTMFG5_CACERTS "CA/mfgCAs/TestMfgCA4/cacert.crt"
#define US5244_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5244_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5244_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5244_CLIENT1_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA0/private/certandkey1-esttestmfg0.pem"
#define US5244_CLIENT2_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA1/private/certandkey1-esttestmfg1.pem"
#define US5244_CLIENT3_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA2/private/certandkey1-esttestmfg2.pem"
#define US5244_CLIENT4_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA3/private/certandkey1-esttestmfg3.pem"
#define US5244_CLIENT5_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA4/private/certandkey1-esttestmfg4.pem"
#define US5244_CA_CNF "CA/estExampleCA.cnf"
#define US5244_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5244_CACERTS "CA\\estCA\\cacert.crt"
#define US5244_CLIENT1_CACERTS "CA\\mfgCAs\\trustedcertswithmfg0chain.crt"
#define US5244_CLIENT2_CACERTS "CA\\mfgCAs\\trustedcertswithmfg1chain.crt"
#define US5244_CLIENT3_CACERTS "CA\\mfgCAs\\trustedcertswithmfg2chain.crt"
#define US5244_CLIENT4_CACERTS "CA\\mfgCAs\\trustedcertswithmfg3chain.crt"
#define US5244_CLIENT5_CACERTS "CA\\mfgCAs\\trustedcertswithmfg4chain.crt"
#define US5244_SERVER_TESTMFG1_CACERTS "CA\\mfgCAs\\TestMfgCA0\\cacert.crt"
#define US5244_SERVER_TESTMFG2_CACERTS "CA\\mfgCAs\\TestMfgCA1\\cacert.crt"
#define US5244_SERVER_TESTMFG3_CACERTS "CA\\mfgCAs\\TestMfgCA2\\cacert.crt"
#define US5244_SERVER_TESTMFG4_CACERTS "CA\\mfgCAs\\TestMfgCA3\\cacert.crt"
#define US5244_SERVER_TESTMFG5_CACERTS "CA\\mfgCAs\\TestMfgCA4\\cacert.crt"
#define US5244_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5244_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5244_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5244_CLIENT1_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA0\\private\\certandkey1-esttestmfg0.pem"
#define US5244_CLIENT2_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA1\\private\\certandkey1-esttestmfg1.pem"
#define US5244_CLIENT3_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA2\\private\\certandkey1-esttestmfg2.pem"
#define US5244_CLIENT4_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA3\\private\\certandkey1-esttestmfg3.pem"
#define US5244_CLIENT5_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA4\\private\\certandkey1-esttestmfg4.pem"
#define US5244_CA_CNF "CA\\estExampleCA.cnf"
#define US5244_COAP_CLIENT_EMU_PATH "..\\util\\"
#endif

#define US5244_TESTMFG1_EXPECTED_USER "SN:x, PID:x"
#define US5244_TESTMFG2_EXPECTED_USER "127.0.0.1"
#define US5244_TESTMFG3_EXPECTED_USER "ToysRUsKnockOff"
#define US5244_TESTMFG4_EXPECTED_USER "IOOT(Internet Of Other Things)"

static int auth_cb_called = 0;
static int expected_auth_result = 0;
static char temp_dir[MAX_FILENAME_LEN];
static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

const char *testMfgNames[NUM_MFGS] = {"Cisco", "Itron", "MetersRUs",
                                      "ReadItYourself"};
int testMfgNIDs[NUM_MFGS] = {NID_serialNumber, NID_commonName,
                             NID_organizationName, NID_organizationalUnitName};
const char *testMfgTruststoreFiles[NUM_MFGS] = {
    US5244_SERVER_TESTMFG1_CACERTS, US5244_SERVER_TESTMFG2_CACERTS,
    US5244_SERVER_TESTMFG3_CACERTS, US5244_SERVER_TESTMFG4_CACERTS};
unsigned char *testMfgTruststores[NUM_MFGS] = {NULL, NULL, NULL, NULL};
int testMfgTruststoreLengths[NUM_MFGS] = {0, 0, 0, 0};

const char *client_cacert_files[NUM_MFGS + 1] = {
    US5244_CLIENT1_CACERTS, US5244_CLIENT2_CACERTS, US5244_CLIENT3_CACERTS,
    US5244_CLIENT4_CACERTS, US5244_CLIENT5_CACERTS};
const char *client_certandkey_files[NUM_MFGS + 1] = {
    US5244_CLIENT1_CERTKEY, US5244_CLIENT2_CERTKEY, US5244_CLIENT3_CERTKEY,
    US5244_CLIENT4_CERTKEY, US5244_CLIENT5_CERTKEY};
const char *expected_usernames[NUM_MFGS] = {
    US5244_TESTMFG1_EXPECTED_USER, US5244_TESTMFG2_EXPECTED_USER,
    US5244_TESTMFG3_EXPECTED_USER, US5244_TESTMFG4_EXPECTED_USER};
int testMfgIndex = 0;
/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int us5244_server_process_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
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
        if (!strcmp(ah->user, expected_usernames[testMfgIndex]) &&
            !strcmp(ah->pwd, "cisco")) {
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

static int us5244_start_server_coap(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST CoAP server acting as the CA
     */
    rv = st_start_coap(US5244_TCP_SERVER_PORT, US5244_SERVER_CERTKEY,
                       US5244_SERVER_CERTKEY, "US5244 test realm",
                       US5244_CACERTS, US5244_TRUSTED_CERTS, US5244_CA_CNF,
                       manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_server_set_http_auth_cb(us5244_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }
    return rv;
}

static int us5244_start_proxy(int manual_enroll, int nid)
{
    int rv;
    /*
     * Start an EST proxy acting as an RA
     */
    rv = st_proxy_start_coap(
        US5244_TCP_PROXY_PORT, US5244_PROXY_CERTKEY, US5244_PROXY_CERTKEY,
        "US5244 test realm", US5244_CACERTS, US5244_TRUSTED_CERTS, "estuser",
        "estpwd", "127.0.0.1", US5244_TCP_SERVER_PORT, 0, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5244_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
    }
    return rv;
}

static int us5244_start_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST server acting as the CA
     */
    rv = st_start_coap(US5244_TCP_SERVER_PORT, US5244_SERVER_CERTKEY,
                       US5244_SERVER_CERTKEY, "US5244 test realm",
                       US5244_CACERTS, US5244_TRUSTED_CERTS, US5244_CA_CNF,
                       manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    /*
     *  Remove auth callback for HTTP server
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
static int us5244_init_suite(void)
{
    int rv;
    int i;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    for (i = 0; i < NUM_MFGS; i++) {
        testMfgTruststoreLengths[i] = read_binary_file(
            (char *)testMfgTruststoreFiles[i], &testMfgTruststores[i]);
        if (testMfgTruststoreLengths[0] <= 0) {
            printf("The TestMFG %d truststore failed to load from file\n", i);
            return 1;
        }
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
    rv = us5244_start_server_coap(0, 0);
    if (rv == EST_ERR_NONE) {
        rv = us5244_start_proxy(0, 0);
    }

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5244_destroy_suite(void)
{
    int i;
    st_stop();
    st_proxy_stop();
    for (i = 0; i < NUM_MFGS; i++) {
        free(testMfgTruststores[i]);
    }
    return 0;
}

/*
 * TC5983-5984: This function tests the use of Enhanced Cert Auth during a
 * simple enroll request to an EST over CoAP server
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert. After the four simple enrolls it will
 * perform one more simple enroll in the local pki domain to ensure it fails
 * as expected.
 */
static void us5244_test1(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5244_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv =
        st_enable_enhanced_cert_auth(NID_buildingName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_enhanced_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5244_est_tc1.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(
            cmd, EST_MAX_CMD_LEN,
            "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
            "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
            "> %s 2>&1",
            cssl_emulator_path, cssl_emulator_path, US5244_COAP_CLIENT_EMU_PATH,
            US5244_COAP_CLIENT_EMU, US5244_TCP_SERVER_PORT,
            client_certandkey_files[i], client_certandkey_files[i],
            client_cacert_files[i], coap_client_logs);
        if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
            CU_FAIL(
                "Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
            return;
        }
        system(cmd);
        CU_ASSERT(auth_cb_called);
    }

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
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_enable_enhanced_cert_auth(NID_buildingName, "cisco",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_enhanced_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(
            cmd, EST_MAX_CMD_LEN,
            "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
            "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
            "> %s 2>&1",
            cssl_emulator_path, cssl_emulator_path, US5244_COAP_CLIENT_EMU_PATH,
            US5244_COAP_CLIENT_EMU, US5244_TCP_SERVER_PORT,
            client_certandkey_files[i], client_certandkey_files[i],
            client_cacert_files[i], coap_client_logs);
        if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
            CU_FAIL(
                "Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
            return;
        }
        system(cmd);
        CU_ASSERT(auth_cb_called);
    }
    /*
     * Simple enroll expected to fail since local pki domain is set to
     * NID_buildingName
     */
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5244_COAP_CLIENT_EMU_PATH, US5244_COAP_CLIENT_EMU,
             US5244_TCP_SERVER_PORT, client_certandkey_files[i],
             client_certandkey_files[i], client_cacert_files[i],
             coap_client_logs);
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
 * TC5991-5992: This function tests the use of Enhanced Cert Auth during a
 * simple enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert. After the four simple enrolls it will
 * perform one more simple enroll in the local pki domain to ensure it fails
 * as expected.
 */
static void us5244_test1p(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5244_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    if (us5244_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5244_HTTP_SERVER_ERR_MSG);
        return;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_buildingName, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_proxy_enhcd_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5244_est_tc1p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(
            cmd, EST_MAX_CMD_LEN,
            "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
            "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
            "> %s 2>&1",
            cssl_emulator_path, cssl_emulator_path, US5244_COAP_CLIENT_EMU_PATH,
            US5244_COAP_CLIENT_EMU, US5244_TCP_PROXY_PORT,
            client_certandkey_files[i], client_certandkey_files[i],
            client_cacert_files[i], coap_client_logs);
        if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
            CU_FAIL(
                "Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
            return;
        }
        system(cmd);
        CU_ASSERT(auth_cb_called);
    }

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
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_buildingName, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_proxy_enhcd_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(
            cmd, EST_MAX_CMD_LEN,
            "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
            "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
            "> %s 2>&1",
            cssl_emulator_path, cssl_emulator_path, US5244_COAP_CLIENT_EMU_PATH,
            US5244_COAP_CLIENT_EMU, US5244_TCP_PROXY_PORT,
            client_certandkey_files[i], client_certandkey_files[i],
            client_cacert_files[i], coap_client_logs);
        if (strnlen(cmd, EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
            CU_FAIL(
                "Commmand for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
            return;
        }
        system(cmd);
        CU_ASSERT(auth_cb_called);
    }
    /*
     * Simple enroll expected to fail since local pki domain is set to
     * NID_buildingName
     */
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5244_COAP_CLIENT_EMU_PATH, US5244_COAP_CLIENT_EMU,
             US5244_TCP_PROXY_PORT, client_certandkey_files[i],
             client_certandkey_files[i], client_cacert_files[i],
             coap_client_logs);
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
 * TC5985: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the server will use the local pki domain auth credentials
 * which are provided in the peer cert.
 */
static void us5244_test2(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5244_CSSL_NOT_SET_MSG);
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

    /*
     * The NID is set to NID_buildingName which the peer cert doesn't have.
     * If any of the mfg PKI domains is used the test will fail.
     */
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_enhanced_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], NID_buildingName, testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5244_est_tc2.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5244_COAP_CLIENT_EMU_PATH, US5244_COAP_CLIENT_EMU,
             US5244_TCP_SERVER_PORT, client_certandkey_files[i],
             client_certandkey_files[i], client_cacert_files[i],
             coap_client_logs);
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
 * TC5993: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert.
 */
static void us5244_test2p(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5244_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    us5244_start_server(0, 0);
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
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

    /*
     * The NID is set to NID_buildingName which the peer cert doesn't have.
     * If any of the mfg PKI domains is used the test will fail.
     */
    for (i = 0; i < NUM_MFGS; i++) {
        rv = st_proxy_enhcd_cert_auth_add_mfg_info(
            (char *)testMfgNames[i], NID_buildingName, testMfgTruststores[i],
            testMfgTruststoreLengths[i]);
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5244_est_tc2p.log",
             temp_dir);
    if (strnlen(coap_client_logs, MAX_FILENAME_LEN) >= MAX_FILENAME_LEN) {
        CU_FAIL("The logfile for the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5244_COAP_CLIENT_EMU_PATH, US5244_COAP_CLIENT_EMU,
             US5244_TCP_PROXY_PORT, client_certandkey_files[i],
             client_certandkey_files[i], client_cacert_files[i],
             coap_client_logs);
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
 * TC5986: This function tests the use of the
 * est_server_enhanced_cert_auth_add_mfg_info API.
 *
 * sub-tests include:
 *  NULL ctx test
 *  Enhcd Cert Auth disabled test
 *  NULL name test
 *  NULL truststore test
 *  0 len truststore
 *  bogus truststore (len doesn't match data)
 *
 */
static void us5244_test3(void)
{
    int rv;
    int mfg_ind = 0;

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5244_CSSL_NOT_SET_MSG);
        return;
    }
    /* NULL ctx test */
    rv = est_server_enhanced_cert_auth_add_mfg_info(
        NULL, (char *)testMfgNames[mfg_ind], testMfgNIDs[mfg_ind],
        testMfgTruststores[mfg_ind], testMfgTruststoreLengths[mfg_ind]);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    /* Enhcd Cert Auth disabled test */
    rv = st_enhanced_cert_auth_add_mfg_info(
        (char *)testMfgNames[mfg_ind], testMfgNIDs[mfg_ind],
        testMfgTruststores[mfg_ind], testMfgTruststoreLengths[mfg_ind]);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
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

    /* NULL name test */
    rv = st_enhanced_cert_auth_add_mfg_info(NULL, testMfgNIDs[mfg_ind],
                                            testMfgTruststores[mfg_ind],
                                            testMfgTruststoreLengths[mfg_ind]);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);

    /* NULL truststore test */
    rv = st_enhanced_cert_auth_add_mfg_info((char *)testMfgNames[mfg_ind],
                                            testMfgNIDs[mfg_ind], NULL,
                                            testMfgTruststoreLengths[mfg_ind]);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);

    /* 0 len truststore */
    rv = st_enhanced_cert_auth_add_mfg_info((char *)testMfgNames[mfg_ind],
                                            testMfgNIDs[mfg_ind],
                                            testMfgTruststores[mfg_ind], 0);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    /*
     * bogus truststore (len doesn't match data)
     *  - 2 from the len since the last index is a null terminator
     */
    rv = st_enhanced_cert_auth_add_mfg_info(
        (char *)testMfgNames[mfg_ind], testMfgNIDs[mfg_ind],
        testMfgTruststores[mfg_ind], testMfgTruststoreLengths[mfg_ind] - 2);
    CU_ASSERT(rv == EST_ERR_NO_CERTS_FOUND);

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

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5244_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5244_SERVER_CERTKEY, US5244_TRUSTED_CERTS,
                             US5244_CACERTS, US5244_TCP_SERVER_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5244_coap_enhanced_cert_auth_mode",
                          us5244_init_suite, us5244_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5983-4: Server Enhanced Cert Auth 4 Mfgs Success",
                         us5244_test1))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite,
                                 "TC5985: Enhcd Cert Auth CoAP Server 4 "
                                 "Mfg Local PKI Success",
                                 us5244_test2))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5991-2: Proxy Enhanced Cert Auth 4 Mfgs Success",
                         us5244_test1p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL == CU_add_test(pSuite,
                                 "TC5993: Enhcd Cert Auth CoAP Proxy 4 "
                                 "Mfg Local PKI Success",
                                 us5244_test2p))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
        if ((NULL ==
             CU_add_test(pSuite,
                         "TC5986: Enhcd Cert Auth CoAP Mfg Register API",
                         us5244_test3))) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
