/*------------------------------------------------------------------
 * us5248.c - Unit Tests for User Story 5248 - Extend Enhanced Cert
 *                                             Auth mode feature
 *                                             (CSR Checking)
 April 2019
 *
 * Copyright (c) 2019 by Cisco Systems, Inc.
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

#define US5248_TCP_SERVER_PORT 25248
#define US5248_TCP_PROXY_PORT 25249
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256

#define US5248_SERVER_IP "127.0.0.1"
#define US5248_COAP_CLIENT_EMU "est_coap_client.py"
#define US5248_CSSL_NOT_SET_MSG                                                \
    "The path for the openssl installation used by"                            \
    " the python emulator was not specified.\n Please set the environment "    \
    "variable"                                                                 \
    " COAP_EMU_SSL"
#define US5248_HTTP_SERVER_ERR_MSG                                             \
    "The test failed to start the HTTP endpoint server"
#define NUM_MFGS 4

#ifndef WIN32
#define US5248_CACERTS "CA/estCA/cacert.crt"
#define US5248_CLIENT1_CACERTS "CA/mfgCAs/trustedcertswithmfg0chain.crt"
#define US5248_CLIENT2_CACERTS "CA/mfgCAs/trustedcertswithmfg1chain.crt"
#define US5248_CLIENT3_CACERTS "CA/mfgCAs/trustedcertswithmfg2chain.crt"
#define US5248_CLIENT4_CACERTS "CA/mfgCAs/trustedcertswithmfg3chain.crt"
#define US5248_CLIENT5_CACERTS "CA/mfgCAs/trustedcertswithmfg4chain.crt"
#define US5248_SERVER_TESTMFG1_CACERTS "CA/mfgCAs/TestMfgCA0/cacert.crt"
#define US5248_SERVER_TESTMFG2_CACERTS "CA/mfgCAs/TestMfgCA1/cacert.crt"
#define US5248_SERVER_TESTMFG3_CACERTS "CA/mfgCAs/TestMfgCA2/cacert.crt"
#define US5248_SERVER_TESTMFG4_CACERTS "CA/mfgCAs/TestMfgCA3/cacert.crt"
#define US5248_SERVER_TESTMFG5_CACERTS "CA/mfgCAs/TestMfgCA4/cacert.crt"
#define US5248_SERVER_TESTMFG1_CSR "CA/mfgCAs/TestMfgCA0/test.csr"
#define US5248_SERVER_TESTMFG2_CSR "CA/mfgCAs/TestMfgCA1/test.csr"
#define US5248_SERVER_TESTMFG3_CSR "CA/mfgCAs/TestMfgCA2/test.csr"
#define US5248_SERVER_TESTMFG4_CSR "CA/mfgCAs/TestMfgCA3/test.csr"
#define US5248_SERVER_TESTMFG5_CSR "CA/mfgCAs/TestMfgCA4/test.csr"
#define US5248_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5248_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5248_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5248_CLIENT1_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA0/private/certandkey1-esttestmfg0.pem"
#define US5248_CLIENT2_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA1/private/certandkey1-esttestmfg1.pem"
#define US5248_CLIENT3_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA2/private/certandkey1-esttestmfg2.pem"
#define US5248_CLIENT4_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA3/private/certandkey1-esttestmfg3.pem"
#define US5248_CLIENT5_CERTKEY                                                 \
    "CA/mfgCAs/TestMfgCA4/private/certandkey1-esttestmfg4.pem"
#define US5248_CA_CNF "CA/estExampleCA.cnf"
#define US5248_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5248_CACERTS "CA\\estCA\\cacert.crt"
#define US5248_CLIENT1_CACERTS "CA\\mfgCAs\\trustedcertswithmfg0chain.crt"
#define US5248_CLIENT2_CACERTS "CA\\mfgCAs\\trustedcertswithmfg1chain.crt"
#define US5248_CLIENT3_CACERTS "CA\\mfgCAs\\trustedcertswithmfg2chain.crt"
#define US5248_CLIENT4_CACERTS "CA\\mfgCAs\\trustedcertswithmfg3chain.crt"
#define US5248_CLIENT5_CACERTS "CA\\mfgCAs\\trustedcertswithmfg4chain.crt"
#define US5248_SERVER_TESTMFG1_CACERTS "CA\\mfgCAs\\TestMfgCA0\\cacert.crt"
#define US5248_SERVER_TESTMFG2_CACERTS "CA\\mfgCAs\\TestMfgCA1\\cacert.crt"
#define US5248_SERVER_TESTMFG3_CACERTS "CA\\mfgCAs\\TestMfgCA2\\cacert.crt"
#define US5248_SERVER_TESTMFG4_CACERTS "CA\\mfgCAs\\TestMfgCA3\\cacert.crt"
#define US5248_SERVER_TESTMFG5_CACERTS "CA\\mfgCAs\\TestMfgCA4\\cacert.crt"
#define US5248_SERVER_TESTMFG1_CSR "CA\\mfgCAs\\TestMfgCA0\\test.csr"
#define US5248_SERVER_TESTMFG2_CSR "CA\\mfgCAs\\TestMfgCA1\\test.csr"
#define US5248_SERVER_TESTMFG3_CSR "CA\\mfgCAs\\TestMfgCA2\\test.csr"
#define US5248_SERVER_TESTMFG4_CSR "CA\\mfgCAs\\TestMfgCA3\\test.csr"
#define US5248_SERVER_TESTMFG5_CSR "CA\\mfgCAs\\TestMfgCA4\\test.csr"
#define US5248_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5248_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5248_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5248_CLIENT1_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA0\\private\\certandkey1-esttestmfg0.pem"
#define US5248_CLIENT2_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA1\\private\\certandkey1-esttestmfg1.pem"
#define US5248_CLIENT3_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA2\\private\\certandkey1-esttestmfg2.pem"
#define US5248_CLIENT4_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA3\\private\\certandkey1-esttestmfg3.pem"
#define US5248_CLIENT5_CERTKEY                                                 \
    "CA\\mfgCAs\\TestMfgCA4\\private\\certandkey1-esttestmfg4.pem"
#define US5248_CA_CNF "CA\\estExampleCA.cnf"
#define US5248_COAP_CLIENT_EMU_PATH "..\\util\\"
#endif

#define US5248_TESTMFG1_EXPECTED_USER "SN:x, PID:x"
#define US5248_TESTMFG2_EXPECTED_USER "127.0.0.1"
#define US5248_TESTMFG3_EXPECTED_USER "ToysRUsKnockOff"
#define US5248_TESTMFG4_EXPECTED_USER "IOOT(Internet Of Other Things)"

static int auth_cb_called = 0;
static int expected_auth_result = 0;
static char temp_dir[MAX_FILENAME_LEN];
static char *cssl_emulator_path = NULL;

static const char *testMfgNames[NUM_MFGS] = {"Cisco", "Itron", "MetersRUs",
                                             "ReadItYourself"};
static int testMfgNIDs[NUM_MFGS] = {NID_serialNumber, NID_commonName,
                                    NID_organizationName,
                                    NID_organizationalUnitName};
static const char *testMfgTruststoreFiles[NUM_MFGS + 1] = {
    US5248_SERVER_TESTMFG1_CACERTS, US5248_SERVER_TESTMFG2_CACERTS,
    US5248_SERVER_TESTMFG3_CACERTS, US5248_SERVER_TESTMFG4_CACERTS,
    US5248_SERVER_TESTMFG5_CACERTS};
static unsigned char *testMfgTruststores[NUM_MFGS + 1] = {NULL, NULL, NULL,
                                                          NULL, NULL};
static int testMfgTruststoreLengths[NUM_MFGS + 1] = {0, 0, 0, 0, 0};

static const char *coap_client_cacert_files[NUM_MFGS + 1] = {
    US5248_CLIENT1_CACERTS, US5248_CLIENT2_CACERTS, US5248_CLIENT3_CACERTS,
    US5248_CLIENT4_CACERTS, US5248_CLIENT5_CACERTS};
static unsigned char *http_client_cacerts[NUM_MFGS + 1] = {NULL, NULL, NULL,
                                                           NULL, NULL};
static int http_client_cacerts_lengths[NUM_MFGS + 1] = {0, 0, 0, 0, 0};
static const char *client_certandkey_files[NUM_MFGS + 1] = {
    US5248_CLIENT1_CERTKEY, US5248_CLIENT2_CERTKEY, US5248_CLIENT3_CERTKEY,
    US5248_CLIENT4_CERTKEY, US5248_CLIENT5_CERTKEY};
typedef struct client_info {
    X509 *cert;
    EVP_PKEY *key;
    X509_REQ *csr;
} client_info;
static client_info http_client_info[NUM_MFGS + 1] = {{NULL, NULL, NULL},
                                                     {NULL, NULL, NULL},
                                                     {NULL, NULL, NULL},
                                                     {NULL, NULL, NULL},
                                                     {NULL, NULL, NULL}};
static const char *client_csr_files[NUM_MFGS + 1] = {
    US5248_SERVER_TESTMFG1_CSR, US5248_SERVER_TESTMFG2_CSR,
    US5248_SERVER_TESTMFG3_CSR, US5248_SERVER_TESTMFG4_CSR,
    US5248_SERVER_TESTMFG5_CSR};
static const char *expected_usernames[NUM_MFGS] = {
    US5248_TESTMFG1_EXPECTED_USER, US5248_TESTMFG2_EXPECTED_USER,
    US5248_TESTMFG3_EXPECTED_USER, US5248_TESTMFG4_EXPECTED_USER};
static int testMfgIndex = 0;
/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int us5248_server_process_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
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

static int us5248_start_server_coap(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST CoAP server acting as the CA
     */
    rv = st_start_coap(US5248_TCP_SERVER_PORT, US5248_SERVER_CERTKEY,
                       US5248_SERVER_CERTKEY, "US5248 test realm",
                       US5248_CACERTS, US5248_TRUSTED_CERTS, US5248_CA_CNF,
                       manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_server_set_http_auth_cb(us5248_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }
    return rv;
}

static int us5248_start_proxy_coap(int manual_enroll, int nid)
{
    int rv;
    /*
     * Start an EST proxy acting as an RA
     */
    rv = st_proxy_start_coap(
        US5248_TCP_PROXY_PORT, US5248_PROXY_CERTKEY, US5248_PROXY_CERTKEY,
        "US5248 test realm", US5248_CACERTS, US5248_TRUSTED_CERTS, "estuser",
        "estpwd", "127.0.0.1", US5248_TCP_SERVER_PORT, 0, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5248_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
    }
    return rv;
}

static int us5248_start_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * Start an EST server acting as the CA
     */
    rv = st_start(US5248_TCP_SERVER_PORT, US5248_SERVER_CERTKEY,
                  US5248_SERVER_CERTKEY, "US5248 test realm", US5248_CACERTS,
                  US5248_TRUSTED_CERTS, US5248_CA_CNF, manual_enroll, 0, nid);
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

static int us5248_start_proxy(int manual_enroll, int nid)
{
    int rv;
    /*
     * Start an EST proxy acting as an RA
     */
    rv = st_proxy_start(US5248_TCP_PROXY_PORT, US5248_PROXY_CERTKEY,
                        US5248_PROXY_CERTKEY, "US5248 test realm",
                        US5248_CACERTS, US5248_TRUSTED_CERTS, "estuser",
                        "estpwd", "127.0.0.1", US5248_TCP_SERVER_PORT, 0, nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return rv;
    }
    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5248_server_process_auth);
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
static int us5248coap_init_suite(void)
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
        if (testMfgTruststoreLengths[i] <= 0) {
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
    rv = us5248_start_server_coap(0, 0);
    if (rv == EST_ERR_NONE) {
        rv = us5248_start_proxy_coap(0, 0);
    }

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5248coap_destroy_suite(void)
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
 * TC6078: This function tests the use of Enhanced Cert Auth with the CSR check
 * on during a simple enroll request to an EST over CoAP server
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert and the csrs being enrolled have the
 * manufacturer's identity information copied in the appropriate location. After
 * the four simple enrolls it will perform one more simple enroll in the local
 * pki domain to ensure it fails as expected.
 */
static void us5248_test1_coap(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
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
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc1.log",
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
        snprintf(cmd, EST_MAX_CMD_LEN,
                 "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
                 "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
                 "%s --csr %s "
                 "> %s 2>&1",
                 cssl_emulator_path, cssl_emulator_path,
                 US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
                 US5248_TCP_SERVER_PORT, client_certandkey_files[i],
                 client_certandkey_files[i], coap_client_cacert_files[i],
                 client_csr_files[i], coap_client_logs);
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
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, "cisco",
                                      ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(cmd, EST_MAX_CMD_LEN,
                 "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
                 "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
                 "%s --csr %s "
                 "> %s 2>&1",
                 cssl_emulator_path, cssl_emulator_path,
                 US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
                 US5248_TCP_SERVER_PORT, client_certandkey_files[i],
                 client_certandkey_files[i], coap_client_cacert_files[i],
                 client_csr_files[i], coap_client_logs);
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
     * Simple enroll expected to fail the CSR check since uniqueMember is where
     * the identifying information is in the cert but the local pki domain nid
     * is set to serialNumber
     */
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_SERVER_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
 * TC6079: This function tests the use of Enhanced Cert Auth with the CSR check
 * on during a simple enroll request through an EST over CoAP proxy to an EST
 * server.
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert and the csrs being enrolled have the
 * manufacturer's identity information copied in the appropriate location. After
 * the four simple enrolls it will perform one more simple enroll in the local
 * pki domain to ensure it fails as expected.
 */
static void us5248_test1_coap_p(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    if (us5248_start_server(0, 0) != EST_ERR_NONE) {
        printf(US5248_HTTP_SERVER_ERR_MSG);
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
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, NULL,
                                         ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc1p.log",
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
        snprintf(cmd, EST_MAX_CMD_LEN,
                 "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
                 "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
                 "%s --csr %s "
                 "> %s 2>&1",
                 cssl_emulator_path, cssl_emulator_path,
                 US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
                 US5248_TCP_PROXY_PORT, client_certandkey_files[i],
                 client_certandkey_files[i], coap_client_cacert_files[i],
                 client_csr_files[i], coap_client_logs);
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
     * The NID is NID_serialNumber which is the field that the id information is
     * copied to
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "cisco",
                                         ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        snprintf(cmd, EST_MAX_CMD_LEN,
                 "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
                 "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
                 "%s --csr %s "
                 "> %s 2>&1",
                 cssl_emulator_path, cssl_emulator_path,
                 US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
                 US5248_TCP_PROXY_PORT, client_certandkey_files[i],
                 client_certandkey_files[i], coap_client_cacert_files[i],
                 client_csr_files[i], coap_client_logs);
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
     * Simple enroll expected to fail the CSR check since uniqueMember is where
     * the identifying information is in the cert but the local pki domain nid
     * is set to serialNumber.
     */
    auth_cb_called = 0;
    expected_auth_result = 1;
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_PROXY_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
    st_stop();
    us5248_start_server_coap(0, 0);
    return;
}

/*
 * TC6080: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert and the CSR check passed.
 */
static void us5248_test2_coap(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
        if (i == 1) {
            rv = st_enhanced_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
                testMfgTruststoreLengths[i]);
        } else {
            rv = st_enhanced_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], NID_buildingName,
                testMfgTruststores[i], testMfgTruststoreLengths[i]);
        }
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc2.log",
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
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_SERVER_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
 * TC6080: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert and the CSR check passed.
 */
static void us5248_test2_coap_p(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    us5248_start_server(0, 0);
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
        if (i == 1) {
            rv = st_proxy_enhcd_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
                testMfgTruststoreLengths[i]);
        } else {
            rv = st_proxy_enhcd_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], NID_buildingName,
                testMfgTruststores[i], testMfgTruststoreLengths[i]);
        }
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc2p.log",
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
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_PROXY_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
    st_stop();
    us5248_start_server_coap(0, 0);
    return;
}

/*
 * TC6094: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * fail since the server will use the local pki domain auth credentials
 * which are provided in the peer cert but the CSR check will fail since there
 * is no building name in the cert or CSR.
 */
static void us5248_test3_coap(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc2.log",
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
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_SERVER_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
 * TC6093: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert but the CSR check will fail since there
 * is no building name in the cert or CSR.
 */
static void us5248_test3_coap_p(void)
{
    int rv;
    int i;
    char cmd[EST_MAX_CMD_LEN];
    char coap_client_logs[MAX_FILENAME_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5248_CSSL_NOT_SET_MSG);
        return;
    }

    st_stop();
    us5248_start_server(0, 0);
    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    snprintf(coap_client_logs, MAX_FILENAME_LEN, "%sus5248_est_tc2p.log",
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
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert "
             "%s --csr %s "
             "> %s 2>&1",
             cssl_emulator_path, cssl_emulator_path,
             US5248_COAP_CLIENT_EMU_PATH, US5248_COAP_CLIENT_EMU,
             US5248_TCP_PROXY_PORT, client_certandkey_files[i],
             client_certandkey_files[i], coap_client_cacert_files[i],
             client_csr_files[i], coap_client_logs);
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
    st_stop();
    us5248_start_server_coap(0, 0);
    return;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5248coap_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5248_SERVER_CERTKEY, US5248_TRUSTED_CERTS,
                             US5248_CACERTS, US5248_TCP_SERVER_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        return 0;
    }

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5248_coap_ECA_CSR_Check", us5248coap_init_suite,
                          us5248coap_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite,
                             "TC6078: Server ECA CoAP CSR On 4 Mfgs Success",
                             us5248_test1_coap))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6081: Server ECA CoAP CSR On 4 "
                             "Mfg Local PKI Success",
                             us5248_test2_coap))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6094: Server ECA CoAP CSR On 4 "
                             "Mfg Local PKI Failure",
                             us5248_test3_coap))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6079: Proxy ECA CoAP CSR On 4 Mfgs Success",
                             us5248_test1_coap_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6080: Proxy ECA CoAP CSR On 4 "
                             "Mfg Local PKI Success",
                             us5248_test2_coap_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6093: Proxy ECA CoAP CSR On 4 "
                             "Mfg Local PKI Failure",
                             us5248_test3_coap_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

/********************************HTTPS*****************************************/

static int client_manual_cert_verify_US5248(X509 *cur_cert,
                                            int openssl_cert_error)
{
    int approve = 0;

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
        return approve;
    }

    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following "
           "error: openssl_cert_error = %d (%s)\n",
           __FUNCTION__, openssl_cert_error,
           X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);

    return approve;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5248http_init_suite(void)
{
    int rv;
    int i;
    unsigned char *temp;
    int temp_len;

    est_init_logger(EST_LOG_LVL_INFO, NULL);
    /*
     * Read in the CA certificates
     */
    for (i = 0; i < NUM_MFGS + 1; i++) {
        testMfgTruststoreLengths[i] = read_binary_file(
            (char *)testMfgTruststoreFiles[i], &testMfgTruststores[i]);
        if (testMfgTruststoreLengths[i] <= 0) {
            printf("The TestMFG %d truststore failed to load from file\n", i);
            return 1;
        }
        http_client_cacerts_lengths[i] = read_binary_file(
            (char *)coap_client_cacert_files[i], &http_client_cacerts[i]);
        if (http_client_cacerts_lengths[i] <= 0) {
            printf("The TestMFG %d truststore failed to load from file\n", i);
            return 1;
        }
        if (read_x509_cert_and_key_file((char *)client_certandkey_files[i],
                                        (char *)client_certandkey_files[i],
                                        &(http_client_info[i].cert),
                                        &(http_client_info[i].key))) {
            printf("The TestMFG %d cert and key failed to load from file\n", i);
            return 1;
        }
        temp_len = read_binary_file((char *)client_csr_files[i], &temp);
        http_client_info[i].csr =
            est_read_x509_request(temp, temp_len, EST_CERT_FORMAT_PEM);
        free(temp);
        if (http_client_info[i].csr == NULL) {
            printf("The TestMFG %d CSR failed to load from file\n", i);
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
    rv = us5248_start_server(0, 0);
    if (rv == EST_ERR_NONE) {
        rv = us5248_start_proxy(0, 0);
    }

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5248http_destroy_suite(void)
{
    int i;
    st_stop();
    st_proxy_stop();
    for (i = 0; i < NUM_MFGS; i++) {
        free(testMfgTruststores[i]);
        free(http_client_cacerts[i]);
        X509_free(http_client_info[i].cert);
        EVP_PKEY_free(http_client_info[i].key);
        X509_REQ_free(http_client_info[i].csr);
    }
    return 0;
}
static EST_ERROR us5248_http_client_enroll(int port_str, unsigned char *cacerts,
                                           int cacerts_len, client_info info)
{
    /*
     * Create a client context
     */
    EST_CTX *ecctx;
    EST_ERROR rv;
    int pkcs7_len;
    ecctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5248);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        return EST_ERR_NO_CTX;
    }
    /*
     * Set the authentication mode to use a user id/password. These
     * credentials should be ignored by the server since we are in Enhanced
     * Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, "user", "pwd", info.cert, info.key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        est_destroy(ecctx);
        return rv;
    }

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ecctx, US5248_SERVER_IP, port_str, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set the server to connect to\n");
        est_destroy(ecctx);
        return rv;
    }

    rv = est_client_enroll_csr(ecctx, info.csr, &pkcs7_len, info.key);
    if (pkcs7_len <= 0) {
        rv = EST_ERR_HTTP_NO_CONTENT;
    }
    est_destroy(ecctx);
    return rv;
}
/*
 * TC6078: This function tests the use of Enhanced Cert Auth with the CSR check
 * on during a simple enroll request to an EST server
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert and the csrs being enrolled have the
 * manufacturer's identity information copied in the appropriate location. After
 * the four simple enrolls it will perform one more simple enroll in the local
 * pki domain to ensure it fails as expected.
 */
static void us5248_test1_http(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    rv = st_server_set_http_auth_cb(us5248_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        CU_FAIL("Couldn't set auth callback");
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            goto cleanup_enhcd_cert_auth;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        rv = us5248_http_client_enroll(
            US5248_TCP_SERVER_PORT, http_client_cacerts[i],
            http_client_cacerts_lengths[i], http_client_info[i]);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Failed enrollment");
            printf("Failed enrollment with %s (%d)\n", EST_ERR_NUM_TO_STR(rv),
                   rv);
            goto cleanup_enhcd_cert_auth;
        }
        CU_ASSERT(auth_cb_called);
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        st_server_set_http_auth_cb(NULL);
        return;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_enable_enhanced_cert_auth(NID_serialNumber, "cisco",
                                      ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            goto cleanup_enhcd_cert_auth;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        rv = us5248_http_client_enroll(
            US5248_TCP_SERVER_PORT, http_client_cacerts[i],
            http_client_cacerts_lengths[i], http_client_info[i]);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Failed enrollment");
            printf("Failed enrollment %d with %s (%d)\n", i,
                   EST_ERR_NUM_TO_STR(rv), rv);
        }
        CU_ASSERT(auth_cb_called);
    }
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
    st_server_set_http_auth_cb(NULL);
    return;
}

/*
 * TC6079: This function tests the use of Enhanced Cert Auth with the CSR check
 * on during a simple enroll request through an EST proxy to an EST
 * server.
 *
 * This test attempts to perform four simple enrolls using each valid
 * manufacturer certificate. These simple enroll request will
 * succeed since the server will use the mfg pki domain auth credentials
 * which are provided by each mfg cert and the csrs being enrolled have the
 * manufacturer's identity information copied in the appropriate location. After
 * the four simple enrolls it will perform one more simple enroll in the local
 * pki domain to ensure it fails as expected.
 */
static void us5248_test1_http_p(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     *
     * The NID is NID_buildingName which none of the mfg certs have.
     * If the local PKI domain is used the test will fail.
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, NULL,
                                         ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        rv = us5248_http_client_enroll(
            US5248_TCP_PROXY_PORT, http_client_cacerts[i],
            http_client_cacerts_lengths[i], http_client_info[i]);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Failed enrollment");
            printf("Failed enrollment %d with %s (%d)\n", i,
                   EST_ERR_NUM_TO_STR(rv), rv);
        }
        CU_ASSERT(auth_cb_called);
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_proxy_disable_enhcd_cert_auth();
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
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "cisco",
                                         ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }
    for (i = 0; i < NUM_MFGS; i++) {
        /* Build out est_coap_client.py command and log the output */
        auth_cb_called = 0;
        expected_auth_result = 1;
        testMfgIndex = i;
        rv = us5248_http_client_enroll(
            US5248_TCP_PROXY_PORT, http_client_cacerts[i],
            http_client_cacerts_lengths[i], http_client_info[i]);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Failed enrollment");
            printf("Failed enrollment %d with %s (%d)\n", i,
                   EST_ERR_NUM_TO_STR(rv), rv);
        }
        CU_ASSERT(auth_cb_called);
    }
    /*
     * Cleanup
     */

cleanup_enhcd_cert_auth:
    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * TC6081: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the server will use the local pki domain auth credentials
 * which are provided in the peer cert and the CSR check passed.
 */
static void us5248_test2_http(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    rv = st_server_set_http_auth_cb(us5248_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        CU_FAIL("Couldn't set auth callback");
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
        if (i == 1) {
            rv = st_enhanced_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
                testMfgTruststoreLengths[i]);
        } else {
            rv = st_enhanced_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], NID_buildingName,
                testMfgTruststores[i], testMfgTruststoreLengths[i]);
        }
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i + 1);
            goto cleanup_enhcd_cert_auth;
        }
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    rv = us5248_http_client_enroll(
        US5248_TCP_SERVER_PORT, http_client_cacerts[i],
        http_client_cacerts_lengths[i], http_client_info[i]);
    if (rv != EST_ERR_NONE) {
        CU_FAIL("Failed enrollment");
        printf("Failed enrollment with %s (%d)\n", EST_ERR_NUM_TO_STR(rv), rv);
    }
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
    st_server_set_http_auth_cb(NULL);
    return;
}

/*
 * TC6080: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * succeed since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert and the CSR check passed.
 */
static void us5248_test2_http_p(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
        if (i == 1) {
            rv = st_proxy_enhcd_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], testMfgNIDs[i], testMfgTruststores[i],
                testMfgTruststoreLengths[i]);
        } else {
            rv = st_proxy_enhcd_cert_auth_add_mfg_info(
                (char *)testMfgNames[i], NID_buildingName,
                testMfgTruststores[i], testMfgTruststoreLengths[i]);
        }
        CU_ASSERT(rv == EST_ERR_NONE);
        if (rv != EST_ERR_NONE) {
            CU_FAIL("Unexpected failure to add mfg");
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    rv = us5248_http_client_enroll(
        US5248_TCP_PROXY_PORT, http_client_cacerts[i],
        http_client_cacerts_lengths[i], http_client_info[i]);
    if (rv != EST_ERR_NONE) {
        CU_FAIL("Failed enrollment");
        printf("Failed enrollment with %s (%d)\n", EST_ERR_NUM_TO_STR(rv), rv);
    }
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
 * TC6096: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * fail since the server will use the local pki domain auth credentials
 * which are provided in the peer cert but the CSR check will fail since there
 * is no building name in the cert or CSR.
 */
static void us5248_test3_http(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    rv = st_server_set_http_auth_cb(us5248_server_process_auth);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        CU_FAIL("Couldn't set auth callback");
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            goto cleanup_enhcd_cert_auth;
        }
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    rv = us5248_http_client_enroll(
        US5248_TCP_SERVER_PORT, http_client_cacerts[i],
        http_client_cacerts_lengths[i], http_client_info[i]);
    if (rv == EST_ERR_NONE) {
        CU_FAIL("Enrollment unexpectedly passed");
        printf("Enrollment unexpectedly passed");
    }
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
    st_server_set_http_auth_cb(NULL);
    return;
}

/*
 * TC6097: This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an EST over CoAP proxy through to an EST server
 *
 * This test attempts to perform a simple enroll using a valid
 * local PKI domain certificate. This enroll request will
 * fail since the proxy will use the local pki domain auth credentials
 * which are provided in the peer cert but the CSR check will fail since there
 * is no building name in the cert or CSR.
 */
static void us5248_test3_http_p(void)
{
    int rv;
    int i;

    LOG_FUNC_NM;

    /*
     * Enable Enhanced Cert Auth Mode on the proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv =
        st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_ON);
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
            printf("Unexpected failure to add mfg %d\n", i + 1);
            return;
        }
    }

    /* Use last client credentials to test local pki domain */
    auth_cb_called = 0;
    expected_auth_result = 1;
    testMfgIndex = 1;
    rv = us5248_http_client_enroll(
        US5248_TCP_PROXY_PORT, http_client_cacerts[i],
        http_client_cacerts_lengths[i], http_client_info[i]);
    if (rv == EST_ERR_NONE) {
        CU_FAIL("Enrollment unexpectedly passed");
        printf("Enrollment unexpectedly passed");
    }
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

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5248http_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5248_http_ECA_CSR_Check", us5248http_init_suite,
                          us5248http_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite,
                             "TC6082: Server ECA HTTP CSR On 4 Mfgs Success",
                             us5248_test1_http))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6085: Server ECA HTTP CSR On 4 "
                             "Mfg Local PKI Success",
                             us5248_test2_http))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6096: Server ECA HTTP CSR On 4 "
                             "Mfg Local PKI Failure",
                             us5248_test3_http))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6083: Proxy ECA HTTP CSR On 4 Mfgs Success",
                             us5248_test1_http_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6084: Proxy ECA HTTP CSR On 4 "
                             "Mfg Local PKI Success",
                             us5248_test2_http_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    if ((NULL == CU_add_test(pSuite,
                             "TC6097: Proxy ECA HTTP CSR On 4 "
                             "Mfg Local PKI Failure",
                             us5248_test3_http_p))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}
