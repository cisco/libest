/*------------------------------------------------------------------
 * us5121.c - Unit Tests for User Story 5121 - Add Enhanced Cert Auth
 *                                             mode feature
 *
 * May 2018
 *
 * Copyright (c) 2018-2019 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>

#ifndef WIN32

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

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static unsigned char *server_enhcd_cert_cacert = NULL;
static int server_enhcd_cert_cacert_len = 0;
static X509 *client_enhcd_cert = NULL;
static EVP_PKEY *client_enhcd_cert_key = NULL;
static X509 *client_non_enhcd_cert = NULL;
static EVP_PKEY *client_non_enhcd_cert_key = NULL;

#define US5121_TCP_SERVER_PORT 25121
#define US5121_TCP_PROXY_PORT 25122

#define US5121_SERVER_IP "127.0.0.1"
#define US5121_KEYGEN_URL_BA                                                   \
    "https://127.0.0.1:25121/.well-known/est/serverkeygen"
#define US5121_PKCS10_CT "Content-Type: application/pkcs10"
#define US5121_UIDPWD_GOOD "estuser:estpwd"
#define US5121_UID "estuser"
#define US5121_PWD "estpwd"
#define US5121_BAD_STORE_LEN 256

#ifndef WIN32
#define US5121_CACERTS "CA/estCA/cacert.crt"
#define US5121_CLIENT_CACERTS "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5121_SERVER_ENHCD_CERT_CACERTS "CA/mfgCAs/sudiCA/cacert.crt"
#define US5121_TRUSTED_CERTS "CA/trustedcerts.crt"
#define US5121_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#define US5121_PROXY_CERTKEY "CA/estCA/private/proxy-certandkey.pem"
#define US5121_CLIENT_CERTKEY "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5121_CA_CNF "CA/estExampleCA.cnf"

#else
#define US5121_CACERTS "CA\\estCA\\cacert.crt"
#define US5121_CLIENT_CACERTS "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5121_SERVER_ENHCD_CERT_CACERTS "CA\\mfgCAs\\sudiCA\\cacert.crt"
#define US5121_TRUSTED_CERTS "CA\\trustedcerts.crt"
#define US5121_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5121_PROXY_CERTKEY "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5121_CLIENT_CERTKEY                                                  \
    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5121_CA_CNF "CA\\estExampleCA.cnf"
#endif

/*
 * Bufffer for representing a bad truststore
 */
static unsigned char est_bad_enhcd_cert_store[US5121_BAD_STORE_LEN] = {
    0x03, 0xca, 0x47, 0x1e, 0xe4, 0x00, 0x67, 0xf1, 0xb2, 0x72, 0x76, 0xa1,
    0x7b, 0xa7, 0x58, 0x7c, 0x0e, 0x06, 0x8f, 0x63, 0xba, 0x6b, 0x90, 0xc7,
    0xd9, 0xd3, 0xbc, 0xa1, 0xda, 0xf1, 0xc9, 0x6c, 0xce, 0x9c, 0x37, 0x22,
    0xeb, 0xb6, 0x53, 0xc6, 0xe2, 0x5a, 0xd2, 0x83, 0x4c, 0x2a, 0xbc, 0x8d,
    0x24, 0x71, 0xf6, 0x58, 0x86, 0x28, 0xda, 0x9d, 0xce, 0x68, 0xc3, 0x80,
    0x1c, 0xc6, 0xb4, 0x49, 0x47, 0xcb, 0xa7, 0xec, 0xc0, 0x32, 0xe3, 0x74,
    0x9c, 0xfa, 0x23, 0x09, 0xa6, 0x01, 0x82, 0x41, 0x9e, 0x04, 0x6d, 0x6d,
    0x49, 0xce, 0x40, 0xf6, 0xd6, 0xa7, 0xd6, 0xa0, 0xc1, 0x2b, 0x47, 0x2f,
    0x59, 0x6e, 0x60, 0xfb, 0xde, 0xd0, 0xef, 0x56, 0x36, 0xcb, 0x38, 0xe8,
    0x1d, 0x98, 0x54, 0x93, 0xa9, 0xb6, 0xea, 0x64, 0x09, 0x27, 0xec, 0x69,
    0x3a, 0xab, 0x46, 0xca, 0x7b, 0x38, 0x08, 0x84, 0xc4, 0xdd, 0x32, 0x37,
    0x6a, 0x40, 0x2a, 0xcd, 0x98, 0xa3, 0xee, 0x0e, 0xbf, 0x4c, 0x1d, 0x6f,
    0xb6, 0xe5, 0x6f, 0x1b, 0x2d, 0x49, 0x96, 0x8d, 0x68, 0xe7, 0x44, 0x3c,
    0xf6, 0xcc, 0xff, 0x81, 0x0a, 0x28, 0x7a, 0xc4, 0x19, 0xa0, 0xb2, 0x23,
    0x41, 0x00, 0xba, 0x24, 0x00, 0x5c, 0x11, 0x70, 0x60, 0xa5, 0x34, 0xc8,
    0x60, 0x3e, 0x6a, 0x23, 0x8a, 0xf1, 0xac, 0x4e, 0xe1, 0x61, 0xdc, 0xc5,
    0xd6, 0x30, 0x80, 0x94, 0xcf, 0x71, 0x55, 0xef, 0xbf, 0x79, 0x70, 0x4e,
    0x19, 0xa9, 0x45, 0xcd, 0x0e, 0x38, 0x52, 0x69, 0xb7, 0xdd, 0xc4, 0xa9,
    0xd3, 0xbe, 0xed, 0xf6, 0x5a, 0x13, 0x31, 0x08, 0xb3, 0xe8, 0x86, 0x32,
    0x8e, 0x1f, 0x32, 0x99, 0x6d, 0x51, 0x8e, 0xae, 0xaa, 0x53, 0x55, 0xd9,
    0xab, 0xb7, 0xfb, 0xef, 0x16, 0x32, 0x88, 0xc7, 0xd5, 0xe7, 0xee, 0x47,
    0x6a, 0x13, 0xca, 0x87};

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int us5121_server_process_http_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
                                           X509 *peer_cert, char *path_seg,
                                           void *app_data)
{
    int user_valid = 0;

    if (path_seg) {
        printf("\n %s: Path segment in the authenticate callback is: %s\n",
               __FUNCTION__, path_seg);
    }

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
        return 0;
    }
    return user_valid;
}

static int us5121_start_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5121_TCP_SERVER_PORT, US5121_SERVER_CERTKEY,
                  US5121_SERVER_CERTKEY, "US5121 test realm", US5121_CACERTS,
                  US5121_TRUSTED_CERTS, US5121_CA_CNF, manual_enroll, 0, nid);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy actging as an RA
     */
    rv = st_proxy_start(US5121_TCP_PROXY_PORT, US5121_PROXY_CERTKEY,
                        US5121_PROXY_CERTKEY, "US5121 test realm",
                        US5121_CACERTS, US5121_TRUSTED_CERTS, "estuser",
                        "estpwd", "127.0.0.1", US5121_TCP_SERVER_PORT, 0, nid);
    return rv;
}

static EVP_PKEY *generate_private_key(void)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey;

    /*
     * create an RSA keypair and assign them to a PKEY and return it.
     */
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, 4096, bn, NULL);

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        printf("\nError allocating PKEY structure for new key pair\n");
        return NULL;
    }
    if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
        printf("\nError assigning RSA key pair to PKEY structure\n");
        return NULL;
    }

    RSA_free(rsa);
    BN_free(bn);

    return (pkey);
}

static int client_manual_cert_verify_US5121(X509 *cur_cert,
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
static int us5121_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5121_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }
    server_enhcd_cert_cacert_len = read_binary_file(
        US5121_SERVER_ENHCD_CERT_CACERTS, &server_enhcd_cert_cacert);
    if (server_enhcd_cert_cacert_len <= 0) {
        return 1;
    }

    if (read_x509_cert_and_key_file(US5121_CLIENT_CERTKEY,
                                    US5121_CLIENT_CERTKEY, &client_enhcd_cert,
                                    &client_enhcd_cert_key)) {
        return 1;
    }
    if (read_x509_cert_and_key_file(US5121_PROXY_CERTKEY, US5121_PROXY_CERTKEY,
                                    &client_non_enhcd_cert,
                                    &client_non_enhcd_cert_key)) {
        return 1;
    }

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5121_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5121_destroy_suite(void)
{
    st_stop();
    st_proxy_stop();
    X509_free(client_enhcd_cert);
    EVP_PKEY_free(client_enhcd_cert_key);
    X509_free(client_non_enhcd_cert);
    EVP_PKEY_free(client_non_enhcd_cert_key);
    free(server_enhcd_cert_cacert);
    free(cacerts);
    return 0;
}

/*
 * This function performs a basic simple enroll using
 * Enhanced Cert Authentication to identify the client to the server.
 */
static void us5121_test1(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_server_set_http_auth_cb(us5121_server_process_http_auth);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        goto end;
    }

    /*
     * Require HTTP Auth on server to use Enhanced Cert Auth mode
     */
    st_set_http_auth_required();

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto end;
    }
    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5121);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password. These credentials
     * should be ignored by the server since we are in Enhanced Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, US5121_UID, US5121_PWD, client_enhcd_cert,
                             client_enhcd_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ecctx, US5121_SERVER_IP, US5121_TCP_SERVER_PORT,
                               NULL);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set the server to connect to\n");
        goto end;
    }

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-1-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
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
        goto end;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-1-2", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to BadPass. This will cause the request
     * to not succeed since the credentials for
     * the authentication callback are set to
     * User: "/CN=127.0.0.1" Pass: "cisco"
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "BadPass",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto cleanup_enhcd_cert_auth;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-1-3", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
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

end:
    if (cert)
        X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ecctx);
}

/*
 * This function performs a basic simple enroll through a proxy using
 * Enhanced Cert Authentication to identify the client to the server.
 */
static void us5121_test2(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5121_server_process_http_auth);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        goto end;
    }

    /*
     * Turn off HTTP Auth requirement on server to allow requests from the proxy
     */
    st_set_http_auth_optional();

    /*
     * Require HTTP Auth on server to use Enhanced Cert Auth mode
     */
    st_proxy_set_http_auth_required();

    /*
     * Enable Enhanced Cert Auth Mode on the EST Proxy
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to require HTTP auth on st_proxy\n");
        goto end;
    }
    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5121);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password. These credentials
     * should be ignored by the server since we are in Enhanced Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, US5121_UID, US5121_PWD, client_enhcd_cert,
                             client_enhcd_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ecctx, US5121_SERVER_IP, US5121_TCP_PROXY_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-2-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
    }
    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto end;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-2-2", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to BadPass. This will cause the request
     * to not succeed since the credentials for
     * the authentication callback are set to
     * User: "127.0.0.1" Pass: "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_commonName, "BadPass",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto end;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-2-3", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
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

end:
    if (cert)
        X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ecctx);
}

/*
 * This function tests the est_server_enable_enhanced_cert_auth and
 * est_server_disable_enhanced_cert_auth API
 *
 * This test attempts to use both the est_server_enable_enhanced_cert_auth
 * and est_server_disable_enhanced_cert_auth API with a NULL EST_CTX pointer
 */
static void us5121_test3(void)
{
    int rv;

    LOG_FUNC_NM;

    /* Enable with NULL CTX and NULL password */
    rv = est_server_enable_enhanced_cert_auth(NULL, NID_commonName, NULL,
                                              ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NO_CTX);
    if (rv != EST_ERR_NO_CTX) {
        printf("Unexpected return with pwd: NULL\n");
    }

    /* Enable with NULL CTX and a blank password */
    rv = est_server_enable_enhanced_cert_auth(NULL, NID_commonName, "",
                                              ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NO_CTX);
    if (rv != EST_ERR_NO_CTX) {
        printf("Unexpected return with pwd: ''\n");
    }

    /* Enable with NULL CTX and a non blank password */
    rv = est_server_enable_enhanced_cert_auth(NULL, NID_commonName, "hello",
                                              ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NO_CTX);
    if (rv != EST_ERR_NO_CTX) {
        printf("Unexpected return with pwd: 'hello'\n");
    }

    /* Enable with NULL CTX */
    rv = est_server_disable_enhanced_cert_auth(NULL);
    CU_ASSERT(rv == EST_ERR_NO_CTX);
    if (rv != EST_ERR_NO_CTX) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
    }
    return;
}

/*
 * This function tests the est_server_enable_enhanced_cert_auth API
 *
 * This test attempts to use the est_server_enable_enhanced_cert_auth API with
 * a bogus Enhanced Cert trust store
 */
static void us5121_test4(void)
{
    int rv;

    LOG_FUNC_NM;

    /* Enable with bogus truststore and NULL password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("cisco", NID_commonName,
                                            est_bad_enhcd_cert_store,
                                            US5121_BAD_STORE_LEN);
    CU_ASSERT(rv == EST_ERR_NO_CERTS_FOUND);
    if (rv != EST_ERR_NO_CERTS_FOUND) {
        printf("Unexpected return with pwd: NULL\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /* Enable with bugus truststore and a blank password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "", ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("cisco", NID_commonName,
                                            est_bad_enhcd_cert_store,
                                            US5121_BAD_STORE_LEN);
    CU_ASSERT(rv == EST_ERR_NO_CERTS_FOUND);
    if (rv != EST_ERR_NO_CERTS_FOUND) {
        printf("Unexpected return with pwd: ''\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /* Enable with bogus truststore and a non blank password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "hello",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("cisco", NID_commonName,
                                            est_bad_enhcd_cert_store,
                                            US5121_BAD_STORE_LEN);
    CU_ASSERT(rv == EST_ERR_NO_CERTS_FOUND);
    if (rv != EST_ERR_NO_CERTS_FOUND) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    return;
}

/*
 * This function tests the use of Enhanced Cert Auth during a simple
 * enroll request to an est server
 *
 * This test attempts to perform a simple enroll using a valid
 * non-manufacturer certificate.  This simple enroll request will fail since
 * the proxy will attempt to use the serialNumber subject line field and fail
 * since there is none in the cert.
 */
static void us5121_test5(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_server_set_http_auth_cb(us5121_server_process_http_auth);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        goto end;
    }

    /*
     * Require HTTP Auth on server to use Enhanced Cert Auth mode
     */
    st_set_http_auth_required();

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
        goto end;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to add cisco manufacturer\n");
        goto end;
    }
    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5121);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password. These credentials
     * should be ignored by the server since we are in Enhanced Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, US5121_UID, US5121_PWD,
                             client_non_enhcd_cert, client_non_enhcd_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ecctx, US5121_SERVER_IP, US5121_TCP_SERVER_PORT,
                               NULL);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set the server to connect to\n");
        goto end;
    }

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-5-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
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
        goto end;
    }
    rv = st_enhanced_cert_auth_add_mfg_info("cisco", NID_commonName,
                                            server_enhcd_cert_cacert,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to add cisco manufacturer\n");
        goto end;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-5-2", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
        goto cleanup_enhcd_cert_auth;
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

end:
    EVP_PKEY_free(key);
    est_destroy(ecctx);
}

/*
 * This function tests the use of Enhanced Cert Auth during a simple
 * enroll request through an est proxy
 *
 * This test attempts to use perform a simple enroll using a valid
 * non-manufacturer certificate. This simple enroll request will fail since
 * the proxy will attempt to use the serialNumber subject line field and fail
 * since there is none in the cert.
 */
static void us5121_test6(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Set HTTP Authentication Callback function to verify
     * Enhanced Cert Auth Credentials
     */
    rv = st_proxy_set_http_auth_cb(us5121_server_process_http_auth);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
        goto end;
    }

    /*
     * Turn off HTTP Auth requirement on server to allow requests from the proxy
     */
    st_set_http_auth_optional();

    /*
     * Require HTTP Auth on server to use Enhanced Cert Auth mode
     */
    st_proxy_set_http_auth_required();

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to NULL meaning
     * that it will be set to the default password "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, NULL,
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto end;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to add cisco manufacturer\n");
        goto end;
    }
    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5121);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password. These credentials
     * should be ignored by the server since we are in Enhanced Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, US5121_UID, US5121_PWD,
                             client_non_enhcd_cert, client_non_enhcd_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ecctx, US5121_SERVER_IP, US5121_TCP_PROXY_PORT,
                               NULL);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set the server to connect to\n");
        goto end;
    }

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-5-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
        goto cleanup_enhcd_cert_auth;
    }

    /*
     * Disable Enhanced Cert Auth Mode on the Server
     */
    rv = st_proxy_disable_enhcd_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to disable Enhanced Cert Auth mode\n");
        goto end;
    }

    /*
     * Enable Enhanced Cert Auth Mode on the Server
     * This enable sets the password to "cisco"
     */
    rv = st_proxy_enable_enhcd_cert_auth(NID_serialNumber, "cisco",
                                         ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to enable Enhanced Cert Auth mode\n");
        goto end;
    }
    rv = st_proxy_enhcd_cert_auth_add_mfg_info("cisco", NID_commonName,
                                               server_enhcd_cert_cacert,
                                               server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to add cisco manufacturer\n");
        goto end;
    }
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5121-5-2", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);
    if (rv != EST_ERR_AUTH_FAIL) {
        printf("Unexpected result from simple enroll\n");
        goto cleanup_enhcd_cert_auth;
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

end:
    EVP_PKEY_free(key);
    est_destroy(ecctx);
}

/*
 * This function tests the est_server_enable_enhanced_cert_auth API
 *
 * This test attempts to use the est_server_enable_enhanced_cert_auth
 * with a NULL manufacturer truststore with a non-zero length
 */
static void us5121_test9(void)
{
    int rv;

    LOG_FUNC_NM;

    /* Enable with NULL truststore, non-zero buffer len, and NULL password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName, NULL,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: NULL\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /* Enable with NULL truststore, non-zero buffer len, and a blank password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "", ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName, NULL,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: ''\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enable with NULL truststore, non-zero buffer len, and a non blank
     * password
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "hello",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName, NULL,
                                            server_enhcd_cert_cacert_len);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);
    return;
}

/*
 * This function tests the est_server_enable_enhanced_cert_auth API
 *
 * This test attempts to use the est_server_enable_enhanced_cert_auth API with
 * a valid manufacturer trust store with the length of the trustore being 0
 */
static void us5121_test10(void)
{
    int rv;

    LOG_FUNC_NM;

    /* Enable with truststore, zero buffer len, and NULL password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, NULL, ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert, 0);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: NULL\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /* Enable with a truststore, zero buffer len, and a blank password */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "", ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert, 0);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: ''\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enable with truststore, zero buffer len, and a non blank
     * password
     */
    rv = st_enable_enhanced_cert_auth(NID_commonName, "hello",
                                      ECA_CSR_CHECK_OFF);
    CU_ASSERT(rv == EST_ERR_NONE);
    rv = st_enhanced_cert_auth_add_mfg_info("Cisco", NID_commonName,
                                            server_enhcd_cert_cacert, 0);
    CU_ASSERT(rv == EST_ERR_INVALID_PARAMETERS);
    if (rv != EST_ERR_INVALID_PARAMETERS) {
        printf("Unexpected return with pwd: 'hello'\n");
    }
    rv = st_disable_enhanced_cert_auth();
    CU_ASSERT(rv == EST_ERR_NONE);

    return;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5121_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5121_enhanced_cert_auth_mode", us5121_init_suite,
                          us5121_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "Server Enhanced Cert Auth On", us5121_test1))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "Proxy Enhanced Cert Auth On", us5121_test2))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "Enhcd Cert Auth API NULL EST_CTX",
                             us5121_test3))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "Bogus Enhcd Cert Auth truststore",
                             us5121_test4))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "Non-Mfg Cert Auth cert Server", us5121_test5))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "Non-Mfg Cert Auth cert Proxy", us5121_test6))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "NULL Manufacturer truststore", us5121_test9))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL ==
         CU_add_test(pSuite, "0 Len Manufacturer truststore", us5121_test10))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}
