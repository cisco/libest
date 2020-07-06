/*------------------------------------------------------------------
 * us4880.c - Unit Tests for User Story 4880 - proxy server-side keygen
 *
 * January 2018
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
#include "st_proxy.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US4880_TCP_SERVER_PORT       24880
#define US4880_TCP_PROXY_PORT        24881

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US4880_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US4880_PKCS10_CORRUPT "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDfffmdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US4880_SERVER_IP         "127.0.0.1" 
#define US4880_KEYGEN_URL_BA     "https://127.0.0.1:24881/.well-known/est/serverkeygen"
#define US4880_PKCS10_CT         "Content-Type: application/pkcs10" 
#define US4880_UIDPWD_GOOD       "estuser:estpwd"
#define US4880_UID               "estuser"
#define US4880_PWD               "estpwd"
#ifndef WIN32
#define US4880_CACERTS           "CA/estCA/cacert.crt"
#define US4880_TRUSTED_CERTS     "CA/trustedcerts.crt"
#define US4880_SERVER_CERTKEY    "CA/estCA/private/estservercertandkey.pem"
#define US4880_PROXY_CERT        "US4880/cert.pem"
#define US4880_PROXY_KEY         "US4880/key.pem"

#define US4880_TC2_CERT_B64      "US4880/tc2-new-cert.pkcs7b64"
#define US4880_TC2_KEY_B64      "US4880/tc2-new-key.keyb64"

#else
#define US4880_CACERTS           "CA\\estCA\\cacert.crt"
#define US4880_TRUSTED_CERTS     "CA\\trustedcerts.crt"
#define US4880_SERVER_CERTKEY    "CA\\estCA\\private\\estservercertandkey.pem"
#define US4880_PROXY_CERT        "US4880\\cert.pem"
#define US4880_PROXY_KEY         "US4880\\key.pem"

#define US4880_TC2_CERT_B64      "US4880\\tc2-new-cert.pkcs7b64"
#define US4880_TC2_KEY_B64      "US4880\\tc2-new-key.keyb64"
#endif

static void us4880_clean (void)
{
    char cmd[200];

    /*
     * These are all temporary files created
     * by the various test cases.
     */
#ifndef WIN32
    sprintf(cmd, "rm %s", US4880_TC2_KEY_B64);
    system(cmd);
    sprintf(cmd, "rm %s", US4880_TC2_CERT_B64);
    system(cmd);
#else
    sprintf(cmd, "del %s", US4880_TC2_KEY_B64);
    system(cmd);
    sprintf(cmd, "del %s", US4880_TC2_CERT_B64);
    system(cmd);
#endif
}

static int us4880_start_server (int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US4880_TCP_SERVER_PORT,
                  US4880_SERVER_CERTKEY,
                  US4880_SERVER_CERTKEY,
                  "US4880 test realm",
                  US4880_CACERTS,
                  US4880_TRUSTED_CERTS,
                  "US4880/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy actging as an RA
     */
    rv = st_proxy_start(US4880_TCP_PROXY_PORT,
                        US4880_PROXY_CERT,
                        US4880_PROXY_KEY,
                        "US4880 test realm",
                        US4880_CACERTS,
                        US4880_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US4880_TCP_SERVER_PORT,
                        0,
                        nid);
    return rv;
}

static EVP_PKEY * generate_private_key (void)
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
    if (pkey==NULL) {
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

static int populate_x509_csr (X509_REQ *req, EVP_PKEY *pkey, char *cn)
{
    X509_NAME *subj;

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L)) {
        printf("\nUnable to set X509 version#\n");
        return (-1);
    }

    /*
     * Add Common Name entry
     */
    subj = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                    (unsigned char*)cn, -1, -1, 0)) {
        printf("\nUnable to create X509 Common Name entry\n");
        return (-1);
    }

    /*
     * Set the public key on the request
     */
    if (!X509_REQ_set_pubkey(req, pkey)) {
        printf("\nUnable to set X509 public key\n");
        return (-1);
    }

    return (0);
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us4880_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US4880_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us4880_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us4880_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us4880_destory_suite (void)
{
    st_stop();
    st_proxy_stop();
    free(cacerts);
    return 0;
}

/*
 * Server keygen simple enrollment - RSA 2048
 *
 * This test case uses libcurl to test server side key
 * generation enrollment of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us4880_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US4880_KEYGEN_URL_BA, US4880_PKCS10_CT,
    US4880_PKCS10_RSA2048,
    US4880_UIDPWD_GOOD, US4880_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test case verifies that server-side key generation
 * enrollment works in proxy mode using the common name
 * method of enrolling.
 */
static void us4880_test2 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int key_len;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL, *new_key = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM
    ;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US4880_UID, US4880_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4880_SERVER_IP, US4880_TCP_PROXY_PORT, NULL);

    /*
     * Generate a key to use
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll using common name
    */
    rv = est_client_server_keygen_enroll(ectx, "us4880_test2", &pkcs7_len, &key_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);

        new_key = malloc(key_len);
        rv = est_client_copy_server_generated_key(ectx, new_key);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Save the cert to a local file
     */
    rv = write_binary_file(US4880_TC2_CERT_B64, new_cert, pkcs7_len);
    CU_ASSERT(rv == 1);

    /*
     * Save the key to a local file
     */
    rv = write_binary_file(US4880_TC2_KEY_B64, new_key, key_len);
    CU_ASSERT(rv == 1);

    /*
     * Clean up
     */
    if (new_cert) {
        free(new_cert);
    }
    if (new_key) {
        free(new_key);
    }
    est_destroy(ectx);
}

/*
 * This test case verifies that server-side key generation
 * enrollment works in proxy mode using the csr
 * method of enrolling.
 */
static void us4880_test3 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int key_len;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL, *new_key = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;
    X509_REQ *csr;

    LOG_FUNC_NM
            ;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US4880_UID, US4880_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4880_SERVER_IP, US4880_TCP_PROXY_PORT, NULL);

    /*
     * Generate a key to use
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Generate a new CSR
     */
    csr = X509_REQ_new();
    CU_ASSERT(csr != NULL);
    rv = populate_x509_csr(csr, key, "US4752-TC5");
    CU_ASSERT(csr != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll using CSR
     */
    rv = est_client_server_keygen_enroll_csr (ectx, csr, &pkcs7_len, &key_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);

        new_key = malloc(key_len);
        rv = est_client_copy_server_generated_key(ectx, new_key);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Save the cert to a local file
     */
    rv = write_binary_file(US4880_TC2_CERT_B64, new_cert, pkcs7_len);
    CU_ASSERT(rv == 1);

    /*
     * Save the key to a local file
     */
    rv = write_binary_file(US4880_TC2_KEY_B64, new_key, key_len);
    CU_ASSERT(rv == 1);

    /*
     * Clean up
     */
    if (new_cert) {
        free(new_cert);
    }
    if (new_key) {
        free(new_key);
    }
    est_destroy(ectx);
}

/*
 * This test attempts to do a server keygen enroll CSR with
 * a NULL CSR - this should fail.
 */
static void us4880_test4 (void) {
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0, pkcs8_len = 0;

    LOG_FUNC_NM;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US4880_UID, US4880_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4880_SERVER_IP, US4880_TCP_PROXY_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the alternate API to enroll a null CSR
     */
    rv = est_client_server_keygen_enroll_csr(ectx, NULL, &pkcs7_len, &pkcs8_len, key);
    CU_ASSERT(rv == EST_ERR_NO_CSR);

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    est_destroy(ectx);
}

/*
 * This test attempts to do a server keygen enroll simple
 * (using common name) with a NULL CN - this should fail.
 */
static void us4880_test5 (void) {
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0, pkcs8_len = 0;

    LOG_FUNC_NM;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US4880_UID, US4880_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4880_SERVER_IP, US4880_TCP_PROXY_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the alternate API to enroll a null CSR
     */
    rv = est_client_server_keygen_enroll(ectx, NULL, &pkcs7_len, &pkcs8_len, key);
    CU_ASSERT(rv == EST_ERR_X509_CN);

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    est_destroy(ectx);
}

/*
 * This test attempts to do a server keygen enroll simple
 * (using common name) with a NULL key - this should fail.
 */
static void us4880_test6 (void) {
    EST_CTX *ectx;
    int rv;
    int pkcs7_len = 0, pkcs8_len = 0;

    LOG_FUNC_NM;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US4880_UID, US4880_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4880_SERVER_IP, US4880_TCP_PROXY_PORT, NULL);

    /*
     * Use the alternate API to enroll a null CSR
     */
    rv = est_client_server_keygen_enroll(ectx, NULL, &pkcs7_len, &pkcs8_len, NULL);
    CU_ASSERT(rv == EST_ERR_NO_KEY);

    /*
     * Cleanup
     */
    est_destroy(ectx);
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us4880_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us4880_proxy_serverkeygen",
                           us4880_init_suite,
                           us4880_destory_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "Server keygen enroll RSA cert", us4880_test1)) ||
        (NULL == CU_add_test(pSuite, "Server keygen simple enroll (CN)", us4880_test2)) ||
        (NULL == CU_add_test(pSuite, "Server keygen enroll (CSR)", us4880_test3)) ||
        (NULL == CU_add_test(pSuite, "Server keygen enroll (CSR - NULL)", us4880_test4)) ||
        (NULL == CU_add_test(pSuite, "Server keygen enroll (CN - NULL)", us4880_test5)) ||
        (NULL == CU_add_test(pSuite, "Server keygen enroll (NULL key)", us4880_test6))
        )
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

