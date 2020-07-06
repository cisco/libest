/*------------------------------------------------------------------
 * us893.c - Unit Tests for User Story 893 - proxy reenroll
 *
 * October, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
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

#define US893_TCP_SERVER_PORT       29893
#define US893_TCP_PROXY_PORT        29093

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US893_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US893_PKCS10_CORRUPT "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDfffmdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US893_SERVER_IP         "127.0.0.1" 
#define US893_REENROLL_URL_BA   "https://127.0.0.1:29093/.well-known/est/simplereenroll"
#define US893_PKCS10_CT         "Content-Type: application/pkcs10" 
#define US893_UIDPWD_GOOD       "estuser:estpwd"
#define US893_UID               "estuser"
#define US893_PWD               "estpwd"
#ifndef WIN32
#define US893_CACERTS           "CA/estCA/cacert.crt"
#define US893_TRUSTED_CERTS     "CA/trustedcerts.crt"
#define US893_SERVER_CERTKEY    "CA/estCA/private/estservercertandkey.pem"
#define US893_PROXY_CERT        "US893/cert.pem"
#define US893_PROXY_KEY         "US893/key.pem"
#define US893_UNTRUSTED_CERT    "US893/cert-untrusted.pem"
#define US893_UNTRUSTED_KEY     "US893/key-untrusted.pem"
#define US893_EXPIRED_KEY       "US893/key-expired.pem"
#define US893_EXPIRED_CERT      "US893/cert-expired.pem"

#define US893_TC2_CERT_TXT      "US893/tc2-new-cert.txt"
#define US893_TC2_CERT_B64      "US893/tc2-new-cert.pkcs7b64"
#define US893_TC2_CERT_PK7      "US893/tc2-new-cert.pkcs7"
#define US893_TC2_CERT_PEM      "US893/tc2-new-cert.pem"
#else
#define US893_CACERTS           "CA\\estCA\\cacert.crt"
#define US893_TRUSTED_CERTS     "CA\\trustedcerts.crt"
#define US893_SERVER_CERTKEY    "CA\\estCA\\private\\estservercertandkey.pem"
#define US893_PROXY_CERT        "US893\\cert.pem"
#define US893_PROXY_KEY         "US893\\key.pem"
#define US893_UNTRUSTED_CERT    "US893\\cert-untrusted.pem"
#define US893_UNTRUSTED_KEY     "US893\\key-untrusted.pem"
#define US893_EXPIRED_KEY       "US893\\key-expired.pem"
#define US893_EXPIRED_CERT      "US893\\cert-expired.pem"

#define US893_TC2_CERT_TXT      "US893\\tc2-new-cert.txt"
#define US893_TC2_CERT_B64      "US893\\tc2-new-cert.pkcs7b64"
#define US893_TC2_CERT_PK7      "US893\\tc2-new-cert.pkcs7"
#define US893_TC2_CERT_PEM      "US893\\tc2-new-cert.pem"
#endif

static void us893_clean (void)
{
    char cmd[200];

    /*
     * These are all temporary files created
     * by the various test cases.
     */
#ifndef WIN32
    sprintf(cmd, "rm %s", US893_TC2_CERT_TXT);
    system(cmd);
    sprintf(cmd, "rm %s", US893_TC2_CERT_B64);
    system(cmd);
    sprintf(cmd, "rm %s", US893_TC2_CERT_PK7);
    system(cmd);
    sprintf(cmd, "rm %s", US893_TC2_CERT_PEM);
    system(cmd);
#else
    sprintf(cmd, "del %s", US893_TC2_CERT_TXT);
    system(cmd);
    sprintf(cmd, "del %s", US893_TC2_CERT_B64);
    system(cmd);
    sprintf(cmd, "del %s", US893_TC2_CERT_PK7);
    system(cmd);
    sprintf(cmd, "del %s", US893_TC2_CERT_PEM);
    system(cmd);
#endif
}

static int us893_start_server (int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US893_TCP_SERVER_PORT,
                  US893_SERVER_CERTKEY,
                  US893_SERVER_CERTKEY,
                  "US893 test realm",
                  US893_CACERTS,
                  US893_TRUSTED_CERTS,
                  "US893/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy acting as an RA
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us893_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US893_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us893_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us893_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us893_destory_suite (void)
{
    st_stop();
    st_proxy_stop();
    free(cacerts);
    return 0;
}

/*
 * Simple reenroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * reenroll of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us893_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
    US893_PKCS10_RSA2048,
    US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test case uses an existing expired cert and
 * attempts to re-enroll it.  The expired certs contains
 * several X509 extensions. We verify the new issued
 * cert preserves these extensions using grep.  Note,
 * preserving these extensions requires the OpenSSL CA
 * to enable the "copy_extensions" knob in the OpenSSL
 * config file.  This is why this test suite uses a
 * unique copy of estExampleCA.cnf.
 */
static void us893_test2 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    BIO *in;
    char cmd[200];
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
    rv = est_client_set_auth(ectx, US893_UID, US893_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US893_SERVER_IP, US893_TCP_PROXY_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US893_EXPIRED_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US893_EXPIRED_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in)
        return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert)
        return;
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Save the cert to a local file
     */
    rv = write_binary_file(US893_TC2_CERT_B64, new_cert, pkcs7_len);
    CU_ASSERT(rv == 1);

    /*
     * Base 64 decode the cert response
     */
    sprintf(cmd, "openssl base64 -d -in %s -out %s", US893_TC2_CERT_B64,
    US893_TC2_CERT_PK7);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Convert the pkcs7 cert to a PEM cert
     */
    sprintf(cmd, "openssl pkcs7 -in %s -inform DER -print_certs -out %s",
    US893_TC2_CERT_PK7,
    US893_TC2_CERT_PEM);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Convert PEM cert to a textual representation of the cert
     */
    sprintf(cmd, "openssl x509 -text -in %s > %s", US893_TC2_CERT_PEM,
    US893_TC2_CERT_TXT);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Verify the jimbob DNS extension was preserved
     */
    rv = grep(US893_TC2_CERT_TXT, "jimbob");
    CU_ASSERT(rv == 0);

    /*
     * Verify the bobcat DNS extension was preserved
     */
    rv = grep(US893_TC2_CERT_TXT, "bobcat");
    CU_ASSERT(rv == 0);

    /*
     * Verify the IP address extension was preserved
     */
    rv = grep(US893_TC2_CERT_TXT, "172");
    CU_ASSERT(rv == 0);

    /*
     * Verify the Repudiation key usage extension was preserved
     */
    rv = grep(US893_TC2_CERT_TXT, "Repudiation");
    CU_ASSERT(rv == 0);

    /*
     * Verify the public key was preserved
     */
    rv = grep(US893_TC2_CERT_TXT,
        "00:e3:ca:38:65:fb:9c:46:a6:22:b1:be:17:bc:50");
    CU_ASSERT(rv == 0);

    /*
     * Clean up
     */
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

/*
 * Simple reenroll - Corrupt CSR
 *
 * Use libcurl to send a reenroll request containing
 * a corrupted CSR.
 */
static void us893_test3 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
    US893_PKCS10_CORRUPT,
    US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a bad CSR,
     * we expect the server to respond with 400
     */
    CU_ASSERT(rv == 400);
}

/*
 * This test attempts to re-enroll an expired cert
 * while the EST server is configured for manual
 * approval.  The server will send back a retry-after
 * response.  This verifies the proxy propagates the
 * retry-after response to the client.
 */
static void us893_test4 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    int retry_val = 0;
    time_t time_val;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM
    ;

    /*
     * Stop the server.
     */
    st_stop();
    st_proxy_stop();

    /*
     * Restart the server with manual approval enabled
     */
    rv = us893_start_server(1, 0);
    CU_ASSERT(rv == 0);

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US893_UID, US893_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US893_SERVER_IP, US893_TCP_PROXY_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US893_EXPIRED_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US893_EXPIRED_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in)
        return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert)
        return;
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_CA_ENROLL_RETRY);

    /*
     * The server should be configured with a retry-after
     * value of 3600 seconds, which is the default.
     */
    rv = est_client_copy_retry_after(ectx, &retry_val, &time_val);
    CU_ASSERT(rv == EST_ERR_NONE);
    CU_ASSERT(retry_val == 3600);

    /*
     * Clean up
     */
    est_destroy(ectx);

    /*
     * Stop the server.
     */
    st_stop();
    st_proxy_stop();

    /*
     * Restart the server with manual approval disabled
     */
    rv = us893_start_server(0, 0);
    CU_ASSERT(rv == 0);
}

/*
 * This test attempts to re-enroll an expired cert
 * while the EST server is configured with PoP
 * enabled, but the proxy server is using a cert
 * that doesn't contain id-kp-cmcRA.  This should
 * result in a failure.
 */
static void us893_test5 (void)
{
    int rv;

    LOG_FUNC_NM
    ;

    /*
     * Make sure PoP is enabled on the server
     */
    st_enable_pop();

    /*
     * Stop the proxy server so we can restart
     * it using a different identity cert.
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_SERVER_CERTKEY,
                        US893_SERVER_CERTKEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * Use libcurl to send an enroll request.  We use libcurl
     * because it will not include the PoP.
     */
    rv = curl_http_post(US893_REENROLL_URL_BA,
                        US893_PKCS10_CT,
                        US893_PKCS10_RSA2048,
                        US893_UIDPWD_GOOD,
                        US893_CACERTS,
                        CURLAUTH_BASIC,
                        NULL,
                        NULL,
                        NULL);
    /*
     * The PoP check should fail
     */
    CU_ASSERT(rv == 401);

    /*
     * Stop the proxy server
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser", "estpwd", "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);
}

/*
 * This test attempts to re-enroll an expired cert
 * while the EST server is configured with PoP
 * disabled, but the proxy server is using a cert
 * that doesn't contain id-kp-cmcRA.  This should
 * result in a successful reenroll.
 */
static void us893_test6 (void)
{
    int rv;

    LOG_FUNC_NM
    ;

    /*
     * Make sure PoP is disabled on the server
     */
    st_disable_pop();

    /*
     * Stop the proxy server so we can restart
     * it using a different identity cert.
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_SERVER_CERTKEY,
                        US893_SERVER_CERTKEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * Use libcurl to send an enroll request.  We use libcurl
     * because it will not include the PoP.
     */
    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
    US893_PKCS10_RSA2048,
    US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * The reenroll should work since PoP is not enabled anywhere.
     */
    CU_ASSERT(rv == 200);

    /*
     * Stop the proxy server
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * Re-enable PoP on the server for the forthcoming test cases.
     */
    st_enable_pop();
}

/*
 * This test attempts to re-enroll an expired cert
 * while the EST server is configured with PoP
 * disabled, but the proxy server is using a cert
 * that doesn't contain id-kp-cmcRA.  The CSR will
 * contain the PoP, which forces it to be checked.
 * This should result in a failure since the RA
 * cert doesn't contain id-kp-cmcRA.
 */
//The following include should never be used by an application
//be we use it here to hack the EST_CTX values mid-way
//through this test
#include "../../src/est/est_locl.h"
static void us893_test7 (void)
{
    int rv;
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM
    ;

    /*
     * Make sure PoP is disabled on the server
     */
    st_disable_pop();

    /*
     * Stop the proxy server so we can restart
     * it using a different identity cert.
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_SERVER_CERTKEY,
                        US893_SERVER_CERTKEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US893_UID, US893_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US893_SERVER_IP, US893_TCP_PROXY_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US893_EXPIRED_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US893_EXPIRED_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in)
        return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert)
        return;
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    ectx->csr_pop_required = 1; //This is a hack for testing only, do not attempt this 
    //We need to force the challengePassword into the CSR
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);

    /*
     * Stop the proxy server
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * Re-enable PoP on the server for the forthcoming test cases.
     */
    st_enable_pop();

    est_destroy(ectx);
}

/*
 * This test case uses an existing expired cert and
 * attempts to re-enroll it.  PoP is disabled on
 * the EST server.
 */
static void us893_test8 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    X509 *cert = NULL;
    int rv;
    int pkcs7_len = 0;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM
    ;

    /*
     * Make sure PoP is disabled on the server
     */
    st_disable_pop();

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US893_UID, US893_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US893_SERVER_IP, US893_TCP_PROXY_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US893_EXPIRED_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US893_EXPIRED_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in)
        return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert)
        return;
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    est_destroy(ectx);

    /*
     * Re-enable PoP on the server for the forthcoming test cases.
     */
    st_enable_pop();
}

/*
 * This test case uses an existing expired cert and
 * attempts to re-enroll it.  PoP is disabled on
 * the EST server.  The CSR does not contain a PoP.
 */
static void us893_test9 (void)
{
    int rv;

    LOG_FUNC_NM
    ;

    /*
     * Make sure PoP is disabled on the server
     */
    st_disable_pop();

    /*
     * Use libcurl to send an enroll request.  We use libcurl
     * because it will not include the PoP.
     */
    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
                        US893_PKCS10_RSA2048,
                        US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * The reenroll should work since PoP is not enabled anywhere.
     */
    CU_ASSERT(rv == 200);

    /*
     * Re-enable PoP on the server for the forthcoming test cases.
     */
    st_enable_pop();
}

/*
 * This test case uses a bad password configured on
 * the EST proxy context.  This should cause the EST
 * server to reject the reenroll request.
 */
static void us893_test10 (void)
{
    int rv;

    LOG_FUNC_NM
    ;

    /*
     * Stop the proxy server so we can restart
     * it using a different identity cert.
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "bogus",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
                        US893_PKCS10_RSA2048,
                        US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    CU_ASSERT(rv == 401);


    /*
     * Stop the proxy server
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);
}

static void us893_test11 (void)
{
    int rv;
    long http_code = 0;
    CURL *hnd;
    struct curl_slist *slist1;

    LOG_FUNC_NM
    ;

    /*
     * Stop the proxy server so we can restart
     * it using a different identity cert.
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using an untrusted cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_UNTRUSTED_CERT,
                        US893_UNTRUSTED_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);

    /*
     * We don't use the normal curl util API here because
     * we need to disable TLS peer verification for this
     * special test case.
     */
    /*
     * Set the Content-Type header in the HTTP request
     */
    slist1 = NULL;
    slist1 = curl_slist_append(slist1, US893_PKCS10_CT);

    /*
     * Setup all the other fields that CURL requires
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, US893_REENROLL_URL_BA);
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERPWD, US893_UIDPWD_GOOD);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, US893_PKCS10_RSA2048);
    curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(US893_PKCS10_RSA2048));
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.27.0");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(hnd, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(hnd, CURLOPT_CAINFO, US893_CACERTS);
    curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(hnd, CURLOPT_FORBID_REUSE, 1L);

    /*
     * Issue the HTTP request
     */
    curl_easy_perform(hnd);

    /*
     * Get the HTTP response status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(hnd);
    hnd = NULL;
    curl_slist_free_all(slist1);
    slist1 = NULL;
    /* Set up  */
    CU_ASSERT(http_code == 502);

    /*
     * Stop the proxy server
     */
    st_proxy_stop();

    /*
     * Restart the proxy server using the other cert
     */
    rv = st_proxy_start(US893_TCP_PROXY_PORT,
                        US893_PROXY_CERT,
                        US893_PROXY_KEY,
                        "US893 test realm",
                        US893_CACERTS,
                        US893_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US893_TCP_SERVER_PORT,
                        0,
                        0);
    CU_ASSERT(rv == 0);
}

/*
 * Simple reenroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * reenroll of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.  However, PoP is now
 * enabled on the proxy, which should cause a
 * failure since libcurl doesn't include the PoP.
 */
static void us893_test12 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_proxy_enable_pop();

    rv = curl_http_post(US893_REENROLL_URL_BA, US893_PKCS10_CT,
                        US893_PKCS10_RSA2048,
                        US893_UIDPWD_GOOD, US893_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Should fail since the proxy will fail the PoP check
     */
    CU_ASSERT(rv == 401);

    st_proxy_disable_pop();
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us893_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us893_proxy_simpreenroll",
                           us893_init_suite,
                           us893_destory_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "ReEnroll RSA cert", us893_test1)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll expired cert", us893_test2)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll corrupt CSR", us893_test3)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll expired cert with retry-after", us893_test4)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll no proxy id-kp-cmcRA with srv PoP", us893_test5)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll no proxy id-kp-cmcRA w/o srv PoP", us893_test6)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll no proxy id-kp-cmcRA w/o srv PoP CSR PoP", us893_test7)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll expired cert w/o srv PoP CSR PoP", us893_test8)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll expired cert w/o srv PoP no CSR PoP", us893_test9)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll proxy misconfigured HTTP auth", us893_test10)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll proxy untrusted identity cert", us893_test11)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll PoP enabled proxy no CSR PoP", us893_test12)))
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

