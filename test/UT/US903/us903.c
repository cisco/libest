/*------------------------------------------------------------------
 * us903.c - Unit Tests for User Story 903 - Server simple enroll
 *
 * August, 2013
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
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#ifndef WIN32
static char test5_outfile[FILENAME_MAX] = "US903/test5.hdr";
#define US903_CACERTS       "CA/estCA/cacert.crt"
#define US903_EXPLICIT_CERT "US903/cert-RA.pem" 
#define US903_EXPLICIT_KEY  "US903/key-RA.pem"
#define US903_CACERTS       "CA/estCA/cacert.crt"
#define US903_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US903_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#else
static char test5_outfile[FILENAME_MAX] = "US903\\test5.hdr";
#define US903_CACERTS       "CA\\estCA\\cacert.crt"
#define US903_EXPLICIT_CERT "US903\\cert-RA.pem" 
#define US903_EXPLICIT_KEY  "US903\\key-RA.pem"
#define US903_CACERTS       "CA\\estCA\\cacert.crt"
#define US903_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US903_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US903_RETRY_INTERVAL    3600
#define US903_TCP_PORT      29001

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US903_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the ec.req file:
 *
 * openssl req -newkey ec:256parms -keyout eckey.pem -keyform PEM -out ec.req -outform PEM
 */
#define US903_PKCS10_DSA1024 "MIICfjCCAj0CAQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEzARBgNVBAoMCkRTQUNvbXBhbnkxDzANBgNVBAsMBkRTQW9yZzEQMA4G\nA1UEAwwHZHNhIGRvZTEaMBgGCSqGSIb3DQEJARYLZHNhQGRvZS5jb20wggG2MIIB\nKwYHKoZIzjgEATCCAR4CgYEAqIfbyk7rEAaULIPB1GcHHc0ctx6g0dhBfdUdOPNG\nBSE+TP5UF5lw8Qm6oCXstU3nYEJalmMvkjFwbgvBws8aJBnj09dDDn8spKEGcG0M\nZpqdMys6+b4QJjq5YAxEaATVY/1L/rBgGGm1EFDhc/6Ezm2T3CGeQklwo5aBZQCc\naIsCFQDC1olBFuE+phOhjXAwEE5EPJkRJwKBgD+vZ+tLCTjBzVFNjAO8X/SMamwW\noraNfdyZ+ZCEAmYI/D4838nCGAjVRQyDb1q5akkLyxoJX1YV7gNbaBNUys3waqdu\nso1HtuEur2cbhU5iOeKBWpj6MIWlPdD3uCRu4uiBF9XBiANaRID8CT2kchhwy4Ok\nFfQMuYOz4eBhMQqmA4GEAAKBgDuwR7H3U4CfuQjWeTtrI50M1TxhlVZ3TonRtVIx\nEHpuXxAouxATVkthJtaCBKc0EHii1bE/kgNUgGX/ZdFjBUb/XfpkYsRT3QRLF0+s\nPZGY/0TovO9pKjqiw0C10leNKFbEVdlXYtAkjXUbHmyNog3195/t7oKXHMT1A/5p\nhUCRoAAwCQYHKoZIzjgEAwMwADAtAhUAhPCqQG3gKUUPKdwBNCmZfzWDqjsCFAh0\nzn9HujlXNaTA1OhjmPmcJSxT"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the dsa.req file:
 *
 * openssl req -newkey dsa:dsaparms -keyout dsakey.pem -keyform PEM -out dsa.req -outform PEM
 */
#define US903_PKCS10_ECDSA256 "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ29yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

#define US903_PKCS10_CORRUPT "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ39yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

/*
 * The following is a valid CSR that already contains a PoP
 * challengePassword.  This was collected using estserver with
 * the dumpbin() function.  This CSR should never work since
 * the PoP value in it will be stale.
 */
#define US903_PKCS10_STALE_POP "MIIBcjCB3AIBADARMQ8wDQYDVQQDEwZURVNUQ04wgZ8wDQYJKoZIhvcNAQEBBQAD\ngY0AMIGJAoGBAPDHvrkVB3+rFHl+KuIsrZGixldRYRD50S2vFs8mW5wWVxDS3xFR\nzcKtqg7JUyW8NYOFNWX0ozhCe87XP2h7tUpHyHlL/8N/84zuMtAtKTLU3Bjgq1xg\nuu8a1ht10wiy8u2r/uEKMhQwpvt56UY5pHzuqmqlO0qlmE+M58WN49IhAgMBAAGg\nIjAgBgkqhkiG9w0BCQcxExYRUjdGN1ZUNUwyd2VueWtMcAowDQYJKoZIhvcNAQEF\nBQADgYEAyenrskmfRIXcpeKBvL3VnW5N4HcLTwI9Hcbr744SWFQaw/R+ru+UXd2j\n99AGBr/GvTkTghINWg2C7vzGF/zhIuG6Ok9FtiMnNr9hZ+5SLYhfSFJbuIv65rWH\nvfLR9N9M2Q9jlf7p4AYfWXD2qD2XOTZw2t4trGZGKA2JR/OiB40="

#define US903_ENROLL_URL_BA "https://127.0.0.1:29001/.well-known/est/simpleenroll"
#define US903_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US903_UIDPWD_GOOD   "estuser:estpwd"

static EVP_PKEY * generate_private_key (void)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey;

    /*
     * create an RSA keypair and assign them to a PKEY and return it.
     */
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);

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

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
{
    BIO * bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;

    /*
     * Print out the specifics of this cert
     */
    printf(
        "%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
        __FUNCTION__,
        openssl_cert_error,
        X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
#ifdef HAVE_OLD_OPENSSL    
    X509_get0_signature((ASN1_BIT_STRING **)&cur_cert_sig,
                        (X509_ALGOR **)&cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, (X509_ALGOR *)cur_cert_sig_alg,
                         (ASN1_BIT_STRING *)cur_cert_sig);
#else    
    X509_get0_signature(&cur_cert_sig, &cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, cur_cert_sig_alg, cur_cert_sig);
#endif    

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
    }

    BIO_free(bio_err);

    return approve;
}

static FILE *outfile;
static size_t write_func (void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t written;
    written = fwrite(ptr, size, nmemb, outfile);
    return written;
}

static void us903_clean (void)
{
}

static int us903_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US903_TCP_PORT,
                  US903_SERVER_CERT_AND_KEY,
                  US903_SERVER_CERT_AND_KEY,
                  "US903 test realm",
                  US903_CACERTS,
                  US903_TRUSTED_CERT,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us903_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US903_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us903_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us903_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us903_destory_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Simple enroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * enrollment of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us903_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
    US903_PKCS10_RSA2048,
    US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple enroll - EC prime 256
 *
 * This test case uses libcurl to test simple
 * enrollment of a 256 bit EC CSR.  HTTP Basic
 * authentication is used.
 */
static void us903_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_ECDSA256,US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple enroll - DSA prime 1024
 *
 * This test case uses libcurl to test simple
 * enrollment of a 1024 bit DSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us903_test3 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_DSA1024, US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple enroll - Corrupted PKCS10
 *
 * This test case uses libcurl to test simple
 * enrollment using a corrupted CSR.  HTTP Basic
 * authentication is used.
 */
static void us903_test4 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_CORRUPT, US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since the CSR is not valid, the server should
     * respond with a 400.
     */
    CU_ASSERT(rv == 400);
}

/*
 * Simple enroll - manual enrollment
 *
 * This test case verifies the server is
 * sending the appropriate retry-after response.
 */
static void us903_test5 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /* Stop the EST server */
    st_stop();

    /* Restart the server with manual enrollment enabled */
    us903_start_server(1, 0);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_RSA2048, US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, &write_func);
    fclose(outfile);

    /*
     * Since the server hasn't seen this CSR in the past,
     * it should respond with a retry-after 202 response.
     */
    CU_ASSERT(rv == 202);

    /*
     * Verify the retry-after value
     */
    rv = grep(test5_outfile, "Retry-After: 3600");
    CU_ASSERT(rv == 0);

    /*
     * We will avoid waiting the full retry period since we're
     * only simulating manual enrollment.  Wait a second and then
     * try to enroll the cert again.
     */
    SLEEP(1);
    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_RSA2048, US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);

    /*
     * This enrollment request should succeed this time
     * Our simulated manual enrollment will automatically
     * enroll on the second attempt.
     */
    CU_ASSERT(rv == 200);

    /* Stop the EST server */
    st_stop();

    /* Restart the server with manual enrollment disabled */
    us903_start_server(0, 0);
}

/*
 * Simple enroll - PoP check fails with curl
 *
 * This test case verifies the server is
 * verifying the PoP from the client CSR.  Since curl does not
 * set the PoP, the EST enrollment should fail.
 */
static void us903_test6 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_enable_pop();

    /*
     * Send a valid enroll request using curl.  Curl does not
     * include the PoP
     */
    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                        US903_PKCS10_RSA2048, US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);

    /*
     * The server should respond with a failure code
     */
    CU_ASSERT(rv == 401);

    st_disable_pop();
}

/*
 * Simple enroll - PoP check succeeds with estclient
 *
 * This test case verifies the server is
 * verifying the PoP from the client CSR.  We use
 * estclient since it supports the PoP.
 */
static void us903_test7 (void)
{
    long rv;
    EST_CTX *c_ctx;
    EVP_PKEY *new_pkey;
    unsigned char *pkcs7;
    int pkcs7_len;
    unsigned char *attr_data;
    int attr_len;
    int http_status;

    LOG_FUNC_NM
    ;

    /*
     * This test case requires PoP to be enabled
     */
    st_enable_pop();

    /*
     * Create a client context
     */
    c_ctx = est_client_init(
        cacerts,
        cacerts_len,
        EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(c_ctx != NULL);
    if (!c_ctx) {
        return;
    }

    /*
     * Specify user ID and password since the server is running
     * in Basic Authentication mode.
     */
    rv = est_client_set_auth(c_ctx, "estuser", "estpwd", NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);
    est_client_set_server(c_ctx, "127.0.0.1", US903_TCP_PORT, NULL);

    /*
     * get a keypair to be used in the enroll.
     */
    new_pkey = generate_private_key();

    rv = est_client_get_csrattrs(c_ctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Attempt to enroll a CSR
     */
    rv = est_client_enroll(c_ctx, "US903-test7 CN", &pkcs7_len, new_pkey);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Check HTTP status code received from server is 200
     */
    http_status = est_client_get_last_http_status(c_ctx);
    CU_ASSERT(http_status == 200);

    /*
     * Client library has obtained the new client certificate.
     * Now retrieve it from the library.
     */
    pkcs7 = malloc(pkcs7_len);
    if (!pkcs7) {
        return;
    }
    rv = est_client_copy_enrolled_cert(c_ctx, pkcs7);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Clean up
     */
    est_destroy(c_ctx);
    EVP_PKEY_free(new_pkey);
    free(pkcs7);

    /*
     * Disable PoP for future test cases
     */
    st_disable_pop();
}

/*
 * Simple enroll - Use a non-default ECDHE curve
 *
 * This test case verifies the est_server_set_ecdhe_curve()
 * function is working.
 */
static void us903_test8 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /* Stop the EST server */
    st_stop();

    /* Restart the server using the secp384r1 curve  */
    us903_start_server(0, NID_secp384r1);

    rv = curl_http_post(
        US903_ENROLL_URL_BA,
        US903_PKCS10_CT,
        US903_PKCS10_RSA2048,
        US903_UIDPWD_GOOD,
        US903_CACERTS,
        CURLAUTH_BASIC,
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        NULL,
        NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple enroll - PoP is disabled, the CSR contains a
 *                 valid PoP.
 *
 * This test case ensures the server can handle the
 * scenario where the CSR includes a valid PoP even when
 * the server didn't request it.  We have to use
 * CiscoEST as the client to generate a CSR containing
 * a valid PoP.  There's no way to include a valid PoP
 * using Curl since the TLS channel binding information
 * is not known in advance.
 */
//The following include should never be used by an application
//be we use it here to hack the EST_CTX values mid-way
//through this test
#include "../../src/est/est_locl.h"
static void us903_test9 (void)
{
    EST_CTX *ctx;
    int rv;
    unsigned char *cacerts;
    int caclen = 0;
    EVP_PKEY *new_pkey;
    unsigned char *pkcs7;
    int pkcs7_len = 0;
    unsigned char *attr_data;
    int attr_len;

    LOG_FUNC_NM
    ;

    /*
     * Make sure our EST server has PoP disabled
     */
    st_disable_pop();

    /*
     * Read in the CA certs
     */
    caclen = read_binary_file(US903_CACERTS, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Init the client context
     */
    ctx = est_client_init(
        cacerts,
        caclen,
        EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);

    /*
     * We'll use simple HTTP auth to identify ourselves
     */
    rv = est_client_set_auth(ctx, "estuser", "estpwd", NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    est_client_set_server(ctx, "127.0.0.1", US903_TCP_PORT, NULL);

    /*
     * Create some space to hold the cert and generate
     * a private key
     */
    new_pkey = generate_private_key();

    rv = est_client_get_csrattrs(ctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Attempt to enroll
     */
    ctx->csr_pop_required = 1; //This is a hack for testing only, do not attempt this 
    //We need to force the challengePassword into the CSR    
    rv = est_client_enroll(ctx, "TestCase9", &pkcs7_len, new_pkey);
    CU_ASSERT(rv == EST_ERR_NONE);

    pkcs7 = malloc(pkcs7_len);
    rv = est_client_copy_enrolled_cert(ctx, pkcs7);

    free(pkcs7);
    est_destroy(ctx);
}

/*
 * Simple enroll - PoP is disabled, the CSR contains a
 *                 invalid PoP.
 *
 * This test case ensures the server can handle the
 * scenario where the CSR includes an invalid PoP even when
 * the server didn't request it.
 */
static void us903_test10 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /*
     * Make sure our EST server has PoP disabled
     */
    st_disable_pop();

    rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
    US903_PKCS10_STALE_POP,
    US903_UIDPWD_GOOD, US903_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * The enroll request should fail since the PoP was invalid
     * We expect a 401 response.
     */
    CU_ASSERT(rv == 401);
}

/*
 * Simple enroll - PoP is enabled, the CSR contains a
 *                 invalid PoP, and the client uses
 *                 a cert that contains id-kp-cmcRA.
 *
 * This test case ensures the server disables the PoP
 * check when the client is using a cert that contains
 * id-kp-cmcRA, which indicates the client is an RA.
 */
static void us903_test11 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /*
     * Make sure our EST server has PoP disabled
     */
    st_enable_pop();

    rv = curl_http_post_certuid(
    US903_ENROLL_URL_BA,
    US903_PKCS10_CT,
    US903_PKCS10_STALE_POP,
    US903_UIDPWD_GOOD,
    US903_EXPLICIT_CERT,
    US903_EXPLICIT_KEY,
    US903_CACERTS, NULL);

    /*
     * Even though the PoP value doesn't match in this CSR,
     * the enroll will succeed since the client is using
     * an RA certificate. We expect a 200 response.
     */
    CU_ASSERT(rv == 200);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us903_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us903_srv_simpenroll",
            us903_init_suite,
            us903_destory_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "Enroll RSA cert", us903_test1)) ||
        (NULL == CU_add_test(pSuite, "Enroll ECDSA cert", us903_test2)) ||
        (NULL == CU_add_test(pSuite, "Enroll DSA cert", us903_test3)) ||
        (NULL == CU_add_test(pSuite, "Enroll corrupted ECDSA cert", us903_test4)) ||
        (NULL == CU_add_test(pSuite, "Enroll retry-after manual approval ", us903_test5)) ||
        (NULL == CU_add_test(pSuite, "Enroll PoP fail with Curl", us903_test6)) ||
        (NULL == CU_add_test(pSuite, "Enroll PoP succeed with estclient", us903_test7)) ||
        (NULL == CU_add_test(pSuite, "Non-default ECDHE curve", us903_test8)) ||
        (NULL == CU_add_test(pSuite, "Enroll w/PoP disabled, CSR includes valid PoP", us903_test9)) ||
        (NULL == CU_add_test(pSuite, "Enroll w/PoP disabled, CSR includes invalid PoP", us903_test10)) ||
        (NULL == CU_add_test(pSuite, "Enroll w/PoP enabled using RA cert, CSR includes invalid PoP", us903_test11)))
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

