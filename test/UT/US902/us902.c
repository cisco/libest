/*------------------------------------------------------------------
 * us902.c - Unit Tests for User Story 902 - Server simple reenroll
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
static char test5_outfile[FILENAME_MAX] = "US902/test5.hdr";
#define US902_CACERTS       "CA/estCA/cacert.crt"
#define US902_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US902_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#else
static char test5_outfile[FILENAME_MAX] = "US902\\test5.hdr";
#define US902_CACERTS       "CA\\estCA\\cacert.crt"
#define US902_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US902_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#endif
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US902_RETRY_INTERVAL    3600
#define US902_TCP_PORT      29001

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US902_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the ec.req file:
 *
 * openssl req -newkey ec:256parms -keyout eckey.pem -keyform PEM -out ec.req -outform PEM
 */
#define US902_PKCS10_DSA1024 "MIICfjCCAj0CAQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEzARBgNVBAoMCkRTQUNvbXBhbnkxDzANBgNVBAsMBkRTQW9yZzEQMA4G\nA1UEAwwHZHNhIGRvZTEaMBgGCSqGSIb3DQEJARYLZHNhQGRvZS5jb20wggG2MIIB\nKwYHKoZIzjgEATCCAR4CgYEAqIfbyk7rEAaULIPB1GcHHc0ctx6g0dhBfdUdOPNG\nBSE+TP5UF5lw8Qm6oCXstU3nYEJalmMvkjFwbgvBws8aJBnj09dDDn8spKEGcG0M\nZpqdMys6+b4QJjq5YAxEaATVY/1L/rBgGGm1EFDhc/6Ezm2T3CGeQklwo5aBZQCc\naIsCFQDC1olBFuE+phOhjXAwEE5EPJkRJwKBgD+vZ+tLCTjBzVFNjAO8X/SMamwW\noraNfdyZ+ZCEAmYI/D4838nCGAjVRQyDb1q5akkLyxoJX1YV7gNbaBNUys3waqdu\nso1HtuEur2cbhU5iOeKBWpj6MIWlPdD3uCRu4uiBF9XBiANaRID8CT2kchhwy4Ok\nFfQMuYOz4eBhMQqmA4GEAAKBgDuwR7H3U4CfuQjWeTtrI50M1TxhlVZ3TonRtVIx\nEHpuXxAouxATVkthJtaCBKc0EHii1bE/kgNUgGX/ZdFjBUb/XfpkYsRT3QRLF0+s\nPZGY/0TovO9pKjqiw0C10leNKFbEVdlXYtAkjXUbHmyNog3195/t7oKXHMT1A/5p\nhUCRoAAwCQYHKoZIzjgEAwMwADAtAhUAhPCqQG3gKUUPKdwBNCmZfzWDqjsCFAh0\nzn9HujlXNaTA1OhjmPmcJSxT"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the dsa.req file:
 *
 * openssl req -newkey dsa:dsaparms -keyout dsakey.pem -keyform PEM -out dsa.req -outform PEM
 */
#define US902_PKCS10_ECDSA256 "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ29yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

#define US902_PKCS10_CORRUPT "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ39yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

#define US902_ENROLL_URL_BA "https://127.0.0.1:29001/.well-known/est/simplereenroll"
#define US902_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US902_UIDPWD_GOOD   "estuser:estpwd"

static FILE *outfile;
static size_t write_func (void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t written;
    written = fwrite(ptr, size, nmemb, outfile);
    return written;
}

static void us902_clean (void)
{
}

static int us902_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US902_TCP_PORT,
    US902_SERVER_CERT_AND_KEY,
    US902_SERVER_CERT_AND_KEY, "US902 test realm",
    US902_CACERTS,
    US902_TRUSTED_CERT, "CA/estExampleCA.cnf", manual_enroll, 0, nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us902_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US902_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us902_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us902_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us902_destory_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Simple reenroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * enrollment of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us902_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_RSA2048,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple reenroll - EC prime 256
 *
 * This test case uses libcurl to test simple
 * enrollment of a 256 bit EC CSR.  HTTP Basic
 * authentication is used.
 */
static void us902_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_ECDSA256,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple reenroll - DSA prime 1024
 *
 * This test case uses libcurl to test simple
 * enrollment of a 1024 bit DSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us902_test3 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_DSA1024,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Simple reenroll - Corrupted PKCS10
 *
 * This test case uses libcurl to test simple
 * enrollment usinga corrupted CSR.  HTTP Basic
 * authentication is used.
 */
static void us902_test4 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_CORRUPT,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since the CSR is not valid, the server should
     * respond with a 400.
     */
    CU_ASSERT(rv == 400);
}

/*
 * Simple reenroll - manual enrollment
 *
 * This test case verifies the server is
 * sending the appropriate retry-after response.
 */
static void us902_test5 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /* Stop the EST server */
    st_stop();

    /* Restart the server with manual enrollment enabled */
    us902_start_server(1, 0);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_RSA2048,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, &write_func);
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
    rv = curl_http_post(US902_ENROLL_URL_BA, US902_PKCS10_CT,
    US902_PKCS10_RSA2048,
    US902_UIDPWD_GOOD, US902_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);

    /*
     * This enrollment request should succeed this time
     * Our simulated manual enrollment will automatically
     * enroll on the second attempt.
     */
    CU_ASSERT(rv == 200);

    /* Stop the EST server */
    st_stop();

    /* Restart the server with manual enrollment disabled */
    us902_start_server(0, 0);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us902_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us902_srv_simpreenroll",
            us902_init_suite,
            us902_destory_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "ReEnroll RSA cert", us902_test1)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll ECDSA cert", us902_test2)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll DSA cert", us902_test3)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll corrupted ECDSA cert", us902_test4)) ||
        (NULL == CU_add_test(pSuite, "ReEnroll retry-after manual approval ", us902_test5)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

