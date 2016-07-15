/*------------------------------------------------------------------
 * us1884.c - Unit Tests for User Story 1884 - Parse token based
 *            requests by the EST Server, handle mismatches.
 *            Successful token auth processing is covered by tests
 *            in US1883/us1883.c.
 *
 * April, 2015
 *
 * Copyright (c) 2015, 2016 by cisco Systems, Inc.
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
#include <errno.h>

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US1884_SERVER_IP            "127.0.0.1"
#define US1884_TCP_PORT             29001

#define US1884_PKCS10_RSA2048       "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US1884_ENROLL_URL_BA        "https://127.0.0.1:29001/.well-known/est/simpleenroll"
#define US1884_PKCS10_CT            "Content-Type: application/pkcs10"
#define US1884_UIDPWD_GOOD          "estuser:estpwd"
#ifndef WIN32
#define US1884_CACERTS              "CA/estCA/cacert.crt"
#define US1884_CACERT               "CA/estCA/cacert.crt"
#define US1884_SERVER_CERT_AND_KEY  "CA/estCA/private/estservercertandkey.pem"
#define US1884_TRUSTED_CERTS        "CA/trustedcerts.crt"
#else
#define US1884_CACERTS              "CA\\estCA\\cacert.crt"
#define US1884_CACERT               "CA\\estCA\\cacert.crt"
#define US1884_SERVER_CERT_AND_KEY  "CA\\estCA\\private\\estservercertandkey.pem"
#define US1884_TRUSTED_CERTS        "CA\\trustedcerts.crt"
#endif

static void us1884_clean (void)
{
}

static int us1884_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US1884_TCP_PORT,
                  US1884_SERVER_CERT_AND_KEY,
                  US1884_SERVER_CERT_AND_KEY,
                  "estrealm",
                  US1884_CACERT,
                  US1884_TRUSTED_CERTS,
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
static int us1884_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1884_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us1884_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1884_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1884_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

#if 0
/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify(X509 *cur_cert, int openssl_cert_error)
{
    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;

    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
            __FUNCTION__, openssl_cert_error,
            X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
    X509_signature_print(bio_err, cur_cert->sig_alg, cur_cert->signature);

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
    }

    BIO_free(bio_err);

    return approve;
}

static EVP_PKEY * generate_private_key(void)
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
#endif
/*
 * curl_data_cb is passed to Curl and will be called from Curl whenever data
 * has been received, or if this function has been specified to retrieve the
 * http headers.  In this test it's used to retrieve the http headers and
 * look for the "bearer" token Authorization challenge.
 */
static int bearer_found = 0;
static size_t curl_data_cb (void *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
    void * rc;

    if (bearer_found == 0) {

        /*
         * WARNING: strstr can be dangerous because it assumes null terminated
         * strings.  In this case the http headers came from EST server and we
         * know they are null terminated
         */
        rc = strstr(ptr, "WWW-Authenticate: Bearer");
        if (rc) {
            bearer_found = 1;
        }
    }

    return size * nmemb;
}

#define GOOD_TOKEN "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U="
#define DIFFERENT_TOKEN "V2VsbCwgSSd2ZSBnb3QgdG8gcnVuIHRvIGtlZXAgZnJvbSBoaWRpbicNCkFuZCBJJ20gYm91bmQgdG8ga2VlcCBvbiByaWRpbicNCkFuZCBJJ3ZlIGdvdCBvbmUgbW9yZSBzaWx2ZXIgZG9sbGFyDQpCdXQgSSdtIG5vdCBnb25uYSBsZXQgJ2VtIGNhdGNoIG1lLCBubw0KTm90IGdvbm5hIGxldCAnZW0gY2F0Y2ggdGhlIG1pZG5pZ2h0IHJpZGVy"
#define NULL_TOKEN NULL;
#define LONG_TOKEN "SSBjYW4ndCBhZ3JlZSB0byBkaXNhZ3JlZSANCkZpZ2h0aW5nIGxpa2UgSSdtIGZpZ2h0aW5nIGZvciBsaWZlIA0KVGhleSdyZSBvbmx5IHdvcmRzIGJ1dCB0aGV5IGN1dCBsaWtlIGEgYmxhZGUgDQpTd2luZ2luZyB3aWRlIHdpdGggYWxsIG9mIG15IG1pZ2h0IA0KDQpBaCB5ZWFoLCBJIGd1ZXNzIGl0J3MgYWxsIG9mIHRoYXQgY29mZmVlLCB0aGF0J3MgZ290IG15IG1pbmQgaW4gYSB3aGlybCANCkknbSBzdGlsbCBjdXNzaW5nIGFuZCBiaXRjaGluZyBhbmQgdGhlcmUgYWluJ3Qgbm9ib2R5IGhlcmUgDQoNCk9oIHllYWgsIHlvdSBkb24ndCBoYXZlIHRvIGhvbGxlciBJIGhlYXIgeW91IA0KSSdtIHN0YW5kaW5nIHJpZ2h0IGhlcmUgYmVzaWRlIHlvdSANCk9oLCA5OSBzaGFkZXMgb2YgY3JhenksIEknbSA5OSBzaGFkZXMgb2YgY3JhenkgDQpDcmF6eSwgY3JhenksIGNyYXp5LCBjcmF6eSANCg0KUG91ciBhbm90aGVyIGRyaW5rLCBtYWtlIGl0IGEgZG91YmxlIGZvciBtZSANCk1heWJlIEkgY2FuIGRyaW5rIHRoaXMgYXdheSANCkl0J3MgbmV2ZXIgZnVuIHdoZW4gdGhleSBwdWxsIG91dCB0aGUgZ3VuIA0KQmVhdCB5b3UgYmxhY2sgYW5kIGJsdWUsIGJveSANCllvdSBnb3R0YSBwYXksIHlvdSBnb3R0YSBwYXkgDQoNCk9oLCB3aGVyZSB0aGUgaGVsbCBhbSBJPyBJIGhvcGUgYXQgbGVhc3QgSSBoYWQgZnVuIA0KSSdtIHN0dW1ibGluZyB0aHJvdWdoIE5ldyBPcmxlYW5zIG9oLCB0byB0aGUgcmlzaW5nIHN1biANCg0KT2ggeWVhaCwgeW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3UgDQpJJ20gc3RhbmRpbmcgcmlnaHQgaGVyZSBiZXNpZGUgeW91IA0KT2gsIDk5IHNoYWRlcyBvZiBjcmF6eSwgSSdtIDk5IHNoYWRlcyBvZiBjcmF6eSANCkNyYXp5LCBjcmF6eSwgY3JhenksIGNyYXp5IA0KDQpMb3JkIGhhdmUgbWVyY3kgb24gbWUgDQpOb3ZlbnRhIG51ZXZhIHRvbm9zIGRlIGxvY28gDQoNCkkgbmVlZCBzb21lIHBlYWNlLCBqdXN0IHNvbWUgcmVsaWVmIA0KRnJvbSB0aGlzIHZvaWNlLCBraWxsaW5nIG1lIA0KWW91IHN0YXJlIGF0IG1lLCBhbmQgeW91IGdsYXJlIGF0IG1lIA0KQWxsIHRoaXMgcGFpbiBpdCdzIGFsbCB0aGUgc2FtZSwgaXQncyBhbGwgaW5zYW5lIA0KKHlvdSBzZWUpIA0KDQpJcyB0aGlzIHJlYWxseSBoYXBwZW5pbmcgb3IgZGlkIEkgbWFrZSBpdCBhbGwgdXA/IA0KSSdtIGJvdW5kIGZvciBDaGF0dGFob29jaGVlIG9uIGEgdHVybmlwIHRydWNrIA0KDQpPaCB5ZWFoLCB5b3UgZG9uJ3QgaGF2ZSB0byBob2xsZXIgSSBoZWFyIHlvdSANCkknbSBzdGFuZGluZyByaWdodCBoZXJlIGJlc2lkZSB5b3UgDQpPaCwgOTkgc2hhZGVzIG9mIGNyYXp5LCBJJ20gOTkgc2hhZGVzIG9mIGNyYXp5IA0KQ3JhenksIGNyYXp5LCBjcmF6eSwgY3JhenkgDQoNCkFoIHlvdSdyZSBjcmF6eSB5b3UncmUgY3JhenkgDQpIb2xkIG15IGZlZXQsIGZlZXQgdG8gdGhlIGZpcmUgDQpZb3UgaG9sZCBteSBmZWV0IHRvIHRoZSBmaXJlIA0KSSBuZXZlciBzYWlkIEkgd2FzIGRvd24gd2l0aCB5b3U="
static char *test_token = "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U=";

static int auth_cred_callback_called = 0;
static int auth_cred_force_error = 0;

/*
 * Test1 - Make sure the server returns an error to the client when the
 *         server is in token mode and it receives a BASIC based request
 *         from the client.
 *         We need to use CURL here since the est client now will
 *         attempt to send whatever the server requests.  We can hard code
 *         BASIC and DIGEST with CURL.
 *
 * In this test,
 * - server into TOKEN mode
 * - Client application registers its BASIC based callback
 * - Client should get an error response and not get a cert
 */
static void us1884_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    rv = curl_http_post(US1884_ENROLL_URL_BA, US1884_PKCS10_CT,
    US1884_PKCS10_RSA2048,
    US1884_UIDPWD_GOOD, US1884_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we specify BASIC and the server is still in TOKEN
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);

}

/*
 * Test2 - Make sure the server returns an error to the client when the
 *         server is in token mode and it receives a DIGEST based request
 *         from the client.
 *         We need to use CURL here since the est client now will
 *         attempt to send whatever the server requests.  We can hard code
 *         BASIC and DIGEST with CURL.
 *
 * In this test,
 * - server into TOKEN mode
 * - Client sends DIGEST based request.
 * - Client should get an error response and not get a cert
 */
static void us1884_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    rv = curl_http_post(US1884_ENROLL_URL_BA, US1884_PKCS10_CT,
    US1884_PKCS10_RSA2048,
    US1884_UIDPWD_GOOD, US1884_CACERTS, CURLAUTH_DIGEST, NULL, NULL, NULL);
    /*
     * Since we specify DIGEST and the server is in TOKEN
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);

}

#define US1884_CT_AH_1 "Content-Type: application/pkcs10\nAuthorization: Bearer 12345abcde"
#ifndef WIN32
#define US1884_CLIENT_CERT "CA/estCA/private/estservercertandkey.pem"
#define US1884_CLIENT_KEY  "CA/estCA/private/estservercertandkey.pem"
#else
#define US1884_CLIENT_CERT "CA\\estCA\\private\\estservercertandkey.pem"
#define US1884_CLIENT_KEY  "CA\\estCA\\private\\estservercertandkey.pem"
#endif
/*
 * Test3 - Make sure the server returns an error to the client when the
 *         server is in token mode and it receives a DIGEST based request
 *         from the client.
 *         In this test we force Curl to send a token (bearer) based
 *         request.  We expect this to fail.
 *
 * In this test,
 * - server into BASIC mode
 * - Client send a TOKEN based request
 * - Client should get an error response and not get a cert
 */
static void us1884_test3 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    st_enable_http_basic_auth();

    rv = curl_http_post_cert_write(US1884_ENROLL_URL_BA,
    US1884_CT_AH_1,
    US1884_PKCS10_RSA2048,
    US1884_CLIENT_CERT,
    US1884_CLIENT_KEY,
    US1884_CACERTS, curl_data_cb, curl_data_cb);
    /*
     * Since we specify TOKEN and the server is in BASIC
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us1884_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1884_tok_auth_server_errors",
            us1884_init_suite,
            us1884_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "server token - client basic", us1884_test1)) ||
        (NULL == CU_add_test(pSuite, "server token - client digest", us1884_test2)) ||
        (NULL == CU_add_test(pSuite, "server basic - client token", us1884_test3))
        )
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

