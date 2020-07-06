/*------------------------------------------------------------------
 * us1864.c - Unit Tests for User Story 1864 - Enable Token Auth mode in server
 *
 * March, 2015
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

#define US1864_TCP_PORT     29001

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US1864_PKCS10_RSA2048   "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"
#define US1864_PKCS10_4096_REQ  "MIIEZjCCAk4CAQAwITEPMA0GA1UEAwwGSkpUZXN0MQ4wDAYDVQQFEwUwMDAwMTCC\nAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALfLlHxqzObiKWDfX8saZ4l3\n1JyrCP4xmyQitY2pIIGlLvHT7t1WZ0LO9uo0uB7b/8iGbXki8FgqSm1jROe5lwCN\nDIhTJdG4b705c6XmD3Mh436De9d4gzpjedA2qurSI9+GVNVgU0ZOWJFu9g+y3iRH\ndfsjO9u0E2MfZWWR8M72gBqzvbDDPN4BDwLa9TkQ2Rsxf3h2d7bN2DNShNSYX/dE\nIX89d9uC6FegsHQxHINUOdZzeAn3yuQMBU+FwohEl9Ub8Qu9gub2MJUrYNRQnii7\nduvq5/UjkhjNWzIh7LAbdaM+0wSmCe0ju+wKbayUZZkrqoVK6bWZzFs4dYtn95/S\nVVOv95MD5D1EokXw3Iih7GRJygtWn5e4/YO68LONBF7UE24vgBwEieF6J0bFAlxw\n15s7pIalkGF7CUbitRhbB3kTjGfUDR8YpSsKdqxHNmWBXY7ZVk4T8K7168cNWSOL\netZpTk4BtoUJBnWP8Uq38YOi6389U24gmZtGpSpJEEtDy1MJ8Ha4PZE/VkFtmUWq\nbETOx2kubGwc9vXvWfi5BxE2VvetGNsy2EQEZPVwscYaCy0/yO3fu06coEtr7Ekr\ngapDDEzVtiP9NPe5q18Azu+T9ngoOx3PqrCPG1BDN6z1Ue2tSDdOxKNFMNMwqYIn\nZP9MXh+tz8RaKvsclv9JAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAgEAJMwZ4IUB\nUSH5wQBfsYT4SxtKsZtvun6QX0+7jNMtzzQUOqO79Kx/DKpzsKxLNvHKmFqcxA7g\ngbEwXkAP5+VaMD92DghcNjXOqGKclZdmGj2oREqZwzvTDRo4zP1yen5vgL/Yz7SA\nxze8wPg2WhlV9+qvkVCpHN3EUIfO+rBgi2reo/vF7xq5CAU4UtQ1h4gHax67Yww8\nJmypyGGa0ad0Z8ruiclI/QtluADUxy1YM0Up2FC0s7j72xzrRpEl1fPlOi/bFaZp\nsr4zllOpwnRdxvffXO7gXtXVIr4IHVHNWj6kmDzyk0ovat2Ms5aGUcMDN6Jm8KIB\nNBVH5FgkBVQOPSngkwnEOj0RsaKSxT5EfmOxm9pCrAE3rNdVOgO4t8wZ6DQUqye/\nBUdmgXtWoGsKIg8oR5HAWBER8yw/qdiRlBGgN/PKZdpmYI2TEfZvp/nXwG7QLjGx\nsj5TWeRKNgghUCu3uF+1s0R+gqgY1S9GgiDSifL7+h+bXJ4ncyRGq+XPnrfMiRkB\neSyv3kyIxtZfAB6TjkUbtVfo2KrfqNxu4lbJYE2b6hs1L6t7YPhjubz9aES7wES7\nk+ZZPZn/k/GsqUpsWHnEFEvi5C5WPrnpvVN6rKh0fB+AukGrS+9EK4KNZWfV/yf8\nXN5qWyOtgd4oLUUsgFDJsqNh6A1mlmx6CnY=\n"

#define US1864_ENROLL_URL_BA    "https://127.0.0.1:29001/.well-known/est/simpleenroll"
#define US1864_PKCS10_CT        "Content-Type: application/pkcs10"
#define US1864_UIDPWD_GOOD      "estuser:estpwd"
#ifndef WIN32
#define US1864_CACERTS          "CA/estCA/cacert.crt"
#define US1864_CACERT           "CA/estCA/cacert.crt"
#define US1864_TRUSTED_CERT     "CA/trustedcerts.crt"
#define US1864_SERVER_CERT      "CA/estCA/private/estservercertandkey.pem"
#define US1864_SERVER_KEY       "CA/estCA/private/estservercertandkey.pem"
#define US1864_CLIENT_CERT      "CA/estCA/private/estservercertandkey.pem"
#define US1864_CLIENT_KEY       "CA/estCA/private/estservercertandkey.pem"
#else
#define US1864_CACERTS          "CA\\estCA\\cacert.crt"
#define US1864_CACERT           "CA\\estCA\\cacert.crt"
#define US1864_TRUSTED_CERT     "CA\\trustedcerts.crt"
#define US1864_SERVER_CERT      "CA\\estCA\\private\\estservercertandkey.pem"
#define US1864_SERVER_KEY       "CA\\estCA\\private\\estservercertandkey.pem"
#define US1864_CLIENT_CERT      "CA\\estCA\\private\\estservercertandkey.pem"
#define US1864_CLIENT_KEY       "CA\\estCA\\private\\estservercertandkey.pem"
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

static void us1864_clean (void)
{
}

static int us1864_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US1864_TCP_PORT,
                  US1864_SERVER_CERT,
                  US1864_SERVER_KEY,
                  "US1864 test realm",
                  US1864_CACERTS,
                  US1864_TRUSTED_CERT,
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
static int us1864_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1864_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us1864_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1864_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1864_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * est_server_set_auth_mode() - unit test
 *
 * First, Test the parameters of est_server_set_auth_mode()
 */
static void us1864_test1 (void)
{
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;
    EST_ERROR est_rv;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1864_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(certin, US1864_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(keyin, US1864_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * init EST in server mode
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init(cacerts, cacerts_len, cacerts, cacerts_len,
        EST_CERT_FORMAT_PEM, "testrealm", x, priv_key);

    CU_ASSERT(ctx != NULL);

    est_rv = est_server_set_auth_mode(ctx, AUTH_NONE);
    CU_ASSERT(est_rv == EST_ERR_BAD_MODE);
    est_rv = est_server_set_auth_mode(ctx, AUTH_BASIC);
    CU_ASSERT(est_rv == EST_ERR_NONE);
    est_rv = est_server_set_auth_mode(ctx, AUTH_DIGEST);
    CU_ASSERT(est_rv == EST_ERR_NONE);
    est_rv = est_server_set_auth_mode(ctx, AUTH_TOKEN);
    CU_ASSERT(est_rv == EST_ERR_NONE);
    est_rv = est_server_set_auth_mode(ctx, 0xffffffff);
    CU_ASSERT(est_rv == EST_ERR_BAD_MODE);

    /*
     * Make sure we don't allow DIGEST mode when in FIPS mode
     */
    if (!FIPS_mode_set(1)) {
        printf("FIPS mode not supported, skipping test to prevent digest auth when in FIPS mode");
    } else {
        est_rv = est_server_set_auth_mode(ctx, AUTH_DIGEST);
        CU_ASSERT(est_rv == EST_ERR_BAD_MODE);
        FIPS_mode_set(0);
    }

    X509_free(x);
    EVP_PKEY_free(priv_key);

    est_destroy(ctx);
}

/*
 * Simple enroll - Token Auth Mode
 *
 * The goal of this test is to verify that the EST server responds with the
 * correct auth challenge when it's configured for Token Auth mode.  It will
 * first perform a sanity check by performing an HTTP Basic request while the
 * server is still in its default mode of HTTP Basic auth.  The test will then
 * configure the server for Token Auth mode and issue a request that does not
 * contain any auth header.  This should force the server to respond with a
 * token auth challenge header.
 */
static void us1864_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US1864_ENROLL_URL_BA, US1864_PKCS10_CT,
    US1864_PKCS10_RSA2048,
    US1864_UIDPWD_GOOD, US1864_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
    /*
     * Since we specify BASIC and the server is still in BASIC
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);

    /*
     * Switch the server over to Token mode.
     *
     * NOTE: I see this being done in numerous places, and it's probably safe
     * in a test setting, but it is dangerous to change this on the fly in an
     * operational setting.  Also note, no return code for any of these
     * set/enable functions.
     */
    st_enable_http_token_auth();

    bearer_found = 0;

    rv = curl_http_post_cert_write(US1864_ENROLL_URL_BA,
    US1864_PKCS10_CT,
    US1864_PKCS10_RSA2048,
    US1864_CLIENT_CERT,
    US1864_CLIENT_KEY,
    US1864_CACERTS, curl_data_cb, curl_data_cb);

    /*
     * Since we changed auth modes on the server we expect this to now
     * fail.  We're not capturing the actual auth challenge we
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 401);
    CU_ASSERT(bearer_found == 1);

}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us1864_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1864_cfg_tok_auth",
            us1864_init_suite,
            us1864_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "Check parms", us1864_test1)) ||
        (NULL == CU_add_test(pSuite, "Attempt enroll - BASIC pass", us1864_test2))
        )
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
 #endif
 }

