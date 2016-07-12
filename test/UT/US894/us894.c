/*------------------------------------------------------------------
 * us894.c - Unit Tests for User Story 894 - Proxy cacerts
 *
 * November, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 *
 *  Proxy mode is primarily server mode where the processing of certain
 *  requests from clients are passed long to the upstream server using
 *  client mode functionality.  In the case of Get CACerts, proxy mode
 *  functions almost identically as server mode.  The CA certs response
 *  chain is passed in and is then sent in reply to the Get CACerts
 *  requests from downstream clients.
 *
 *  This test code is taken largely from US901, Server Get CACerts,
 *
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <est.h>
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include <openssl/ssl.h>
#include "st_server.h"
#include "st_proxy.h"

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define US894_PKCS10_REQ    "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"
#define US894_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US894_UIDPWD_GOOD   "estuser:estpwd"
#define US894_UIDPWD_BAD    "estuser:bogus"
#ifndef WIN32
#define US894_CACERTS       "CA/estCA/cacert.crt"
#define US894_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US894_TRUSTED_CERT_AND_CRL "US894/trustedcertsandcrl.crt"
#define US894_EXPLICIT_CERT "US894/explicit-cert.pem" 
#define US894_EXPLICIT_KEY "US894/explicit-key.pem"
#define US894_IMPLICIT_CERT "US894/implicit-cert.pem" 
#define US894_IMPLICIT_KEY "US894/implicit-key.pem"
#define US894_REVOKED_CERT "US894/revoked-cert.pem" 
#define US894_REVOKED_KEY "US894/revoked-key.pem"
#define US894_SELFSIGN_CERT "US894/selfsigned-cert.pem" 
#define US894_SELFSIGN_KEY "US894/selfsigned-key.pem"
#define US894_CACERT "CA/estCA/cacert.crt"
#define US894_EXTCERT "CA/extCA/cacert.crt"
#define US894_SERVER_CERT "CA/estCA/private/estservercertandkey.pem"
#define US894_SERVER_KEY "CA/estCA/private/estservercertandkey.pem"
#define US894_PROXY_CERT "CA/estCA/private/estservercertandkey.pem"  // change these other to dedicated ones
#define US894_PROXY_KEY "CA/estCA/private/estservercertandkey.pem"
static char test5_outfile[FILENAME_MAX] = "US894/test5.crt";
static char test26_outfile[FILENAME_MAX] = "US894/test26.crt";
static char test27_outfile[FILENAME_MAX] = "US894/test27.crt";
#else
#define US894_CACERTS       "CA\\estCA\\cacert.crt"
#define US894_TRUSTED_CERT "CA\\trustedcerts.crt"
#define US894_TRUSTED_CERT_AND_CRL  "US894\\trustedcertsandcrl.crt"
#define US894_EXPLICIT_CERT "US894\\explicit-cert.pem" 
#define US894_EXPLICIT_KEY "US894\\explicit-key.pem"
#define US894_IMPLICIT_CERT "US894\\implicit-cert.pem" 
#define US894_IMPLICIT_KEY "US894\\implicit-key.pem"
#define US894_REVOKED_CERT "US894\\revoked-cert.pem" 
#define US894_REVOKED_KEY "US894\\revoked-key.pem"
#define US894_SELFSIGN_CERT "US894\\selfsigned-cert.pem" 
#define US894_SELFSIGN_KEY "US894\\selfsigned-key.pem"
#define US894_CACERT "CA\\estCA\\cacert.crt"
#define US894_EXTCERT "CA\\extCA\\cacert.crt"
#define US894_SERVER_CERT "CA\\estCA\\private\\estservercertandkey.pem"
#define US894_SERVER_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US894_PROXY_CERT "CA\\estCA\\private\\estservercertandkey.pem"  // change these other to dedicated ones
#define US894_PROXY_KEY "CA\\estCA\\private\\estservercertandkey.pem"

static char test5_outfile[FILENAME_MAX] = "US894\\test5.crt";
static char test26_outfile[FILENAME_MAX] = "US894\\test26.crt";
static char test27_outfile[FILENAME_MAX] = "US894\\test27.crt";
#endif

/* #define US894_TCP_SERVER_PORT_BASIC     12894 */
#define US894_ENROLL_URL "https://127.0.0.1:16894/.well-known/est/simpleenroll"
#define US894_CACERT_URL "https://127.0.0.1:16894/.well-known/est/cacerts"
/* #define US894_TCP_SERVER_PORT_DIGEST    13894 */
/* #define US894_TCP_SERVER_PORT_HTTP_DISABLE 14894 */
#define US894_TCP_SERVER_PORT       15894
#define US894_TCP_PROXY_PORT        16894

static void us894_clean (void)
{
    char cmd[200];
#ifndef WIN32
    sprintf(cmd, "rm %s", test5_outfile);
    system(cmd);
    sprintf(cmd, "rm %s", test26_outfile);
    system(cmd);
    sprintf(cmd, "rm %s", test27_outfile);
    system(cmd);
#else
    sprintf(cmd, "del %s", test5_outfile);
    system(cmd);
    sprintf(cmd, "del %s", test26_outfile);
    system(cmd);
    sprintf(cmd, "del %s", test27_outfile);
    system(cmd);
#endif
}

int us894_start_server ()
{
    int rv = 0;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US894_TCP_SERVER_PORT,
                  US894_SERVER_CERT,
                  US894_SERVER_KEY,
                  "estrealm",
                  US894_CACERT,
                  US894_TRUSTED_CERT,
                  "US894/estExampleCA.cnf",
                  0,  // manual enroll
                  0,  // disable PoP
                  0); // ecdhe nid info
    SLEEP(1);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy acting as an RA.
     */
    rv = st_proxy_start(US894_TCP_PROXY_PORT,
                        US894_PROXY_CERT,
                        US894_PROXY_KEY,
                        "estrealm",
                        US894_CACERT,
                        US894_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US894_TCP_SERVER_PORT,
                        0,  // disable PoP
                        0);  // ecdhe nid info
    SLEEP(1);

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us894_init_suite (void)
{
    int rv;

    us894_clean();

    printf("\nStarting EST Proxy Get CACerts unit tests.\n");

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us894_start_server();

    return rv;
}

void us894_stop_server ()
{
    st_stop();
    st_proxy_stop();
    SLEEP(2);
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us894_destroy_suite (void)
{
    us894_stop_server();
    printf("Completed EST Proxy Get CACerts unit tests.\n");
    return 0;
}

/*
 * HTTP Basic auth
 *
 * This test case uses libcurl to test HTTP Basic
 * authentication is working on the EST proxy/server.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.
 */
static void us894_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US894_ENROLL_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_GOOD, US894_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * HTTP Basic Auth failure, Bad Password
 *
 * This test case uses libcurl to test HTTP Basic
 * authentication is working on the EST proxy/server,
 * while using a bogus password.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.
 */
static void us894_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US894_ENROLL_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_BAD, US894_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 400
     */
    CU_ASSERT(rv == 401);
}

/*
 * HTTP Digest Auth
 *
 * This test case uses libcurl to test HTTP Digest
 * authentication is working on the EST proxy/server.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.
 *
 * This test also tests the correct operation of est_proxy_set_auth()
 */
static void us894_test3 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_proxy_set_auth(AUTH_DIGEST);
    SLEEP(1);

    rv = curl_http_post(US894_ENROLL_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_GOOD, US894_CACERTS, CURLAUTH_DIGEST,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with success
     */
    CU_ASSERT(rv == 200);

    st_proxy_set_auth(AUTH_BASIC);
}

/*
 * HTTP Digest Auth fail
 *
 * This test case uses libcurl to test HTTP Digest
 * authentication is working on the EST proxy/server.
 * This is the negative test case for Digest auth.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.  The EST proxy/server should be
 * running and listening to port 8087 prior to this
 * test being run.
 */
static void us894_test4 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_proxy_set_auth(AUTH_DIGEST);
    SLEEP(1);

    rv = curl_http_post(US894_ENROLL_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_BAD, US894_CACERTS, CURLAUTH_DIGEST,
                        NULL, NULL, NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with a 400
     */
    CU_ASSERT(rv == 401);

    st_proxy_set_auth(AUTH_BASIC);
}

static FILE *outfile;
static size_t write_func (void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t written;
    written = fwrite(ptr, size, nmemb, outfile);
    return written;
}

/*
 * This test case does a simple cacerts request
 * and looks for the HTTP 200 response code.
 */
static void us894_test5 (void)
{
    long rv;
    char cmd[200];

    LOG_FUNC_NM
    ;

    SLEEP(1);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_get(US894_CACERT_URL, US894_CACERTS, &write_func);
    fclose(outfile);

    /*
     * we expect the server to respond with a 200
     */
    CU_ASSERT(rv == 200);

    sprintf(
        cmd,
        "openssl base64 -d -in %s | openssl pkcs7 -inform DER -text -print_certs",
        test5_outfile);
    rv = system(cmd);
    CU_ASSERT(rv == 0);
}

static void us894_test_sslversion (const SSL_METHOD *m, int expect_fail)
{
    BIO *conn;
    SSL *ssl;
    SSL_CTX *ssl_ctx = NULL;
    int rv;

    ssl_ctx = SSL_CTX_new(m);
    CU_ASSERT(ssl_ctx != NULL);

    /*
     * Now that the SSL context is ready, open a socket
     * with the server and bind that socket to the context.
     */
    conn = open_tcp_socket_ipv4("127.0.0.1", "16894");
    CU_ASSERT(conn != NULL);

    /*
     * Create an SSL session context
     */
    ssl = SSL_new(ssl_ctx);
    SSL_set_bio(ssl, conn, conn);

    /*
     * Now that we have everything ready, let's initiate the TLS
     * handshake.
     */
    rv = SSL_connect(ssl);
    if (!expect_fail) {
        CU_ASSERT(rv > 0);
    } else {
        CU_ASSERT(rv <= 0);
    }

    /*
     * Cleanup all the data
     */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

}

/*
 * This test attempts to create a SSL 3.0 connection
 * with the EST server.  This should fail, as TLS 1.0
 * is not allowed.
 */
static void us894_test6 (void)
{
    LOG_FUNC_NM
    ;

    us894_test_sslversion(SSLv3_client_method(), 1);
}

/*
 * This test attempts to create a TLS 1.0 connection
 * with the EST server.  This should fail, as TLS 1.0
 * is not allowed.
 */
static void us894_test7 (void)
{
    LOG_FUNC_NM
    ;

    us894_test_sslversion(TLSv1_client_method(), 1);
}

/*
 * This test attempts to create a TLS 1.1 connection
 * with the EST server.  This should succeed.
 */
static void us894_test8 (void)
{
    LOG_FUNC_NM
    ;

    us894_test_sslversion(TLSv1_1_client_method(), 0);
}

/*
 * This test attempts to create a TLS 1.2 connection
 * with the EST server.  This should succeed.
 */
static void us894_test9 (void)
{
    LOG_FUNC_NM
    ;

    us894_test_sslversion(TLSv1_2_client_method(), 0);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the explicit cert
 * chain. This should succeed.
 */
static void us894_test10 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = st_proxy_http_disable(1);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }

    SLEEP(1);
    rv = curl_http_post_cert(US894_ENROLL_URL,
    US894_PKCS10_CT,
    US894_PKCS10_REQ,
    US894_EXPLICIT_CERT,
    US894_EXPLICIT_KEY,
    US894_CACERTS,
    NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);

    rv = st_proxy_http_disable(0);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentication is working.
 * The certificate used is signed by the implicit cert
 * chain. This should succeed.
 */
static void us894_test11 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = st_proxy_http_disable(1);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }

    SLEEP(1);
    rv = curl_http_post_cert(US894_ENROLL_URL,
    US894_PKCS10_CT,
    US894_PKCS10_REQ,
    US894_IMPLICIT_CERT,
    US894_IMPLICIT_KEY,
    US894_CACERTS, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);

    rv = st_proxy_http_disable(0);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }
}

/*
 * This test attempts to use a revoked client certificate to
 * verify CRL checks are working in the TLS layer.
 * This should fail.
 */
static void us894_test12 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_proxy_stop();
    rv = st_proxy_start(US894_TCP_PROXY_PORT,
                        US894_PROXY_CERT,
                        US894_PROXY_KEY,
                        "estrealm",
                        US894_CACERT,
                        US894_TRUSTED_CERT_AND_CRL,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US894_TCP_SERVER_PORT,
                        0,  // disable PoP
                        0);  // ecdhe nid info

    SLEEP(1);
    rv = curl_http_post_cert(US894_ENROLL_URL,
    US894_PKCS10_CT,
    US894_PKCS10_REQ,
    US894_REVOKED_CERT,
    US894_REVOKED_KEY,
    US894_CACERTS,
    NULL);


    /*
     * Since the client cert has been revoked the TLS handshake
     * will fail.  The EST server should return a 401 response.
     */
    CU_ASSERT(rv == 0);

    st_proxy_stop();
    rv = st_proxy_start(US894_TCP_PROXY_PORT,
                        US894_PROXY_CERT,
                        US894_PROXY_KEY,
                        "estrealm",
                        US894_CACERT,
                        US894_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US894_TCP_SERVER_PORT,
                        0,  // disable PoP
                        0);  // ecdhe nid info
}

/*
 * This test attempts to use a self-signed client certificate to
 * verify cert chain will reject a cert that has not been
 * signed by a valid CA.  This should fail.
 */
static void us894_test13 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_cert(US894_ENROLL_URL,
    US894_PKCS10_CT,
    US894_PKCS10_REQ,
    US894_SELFSIGN_CERT,
    US894_SELFSIGN_KEY,
    US894_CACERTS, NULL);

    /*
     * Since the client cert is not signed by either the local CA
     * or external CA, the TLS handshake will fail.
     * We will not receive an HTTP status message
     * from the server.
     */
    CU_ASSERT(rv == 0);
}

/*
 * TLS anonymous cipher suites disabled
 *
 * This test case uses libcurl to test that the
 * EST server will not accept anonymous cipher
 * suites from the client.  We only test a single
 * cipher suite here.  This attempts to do a
 * simple enroll with the server.
 */
static void us894_test14 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US894_ENROLL_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_GOOD, US894_CACERTS, CURLAUTH_BASIC,
                        "ADH-AES128-SHA256", NULL, NULL);
    /*
     * TLS handshake should have failed, curl should return 0
     */
    CU_ASSERT(rv == 0);
}

/*
 * Null HTTP realm when initializing server
 */
static void us894_test15 (void)
{
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST server using NULL realm
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(cacerts,
                         cacerts_len,
                         cacerts,
                         cacerts_len,
                         EST_CERT_FORMAT_PEM,
                         NULL,
                         x,
                         priv_key,
                         "estuser",
                         "estpwd");

    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Null Server certificate when initializing server
 */
static void us894_test16 (void)
{
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *keyin;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST proxy using NULL server key
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(cacerts,
                         cacerts_len,
                         cacerts,
                         cacerts_len,
                         EST_CERT_FORMAT_PEM,
                         "testrealm",
                         NULL,
                         priv_key,
                         "estuser",
                         "estpwd");
    CU_ASSERT(ctx == NULL);

    EVP_PKEY_free(priv_key);
}

/*
 * Null Server certificate private key when initializing server
 */
static void us894_test17 (void)
{
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *certin;
    X509 *x;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Attempt to init EST proxy using NULL private key
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(cacerts,
                         cacerts_len,
                         cacerts,
                         cacerts_len,
                         EST_CERT_FORMAT_PEM,
                         "testrealm",
                         x,
                         NULL,
                         "estuser",
                         "estpwd");
    CU_ASSERT(ctx == NULL);

    X509_free(x);
}

/*
 * Null trusted CA chain when initializing server
 */
static void us894_test18 (void)
{
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST proxy using NULL local CA chain
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(NULL,
                         0,
                         NULL,
                         0,
                         EST_CERT_FORMAT_PEM,
                         "testrealm",
                         x,
                         priv_key,
                         "estuser",
                         "estpwd");
    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Corrupted CA chain when initializing server
 */
static void us894_test19 (void)
{
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST proxy a corrupted CA chain
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init((unsigned char*) "Bogus CA chain",
                         14,
                         (unsigned char*) "Bogus CA chain",
                         14,
                         EST_CERT_FORMAT_PEM,
                         "testrealm",
                         x,
                         priv_key,
                         "estuser",
                         "estpwd");

    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * This test case attempts simple cacerts request using
 * POST instead of GET.  It should fail.
 */
static void us894_test20 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_post(US894_CACERT_URL, US894_PKCS10_CT, US894_PKCS10_REQ,
                        US894_UIDPWD_GOOD, US894_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    fclose(outfile);

    /*
     * we expect the server to respond with a 400
     */
    CU_ASSERT(rv == 400);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the explicit cert
 * chain. Valid HTTP authentication credentials are
 * also provided.  This should succeed.
 */
static void us894_test21 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_certuid(US894_ENROLL_URL,
                                US894_PKCS10_CT,
                                US894_PKCS10_REQ,
                                US894_UIDPWD_GOOD,
                                US894_EXPLICIT_CERT,
                                US894_EXPLICIT_KEY,
                                US894_CACERTS, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the explicit cert
 * chain. Invalid HTTP authentication credentials are
 * also provided.  This should fail with a 401 response.
 */
static void us894_test22 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_certuid(US894_ENROLL_URL,
                                US894_PKCS10_CT,
                                US894_PKCS10_REQ,
                                US894_UIDPWD_BAD,
                                US894_EXPLICIT_CERT,
                                US894_EXPLICIT_KEY,
                                US894_CACERTS,
                                NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);
}

/*
 * This test attempts to enroll without using a certificate
 * to identity the client, while using a good user ID/pwd.
 * However, the EST server is setup to only perform
 * certificate authentication (HTTP auth disabled).
 * This should fail with a 401 response.
 */
static void us894_test23 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = st_proxy_http_disable(1);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }

    SLEEP(1);
    rv = curl_http_post(US894_ENROLL_URL,
                        US894_PKCS10_CT,
                        US894_PKCS10_REQ,
                        US894_UIDPWD_GOOD,
                        US894_CACERTS,
                        CURLAUTH_BASIC,
                        NULL,
                        NULL,
                        NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);

    rv = st_proxy_http_disable(0);
    if (rv == -1) {
        printf("Could not set HTTP authentication callback\n");
        return;
    }

}

/*
 * Test the parameters of est_proxy_set_server()
 */
static void us894_test24 (void)
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
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * init EST in proxy mode
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(
        cacerts,
        cacerts_len,
        cacerts,
        cacerts_len,
        EST_CERT_FORMAT_PEM,
        "testrealm",
        x,
        priv_key,
        "estuser",
        "estpwd");

    CU_ASSERT(ctx != NULL);

    est_rv = est_proxy_set_server(NULL, "127.0.0.1", 8080);
    CU_ASSERT(est_rv == EST_ERR_NO_CTX);

    est_rv = est_proxy_set_server(ctx, NULL, 8080);
    CU_ASSERT(est_rv == EST_ERR_INVALID_SERVER_NAME);

    est_rv = est_proxy_set_server(ctx, "127.0.0.1", 65536);
    CU_ASSERT(est_rv == EST_ERR_INVALID_PORT_NUM);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Test the parameters of est_proxy_set_auth_mode()
 */
static void us894_test25 (void)
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
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * init EST in proxy mode
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(cacerts,
                         cacerts_len,
                         cacerts,
                         cacerts_len,
                         EST_CERT_FORMAT_PEM,
                         "testrealm",
                         x,
                         priv_key,
                         "estuser",
                         "estpwd");
    CU_ASSERT(ctx != NULL);

    est_rv = est_proxy_set_auth_mode(ctx, AUTH_NONE);
    CU_ASSERT(est_rv == EST_ERR_BAD_MODE);
    est_rv = est_proxy_set_auth_mode(ctx, AUTH_BASIC);
    CU_ASSERT(est_rv == EST_ERR_NONE);
    est_rv = est_proxy_set_auth_mode(ctx, AUTH_DIGEST);
    CU_ASSERT(est_rv == EST_ERR_NONE);
    est_rv = est_proxy_set_auth_mode(ctx, 0xffffffff);
    CU_ASSERT(est_rv == EST_ERR_BAD_MODE);

    est_rv = est_proxy_set_auth_mode(NULL, AUTH_BASIC);
    CU_ASSERT(est_rv == EST_ERR_NO_CTX);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Test the optional setting of the CA Certs response chain in est_proxy_init()
 * test passthrough (cache disabled) mode of the CA Certs response chain.
 */
static void us894_test26 (void)
{
    long rv;
    char cmd[200];

    LOG_FUNC_NM
    ;

    st_proxy_stop();
    SLEEP(1);

    /*
     * restart the proxy without passing the ca certs response change parameter
     * param 5
     */
    rv = st_proxy_start(US894_TCP_PROXY_PORT,
                        US894_PROXY_CERT,
                        US894_PROXY_KEY,
                        "estrealm",
                        NULL,
                        US894_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US894_TCP_SERVER_PORT,
                        0,  // disable PoP
                        0);  // ecdhe nid info
    SLEEP(1);

    outfile = fopen(test26_outfile, "w");
    rv = curl_http_get(US894_CACERT_URL, US894_CACERTS, &write_func);
    fclose(outfile);

    /*
     * we expect the server to respond with a 200
     */
    CU_ASSERT(rv == 200);

    sprintf(
        cmd,
        "openssl base64 -d -in %s | openssl pkcs7 -inform DER -text -print_certs",
        test26_outfile);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * restart the proxy and include the CA Cert response chain
     */
    st_proxy_stop();
    SLEEP(1);
    rv = st_proxy_start(US894_TCP_PROXY_PORT,
                        US894_PROXY_CERT,
                        US894_PROXY_KEY,
                        "estrealm",
                        US894_CACERT,
                        US894_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US894_TCP_SERVER_PORT,
                        0,  // disable PoP
                        0);  // ecdhe nid info
    SLEEP(1);
}

/*
 * Test the passing of bad userid/password values to est_proxy_init to make sure
 * they're error checked.
 */
static void us894_test27 (void)
{
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY * priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US894_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(certin, US894_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file_internal());
    rv = BIO_read_filename(keyin, US894_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST proxy using NULL userid
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_proxy_init(
        cacerts,
        cacerts_len,
        cacerts,
        cacerts_len,
        EST_CERT_FORMAT_PEM,
        "estrealm",
        x,
        priv_key,
        NULL,
        "estpwd");

    CU_ASSERT(ctx == NULL);

    ctx =
            est_proxy_init(
                cacerts,
                cacerts_len,
                cacerts,
                cacerts_len,
                EST_CERT_FORMAT_PEM,
                "estrealm",
                x,
                priv_key,
                "bad_userid_too_long_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "estpwd");

    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us894_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us894_proxy_cacerts",
            us894_init_suite,
            us894_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }


    /* add the tests to the suite */
    /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
    if ((NULL == CU_add_test(pSuite, "HTTP Basic Auth", us894_test1)) ||
        (NULL == CU_add_test(pSuite, "HTTP Basic Auth Fail", us894_test2)) ||
        (NULL == CU_add_test(pSuite, "HTTP Digest Auth", us894_test3)) ||
        (NULL == CU_add_test(pSuite, "HTTP Digest Auth Fail", us894_test4)) ||
        (NULL == CU_add_test(pSuite, "Get CA Certificates", us894_test5)) ||
        (NULL == CU_add_test(pSuite, "SSL 3.0 Fail", us894_test6)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.0 Fail", us894_test7)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.1", us894_test8)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.2", us894_test9)) ||
        (NULL == CU_add_test(pSuite, "Certificate auth - explicit cert chain", us894_test10)) ||
        (NULL == CU_add_test(pSuite, "Certificate auth - implicit cert chain", us894_test11)) ||
        (NULL == CU_add_test(pSuite, "Certificate auth - revoked cert", us894_test12)) ||
        (NULL == CU_add_test(pSuite, "Certificate auth - self-signed cert", us894_test13)) ||
        (NULL == CU_add_test(pSuite, "Anon cipher suite disabled", us894_test14)) ||
        (NULL == CU_add_test(pSuite, "NULL Realm", us894_test15)) ||
        (NULL == CU_add_test(pSuite, "NULL server cert", us894_test16)) ||
        (NULL == CU_add_test(pSuite, "NULL server key", us894_test17)) ||
        (NULL == CU_add_test(pSuite, "NULL local CA chain", us894_test18)) ||
        (NULL == CU_add_test(pSuite, "Corrupted local CA chain", us894_test19)) ||
        (NULL == CU_add_test(pSuite, "HTTP POST cacerts", us894_test20)) ||
        (NULL == CU_add_test(pSuite, "SimpleEnroll - good HTTP auth/good Cert", us894_test21)) ||
        (NULL == CU_add_test(pSuite, "SimpleEnroll - bad HTTP auth/good Cert", us894_test22)) ||
        (NULL == CU_add_test(pSuite, "SimpleEnroll - no HTTP auth/no Cert", us894_test23)) ||
        (NULL == CU_add_test(pSuite, "Set Server Invalid parameters", us894_test24)) ||
        (NULL == CU_add_test(pSuite, "Set Auth Mode Invalid parameters", us894_test25)) ||
        (NULL == CU_add_test(pSuite, "Optional CA Chain Response", us894_test26)) ||
        (NULL == CU_add_test(pSuite, "Bad userid/password for proxy init", us894_test27)))
    {
       CU_cleanup_registry();
       return CU_get_error();
    }


    return CUE_SUCCESS;
#endif
}

