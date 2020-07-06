/*------------------------------------------------------------------
 * us901.c - Unit Tests for User Story 901 - Server cacerts
 *
 * June, 2013
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

#define US901_PKCS10_REQ    "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"
#define US901_ENROLL_URL "https://127.0.0.1:29901/.well-known/est/simpleenroll"
#define US901_CACERT_URL "https://127.0.0.1:29901/.well-known/est/cacerts"
#define US901_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US901_UIDPWD_GOOD   "estuser:estpwd"
#define US901_UIDPWD_BAD    "estuser:bogus"
#define US901_SERVER_PORT 29901
#ifndef WIN32
#define US901_CACERTS       "CA/estCA/cacert.crt"
#define US901_EXPLICIT_CERT "US901/explicit-cert.pem" 
#define US901_EXPLICIT_KEY "US901/explicit-key.pem"
#define US901_IMPLICIT_CERT "US901/implicit-cert.pem" 
#define US901_IMPLICIT_KEY "US901/implicit-key.pem"
#define US901_REVOKED_CERT "US901/revoked-cert.pem" 
#define US901_REVOKED_KEY "US901/revoked-key.pem"
#define US901_SELFSIGN_CERT "US901/selfsigned-cert.pem" 
#define US901_SELFSIGN_KEY "US901/selfsigned-key.pem"
#define US901_CACERT "CA/estCA/cacert.crt"
#define US901_EXTCERT "CA/extCA/cacert.crt"
#define US901_SERVER_CERT "CA/estCA/private/estservercertandkey.pem"
#define US901_SERVER_KEY "CA/estCA/private/estservercertandkey.pem"
#define US901_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
static char test5_outfile[FILENAME_MAX] = "US901/test5.crt";
#else
#define US901_CACERTS       "CA\\estCA\\cacert.crt"
#define US901_EXPLICIT_CERT "US901\\explicit-cert.pem" 
#define US901_EXPLICIT_KEY "US901\\explicit-key.pem"
#define US901_IMPLICIT_CERT "US901\\implicit-cert.pem" 
#define US901_IMPLICIT_KEY "US901\\implicit-key.pem"
#define US901_REVOKED_CERT "US901\\revoked-cert.pem" 
#define US901_REVOKED_KEY "US901\\revoked-key.pem"
#define US901_SELFSIGN_CERT "US901\\selfsigned-cert.pem" 
#define US901_SELFSIGN_KEY "US901\\selfsigned-key.pem"
#define US901_CACERT "CA\\estCA\\cacert.crt"
#define US901_EXTCERT "CA\\extCA\\cacert.crt"
#define US901_SERVER_CERT "CA\\estCA\\private\\estservercertandkey.pem"
#define US901_SERVER_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US901_SERVER_CERTKEY "CA\\estCA\\private/estservercertandkey.pem"
static char test5_outfile[FILENAME_MAX] = "US901\\test5.crt";
#endif

static void us901_clean(void) {
    char cmd[200];
    sprintf(cmd, "rm -f %s", test5_outfile);
    system(cmd);
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us901_init_suite(void) {
    us901_clean();

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    return 0;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us901_destory_suite(void) {
    return 0;
}

/*
 * Start the appropriate flavor of st_server
 * based what character is specified
 * B - Basic auth
 * D - Digest auth
 * C - CRL checking
 * N = No auth
 */
static int us901_start_server(char server_type) {
    int rv;

    switch (server_type) {
    case 'B':
        rv = st_start(US901_SERVER_PORT,
        US901_SERVER_CERTKEY,
        US901_SERVER_CERTKEY, "estrealm", "CA/estCA/cacert.crt",
                "CA/trustedcerts.crt", "CA/estExampleCA.cnf", 0, 0, 0);
        st_enable_http_basic_auth();
        break;
    case 'D':
        rv = st_start(US901_SERVER_PORT,
        US901_SERVER_CERTKEY,
        US901_SERVER_CERTKEY, "estrealm", "CA/estCA/cacert.crt",
                "CA/trustedcerts.crt", "CA/estExampleCA.cnf", 0, 0, 0);
        st_enable_http_digest_auth();
        break;
    case 'C':
        system("openssl ca -config CA/estExampleCA.cnf -gencrl -out CA/estCA/crl.pem");
        SLEEP(1);
        system(
                "cat CA/trustedcerts.crt CA/estCA/crl.pem > US901/trustedcertsandcrl.crt");
        SLEEP(1);
        rv = st_start_crl(US901_SERVER_PORT,
        US901_SERVER_CERTKEY,
        US901_SERVER_CERTKEY, "estrealm", "CA/estCA/cacert.crt",
                "US901/trustedcertsandcrl.crt", "CA/estExampleCA.cnf", 0, 0, 0);
        st_disable_http_auth();
        break;
    case 'N':
        rv = st_start(US901_SERVER_PORT,
        US901_SERVER_CERTKEY,
        US901_SERVER_CERTKEY, "estrealm", "CA/estCA/cacert.crt",
                "CA/trustedcerts.crt", "CA/estExampleCA.cnf", 0, 0, 0);
        st_disable_http_auth();
        break;
    default:
        rv = -1;
        break;
    }

    return rv;
}

/*
 * HTTP Basic auth
 *
 * This test case uses libcurl to test HTTP Basic
 * authentication is working on the EST server.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.  The EST server should be
 * running and listing to port 8088 prior to this
 * test being run.
 */
static void us901_test1(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('B');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US901_ENROLL_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_GOOD, US901_CACERTS, CURLAUTH_BASIC,
    NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);

    st_stop();
    SLEEP(1);

}

/*
 * HTTP Basic Auth failure
 *
 * This test case uses libcurl to test HTTP Basic
 * authentication is working on the EST server,
 * while using a bogus password.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.  The EST server should be
 * running prior to this test being run.
 */
static void us901_test2(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('B');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US901_ENROLL_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_BAD, US901_CACERTS, CURLAUTH_BASIC,
    NULL, NULL, NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 400
     */
    CU_ASSERT(rv == 401);

    st_stop();
    SLEEP(1);
}

/*
 * HTTP Digest Auth
 *
 * This test case uses libcurl to test HTTP Digest
 * authentication is working on the EST server.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.  The EST server should be
 * running and listening to port 8087 prior to this
 * test being run.
 */
static void us901_test3(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);

    rv = curl_http_post(US901_ENROLL_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_GOOD, US901_CACERTS, CURLAUTH_DIGEST,
    NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with success
     */
    CU_ASSERT(rv == 200);

    st_stop();
    SLEEP(1);
}

/*
 * HTTP Digest Auth fail
 *
 * This test case uses libcurl to test HTTP Digest
 * authentication is working on the EST server.
 * This is the negative test case for Digest auth.
 * It must use a simpleenroll message since the
 * cacerts message does not require the client
 * to be authenticated.  The EST server should be
 * running and listening to port 8087 prior to this
 * test being run.
 */
static void us901_test4(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);

    rv = curl_http_post(US901_ENROLL_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_BAD, US901_CACERTS, CURLAUTH_DIGEST,
    NULL, NULL, NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with a 400
     */
    CU_ASSERT(rv == 401);
    st_stop();
    SLEEP(1);
}

static FILE *outfile;
static size_t write_func(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t written;
    written = fwrite(ptr, size, nmemb, outfile);
    return written;
}

/*
 * This test case does a simple cacerts request
 * and looks for the HTTP 200 response code.
 */
static void us901_test5(void) {
    long rv;
    char cmd[200];
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_get(US901_CACERT_URL, US901_CACERTS, &write_func);
    fclose(outfile);

    /*
     * we expect the server to respond with a 200
     */
    CU_ASSERT(rv == 200);

    sprintf(cmd,
            "openssl base64 -d -in %s | openssl pkcs7 -inform DER -text -print_certs",
            test5_outfile);
    rv = system(cmd);
    CU_ASSERT(rv == 0);
    st_stop();
    SLEEP(1);
}

#ifdef HAVE_OLD_OPENSSL
static void us901_test_sslversion(const SSL_METHOD *m, int expect_fail)
#else
static void us901_test_sslversion (const SSL_METHOD *m,
                                   int min_version, int max_version,
                                   int expect_fail)
#endif    
{
    BIO *conn;
    SSL *ssl;
    SSL_CTX *ssl_ctx = NULL;
    int rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    ssl_ctx = SSL_CTX_new(m);
    CU_ASSERT(ssl_ctx != NULL);

#ifndef HAVE_OLD_OPENSSL    
    rv = SSL_CTX_set_min_proto_version(ssl_ctx, min_version);
    CU_ASSERT(rv != 0);
    rv = SSL_CTX_set_max_proto_version(ssl_ctx, max_version);
    CU_ASSERT(rv != 0);
#endif
    /*
     * Now that the SSL context is ready, open a socket
     * with the server and bind that socket to the context.
     */
    conn = open_tcp_socket_ipv4("127.0.0.1", "29901");
    CU_ASSERT(conn != NULL);

    /*
     * Creaea SSL session context
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
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to create a SSL 3.0 connection
 * with the EST server.  This should fail, as TLS 1.0
 * is not allowed.
 */
static void us901_test6(void) {
    LOG_FUNC_NM
    ;

#ifdef HAVE_OLD_OPENSSL    
    us901_test_sslversion(SSLv3_client_method(), 1);
#else    
    us901_test_sslversion(TLS_client_method(),
                          SSL3_VERSION, SSL3_VERSION,
                          1);
#endif    
}

/*
 * This test attempts to create a TLS 1.0 connection
 * with the EST server.  This should fail, as TLS 1.0
 * is not allowed.
 */
static void us901_test7(void) {
    LOG_FUNC_NM
    ;

#ifdef HAVE_OLD_OPENSSL    
    us901_test_sslversion(TLSv1_client_method(), 1);
#else    
    us901_test_sslversion(TLS_client_method(),
                          TLS1_VERSION, TLS1_VERSION,
                          1);
#endif    
}

/*
 * This test attempts to create a TLS 1.1 connection
 * with the EST server.  This should succeed.
 */
static void us901_test8(void) {
    LOG_FUNC_NM
    ;

#ifdef HAVE_OLD_OPENSSL    
    us901_test_sslversion(TLSv1_1_client_method(), 0);
#else    
    us901_test_sslversion(TLS_client_method(),
                          TLS1_1_VERSION, TLS1_1_VERSION,
                          0);
#endif    
}

/*
 * This test attempts to create a TLS 1.2 connection
 * with the EST server.  This should succeed.
 */
static void us901_test9(void) {
    LOG_FUNC_NM
    ;

#ifdef HAVE_OLD_OPENSSL    
    us901_test_sslversion(TLSv1_2_client_method(), 0);
#else    
    us901_test_sslversion(TLS_client_method(),
                          TLS1_2_VERSION, TLS1_2_VERSION,
                          0);
#endif    
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentication is working.
 * The certificate used is signed by the explicit cert
 * chain. This should succeed.
 */
static void us901_test10(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('N');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_cert(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_EXPLICIT_CERT,
    US901_EXPLICIT_KEY,
    US901_CACERTS,
    NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the implicit cert
 * chain. This should succeed.
 */
static void us901_test11(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('N');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_cert(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_IMPLICIT_CERT,
    US901_IMPLICIT_KEY,
    US901_CACERTS,
    NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to use a revoked client certificate to
 * verify CRL checks are working in the TLS layer.
 * This should fail.
 */
static void us901_test12(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('C');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_cert(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_REVOKED_CERT,
    US901_REVOKED_KEY,
    US901_CACERTS,
    NULL);

    /*
     * Since the client cert has been revoked the TLS handshake
     * will fail.  The EST server should return a 401 response.
     */
    CU_ASSERT(rv == 0);
    st_stop();
}

/*
 * This test attempts to use a self-signed client certificate to
 * verify cert chain will reject a cert that has not been
 * signed by a valid CA.  This should fail.
 */
static void us901_test13(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_cert(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_SELFSIGN_CERT,
    US901_SELFSIGN_KEY,
    US901_CACERTS,
    NULL);

    /*
     * Since the client cert is not signed by either the local CA
     * or external CA, the TLS handshake will fail.
     * We will not receive an HTTP status message
     * from the server.
     */
    CU_ASSERT(rv == 0);
    st_stop();
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
static void us901_test14(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US901_ENROLL_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_GOOD, US901_CACERTS, CURLAUTH_BASIC, "ADH-AES128-SHA256", NULL,
            NULL);
    /*
     * TLS handshake should have failed, curl should return 0
     */
    CU_ASSERT(rv == 0);
    st_stop();
    SLEEP(1);
}

/*
 * Null HTTP realm when initializing server
 */
static void us901_test15(void) {
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US901_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(certin, US901_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(keyin, US901_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST server using NULL realm
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init(cacerts, cacerts_len, cacerts, cacerts_len,
            EST_CERT_FORMAT_PEM,
            NULL, x, priv_key);
    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Null Server certificate when initializing server
 */
static void us901_test16(void) {
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    BIO *keyin;
    EVP_PKEY *priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US901_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(keyin, US901_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST server using NULL server key
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init(cacerts, cacerts_len, cacerts, cacerts_len,
            EST_CERT_FORMAT_PEM, "testrealm", NULL, priv_key);
    CU_ASSERT(ctx == NULL);

    EVP_PKEY_free(priv_key);
}

/*
 * Null Server certificate private key when initializing server
 */
static void us901_test17(void) {
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
    cacerts_len = read_binary_file(US901_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(certin, US901_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Attempt to init EST server using NULL private key
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init(cacerts, cacerts_len, cacerts, cacerts_len,
            EST_CERT_FORMAT_PEM, "testrealm", x, NULL);
    CU_ASSERT(ctx == NULL);

    X509_free(x);
}

/*
 * Null trusted CA chain when initializing server
 */
static void us901_test18(void) {
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(certin, US901_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(keyin, US901_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST server using NULL local CA chain
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init(NULL, 0, NULL, 0, EST_CERT_FORMAT_PEM, "testrealm", x,
            priv_key);
    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * Corrupted CA chain when initializing server
 */
static void us901_test19(void) {
    BIO *certin, *keyin;
    X509 *x;
    EVP_PKEY *priv_key;
    int rv;
    EST_CTX *ctx;

    LOG_FUNC_NM
    ;

    /*
     * Read the server cert
     */
    certin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(certin, US901_SERVER_CERT);
    CU_ASSERT(rv > 0);
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    CU_ASSERT(x != NULL);
    BIO_free(certin);

    /*
     * Read the server key
     */
    keyin = BIO_new(BIO_s_file());
    rv = BIO_read_filename(keyin, US901_SERVER_KEY);
    CU_ASSERT(rv > 0);
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    CU_ASSERT(priv_key != NULL);
    BIO_free(keyin);

    /*
     * Attempt to init EST server a corrupted CA chain
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
    ctx = est_server_init((unsigned char*) "Bogus CA chain", 14,
            (unsigned char*) "Bogus CA chain", 14, EST_CERT_FORMAT_PEM,
            "testrealm", x, priv_key);
    CU_ASSERT(ctx == NULL);

    X509_free(x);
    EVP_PKEY_free(priv_key);
}

/*
 * This test case attempts simple cacerts request using
 * POST instead of GET.  It should fail.
 */
static void us901_test20(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);

    outfile = fopen(test5_outfile, "w");
    rv = curl_http_post(US901_CACERT_URL, US901_PKCS10_CT, US901_PKCS10_REQ,
    US901_UIDPWD_GOOD, US901_CACERTS, CURLAUTH_BASIC,
    NULL, NULL, NULL);
    fclose(outfile);

    /*
     * we expect the server to respond with a 400
     */
    CU_ASSERT(rv == 400);
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the explicit cert
 * chain. Valid HTTP authentication credentials are
 * also provided.  This should succeed.
 */
static void us901_test21(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('B');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_certuid(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_UIDPWD_GOOD,
    US901_EXPLICIT_CERT,
    US901_EXPLICIT_KEY,
    US901_CACERTS,
    NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to use a client certificate to
 * verify the TLS client authentiaiton is working.
 * The certificate used is signed by the explicit cert
 * chain. Invalid HTTP authentication credentials are
 * also provided.  This should fail with a 401 response.
 */
static void us901_test22(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('D');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post_certuid(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_UIDPWD_BAD,
    US901_EXPLICIT_CERT,
    US901_EXPLICIT_KEY,
    US901_CACERTS,
    NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);
    st_stop();
    SLEEP(1);
}

/*
 * This test attempts to enroll without using a certificate
 * to identity the client, while using a good user ID/pwd.
 * However, the EST server is setup to only perform
 * certificate authentication (HTTP auth disabled).
 * This should fail with a 401 response.
 */
static void us901_test23(void) {
    long rv;
    int st_rv;

    st_rv = us901_start_server('N');
    if (st_rv) {
        return;
    }

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US901_ENROLL_URL,
    US901_PKCS10_CT,
    US901_PKCS10_REQ,
    US901_UIDPWD_GOOD,
    US901_CACERTS,
    CURLAUTH_BASIC,
    NULL, NULL, NULL);
    /*
     * Since we passed in an invalid userID/password,
     * we expect the server to respond with 401
     */
    CU_ASSERT(rv == 401);
    st_stop();
    SLEEP(1);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us901_add_suite(void) {
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us901_srv_cacerts",
            us901_init_suite,
            us901_destory_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
    if ((NULL == CU_add_test(pSuite, "HTTP Basic Auth", us901_test1)) ||
            (NULL == CU_add_test(pSuite, "HTTP Basic Auth Fail", us901_test2)) ||
            (NULL == CU_add_test(pSuite, "HTTP Digest Auth", us901_test3)) ||
            (NULL == CU_add_test(pSuite, "HTTP Digest Auth Fail", us901_test4)) ||
            (NULL == CU_add_test(pSuite, "Get CA Certificates", us901_test5)) ||
            (NULL == CU_add_test(pSuite, "SSL 3.0 Fail", us901_test6)) ||
            (NULL == CU_add_test(pSuite, "TLS 1.0 Fail", us901_test7)) ||
            (NULL == CU_add_test(pSuite, "TLS 1.1", us901_test8)) ||
            (NULL == CU_add_test(pSuite, "TLS 1.2", us901_test9)) ||
            (NULL == CU_add_test(pSuite, "Certificate auth - explicit cert chain", us901_test10)) ||
            (NULL == CU_add_test(pSuite, "Certificate auth - implicit cert chain", us901_test11)) ||
            (NULL == CU_add_test(pSuite, "Certificate auth - revoked cert", us901_test12)) ||
            (NULL == CU_add_test(pSuite, "Certificate auth - self-signed cert", us901_test13)) ||
            (NULL == CU_add_test(pSuite, "Anon cipher suite disabled", us901_test14)) ||
            (NULL == CU_add_test(pSuite, "NULL Realm", us901_test15)) ||
            (NULL == CU_add_test(pSuite, "NULL server cert", us901_test16)) ||
            (NULL == CU_add_test(pSuite, "NULL server key", us901_test17)) ||
            (NULL == CU_add_test(pSuite, "NULL local CA chain", us901_test18)) ||
            (NULL == CU_add_test(pSuite, "Corrupted local CA chain", us901_test19)) ||
            (NULL == CU_add_test(pSuite, "HTTP POST cacerts", us901_test20)) ||
            (NULL == CU_add_test(pSuite, "SimpleEnroll - good HTTP auth/good Cert", us901_test21)) ||
            (NULL == CU_add_test(pSuite, "SimpleEnroll - bad HTTP auth/good Cert", us901_test22)) ||
            (NULL == CU_add_test(pSuite, "SimpleEnroll - no HTTP auth/no Cert", us901_test23)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

