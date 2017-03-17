/*------------------------------------------------------------------
 * us1190.c - Unit Tests for User Story 1190/1115 - Disable TLS 1.0 support
 *
 * September, 2014
 *
 * Copyright (c) 2014, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif 
#include <est.h>
#include "test_utils.h"
#include <openssl/ssl.h>
#include "st_server.h"

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#ifndef WIN32
#define US1190_CACERTS              "CA/estCA/cacert.crt"
#define US1190_CACERT               "CA/estCA/cacert.crt"
#define US1190_TRUSTED_CERT         "CA/trustedcerts.crt"
#define US1190_SERVER_CERT          "CA/estCA/private/estservercertandkey.pem"
#define US1190_SERVER_KEY           "CA/estCA/private/estservercertandkey.pem"
#else
#define US1190_CACERTS              "CA\\estCA\\cacert.crt"
#define US1190_CACERT               "CA\\estCA\\cacert.crt"
#define US1190_TRUSTED_CERT         "CA\\trustedcerts.crt"
#define US1190_SERVER_CERT          "CA\\estCA\\private\\estservercertandkey.pem"
#define US1190_SERVER_KEY           "CA\\estCA\\private\\estservercertandkey.pem"
#endif

#define US1190_TCP_SERVER_PORT      "15895"

static void us1190_clean (void)
{
}

int us1190_start_server ()
{
    int rv = 0;

    /*
     * Start an EST server acting as the CA
     * this server does not support TLS 1.0
     */
    rv = st_start(atoi(US1190_TCP_SERVER_PORT),
                  US1190_SERVER_CERT,
                  US1190_SERVER_KEY,
                  "estrealm",
                  US1190_CACERT,
                  US1190_TRUSTED_CERT,
                  "US1190/estExampleCA.cnf",
                  0,  // manual enroll
                  0,  // disable PoP
                  0); // ecdhe nid info
    SLEEP(1);
    if (rv != EST_ERR_NONE)
        return rv;

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us1190_init_suite (void)
{
    int rv;

    us1190_clean();

    printf("\nStarting no legacy TLS unit tests.\n");

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1190_start_server();

    return rv;
}

void us1190_stop_server ()
{
    st_stop();
    SLEEP(2);
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1190_destroy_suite (void)
{
    us1190_stop_server();
    printf("Completed EST non-compliant TLS 1.0 unit tests.\n");
    return 0;
}

static void us1190_test_sslversion (const SSL_METHOD *m, int expect_fail)
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
    conn = open_tcp_socket_ipv4("127.0.0.1", US1190_TCP_SERVER_PORT);
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
static void us1190_test1 (void)
{
    LOG_FUNC_NM
    ;

    us1190_test_sslversion(SSLv3_client_method(), 1);
}

/*
 * This test attempts to create a TLS 1.0 connection
 * with the EST server.  This should fail, as TLS 1.0
 * is not allowed.
 */
static void us1190_test2 (void)
{
    LOG_FUNC_NM
    ;

    us1190_test_sslversion(TLSv1_client_method(), 1);
}

/*
 * This test attempts to create a TLS 1.1 connection
 * with the EST server.  This should succeed.
 */
static void us1190_test3 (void)
{
    LOG_FUNC_NM
    ;

    us1190_test_sslversion(TLSv1_1_client_method(), 0);
}

/*
 * This test attempts to create a TLS 1.2 connection
 * with the EST server.  This should succeed.
 */
static void us1190_test4 (void)
{
    LOG_FUNC_NM
    ;

    us1190_test_sslversion(TLSv1_2_client_method(), 0);
}

/*
 * Assert that attempting to enable TLS 1.0
 * in an EST context results in an error
 */
static void us1190_test5 (void)
{
    int rc;

    rc = est_server_enable_tls10(NULL);

    CU_ASSERT(rc == EST_ERR_BAD_MODE);

}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us1190_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1190_1115_no_legacy_tls",
            us1190_init_suite,
            us1190_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
    if ((NULL == CU_add_test(pSuite, "SSL 3.0 fails", us1190_test1)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.0 fails", us1190_test2)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.1 works", us1190_test3)) ||
        (NULL == CU_add_test(pSuite, "TLS 1.2 works", us1190_test4)) ||
        (NULL == CU_add_test(pSuite, "enable_tls10 fails", us1190_test5)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

