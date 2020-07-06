/*------------------------------------------------------------------
 * us5367.c - Unit Tests for User Story 5367 - Server-Side Keygen
 *            via CoAP
 *
 * July, 2019
 *
 * Copyright (c) 2019 by cisco Systems, Inc.
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

#define EST_UT_MAX_CMD_LEN       512
#define US5367_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5367_CACERTS       "CA/estCA/cacert.crt"
#define US5367_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5367_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5367_MIDSIZE_CSR "US5367/midsize.csr"
#else
#define US5367_CACERTS       "CA\\estCA\\cacert.crt"
#define US5367_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5367_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5367_MIDSIZE_CSR "US5367\\midsize.csr"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

/* CU_pSuite coap_sanity_psuite = NULL; */

/*
 * Used to start server in CoAP mode
 */
#define US5367_SERVER_PORT      29001
/*
 * Used to test the CoAP init API function
 */
#define US5367_API_TEST_PORT     29002

static void us5367_clean (void)
{
}

static int us5367_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5367_SERVER_PORT,
                       US5367_SERVER_CERT_AND_KEY,
                       US5367_SERVER_CERT_AND_KEY,
                       "US5367 test realm",
                       US5367_CACERTS,
                       US5367_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
    }

    st_set_default_est_event_callbacks();
    
    return rv;

}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5367_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5367_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us5367_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5367_start_server(0, 0);

    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5367_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}

/*
 * Test /server-keygen (skg) over coap.
 */
static void us5367_test1 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;
    
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5367_CSSL_NOT_SET_MSG);
        return;
    }
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "export LD_LIBRARY_PATH=%s/lib; export PATH=%s/bin:$PATH; "
             "/usr/bin/env python ../util/est_coap_client.py --test SERVER_KEYGEN --port %d "
             " --key %s --cert %s --cacert %s --debug --csr %s",
             cssl_emulator_path,
             cssl_emulator_path,
             US5367_SERVER_PORT,
             US5367_SERVER_CERT_AND_KEY, US5367_SERVER_CERT_AND_KEY,
             US5367_CACERTS,
             US5367_MIDSIZE_CSR);

    printf("%s\n", cmd);

    rv = system(cmd);
    CU_ASSERT(rv == 0);

}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5367_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5367_SERVER_CERT_AND_KEY, US5367_TRUSTED_CERT,
                             US5367_CACERTS, US5367_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5367_CoAP_server_keygen",
            us5367_init_suite,
            us5367_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if (NULL == CU_add_test(pSuite, "Test /skg request", us5367_test1)) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    /* coap_sanity_psuite = pSuite; */
     
    return CUE_SUCCESS;
#endif
}

