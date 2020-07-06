/*------------------------------------------------------------------
 * us5240.c - Unit Tests for User Story 5240 - Rework the event notification
 * support in EST.
 *
 * November, 2018
 *
 * Copyright (c) 2018 by cisco Systems, Inc.
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
#include <pthread.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define EST_UT_MAX_CMD_LEN       512
#define US5240_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5240_CACERTS       "CA/estCA/cacert.crt"
#define US5240_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5240_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5240_MIDSIZE_CSR "US5240/midsize.csr"
#define US5240_PROXY_CERT        "US5240/proxy_cert.pem"
#define US5240_PROXY_KEY         "US5240/proxy_key.pem"

#else
#define US5240_CACERTS       "CA\\estCA\\cacert.crt"
#define US5240_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5240_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5240_MIDSIZE_CSR "US5240\\midsize.csr"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

static char *cssl_emulator_path = NULL;

static int coap_mode_support = 0;

/*
 * Used to start server in CoAP mode
 */
#define US5240_SERVER_PORT      29001
#define US5240_PROXY_PORT       29093
/*
 * Used to test the CoAP init API function
 */
#define US5240_API_TEST_PORT     29002

EST_ENROLL_REQ_TYPE expected_reenroll = SIMPLE_ENROLL_REQ;
char *expected_resource = NULL;
static char *expected_err_log_msg = NULL;


/*
 * Event callback routines.  Using the default st_* defined
 * handlers does not provide enough control to test
 */
static void us5240_notify_est_err_cb (char *format, va_list arg_list)
{
    if (expected_err_log_msg) {    
        CU_ASSERT(strstr(format, expected_err_log_msg) != NULL);
    }

    /*
     * Print the incoming EST error message.
     */
    fprintf(stderr, "***EVENT [%s]--> EST Internal Error-> ",
                    __FUNCTION__);

    vfprintf(stderr, format, arg_list);

    return;
}

static void us5240_notify_ssl_proto_err_cb (char *err_msg) {

    /*
     * Print the incoming SSL protocol error message.
     */
    fprintf(stderr, "\n***EVENT [%s]--> SSL Protocol Error-> %s\n",
                    __FUNCTION__, err_msg);

    return;
}

typedef enum {
    CSR_EXPECTED = 1,
    CSR_NOT_EXPECTED
} CSR_STATUS;

static void us5240_verify_subjects (char *id_cert_subj, X509 *peer_cert,
                                    char *csr_subj, X509_REQ *csr_x509, CSR_STATUS csr_status)
{
    char subj_from_cert[255];
    char subj_from_csr[255];
    int rc;


    rc = get_subj_fld_from_cert(peer_cert, 0, &subj_from_cert[0], 255);
    CU_ASSERT(rc == 0);
    if (rc != 0) {
        printf("Failed to obtain subject from cert\n");
    }    
    CU_ASSERT(strcmp(subj_from_cert, id_cert_subj) == 0);

    if (csr_status == CSR_EXPECTED) {
        rc = get_subj_fld_from_cert(csr_x509, 1, &subj_from_csr[0], 255);
        CU_ASSERT(rc == 0);
        if (rc != 0) {
            printf("Failed to obtain subject from CSR\n");
        }    
        CU_ASSERT(strcmp(subj_from_csr, csr_subj) == 0);
    }    
}

static void us5240_notify_enroll_req_cb (char *id_cert_subj, X509 *peer_cert,
                                         char *csr_subj, X509_REQ *csr_x509,
                                         char *ipstr, int port,
                                         char *path_seg,
                                         EST_ENROLL_REQ_TYPE reenroll)
{
    char *req;

    /*
     * Display information about this enroll request event.
     */
    if (reenroll == REENROLL_REQ) {
        req = "Re-enroll";
    } else {
        req = "Enroll";
    }
    fprintf(stderr, "\n***EVENT [%s]--> EST %s Request-> ", __FUNCTION__, req);
    fprintf(stderr, "TLS ID cert subject: %s\n"
                    "CSR subject: %s\n"
                    "IP address: %s,  Port: %d\n",
                    id_cert_subj, csr_subj, ipstr, port);

    /*
     * Make sure some of the values were what was expected
     */
    CU_ASSERT(reenroll == expected_reenroll);

    us5240_verify_subjects(id_cert_subj, peer_cert, csr_subj, csr_x509, CSR_EXPECTED);

    return;
}

static void us5240_notify_enroll_rsp_cb (char *id_cert_subj, X509 *peer_cert,
                                         char *csr_subj, X509_REQ *csr,
                                         char *ip_addr, int port,
                                         unsigned char *returned_cert,
                                         int returned_cert_len,
                                         char *path_seg,
                                         EST_ENROLL_REQ_TYPE reenroll,
                                         EST_ERROR rc) {
    char *rsp;

    /*
     * Display information about this enroll response event.
     */
    if (reenroll == REENROLL_REQ) {
        rsp = "Re-enroll";
    } else {
        rsp = "Enroll";
    }
    fprintf(stderr, "\n***EVENT [%s]--> EST %s Response-> ", __FUNCTION__, rsp);
    fprintf(stderr, "TLS ID cert subject: %s\n"
                    "CSR subject: %s\n"
                    "IP address: %s,  Port: %d\n",
                    id_cert_subj, csr_subj, ip_addr, port);
    /*
     * The newly enrolled cert could be accessed through calls to OpenSSL.
     * First convert it into an X509 structure and then use various get
     * functions to retrieve fields from the cert; such as the subject field,
     * issuer, not before/not after, etc
     *
     * Here, we just print the pointer and length to prove that the
     * buffer has been passed up.
     */
    fprintf(stderr, "Returned cert: %s, returned cert length: %d\n"
                    "status of the enroll: %s\n",
                    returned_cert, returned_cert_len, 
                    EST_ERR_NUM_TO_STR(rc));
    
    return;
}

static char *us5240_print_est_auth_status (EST_AUTH_STATE rv) 
{
    switch (rv) {
    case EST_UNAUTHORIZED:
        return ("EST_UNAUTHORIZED");
        break;
    case EST_HTTP_AUTH:
        return ("EST_HTTP_AUTH");
        break;
    case EST_HTTP_AUTH_PENDING:
        return("EST_HTTP_AUTH_PENDING");
        break;
    case EST_CERT_AUTH:
        return("EST_CERT_AUTH");
        break;
    case EST_SRP_AUTH:
        return("EST_SRP_AUTH");
        break;
    default:
        return("Invalid Auth Status value");
    }
}


static char *us5240_print_est_enhanced_auth_state (EST_ENHANCED_AUTH_TS_AUTH_STATE enh_auth_ts_state) 
{
    switch (enh_auth_ts_state) {
    case EST_ENHANCED_AUTH_TS_VALIDATED:
        return("EST_ENHANCED_AUTH_TS_VALIDATED");
        break;
    case EST_ENHANCED_AUTH_TS_NOT_VALIDATED:
        return("EST_ENHANCED_AUTH_TS_NOT_VALIDATED");
        break;
    default:
        return("Invalid Enhanced Auth State value");
    }
}


static void us5240_notify_enroll_auth_result_cb (X509 *peer_cert, char *path_seg,
                                                 EST_ENROLL_REQ_TYPE reenroll,
                                                 EST_ENHANCED_AUTH_TS_AUTH_STATE state,
                                                 EST_AUTH_STATE rv) {
    char *rsp;

    /*
     * Display information about this enroll authentication response event.
     */
    if (reenroll == REENROLL_REQ) {
        rsp = "Re-enroll";
    } else {
        rsp = "Enroll";
    }
    fprintf(stderr, "\n***EVENT [%s]--> EST %s Authentication Response-> ",
                    __FUNCTION__, rsp);
    /*
     * The attributes from the peer cert can be obtained through calls
     * to openssl X509 get functions.
     *
     * the Auth state (status of the auth check) can be checked against
     * enums defined in est.h
     */
    fprintf(stderr, "Peer cert: %p\n"
                    "path_seq: %p\n"
                    "Enhanced auth Trust store state: %d (%s)\n"
                    "auth-state: %d (%s)\n",
                    peer_cert, path_seg,
                    state, us5240_print_est_enhanced_auth_state(state),
                    rv, us5240_print_est_auth_status(rv));
    return;
}

static void us5240_notify_endpoint_req_cb (char *id_cert_subj, X509 *peer_cert,
                                           const char *uri, char *ip_addr, int port,
                                           EST_ENDPOINT_EVENT_TYPE event_type)
{
    pthread_t tid = pthread_self();
    
    /*
     * Display information about this endpoint request event.  Note that
     * the assumption is  that uri and method are printable if not null.
     */
    if (uri == NULL) {
        uri = "<URI null>";
    }

    if (expected_resource) {
        printf("expected_resource = %s, uri = %s\n", expected_resource, uri);
        CU_ASSERT( strstr(uri, expected_resource) != NULL);
    }
    
    us5240_verify_subjects(id_cert_subj, peer_cert, NULL, NULL, CSR_NOT_EXPECTED);
    
#if 0
    fprintf(stderr, "\n***EVENT [%s]--> EST Endpoint Request-> ", __FUNCTION__);
    fprintf(stderr, "TLS ID cert subject: %s\n"
                    "uri: %s\n"
                    "IP address: %s,  Port: %d\n",
                    id_cert_subj, uri, ip_addr, port);
#endif
    fprintf(stderr, "***SRVR EVENT [%s]--> EST Endpoint Request-> %s %lu ", __FUNCTION__,
            (event_type == EST_ENDPOINT_REQ_START?"start of request":"end of request"),
            tid);
    fprintf(stderr, "TLS ID cert subject: \"%s\", "
                    "uri: \"%s\", "
                    "IP address: \"%s\",  Port: %d\n",
                    id_cert_subj, uri, ip_addr, port);

    return;
}


/*
 * st_notify_event_plugin_config
 *
 * This data structure contains the notify-specific event plugin module
 * data.
 */
static st_est_event_cb_table_t  us5240_est_event_cb_table = {

    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST errors occur.
     */
    us5240_notify_est_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when SSL protocol errors occur.
     */
    us5240_notify_ssl_proto_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * requests are made.
     */
    us5240_notify_enroll_req_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * responses are received.
     */
    us5240_notify_enroll_rsp_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * authentication results are received.
     */
    us5240_notify_enroll_auth_result_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST endpoint requests
     * are received.
     */
    us5240_notify_endpoint_req_cb
};

static void us5240_clean (void)
{
}

/*
 * Start an instance of st_server in coap mode
 */
static int us5240_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_coap(US5240_SERVER_PORT,
                       US5240_SERVER_CERT_AND_KEY,
                       US5240_SERVER_CERT_AND_KEY,
                       "US5240 test realm",
                       US5240_CACERTS,
                       US5240_TRUSTED_CERT,
                       "CA/estExampleCA.cnf",
                       manual_enroll,
                       0,
                       nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_server\n");
    }
    
    return rv;
}

/*
 * Start st_proxy in coap mode and st_server in normal mode
 */
static int us5240_start_proxy_and_server (int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5240_SERVER_PORT,
                  US5240_SERVER_CERT_AND_KEY,
                  US5240_SERVER_CERT_AND_KEY,
                  "US5240 test realm",
                  US5240_CACERTS,
                  US5240_TRUSTED_CERT,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy acting as an RA and in CoAP mode
     */
    rv = st_proxy_start_coap(US5240_PROXY_PORT,
                             US5240_PROXY_CERT,
                             US5240_PROXY_KEY,
                             "US5240 test realm",
                             US5240_CACERTS,
                             US5240_TRUSTED_CERT,
                             "estuser",
                             "estpwd",
                             "127.0.0.1",
                             US5240_SERVER_PORT,
                             0,
                             0,
                             nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 *
 * Move all the st_server management into the individual
 * tests in order to start st_server in different modes
 */
static int us5240_init_suite (void)
{
    int rv = 0;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5240_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us5240_clean();
    
    cssl_emulator_path = getenv("COAP_EMU_SSL");
    
    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5240_destroy_suite (void)
{
    free(cacerts);
    return 0;
}

/*
 * Test /cacerts (crts) over coap.
 */
static void us5240_test1 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;

    /*
     * start the server in coap mode
     */
    rv = us5240_start_server(0, 0);
    if (rv != 0) {
        printf("could not start st server in coap mode");
        return;
    }    
    st_set_est_event_callbacks(&us5240_est_event_cb_table);    
    
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5240_CSSL_NOT_SET_MSG);
        st_disable_est_event_callbacks();
        st_stop();
        return;
    }

    expected_resource = "crts";
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "export LD_LIBRARY_PATH=%s/lib; export PATH=%s/bin:$PATH; "
             "/usr/bin/env python ../util/est_coap_client.py --test GET_CACERTS --port %d "
             " --key %s --cert %s --cacert %s --debug --csr %s",
             cssl_emulator_path,
             cssl_emulator_path,
             US5240_SERVER_PORT,
             US5240_SERVER_CERT_AND_KEY, US5240_SERVER_CERT_AND_KEY,
             US5240_CACERTS,
             US5240_MIDSIZE_CSR);

    printf("%s\n", cmd);

    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * clean up the st_server
     */
    st_disable_est_event_callbacks();
    st_stop();
}


/*
 * Test /simpleenroll (sen) over coap.
 */
static void us5240_test2 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;
    
    /*
     * start the server in coap mode
     */
    rv = us5240_start_server(0, 0);
    if (rv != 0) {
        printf("could not start st server in coap mode");
        return;
    }    
    st_set_est_event_callbacks(&us5240_est_event_cb_table);
    
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5240_CSSL_NOT_SET_MSG);
        st_disable_est_event_callbacks();
        st_stop();
        return;
    }

    expected_reenroll = SIMPLE_ENROLL_REQ;
    expected_resource = "sen";
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "export LD_LIBRARY_PATH=%s/lib; export PATH=%s/bin:$PATH; "
             "/usr/bin/env python ../util/est_coap_client.py --test SIMPLE_ENROLL --port %d "
             " --key %s --cert %s --cacert %s --debug --csr %s",
             cssl_emulator_path,
             cssl_emulator_path,
             US5240_SERVER_PORT,
             US5240_SERVER_CERT_AND_KEY, US5240_SERVER_CERT_AND_KEY,
             US5240_CACERTS,
             US5240_MIDSIZE_CSR);

    printf("%s\n", cmd);

    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * clean up the st_server
     */
    st_disable_est_event_callbacks();
    st_stop();
}
 

/*
 * Test /simplereenroll (sren) over coap.
 */
static void us5240_test3 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
        
    LOG_FUNC_NM;
    
    /*
     * start the server in coap mode
     */
    rv = us5240_start_server(0, 0);
    if (rv != 0) {
        printf("could not start st server in coap mode");
        return;
    }    
    st_set_est_event_callbacks(&us5240_est_event_cb_table);
    
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5240_CSSL_NOT_SET_MSG);
        st_disable_est_event_callbacks();
        st_stop();
        return;
    }

    expected_reenroll = REENROLL_REQ;
    expected_resource = "sren";
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "export LD_LIBRARY_PATH=%s/lib; export PATH=%s/bin:$PATH; "
             "/usr/bin/env python ../util/est_coap_client.py --test SIMPLE_REENROLL --port %d "
             " --key %s --cert %s --cacert %s --debug --csr %s",
             cssl_emulator_path,
             cssl_emulator_path,
             US5240_SERVER_PORT,
             US5240_SERVER_CERT_AND_KEY, US5240_SERVER_CERT_AND_KEY,
             US5240_CACERTS,
             US5240_MIDSIZE_CSR);

    printf("%s\n", cmd);

    rv = system(cmd);
    CU_ASSERT(rv == 0);

    expected_reenroll = SIMPLE_ENROLL_REQ;

    /*
     * clean up the st_server
     */
    st_disable_est_event_callbacks();
    st_stop();
}
 

/*
 * Test /simplereenroll (sren) over coap through a EST proxy running in coap
 * mode.  Also, force an EST error while in proxy mode to make sure the global
 * est error event notificationn works in proxy mode.
 */
static void us5240_test4 (void)
{
    char cmd[EST_UT_MAX_CMD_LEN];
    int rv = 0;
    EST_CTX *est_ctx = NULL;
        
    LOG_FUNC_NM;
    
    /*
     * start the server in coap mode
     */
    rv = us5240_start_proxy_and_server(0, 0);
    if (rv != 0) {
        printf("could not start st server in coap mode");
        return;
    }
    st_proxy_set_default_est_event_callbacks();
    st_set_default_est_event_callbacks();
    
    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5240_CSSL_NOT_SET_MSG);
        st_disable_est_event_callbacks();
        st_proxy_stop();
        st_stop();
        return;
    }

    expected_reenroll = REENROLL_REQ;
    expected_resource = "sren";
    printf("Setting expected_resource = %s\n", expected_resource);
    
    /*
     * Build the est client over coap emulator command and issue it
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "export LD_LIBRARY_PATH=%s/lib; export PATH=%s/bin:$PATH; "
             "/usr/bin/env python ../util/est_coap_client.py --test SIMPLE_REENROLL --port %d "
             " --key %s --cert %s --cacert %s --debug --csr %s",
             cssl_emulator_path,
             cssl_emulator_path,
             US5240_PROXY_PORT,
             US5240_SERVER_CERT_AND_KEY, US5240_SERVER_CERT_AND_KEY,
             US5240_CACERTS,
             US5240_MIDSIZE_CSR);

    printf("%s\n", cmd);

    rv = system(cmd);
    CU_ASSERT(rv == 0);

    expected_reenroll = SIMPLE_ENROLL_REQ;
    expected_resource = NULL;
    printf("Setting expected_resource = %s\n", expected_resource);
    
    /*
     * call a server API entry point with invalid parameters.
     * Set the expected error message so it can be checked in the event handler
     */
    (void)est_ctx;
    expected_err_log_msg = "Trusted CA certificate set is empty";
    est_ctx = est_proxy_init(NULL, 0, NULL, 0, EST_CERT_FORMAT_PEM, NULL, NULL, NULL, NULL, NULL);
    expected_err_log_msg = NULL;
    
    /*
     * clean up the st_proxy
     */
    st_proxy_disable_est_event_callbacks();
    st_disable_est_event_callbacks();
    st_proxy_stop();
    st_stop();
}


/*
 * Test the correct logging of an EST error log entry.  Force an
 * error level EST log message by calling est_server_init() with
 * a NULL pointer for a CA certificate buffer.
 */
static void us5240_test5 (void)
{
    EST_CTX *est_ctx = NULL;
    
    LOG_FUNC_NM;
    
    /*
     * call a server API entry point with invalid parameters.
     * Set the expected error message so it can be checked in the event handler
     */
    (void)est_ctx;
    expected_err_log_msg = "Trusted CA certificate set is empty";
    est_ctx = est_server_init(NULL, 0, NULL, 0, EST_CERT_FORMAT_PEM, NULL, NULL, NULL);
    expected_err_log_msg = NULL;
}


/*
 * Test that EST ctx is checked for NULL on the four event notification
 * set functions that require an EST context.
 */
static void us5240_test6 (void)
{
    LOG_FUNC_NM;

    expected_err_log_msg = "NULL EST context specified to";
    
    /*
     * Call each of the callback registration API functions that take a 
     * ctx and verify that they check that the ctx is not NULL
     */
    est_set_enroll_req_event_cb(NULL, us5240_notify_enroll_req_cb);
    est_set_enroll_rsp_event_cb(NULL, us5240_notify_enroll_rsp_cb);    
    est_set_enroll_auth_result_event_cb(NULL, us5240_notify_enroll_auth_result_cb);
    est_set_endpoint_req_event_cb(NULL, us5240_notify_endpoint_req_cb);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5240_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5240_SERVER_CERT_AND_KEY, US5240_TRUSTED_CERT,
                             US5240_CACERTS, US5240_API_TEST_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild "
               "using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5240_Event_notification",
                          us5240_init_suite,
                          us5240_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {

        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "Test /crts request", us5240_test1)) ||
            (NULL == CU_add_test(pSuite, "Test /sen request", us5240_test2))  ||
            (NULL == CU_add_test(pSuite, "Test /sren request", us5240_test3)) ||
            (NULL == CU_add_test(pSuite, "Test /sren request thru proxy", us5240_test4)) ||
            (NULL == CU_add_test(pSuite, "Test error log entry", us5240_test5)) ||
            (NULL == CU_add_test(pSuite, "Check the context parameter", us5240_test6)) 
/*             (NULL == CU_add_test(pSuite, "Test huge handshake record", us5240_test5)) */
            ) {
            CU_cleanup_registry();
            return CU_get_error();
        }
    }

    return CUE_SUCCESS;
#endif
}
