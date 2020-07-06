/*------------------------------------------------------------------
 * us5241.c - Unit Tests for User Story 5241 - Rework the event notification
 * support in EST. (This test is for event notification while in HTTP transport
 * mode)
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
#define US5241_SERVER_IP         "127.0.0.1"

#ifndef WIN32
#define US5241_CACERTS       "CA/estCA/cacert.crt"
#define US5241_EXPLICIT_CERT "US5241/cert-RA.pem" 
#define US5241_EXPLICIT_KEY  "US5241/key-RA.pem"
#define US5241_TRUSTED_CERT  "CA/trustedcerts.crt"
#define US5241_SERVER_CERT_AND_KEY "CA/estCA/private/estservercertandkey.pem"
#define US5241_HUGE_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugesudichain.crt"
#define US5241_HUGE_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugeSUDI.pem"
#define US5241_HUGER_TRUSTED_CERT "CA/mfgCAs/trustedcertswithhugersudichain.crt"
#define US5241_HUGER_CERT_AND_KEY "CA/mfgCAs/sudiCA/private/certandkey2-estHugerSUDI.pem"
#define US5241_MIDSIZE_CSR "US5241/midsize.csr"
#define US5241_PROXY_CERT        "US5241/proxy_cert.pem"
#define US5241_PROXY_KEY         "US5241/proxy_key.pem"
#else
#define US5241_CACERTS       "CA\\estCA\\cacert.crt"
#define US5241_EXPLICIT_CERT "US5241\\cert-RA.pem" 
#define US5241_EXPLICIT_KEY  "US5241\\key-RA.pem"
#define US5241_TRUSTED_CERT  "CA\\trustedcerts.crt"
#define US5241_SERVER_CERT_AND_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US5241_HUGE_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugesudichain.crt"
#define US5241_HUGE_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugeSUDI.pem"
#define US5241_HUGER_TRUSTED_CERT "CA\\mfgCAs\\trustedcertswithhugersudichain.crt"
#define US5241_HUGER_CERT_AND_KEY "CA\\mfgCAs\\sudiCA\\private\\certandkey2-estHugerSUDI.pem"
#define US5241_MIDSIZE_CSR "US5241\\midsize.csr"
#define US5241_PROXY_CERT        "US5241\\proxy_cert.pem"
#define US5241_PROXY_KEY         "US5241\\proxy_key.pem"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

/*
 * Used to start server and proxy
 */
#define US5241_SERVER_PORT      29005
#define US5241_SERVER_PORT_STR  "29005"
#define US5241_PROXY_PORT       29006
#define US5241_PROXY_PORT_STR  "29006"

static EST_ENROLL_REQ_TYPE expected_reenroll = SIMPLE_ENROLL_REQ;
static char *expected_resource = NULL;
static char *expected_err_log_msg = NULL;

/*
 * Event callback routines.  Using the default st_ defined
 * handlers does not provide enough control to test
 */
static void us5241_notify_est_err_cb (char *format, va_list arg_list)
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

static void us5241_notify_ssl_proto_err_cb (char *err_msg) {

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

static void us5241_verify_subjects (char *id_cert_subj, X509 *peer_cert,
                                    char *csr_subj, X509_REQ *csr_x509, CSR_STATUS csr_status)
{
    char subj_from_cert[255];
    char subj_from_csr[255];
    int rc;

    if (peer_cert) {
        
        rc = get_subj_fld_from_cert(peer_cert, 0, &subj_from_cert[0], 255);
        CU_ASSERT(rc == 0);
        if (rc != 0) {
            printf("Failed to obtain subject from cert\n");
        }    
        CU_ASSERT(strcmp(subj_from_cert, id_cert_subj) == 0);
    }

    if (csr_status == CSR_EXPECTED) {
        rc = get_subj_fld_from_cert(csr_x509, 1, &subj_from_csr[0], 255);
        CU_ASSERT(rc == 0);
        if (rc != 0) {
            printf("Failed to obtain subject from CSR\n");
        }    
        CU_ASSERT(strcmp(subj_from_csr, csr_subj) == 0);
    }    
}

static void us5241_notify_enroll_req_cb (char *id_cert_subj, X509 *peer_cert,
                                         char *csr_subj, X509_REQ *csr_x509,
                                         char *ipstr, int port,
                                         char *path_seg, EST_ENROLL_REQ_TYPE reenroll)
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

    us5241_verify_subjects(id_cert_subj, peer_cert, csr_subj, csr_x509, CSR_EXPECTED);

    return;
}

static void us5241_notify_enroll_rsp_cb (char *id_cert_subj, X509 *peer_cert,
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

static char *us5241_print_est_auth_status (EST_AUTH_STATE rv) 
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


static char *us5241_print_est_enhanced_auth_state (EST_ENHANCED_AUTH_TS_AUTH_STATE enh_auth_ts_state) 
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


static void us5241_notify_enroll_auth_result_cb (X509 *peer_cert, char *path_seg,
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
                    state, us5241_print_est_enhanced_auth_state(state),
                    rv, us5241_print_est_auth_status(rv));
    return;
}

static void us5241_notify_endpoint_req_cb (char *id_cert_subj, X509 *peer_cert,
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

    if (expected_err_log_msg) {    
        CU_ASSERT( strstr(uri, expected_resource) != NULL);
    }
    
    fprintf(stderr, "***SRVR EVENT [%s]--> EST Endpoint Request-> %s %lu ", __FUNCTION__,
            (event_type == EST_ENDPOINT_REQ_START?"start of request":"end of request"),
            tid);
    fprintf(stderr, "TLS ID cert subject: \"%s\", "
                    "uri: \"%s\", "
                    "IP address: \"%s\",  Port: %d\n",
                    id_cert_subj, uri, ip_addr, port);
    return;
}

static void us5241_proxy_notify_endpoint_req_cb (char *id_cert_subj, X509 *peer_cert,
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

    if (expected_err_log_msg) {    
        CU_ASSERT( strstr(uri, expected_resource) != NULL);
    }
    
    fprintf(stderr, "***PROXY EVENT [%s]--> EST Endpoint Request-> %s %lu ", __FUNCTION__,
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
static st_est_event_cb_table_t  us5241_est_event_cb_table = {

    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST errors occur.
     */
    us5241_notify_est_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when SSL protocol errors occur.
     */
    us5241_notify_ssl_proto_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * requests are made.
     */
    us5241_notify_enroll_req_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * responses are received.
     */
    us5241_notify_enroll_rsp_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * authentication results are received.
     */
    us5241_notify_enroll_auth_result_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST endpoint requests
     * are received.
     */
    us5241_notify_endpoint_req_cb
};

/*
 * st_notify_event_plugin_config
 *
 * This data structure contains the notify-specific event plugin module
 * data for the st_proxy process.  Only difference is the endpoint callback
 */
static st_est_event_cb_table_t  us5241_est_proxy_event_cb_table = {

    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST errors occur.
     */
    us5241_notify_est_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when SSL protocol errors occur.
     */
    us5241_notify_ssl_proto_err_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * requests are made.
     */
    us5241_notify_enroll_req_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * responses are received.
     */
    us5241_notify_enroll_rsp_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST enroll or re-enroll
     * authentication results are received.
     */
    us5241_notify_enroll_auth_result_cb,
    
    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST endpoint requests
     * are received.
     */
    us5241_proxy_notify_endpoint_req_cb
};

static void us5241_clean (void)
{
}

static int us5241_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US5241_SERVER_PORT,
                  US5241_SERVER_CERT_AND_KEY,
                  US5241_SERVER_CERT_AND_KEY,
                  "US5241 test realm",
                  US5241_CACERTS,
                  US5241_TRUSTED_CERT,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
    }
    
    return rv;
}

/*
 * Start st_proxy and st_server in normal mode
 */
static int us5241_start_proxy_and_server (int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5241_SERVER_PORT,
                  US5241_SERVER_CERT_AND_KEY,
                  US5241_SERVER_CERT_AND_KEY,
                  "US5241 test realm",
                  US5241_CACERTS,
                  US5241_TRUSTED_CERT,
                  "CA/estExampleCA.cnf",
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy acting as an RA and in HTTP mode
     */
    rv = st_proxy_start(US5241_PROXY_PORT,
                        US5241_PROXY_CERT,
                        US5241_PROXY_KEY,
                        "US5241 test realm",
                        US5241_CACERTS,
                        US5241_TRUSTED_CERT,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US5241_SERVER_PORT,
                        0,
                        nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5241_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5241_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us5241_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us5241_start_server(0, 0);

    st_set_est_event_callbacks(&us5241_est_event_cb_table);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5241_destroy_suite (void)
{
    st_disable_est_event_callbacks();
    st_stop();
    free(cacerts);
    return 0;
}


#define US5241_ENROLL_URL_BA "https://" US5241_SERVER_IP ":" \
    US5241_SERVER_PORT_STR "/.well-known/est/simpleenroll"
#define US5241_PROXY_ENROLL_URL_BA "https://" US5241_SERVER_IP ":" \
    US5241_PROXY_PORT_STR "/.well-known/est/simpleenroll"

#define US5241_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US5241_UIDPWD_GOOD   "estuser:estpwd"
#define US5241_CACERTS       "CA/estCA/cacert.crt"
/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US5241_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US5241_PKCS10_RSA2048_CORRUPTED "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X=4444"

/*
 * This test is from US748/test1
 *
 * Simple enroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * enrollment of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void us5241_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    expected_resource = "simpleenroll";
    
    rv = curl_http_post(US5241_ENROLL_URL_BA, US5241_PKCS10_CT,
                        US5241_PKCS10_RSA2048,
                        US5241_UIDPWD_GOOD, US5241_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test is from US748/test1
 *
 * Simple enroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * enrollment of a 2048 bit RSA CSR, HOWEVER, it sends a
 * corrupted CSR.  An issue was found that a corrupted CSR will
 * cause a seg fault, so make sure the situation where a
 * corrupted CSR is handled correctly.
 */
static void us5241_test2 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    expected_resource = "simpleenroll";
    
    rv = curl_http_post(US5241_ENROLL_URL_BA, US5241_PKCS10_CT,
                        US5241_PKCS10_RSA2048_CORRUPTED,
                        US5241_UIDPWD_GOOD, US5241_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 400);
}

/*
 * Test /simpleenroll (sen) over http through a EST proxy running in HTTP
 * mode. 
 */
static void us5241_test3 (void)
{
    int rv = 0;
        
    LOG_FUNC_NM;

    printf("Stopping st_server\n");
    st_stop();

    /*
     * start the server in coap mode
     */
    rv = us5241_start_proxy_and_server(0, 0);
    if (rv != 0) {
        printf("could not start st server in coap mode");
        return;
    }

    st_proxy_set_est_event_callbacks(&us5241_est_proxy_event_cb_table);
    st_set_est_event_callbacks(&us5241_est_event_cb_table);
    
    printf("Setting expected_resource = %s\n", expected_resource);

    expected_resource = "simpleenroll";
    
    rv = curl_http_post(US5241_PROXY_ENROLL_URL_BA, US5241_PKCS10_CT,
                        US5241_PKCS10_RSA2048,
                        US5241_UIDPWD_GOOD, US5241_CACERTS, CURLAUTH_BASIC,
                        NULL, NULL, NULL);

    expected_reenroll = SIMPLE_ENROLL_REQ;
    expected_resource = NULL;
    printf("Setting expected_resource = %s\n", expected_resource);    
    
    /*
     * clean up the st_proxy and st_server
     */
    st_proxy_disable_est_event_callbacks();
    st_disable_est_event_callbacks();
    st_proxy_stop();
    st_stop();
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5241_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us5241_Event_notification(HTTP)",
                          us5241_init_suite,
                          us5241_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if (
        (NULL == CU_add_test(pSuite, "Test HTTP simpleenroll w/ events", us5241_test1)) ||
        (NULL == CU_add_test(pSuite, "Test HTTP simpleenroll w/ events and corrupt CSR", us5241_test2)) ||
        (NULL == CU_add_test(pSuite, "Test HTTP simpleenroll w/ events thru proxy", us5241_test3)) 
        ) {
        CU_cleanup_registry();
        return CU_get_error();
    }
    
    return CUE_SUCCESS;
#endif
}
