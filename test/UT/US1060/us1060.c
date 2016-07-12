/*------------------------------------------------------------------
 * us1060.c - Unit Tests for User Story 1060 - TLS SRP support (Server/Proxy)
 *
 * May, 2014
 *
 * Copyright (c) 2014-2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#include <pthread.h>
#endif
#include <est.h>
#include <curl/curl.h>
#include "test_utils.h"
#include "curl_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define US1060_SERVER_PORT      31060
#define US1060_SERVER_IP        "127.0.0.1"
#define US1060_UID              "estuser"
#define US1060_PWD              "estpwd"
#ifndef WIN32
#define US1060_CACERTS          "CA/estCA/cacert.crt"
#define US1060_TRUST_CERTS      "CA/trustedcerts.crt"
#define US1060_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
#define US1060_VFILE            "US1060/passwd.srpv"

#define US1060_EXPLICIT_CERT    "US1060/explicit-cert.pem" 
#define US1060_EXPLICIT_KEY     "US1060/explicit-key.pem"
#define US1060_SELFSIGN_CERT    "US1060/selfsigned-cert.pem" 
#define US1060_SELFSIGN_KEY     "US1060/selfsigned-key.pem"
#else
#define US1060_CACERTS          "CA\\estCA\\cacert.crt"
#define US1060_TRUST_CERTS      "CA\\trustedcerts.crt"
#define US1060_SERVER_CERTKEY   "CA\\estCA\\private\\estservercertandkey.pem"
#define US1060_VFILE            "US1060\\passwd.srpv"

#define US1060_EXPLICIT_CERT    "US1060\\explicit-cert.pem" 
#define US1060_EXPLICIT_KEY     "US1060\\explicit-key.pem"
#define US1060_SELFSIGN_CERT    "US1060\\selfsigned-cert.pem" 
#define US1060_SELFSIGN_KEY     "US1060\\selfsigned-key.pem"
#endif

#define US1060_ENROLL_URL       "https://127.0.0.1:31060/.well-known/est/simpleenroll"
#define US1060_UIDPWD_GOOD      "estuser:estpwd"
#define US1060_UIDPWD_BAD       "estuser:xxx111222"
#define US1060_PKCS10_CT        "Content-Type: application/pkcs10"

#define US1060_PROXY_ENROLL_URL "https://127.0.0.1:41060/.well-known/est/simpleenroll"
#define US1060_PROXY_PORT       41060

#define US1060_PKCS10_REQ       "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"

static char *log_search_target = NULL;
static int search_target_found = 0;
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static SRP_VBASE *srpdb = NULL;

#ifdef WIN32
CRITICAL_SECTION logger_critical_section;
#endif

/*
 * This is a simple callback used to override the default
 * logging facility in libest.  We'll use this to look
 * for specific debug output.
 */
static void us1060_logger_stderr (char *format, va_list l)
{
    char t_log[1024];
#ifndef WIN32
    flockfile(stderr);
#else
    EnterCriticalSection(&logger_critical_section);
#endif 
    if (log_search_target) {
        vsnprintf(t_log, 1024, format, l);
        if (strstr(t_log, log_search_target)) {
            search_target_found = 1;
        }
        fprintf(stderr, "%s", t_log);
    } else {
        vfprintf(stderr, format, l);
    }
    fflush(stderr);
#ifndef WIN32
    funlockfile(stderr);
#else
    LeaveCriticalSection(&logger_critical_section);
#endif
}

static int us1060_start_server (char *cert, char *key, int no_http_auth,
                                int enable_pop, int enable_srp)
{
    int rv;

    if (enable_srp) {
        rv = st_start_srp(US1060_SERVER_PORT,
                          cert,
                          key,
                          "US1060 test realm",
                          US1060_CACERTS,
                          US1060_TRUST_CERTS,
                          "CA/estExampleCA.cnf",
                          enable_pop,
                          US1060_VFILE);
    } else {
        rv = st_start(US1060_SERVER_PORT,
                      cert,
                      key,
                      "US1060 test realm",
                      US1060_CACERTS,
                      US1060_TRUST_CERTS,
                      "CA/estExampleCA.cnf",
                      0,
                      enable_pop,
                      0);
    }

    if (no_http_auth) {
        st_disable_http_auth();
    }

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us1060_init_suite (void)
{
    int rv;

#ifdef WIN32
    /* Initialize critical section on Windows*/
    InitializeCriticalSection(&logger_critical_section);
#endif

    est_init_logger(EST_LOG_LVL_INFO, &us1060_logger_stderr);

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0,
        1);

    /*
     * Start an instance of the proxy with SRP enabled
     */
    rv = st_proxy_start_srp(US1060_PROXY_PORT,
                            US1060_SERVER_CERTKEY,
                            US1060_SERVER_CERTKEY,
                            "US1060 proxy realm",
                            US1060_CACERTS,
                            US1060_TRUST_CERTS,
                            US1060_UID,
                            US1060_PWD,
                            US1060_SERVER_IP,
                            US1060_SERVER_PORT,
                            0,
                            US1060_VFILE);

    /*
     * Read in the CA certificates
     * Used for client-side API testing
     */
    cacerts_len = read_binary_file(US1060_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    srpdb = SRP_VBASE_new(NULL);
    if (!srpdb) {
        printf("\nUnable allocate SRP verifier database.  Aborting!!!\n");
    }
    if (SRP_VBASE_init(srpdb, US1060_VFILE) != SRP_NO_ERROR) {
        printf("\nUnable initialize SRP verifier database.  Aborting!!!\n");
    }

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1060_destroy_suite (void)
{
    if (srpdb) {
        SRP_VBASE_free(srpdb);
    }

    st_stop();
    st_proxy_stop();
    free(cacerts);
    return 0;
}

typedef enum {
    SRP_OFF, SRP_ON
} server_srp_mode;

typedef enum {
    SRP_GOOD, SRP_BAD, SRP_NONE,
} client_srp_mode;

typedef enum {
    HTTP_OFF, HTTP_OPTIONAL, HTTP_REQUIRED
} server_http_mode;

typedef struct {
    char *test_name;
    char *curl_cert;
    char *curl_key;
    char *curl_http_auth;
    client_srp_mode curl_srp;
    server_http_mode server_http;
    server_srp_mode server_srp;
    int expected_http_result;
} us1060_matrix;

/*
 * This is the unit test matrix for server-side SRP support.  Curl is
 * used as the EST client.  Because of this PoP is disabled on the
 * server for all test cases.  We try to cover a variety of configurations
 * and potential scenarios.  The client side variations include:
 *
 * curl_cert:  The certificate curl uses, which may be NULL
 * curl_key:   The key curl uses, which may be NULL
 * curl_http_auth:  The HTTP auth credentials used by curl.
 * client_srp_mode: Either GOOD, BAD, NONE.  Determines which SRP credentials are used
 *                  Curl.
 *
 * On the server side we configure the server using the following variations:
 *
 * server_http_mode:  HTTP auth is required, optional, or disabled.
 *                    (optional means it only occurs when TLS auth fails)
 * server_srp_mode:   SRP is either enabled or disabled on the server.
 *
 * expected_http_result:  This is the expected HTTP status code received on by Curl.
 *                        When SRP fails, this results in a failed TLS session.  Curl
 *                        returns a zero in this case since the HTTP layer can not
 *                        communicate.  If TLS succeeds, but HTTP auth fails, then
 *                        the server should return a HTTP 401 response to the client.
 *                        When enrollment succeeds, the server should send a
 *                        HTTP 200 response.
 *
 *
 */
static us1060_matrix test_matrix[] = {
    {"1", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_REQUIRED, SRP_ON, 200},
    {"2", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_REQUIRED, SRP_ON, 0},
    {"3", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON, 200},
    {"4", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OPTIONAL, SRP_ON, 200},
    {"5", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OPTIONAL, SRP_ON, 0},
    {"6", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON, 200},
    {"7", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OFF,      SRP_ON, 200},
    {"8", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OFF,      SRP_ON, 0},
    {"9", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON, 401},

    {"11", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_REQUIRED, SRP_ON, 401},
    {"12", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_REQUIRED, SRP_ON, 0},
    {"13", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_REQUIRED, SRP_ON, 401},
    {"14", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OPTIONAL, SRP_ON, 200},
    {"15", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OPTIONAL, SRP_ON, 0},
    {"16", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OPTIONAL, SRP_ON, 401},
    {"17", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OFF,      SRP_ON, 200},
    {"18", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OFF,      SRP_ON, 0},
    {"19", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OFF,      SRP_ON, 401},

    {"21", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_REQUIRED, SRP_OFF, 0},
    {"22", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_REQUIRED, SRP_OFF, 0},
    {"23", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 200},
    {"24", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OPTIONAL, SRP_OFF, 0},
    {"25", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OPTIONAL, SRP_OFF, 0},
    {"26", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200},
    {"27", NULL, NULL, US1060_UIDPWD_GOOD, SRP_GOOD, HTTP_OFF,      SRP_OFF, 0},
    {"28", NULL, NULL, US1060_UIDPWD_GOOD, SRP_BAD,  HTTP_OFF,      SRP_OFF, 0},
    {"29", NULL, NULL, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 401},

    {"31", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_REQUIRED, SRP_OFF, 0},
    {"32", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_REQUIRED, SRP_OFF, 0},
    {"33", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 401},
    {"34", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OPTIONAL, SRP_OFF, 0},
    {"35", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OPTIONAL, SRP_OFF, 0},
    {"36", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 401},
    {"37", NULL, NULL, US1060_UIDPWD_BAD, SRP_GOOD, HTTP_OFF,      SRP_OFF, 0},
    {"38", NULL, NULL, US1060_UIDPWD_BAD, SRP_BAD,  HTTP_OFF,      SRP_OFF, 0},
    {"39", NULL, NULL, US1060_UIDPWD_BAD, SRP_NONE, HTTP_OFF,      SRP_OFF, 401},

    {"40", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON,  200},
    {"41", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_ON,  401},
    {"42", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON,  200},
    {"43", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_ON,  200},
    {"44", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON,  200},
    {"45", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_ON,  200},
    {"46", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 200},
    {"47", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_OFF, 401},
    {"48", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200},
    {"49", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 200},
    {"50", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 200},
    {"51", US1060_EXPLICIT_CERT, US1060_EXPLICIT_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_OFF, 200},

    {"60", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_ON,  0},
    {"61", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_ON,  0},
    {"62", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_ON,  0},
    {"63", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_ON,  0},
    {"64", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_ON,  0},
    {"65", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_ON,  0},
    {"66", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_REQUIRED, SRP_OFF, 0},
    {"67", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_REQUIRED, SRP_OFF, 0},
    {"68", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 0},
    {"69", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OPTIONAL, SRP_OFF, 0},
    {"70", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_GOOD, SRP_NONE, HTTP_OFF,      SRP_OFF, 0},
    {"71", US1060_SELFSIGN_CERT, US1060_SELFSIGN_KEY, US1060_UIDPWD_BAD,  SRP_NONE, HTTP_OFF,      SRP_OFF, 0},
};

/*
 * This is our worker for each entry in the test matrix above.
 * We read the configuration from the entry, configure the
 * server and client as needed, and attempt a simple enroll
 * using Curl as the client.
 * The argument i is the index of the entry in the table above.
 */
static void us1060_test_matrix_item (int i)
{
    long rv;

    LOG_FUNC_NM
    ;

    printf("\nRunning matrix test %s\n", test_matrix[i].test_name);

    /*
     * Stop the server and restart it to make sure
     * it's in the correct mode.
     */
    st_stop();
    SLEEP(1);
    if (test_matrix[i].server_srp == SRP_ON) {
        rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY,
            0, 0, 1);
    } else {
        rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY,
            0, 0, 0);
    }
    CU_ASSERT(rv == 0);

    /*
     * Set the server HTTP auth configuration
     */
    switch (test_matrix[i].server_http) {
    case HTTP_OFF:
        st_disable_http_auth();
        break;
    case HTTP_OPTIONAL:
        st_enable_http_auth();
        st_set_http_auth_optional();
        break;
    case HTTP_REQUIRED:
        st_enable_http_auth();
        st_set_http_auth_required();
        break;
    }

    switch (test_matrix[i].curl_srp) {
    case SRP_GOOD:
        rv = curl_http_post_srp(US1060_ENROLL_URL, US1060_PKCS10_CT,
        US1060_PKCS10_REQ, test_matrix[i].curl_http_auth, NULL, CURLAUTH_BASIC,
            NULL, "srp_user", "srp_pwd", NULL, NULL);
        break;
    case SRP_BAD:
        rv = curl_http_post_srp(US1060_ENROLL_URL, US1060_PKCS10_CT,
        US1060_PKCS10_REQ, test_matrix[i].curl_http_auth, NULL, CURLAUTH_BASIC,
            NULL, "srp_user", "boguspwd", NULL, NULL);
        break;
    case SRP_NONE:
        /*
         * Some of the SRP disabled test cases use a client
         * certificate.
         */
        if (test_matrix[i].curl_cert) {
            rv = curl_http_post_certuid(US1060_ENROLL_URL, US1060_PKCS10_CT,
            US1060_PKCS10_REQ, test_matrix[i].curl_http_auth,
                test_matrix[i].curl_cert, test_matrix[i].curl_key,
                US1060_CACERTS, NULL);
        } else {
            rv = curl_http_post(US1060_ENROLL_URL, US1060_PKCS10_CT,
            US1060_PKCS10_REQ, test_matrix[i].curl_http_auth,
            US1060_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);
        }
        break;
    }
    CU_ASSERT(rv == test_matrix[i].expected_http_result);
    if (rv != test_matrix[i].expected_http_result) {
        printf("\nMatrix test %s failed with rv = %d\n",
            test_matrix[i].test_name, (int) rv);
    }
}

/*
 * This test case runs all the tests in the matrix
 */
static void us1060_test0 (void)
{
    int i;
    int test_cnt = sizeof(test_matrix) / sizeof(test_matrix[0]);

    for (i = 0; i < test_cnt; i++) {
        us1060_test_matrix_item(i);
    }
}

/*
 * This test case is verifies the happy path when EST
 * proxy is configured in SRP mode.  The client will attempt
 * to use SRP.  The connection between the proxy and
 * server does not use SRP.  We perform a simple enroll
 * operation.
 */
static void us1060_test200 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    /*
     * Restart the EST server with SRP disabled
     */
    st_stop();
    SLEEP(2);
    rv = us1060_start_server(US1060_SERVER_CERTKEY, US1060_SERVER_CERTKEY, 0, 0,
        0);
    CU_ASSERT(rv == 0);

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT,
    US1060_PKCS10_REQ,
    US1060_UIDPWD_GOOD, NULL, CURLAUTH_BASIC, NULL, "srp_user", "srp_pwd", NULL,
        NULL);
    /*
     * Since we passed in a valid SRP userID/password,
     * we expect the server to respond with success
     */
    CU_ASSERT(rv == 200);
}

/*
 * This test case is verifies the simple enroll fails
 * when the EST client provides a bad SRP password.
 * The connection between the proxy and server does not
 * use SRP.
 */
static void us1060_test201 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT,
    US1060_PKCS10_REQ,
    US1060_UIDPWD_GOOD, NULL, CURLAUTH_BASIC, NULL, "srp_user", "boguspwd",
        NULL, NULL);
    CU_ASSERT(rv == 0);
}

/*
 * This test case is verifies the simple enroll fails
 * when the EST client provides a bad HTTP password
 * and SRP is used.  The connection between the proxy
 * and server does not use SRP.
 */
static void us1060_test202 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT,
    US1060_PKCS10_REQ,
    US1060_UIDPWD_BAD, NULL, CURLAUTH_BASIC, NULL, "srp_user", "srp_pwd", NULL,
        NULL);
    CU_ASSERT(rv == 401);
}

/*
 * This test case is verifies the simple enroll works
 * when the EST client provides no HTTP password
 * and SRP is used.  The connection between the proxy
 * and server does not use SRP.  HTTP auth is disabled
 * on the proxy.
 */
static void us1060_test203 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    st_proxy_http_disable(1);

    rv = curl_http_post_srp(US1060_PROXY_ENROLL_URL, US1060_PKCS10_CT,
    US1060_PKCS10_REQ, NULL, NULL, CURLAUTH_NONE, NULL, "srp_user", "srp_pwd",
        NULL, NULL);
    CU_ASSERT(rv == 200);
}

int us1060_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1060_tls_srp (server/proxy)",
            us1060_init_suite,
            us1060_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /*
     * Add the tests to the suite
     *
     * ********************IMPORTANT*********************
     * Do not change the order of these tests.
     * Some of the tests stop the EST server and restart
     * it using different certs.  If you change the order
     * then false negatives may occur.
     * **************************************************
     *
     */
    if ((NULL == CU_add_test(pSuite, "TLS-SRP server: matrix master", us1060_test0)) ||
        (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll w/SRP", us1060_test200)) ||
        (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll bad SRP pwd", us1060_test201)) ||
        (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll bad HTTP pwd", us1060_test202)) ||
        (NULL == CU_add_test(pSuite, "TLS-SRP proxy: enroll w/o HTTP auth", us1060_test203)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

