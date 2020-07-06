/*------------------------------------------------------------------
 * us3512.c - Unit Tests URI path segment support in the Server
 *
 * April, 2016
 *
 * Copyright (c) 2016 by cisco Systems, Inc.
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
#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif
#include "../../util/test_utils.h"
#include "st_server.h"
#include "st_proxy.h"

#include "../../src/est/est_locl.h"

extern char tst_srvr_path_seg_enroll[];
extern char tst_srvr_path_seg_cacerts[];
extern char tst_srvr_path_seg_csrattrs[];
extern char tst_srvr_path_seg_auth[];
extern char tst_proxy_path_seg_auth[];

static int path_segment_support;

/*
 * max command line length when generating system commands
 */
#define EST_UT_MAX_CMD_LEN 256

#define US3512_SERVER_PORT      29496
#define US3512_SERVER_IP        "127.0.0.1"
#define US3512_UIDPWD_GOOD      "estuser:estpwd"
#define US3512_UID              "estuser"
#define US3512_PWD              "estpwd"
#ifndef WIN32
#define US3512_CACERTS          "CA/estCA/cacert.crt"
#define US3512_TRUST_CERTS      "CA/trustedcerts.crt"
#define US3512_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
#define US3512_PROXY_CERT       "CA/estCA/private/estservercertandkey.pem"
#define US3512_PROXY_KEY        "CA/estCA/private/estservercertandkey.pem"
#define US3512_CACERT           "CA/estCA/cacert.crt"
/*
 * The CA certificate used to verify the EST server.  Grab it from the server's directory
 */
/* #define CLIENT_UT_CACERT "../../example/server/estCA/cacert.crt" */
#define CLIENT_UT_CACERT        "CA/estCA/cacert.crt"
#define CLIENT_UT_PUBKEY        "./est_client_ut_keypair"
#else
#define US3512_CACERTS          "CA\\estCA\\cacert.crt"
#define US3512_TRUST_CERTS      "CA/trustedcerts.crt"
#define US3512_SERVER_CERTKEY   "CA\\estCA/private/estservercertandkey.pem"
#define US3512_PROXY_CERT       "CA\\estCA\\private/estservercertandkey.pem"
#define US3512_PROXY_KEY        "CA\\estCA\\private\\estservercertandkey.pem"
#define US3512_CACERT           "CA\\estCA\\cacert.crt"
/*
 * The CA certificate used to verify the EST server.  Grab it from the server's directory
 */
/* #define CLIENT_UT_CACERT "../../example/server/estCA/cacert.crt" */
#define CLIENT_UT_CACERT        "CA\\estCA\\cacert.crt"
#define CLIENT_UT_PUBKEY        "est_client_ut_keypair"
#endif

#define US3512_ENROLL_URL_BA "https://127.0.0.1:29496/.well-known/est/cacerts-somestring/simpleenroll"
#define US3512_ENROLL_URL_BA_BACKSLASH "https://127.0.0.1:29496/.well-known/est/cacerts-\\somestring/simpleenroll"
#define US3512_ENROLL_URL_BA_NOSEGMENT "https://127.0.0.1:29496/.well-known/est/simpleenroll"
#define US3512_PKCS10_CT        "Content-Type: application/pkcs10" 

#define US3512_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

#define US3512_TCP_PROXY_PORT       16894
#define PATH_SEG_VALID    "somestring"
#define PATH_SEG_TOO_MANY_SEGS    "somestring1/somestring2"
#define PATH_SEG_IS_OPERATION    "cacerts"
#define PATH_SEG_CONTAINS_OPERATION    "cacertssomestring"
#define PATH_SEG_MAX "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
#define PATH_SEG_TOO_LONG "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"

#define US3512_PROXY_ENROLL_URL_VALID "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_VALID"/simpleenroll"
#define US3512_PROXY_ENROLL_URL_TOO_LONG "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_TOO_LONG"/simpleenroll"
#define US3512_PROXY_ENROLL_URL_MAX "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_MAX"/simpleenroll"
#define US3512_PROXY_ENROLL_URL_TOO_MANY "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_TOO_MANY_SEGS"/simpleenroll"
#define US3512_PROXY_ENROLL_URL_IS_OPERATION "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_IS_OPERATION"/simpleenroll"
#define US3512_PROXY_ENROLL_URL_CONTAINS_OPERATION "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_CONTAINS_OPERATION"/simpleenroll"
#define US3512_PROXY_CACERTS_URL_VALID "https://127.0.0.1:16894/.well-known/est/"PATH_SEG_VALID"/cacerts"

#define US3512_PKCS10_REQ    "MIIChjCCAW4CAQAwQTElMCMGA1UEAxMccmVxIGJ5IGNsaWVudCBpbiBkZW1vIHN0\nZXAgMjEYMBYGA1UEBRMPUElEOldpZGdldCBTTjoyMIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA/6JUWpXXDwCkvWPDWO0yANDQzFMxroLEIh6/vdNwfRSG\neNGC0efcL5L4NxHZOmO14yqMEMGpCyHz7Ob3hhNPu0K81gMUzRqzwmmJHXwRqobA\ni59OQEkHaPhI1T4RkVnSYZLOowSqonMZjWbT0iqZDY/RD8l3GjH3gEIBMQFv62NT\n1CSu9dfHEg76+DnJAhdddUDJDXO3AWI5s7zsLlzBoPlgd4oK5K1wqEE2pqhnZxei\nc94WFqXQ1kyrW0POVlQ+32moWTQTFA7SQE2uEF+GBXsRPaEO+FLQjE8JHOewLf/T\nqX0ngywnvxKRpKguSBic31WVkswPs8E34pjjZAvdxQIDAQABoAAwDQYJKoZIhvcN\nAQEFBQADggEBAAZXVoorRxAvQPiMNDpRZHhiD5O2Yd7APBBznVgRll1HML5dpgnu\nXY7ZCYwQtxwNGYVtKJaZCiW7dWrZhvnF5ua3wUr9R2ZNoLwVR0Z9Y5wwn1cJrdSG\ncUuBN/0XBGI6g6fQlDDImQoPSF8gygcTCCHba7Uv0i8oiCiwf5UF+F3NYBoBL/PP\nlO2zBEYNQ65+W3YgfUyYP0Cr0NyXgkz3Qh2Xa2eRFeW56oejmcEaMjq6yx7WAC2X\nk3w1G6Le1UInzuenMScNgnt8FaI43eAILMdLQ/Ekxc30fjxA12RDh/YzDYiExFv0\ndPd4o5uPKt4jRitvGiAPm/OCdXiYAwqiu2w=\n"

static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error);

static void us3512_clean (void)
{
}

static int us3512_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start_nocacerts(US3512_SERVER_PORT,
                            US3512_SERVER_CERTKEY,
                            US3512_SERVER_CERTKEY,
                            "US3512 test realm",
                            US3512_CACERTS,
                            US3512_TRUST_CERTS,
                            "CA/estExampleCA.cnf",
                            manual_enroll,
                            0,
                            nid);

    SLEEP(1);

    /*
     * Next we start an EST proxy acting as an RA.
     */
    rv = st_proxy_start_nocacerts(US3512_TCP_PROXY_PORT,
                                  US3512_PROXY_CERT,
                                  US3512_PROXY_KEY,
                                  "estrealm",
                                  US3512_CACERT,
                                  US3512_TRUST_CERTS,
                                  "estuser",
                                  "estpwd",
                                  "127.0.0.1",
                                  US3512_SERVER_PORT,
                                  0,  // disable PoP
                                  0);  // ecdhe nid info
    SLEEP(1);

    return rv;
}

static int path_seg_supported (void)
{

    EST_CTX *ectx;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;

    SLEEP(1);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);

    free(cacerts);
    rc = est_client_set_server(ectx, US3512_SERVER_IP, US3512_SERVER_PORT,
        "test_segment");

    if (ectx) est_destroy(ectx);

    if (rc == EST_ERR_NONE) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.
 * 1. Generate the keypair to be used for this EST Client UT suite
 */
static int us3512_init_suite (void)
{
    int rv = 0;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    char cmd[EST_UT_MAX_CMD_LEN];
    printf("Starting EST Server path segment unit tests.\n");

    if (!path_segment_support) {
        printf(
            "URI Path Segment is not supported in this build of EST.  Rebuild using --with-uriparser-dir \n");
        return 0;
    }

    /*
     * gen the keypair to be used for EST Client testing
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
        "openssl ecparam -name prime256v1 -genkey -out %s",
        CLIENT_UT_PUBKEY);
    printf("%s\n", cmd);

    rv = system(cmd);

    /*
     * start the server for the tests that need to talk to a server
     */
    us3512_clean();
    /*
     * Start an instance of the EST server
     */
    rv = us3512_start_server(0, 0);
    SLEEP(2);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us3512_destroy_suite (void)
{

    st_stop();
    st_proxy_stop();
    return 0;
}

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
{
    BIO * bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;

    /*
     * Print out the specifics of this cert
     */
    printf(
        "%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
        __FUNCTION__, openssl_cert_error,
        X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
#ifdef HAVE_OLD_OPENSSL    
    X509_get0_signature((ASN1_BIT_STRING **)&cur_cert_sig,
                        (X509_ALGOR **)&cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, (X509_ALGOR *)cur_cert_sig_alg,
                         (ASN1_BIT_STRING *)cur_cert_sig);
#else    
    X509_get0_signature(&cur_cert_sig, &cur_cert_sig_alg, cur_cert);
    X509_signature_print(bio_err, cur_cert_sig_alg, cur_cert_sig);
#endif    

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
    }

    BIO_free(bio_err);

    return approve;
}

/*
 * Sanity check of the server side path segment processing.
 * - simple enroll
 * - direct to server
 * - with path segment
 * Outcome: pass
 */
static void us3512_test1 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    rv = curl_http_post(US3512_ENROLL_URL_BA_NOSEGMENT, US3512_PKCS10_CT,
    US3512_PKCS10_RSA2048,
    US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);

    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

static EVP_PKEY * generate_private_key (void)
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

/*
 * This function performs a basic simple enroll using
 * a UID/PWD to identify the client to the server.  This
 * is used for a variety of test cases in this module.
 */
static void us3512_simple_enroll (char *cn, char *server,
                                  EST_ERROR expected_enroll_rv,
                                  char *path_segment)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US3512_UID, US3512_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US3512_SERVER_PORT, path_segment);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, cn, &pkcs7_len, key);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

/*
 * taken from US899/test1
 * Simple enroll -  including a path segment in the uri.
 *
 * Path Segment testing
 * - This verifies the client includes a configured
 *   path segment properly and sends it.
 * - This verifies that the server correctly parses out
 *   a valid path segment and passes it up on a simple enroll.
 *
 */
static void us3512_test2 (void)
{
    LOG_FUNC_NM
    ;
    char *path_segment = "path_segment";

    memset(tst_srvr_path_seg_auth, 0, EST_MAX_PATH_SEGMENT_LEN + 1);
    memset(tst_srvr_path_seg_enroll, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    us3512_simple_enroll("TC3512-2", US3512_SERVER_IP, EST_ERR_NONE,
        path_segment);

    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_auth) == 0);
    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_enroll) == 0);
}

/*
 * taken from US898/test1
 * Simple re-enroll -  including a path segment in the uri.
 *
 * Path Segment testing
 * - Verifies the client includes a configured
 *   path segment
 * - Verifies that the server correctly parses out
 *   a valid path segment and passes it up on a simple re-enroll
 *   as well as the auth callback.
 */
static void us3512_test3 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    PKCS7 *p7 = NULL;
    BIO *b64, *out;
    X509 *cert = NULL;
    STACK_OF(X509) * certs = NULL;
    int i;
    unsigned char *attr_data = NULL;
    int attr_len;
    char *path_segment = "path_seg_us3512_test3";
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US3512_UID, US3512_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US3512_SERVER_IP, US3512_SERVER_PORT,
        path_segment);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, "TC-US898-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE)
        return;

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ectx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Convert the cert to an X509.  Be warned this is
     * pure hackery.
     */
    b64 = BIO_new(BIO_f_base64());
    out = BIO_new_mem_buf(new_cert, pkcs7_len);
    out = BIO_push(b64, out);
    p7 = d2i_PKCS7_bio(out, NULL);
    CU_ASSERT(p7 != NULL);
    BIO_free_all(out);
    i = OBJ_obj2nid(p7->type);
    switch (i) {
    case NID_pkcs7_signed:
        certs = p7->d.sign->cert;
        break;
    case NID_pkcs7_signedAndEnveloped:
        certs = p7->d.signed_and_enveloped->cert;
        break;
    default:
        break;
    }
    CU_ASSERT(certs != NULL);
    if (!certs)
        return;
    /* our new cert should be the one and only
     * cert in the pkcs7 blob.  We shouldn't have to
     * iterate through the full list to find it. */
    cert = sk_X509_value(certs, 0);
    CU_ASSERT(cert != NULL);

    /*
     * Wow, that's a lot of work, but we finally have the X509.
     * (don't you just love OpenSSL!!!)
     * Now that we have an X509 representation of the cert,
     * let's try to re-enroll this cert with the CA
     */
    memset(tst_srvr_path_seg_auth, 0, EST_MAX_PATH_SEGMENT_LEN + 1);
    memset(tst_srvr_path_seg_enroll, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_auth) == 0);
    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_enroll) == 0);

    /*
     * Cleanup
     */
    if (cert)
        X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

/*
 * taken from US897/test11
 * CAcerts to the server - including a path segment in the uri.
 *
 * Path Segment testing
 * - Verifies the client includes a configured
 *   path segment
 * - Verifies that the server correctly parses out
 *   a valid path segment and passes it up on the CA certs callback.
 */
static void us3512_test4 (void)
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;

    unsigned char *retrieved_cacerts = NULL;
    int retrieved_cacerts_len = 0;
    EVP_PKEY * priv_key;

    char *path_segment = "path_seg_us3512_test4";

    SLEEP(1);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
        printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US3512_SERVER_IP, US3512_SERVER_PORT,
        path_segment);

    /*
     * clear out the global that proves that the path segment
     * made it to the application layer's cal back function
     */
    memset(tst_srvr_path_seg_cacerts, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);
    /*
     * verify that the path segment made it all the way to the callback function
     * at the application layer
     */
    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_cacerts) == 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);

    rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

    /*
     * output the retrieved ca certs and compare to what they should be
     */
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);
    }
    free(retrieved_cacerts);

    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}

/*
 * taken from US898/test1
 * CSRAttributes -  including a path segment in the uri.
 *
 * Path Segment testing
 * - Verifies the client includes a configured
 *   path segment
 * - Verifies that the server correctly parses out
 *   a valid path segment and passes it up on a csr attributes callback
 */
static void us3512_test5 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;
    char *path_segment = "path_seg_us3512_test5";
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;

    LOG_FUNC_NM
    ;

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US3512_UID, US3512_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US3512_SERVER_IP, US3512_SERVER_PORT,
        path_segment);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * clear out the global that proves that the path segment
     * made it to the application layer's cal back function
     */
    memset(tst_srvr_path_seg_csrattrs, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    /*
     * issue the get ca certs request
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rv == EST_ERR_NONE);
    /*
     * verify that the path segment made it all the way to the callback function
     * at the application layer
     */
    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_csrattrs) == 0);

    /*
     * Cleanup
     */
    if (cert)
        X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

/*
 * Test the flow of path segments through proxy mode - valid path segment
 * SimpleEnroll
 */
static void us3512_test6 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);

    memset(tst_srvr_path_seg_enroll, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    rv = curl_http_post(US3512_PROXY_ENROLL_URL_VALID, US3512_PKCS10_CT,
    US3512_PKCS10_REQ, US3512_UIDPWD_GOOD,
    US3512_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);

    CU_ASSERT(strcmp(PATH_SEG_VALID, tst_srvr_path_seg_enroll) == 0);

    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}

/*
 * Test the flow of path segments through proxy mode -
 *  path segment is set to the maximum size
 *
 */
static void us3512_test7 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US3512_PROXY_ENROLL_URL_MAX, US3512_PKCS10_CT,
    US3512_PKCS10_REQ, US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL,
        NULL, NULL);
    /*
     * Since we passed in a path segment that is too long, it
     * should get caught at the proxy and a 400 should be returned
     */
    CU_ASSERT(rv == 200);
}

/*
 * Test the flow of path segments through proxy mode -
 *  path segment that is too large
 *
 */
static void us3512_test8 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US3512_PROXY_ENROLL_URL_TOO_LONG, US3512_PKCS10_CT,
    US3512_PKCS10_REQ, US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL,
        NULL, NULL);
    /*
     * Since we passed in a path segment that is too long, it
     * should get caught at the proxy and a 400 should be returned
     */
    CU_ASSERT(rv == 404);
}

/*
 * Test segment that is an operation path
 *
 */
static void us3512_test9 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US3512_PROXY_ENROLL_URL_IS_OPERATION, US3512_PKCS10_CT,
    US3512_PKCS10_REQ, US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL,
        NULL, NULL);
    /*
     * Since we passed in a path segment that equals an operation we
     * should get a 400 in return
     */
    CU_ASSERT(rv == 404);
}

/*
 * Test segment that is an operation path
 *
 */
static void us3512_test10 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);
    rv = curl_http_post(US3512_PROXY_ENROLL_URL_TOO_MANY, US3512_PKCS10_CT,
    US3512_PKCS10_REQ, US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL,
        NULL, NULL);
    /*
     * Since we passed in a path segment that equals an operation we
     * should get a 400 in return
     */
    CU_ASSERT(rv == 400);
}

/*
 * Test segment that contains a valid operation string within it,
 * in this case, at the front.  This is a valid path segment, so
 * the test should pass.
 *
 */
static void us3512_test11 (void)
{
    long rv;

    LOG_FUNC_NM
    ;

    SLEEP(1);

    memset(tst_srvr_path_seg_enroll, 0, EST_MAX_PATH_SEGMENT_LEN + 1);
    memset(tst_proxy_path_seg_auth, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    rv = curl_http_post(US3512_PROXY_ENROLL_URL_CONTAINS_OPERATION,
    US3512_PKCS10_CT, US3512_PKCS10_REQ,
    US3512_UIDPWD_GOOD, US3512_CACERTS, CURLAUTH_BASIC, NULL, NULL, NULL);

    CU_ASSERT(
        strcmp(PATH_SEG_CONTAINS_OPERATION, tst_srvr_path_seg_enroll) == 0);
    CU_ASSERT(
        strcmp(PATH_SEG_CONTAINS_OPERATION, tst_proxy_path_seg_auth) == 0);

    /*
     * Since we passed in a path segment that equals an operation we
     * should get a 400 in return
     */
    CU_ASSERT(rv == 200);
}

/*
 * taken from US897/test11
 * CAcerts to the server - including a path segment in the uri.
 *
 * Path Segment testing
 * - Verifies the client includes a configured
 *   path segment
 * - Verifies that the server correctly parses out
 *   a valid path segment and passes it up on the CA certs callback.
 */
static void us3512_test12 (void)
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;

    unsigned char *retrieved_cacerts = NULL;
    int retrieved_cacerts_len = 0;
    EVP_PKEY * priv_key;

    char *path_segment = "path_seg_us3512_test4";

    SLEEP(1);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);
    CU_ASSERT(cacerts_len > 0);

    /*
     * Read in the private key file
     */
    priv_key = read_private_key(CLIENT_UT_PUBKEY);
    if (priv_key == NULL) {
        printf("\nError while reading private key file %s\n", CLIENT_UT_PUBKEY);
        return;
    }

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    rc = est_client_set_auth(ectx, "", "", NULL, priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    est_client_set_server(ectx, US3512_SERVER_IP, US3512_TCP_PROXY_PORT,
        path_segment);

    /*
     * clear out the global that proves that the path segment
     * made it to the application layer's cal back function
     */
    memset(tst_srvr_path_seg_cacerts, 0, EST_MAX_PATH_SEGMENT_LEN + 1);

    /*
     * issue the get ca certs request
     */
    rc = est_client_get_cacerts(ectx, &retrieved_cacerts_len);
    /*
     * should be successful, and should have obtained a valid buffer
     * containing the CA certs
     */
    CU_ASSERT(rc == EST_ERR_NONE);
    CU_ASSERT(retrieved_cacerts_len > 0);
    /*
     * verify that the path segment made it all the way to the callback function
     * at the application layer
     */
    CU_ASSERT(strcmp(path_segment, tst_srvr_path_seg_cacerts) == 0);

    retrieved_cacerts = malloc(retrieved_cacerts_len);

    rc = est_client_copy_cacerts(ectx, retrieved_cacerts);

    /*
     * output the retrieved ca certs and compare to what they should be
     */
    if (retrieved_cacerts) {

        printf("\nRetrieved CA Certs buffer:\n %s\n", retrieved_cacerts);
        printf("Retrieved CA certs buffer length: %d\n", retrieved_cacerts_len);
    }
    free(retrieved_cacerts);

    if (ectx) {
        est_destroy(ectx);
    }
    if (cacerts) {
        free(cacerts);
    }
    if (pkey) {
        free(pkey);
    }
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us3512_add_suite (void)
{
    CU_ErrorCode CU_error;

#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us3512_server_path_seg",
            us3512_init_suite,
            us3512_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /*
     * check to see if path segment support has been compiled in
     */
    if (!path_seg_supported()) {
        printf("URI Path Segment is not supported in this build of EST.  Rebuild using --with-uriparser-dir= \n");
        path_segment_support = 0;
        return 0;
    }
    path_segment_support = 1;

    if (path_segment_support) {

        /* add the tests to the suite */
        /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
        if (
            (NULL == CU_add_test(pSuite, "EST Client: Simple enroll with no path segment", us3512_test1)) ||
            (NULL == CU_add_test(pSuite, "EST Server: Simple Enroll with path segment", us3512_test2)) ||
            (NULL == CU_add_test(pSuite, "EST Server: Simple Re-enroll with path segment", us3512_test3)) ||
            (NULL == CU_add_test(pSuite, "EST Server: CACerts with path segment", us3512_test4)) ||
            (NULL == CU_add_test(pSuite, "EST Server: CSRAttrs with path segment", us3512_test5)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment", us3512_test6)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment at the max", us3512_test7)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment too long", us3512_test8)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment that is operation", us3512_test9)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment containing too many segments", us3512_test10)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment containing an operation", us3512_test11)) ||
            (NULL == CU_add_test(pSuite, "EST Server: EST Proxy with path segment valid and cacerts", us3512_test12))
            )
            {
                CU_error = CU_get_error();
                printf("%d\n", CU_error);

                CU_cleanup_registry();
                printf("%s\n", CU_get_error_msg());
                return CU_get_error();
            }
        }
        return CUE_SUCCESS;
     #endif
}

