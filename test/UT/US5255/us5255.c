/*------------------------------------------------------------------
 * us5255.c - Unit Tests for User Story 5255 - Proxy Path Segment
 *                                             Injection in CoAP mode
 *
 * January 2019
 *
 * Copyright (c) 2019 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>

#ifndef WIN32

#include <unistd.h>
#include <sys/stat.h>

#endif

#include <est.h>
#include "test_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#define US5255_TCP_SERVER_PORT       25255
#define US5255_TCP_PROXY_PORT        25265
#define US5255_UDP_PROXY_PORT        25258
#define EST_MAX_CMD_LEN 512
#define MAX_FILENAME_LEN 256


#define US5255_SERVER_IP         "127.0.0.1"
#define US5255_UID               "estuser"
#define US5255_PWD               "estpwd"

#define US5255_COAP_CLIENT_EMU   "est_coap_client.py"
#define US5255_CSSL_NOT_SET_MSG "The path for the openssl installation used by"\
" the python emulator was not specified.\n Please set the environment variable"\
" COAP_EMU_SSL"

#ifndef WIN32
#define US5255_CACERTS           "CA/estCA/cacert.crt"
#define US5255_CLIENT_CACERTS    "CA/mfgCAs/trustedcertswithsudichain.crt"
#define US5255_SERVER_ENHCD_CERT_CACERTS "CA/mfgCAs/sudiCA/cacert.crt"
#define US5255_TRUSTED_CERTS     "CA/trustedcerts.crt"
#define US5255_SERVER_CERTKEY    "CA/estCA/private/estservercertandkey.pem"
#define US5255_PROXY_CERTKEY     "CA/estCA/private/proxy-certandkey.pem"
#define US5255_CLIENT_CERTKEY    "CA/mfgCAs/sudiCA/private/certandkey1-estsudi.pem"
#define US5255_CA_CNF            "CA/estExampleCA.cnf"
#define US5255_COAP_CLIENT_EMU_PATH "../util/"

#else
#define US5255_CACERTS           "CA\\estCA\\cacert.crt"
#define US5255_CLIENT_CACERTS    "CA\\mfgCAs\\trustedcertswithsudichain.crt"
#define US5255_SERVER_ENHCD_CERT_CACERTS "CA\\mfgCAs\\sudiCA\\cacert.crt"
#define US5255_TRUSTED_CERTS     "CA\\trustedcerts.crt"
#define US5255_SERVER_CERTKEY    "CA\\estCA\\private\\estservercertandkey.pem"
#define US5255_PROXY_CERTKEY     "CA\\estCA\\private\\proxy-certandkey.pem"
#define US5255_CLIENT_CERTKEY    "CA\\mfgCAs\\sudiCA\\private\\certandkey1-estsudi.pem"
#define US5255_CA_CNF            "CA\\estExampleCA.cnf"
#define US5255_COAP_CLIENT_EMU_PATH "python ..\\util\\"
#endif

#define US5255_EXPECTED_SEG     "expectedseg"
#define US5255_BAD_SEG          "badseg"

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static int auth_cb_called = 0;
static char temp_dir[MAX_FILENAME_LEN];
static char *cssl_emulator_path = NULL;

static EVP_PKEY *client_cert_key = NULL;
static X509 *client_cert = NULL;

static int coap_mode_support = 0;

/*
 * This is used to check the value of the path segment that is
 * sent to the server.
 */
static int us5255_server_process_path_seg (EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
                                           X509 *peer_cert, char *path_seg,
                                           void *app_data)
{
    if (path_seg) {
        printf("\n %s: Path segment in the authenticate callback is: %s\n",
               __FUNCTION__, path_seg);
    }
    auth_cb_called = 1;
    
    CU_ASSERT(!strncmp(path_seg, US5255_EXPECTED_SEG, strlen(US5255_EXPECTED_SEG)));
    return 1;
}

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int us5255_proxy_process_path_seg (EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
                                           X509 *peer_cert, char *path_seg,
                                           void *app_data)
{
    if (path_seg) {
        printf("\n %s: Path segment in the authenticate callback is: %s\n",
               __FUNCTION__, path_seg);
    }
    return 1;
}

static EVP_PKEY *generate_private_key(void)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey;

    /*
     * create an RSA keypair and assign them to a PKEY and return it.
     */
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, 4096, bn, NULL);

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

static int client_manual_cert_verify_US5255(X509 *cur_cert, int openssl_cert_error)
{
    int approve = 0;

    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        approve = 1;
        return approve;
    }

    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
           __FUNCTION__, openssl_cert_error,
           X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);

    return approve;
}


static int us5255_start_server(int manual_enroll, int nid)
{
    int rv;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US5255_TCP_SERVER_PORT,
                  US5255_SERVER_CERTKEY,
                  US5255_SERVER_CERTKEY,
                  "US5255 test realm",
                  US5255_CACERTS,
                  US5255_TRUSTED_CERTS,
                  US5255_CA_CNF,
                  manual_enroll,
                  0,
                  nid);
    if (rv != EST_ERR_NONE) {
        printf("Failed to start st_server\n");
        return rv;
    }

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us5255_init_suite(void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US5255_CLIENT_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

     /* Build out temp directory */
#ifdef WIN32
    snprintf(temp_dir, MAX_FILENAME_LEN, "%s\\", getenv("TEMP"));
#else
    snprintf(temp_dir, MAX_FILENAME_LEN, "/tmp/");
#endif

    /*
     * Start an instance of the EST proxy and server
     * with automatic enrollment enabled.
     */
    rv = us5255_start_server(0, 0);

    /*
     * Set HTTP Authentication Callback function to verify
     * path segment result
     */
    rv = st_server_set_http_auth_cb(us5255_server_process_path_seg);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_server\n");
    }

    if (read_x509_cert_and_key_file(US5255_SERVER_CERTKEY,
                                    US5255_SERVER_CERTKEY,
                                    &client_cert, &client_cert_key)) {
        return 1;
    }

    cssl_emulator_path = getenv("COAP_EMU_SSL");

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us5255_destroy_suite(void)
{
    st_stop();
    if (cacerts) free(cacerts);
    X509_free(client_cert);
    EVP_PKEY_free(client_cert_key);
    return 0;
}

/*
 * This function performs a basic simple enroll over HTTP through a proxy 
 * to the server and checks that the path segment
 * set by the client is passed through to the server.
 */
static void us5255_test1(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Start an EST proxy
     *
     * Store the "bad" path seg in the proxy context
     * using the new api call est_proxy_store_path_segment
     * 
     * Because the http client will give a path segment
     * to use, the bad path seg should not be passed through
     * to the server
     */
    rv = st_proxy_start_pathseg(US5255_TCP_PROXY_PORT,
                        US5255_PROXY_CERTKEY,
                        US5255_PROXY_CERTKEY,
                        "US5255 test realm",
                        US5255_CACERTS,
                        US5255_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US5255_TCP_SERVER_PORT,
                        0,
                        0,
                        US5255_BAD_SEG);

    /*
     * Set HTTP Authentication Callback function
     * This function is used to verify that the correct
     * path segment was sent through to the server
     */
    rv = st_proxy_set_http_auth_cb(us5255_proxy_process_path_seg);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
        goto end;
    }

    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len,
                            EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5255);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password.
     */
    rv = est_client_set_auth(ecctx, US5255_UID, US5255_PWD, client_cert, client_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port and configure the client with
     * the expected path seg.
     * This path seg is not stored in any context until the enroll occurs
     * through the proxy (in which case the expected seg is then stored
     * in the client context and sent through to the server)
     */
    est_client_set_server(ecctx, US5255_SERVER_IP, US5255_TCP_PROXY_PORT, US5255_EXPECTED_SEG);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /* We haven't gone into the auth cb yet */
    auth_cb_called = 0;

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5255-2-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto end;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * check that the expected path seg was found in the server
     * when the auth cb was called and that the injected bad path seg
     * was not sent through to the server
     */
    CU_ASSERT(auth_cb_called);

    st_proxy_stop();

    end:
    if (cert) X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert) free(new_cert);
    est_destroy(ecctx);
}

/*
 * This function performs a basic simple enroll over HTTP through a proxy 
 * to the server and checks that the injected path segment
 * is passed through to the server.
 */
static void us5255_test2(void)
{
    EST_CTX *ecctx = NULL;
    EVP_PKEY *key = NULL;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Start an EST proxy
     *
     * Store the "expected" path seg in the proxy context
     * using the new api call est_proxy_store_path_segment
     * 
     * The expected path seg should
     * be copied from the proxy context into the client
     * context and passed through to the server
     * since, in this test, we are telling the client
     * to set a NULL path segment, and NULL path segments
     * are overwritten with whatever is stored in the
     * proxy context, currently.
     */
    rv = st_proxy_start_pathseg(US5255_TCP_PROXY_PORT,
                        US5255_PROXY_CERTKEY,
                        US5255_PROXY_CERTKEY,
                        "US5255 test realm",
                        US5255_CACERTS,
                        US5255_TRUSTED_CERTS,
                        "estuser",
                        "estpwd",
                        "127.0.0.1",
                        US5255_TCP_SERVER_PORT,
                        0,
                        0,
                        US5255_EXPECTED_SEG);

    /*
     * Set HTTP Authentication Callback function
     * This function is used to verify that the correct
     * path segment was sent through to the server
     */
    rv = st_proxy_set_http_auth_cb(us5255_proxy_process_path_seg);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
        goto end;
    }

    /*
     * Create a client context
     */
    ecctx = est_client_init(cacerts, cacerts_len,
                            EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify_US5255);
    CU_ASSERT(ecctx != NULL);
    if (ecctx == NULL) {
        printf("Failed to init est client\n");
        goto end;
    }

    /*
     * Set the authentication mode to use a user id/password. These credentials
     * should be ignored by the server since we are in Enhanced Cert Auth Mode.
     */
    rv = est_client_set_auth(ecctx, US5255_UID, US5255_PWD, client_cert, client_cert_key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set client auth\n");
        goto end;
    }

    /*
     * Set the EST server address/port
     * and a NULL path segment, which
     * should be overwritten by the
     * expected path seg that is stored
     * in the proxy context
     */
    est_client_set_server(ecctx, US5255_SERVER_IP, US5255_TCP_PROXY_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    if (key == NULL) {
        printf("Failed to generate private key\n");
        goto end;
    }

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ecctx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed to get csr attributes\n");
    }

    /* We haven't gone into the auth cb yet */
    auth_cb_called = 0;

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ecctx, "TC-US5255-2-2", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (rv != EST_ERR_NONE) {
        printf("Failed simple enroll\n");
        goto end;
    }

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    new_cert = malloc(pkcs7_len);
    CU_ASSERT(new_cert != NULL);
    rv = est_client_copy_enrolled_cert(ecctx, new_cert);
    CU_ASSERT(rv == EST_ERR_NONE);
    if (new_cert != NULL) {
        free(new_cert);
        new_cert = NULL;
    }

    /*
     * check that the injected expected path seg was
     * found in the server when the auth cb was called
     * since the client was configured with a NULL path segment
     */
    CU_ASSERT(auth_cb_called);

    st_proxy_stop();

    end:
    if (cert) X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert) free(new_cert);
    est_destroy(ecctx);
}

/*
 * This function performs a basic simple enroll over CoAP through a proxy 
 * to the server and checks that the path segment
 * injected by the api call is passed through to the server.
 */
static void us5255_test3(void)
{
    EST_ERROR rv;
    char cmd[EST_MAX_CMD_LEN];

    LOG_FUNC_NM;

    CU_ASSERT(cssl_emulator_path != NULL);
    if (!cssl_emulator_path) {
        printf(US5255_CSSL_NOT_SET_MSG);
        return;
    }

    /*
     * Start an EST proxy using CoAP
     * 
     * Store the "expected" path seg in the proxy context
     * using the new api call est_proxy_store_path_segment
     * 
     * The expected path seg should be copied from the
     * proxy context into the client context
     * and passed through to the server
     */
    rv = st_proxy_start_pathseg_coap(US5255_UDP_PROXY_PORT,
                             US5255_PROXY_CERTKEY,
                             US5255_PROXY_CERTKEY,
                             "US5255 test realm",
                             US5255_CACERTS,
                             US5255_TRUSTED_CERTS,
                             "estuser",
                             "estpwd",
                             "127.0.0.1",
                             US5255_TCP_SERVER_PORT,
                             0,
                             0,
                             US5255_EXPECTED_SEG); 
    if (rv != EST_ERR_NONE) {
        printf("Failed to start CoAP st_proxy\n");
        return;
    }

    /*
     * Set HTTP Authentication Callback function
     * This function is used to verify that the correct
     * path segment was sent through to the server
     */
    rv = st_proxy_set_http_auth_cb(us5255_proxy_process_path_seg);
    if (rv != EST_ERR_NONE) {
        printf("Failed to set HTTP auth callback function on st_proxy\n");
    }

    /* We haven't gone into the auth cb yet */
    auth_cb_called = 0;

    /* Build out est_coap_client.py command and log the output */
    snprintf(cmd, EST_MAX_CMD_LEN,
             "LD_LIBRARY_PATH=%s/lib OPENSSL_PYTHON_BIN=%s/bin %s%s --test "
             "SIMPLE_ENROLL --port %d --debug --cert %s --key %s --cacert %s ",
             cssl_emulator_path, cssl_emulator_path,
             US5255_COAP_CLIENT_EMU_PATH, US5255_COAP_CLIENT_EMU,
             US5255_UDP_PROXY_PORT, US5255_CLIENT_CERTKEY,
             US5255_CLIENT_CERTKEY, US5255_CLIENT_CACERTS);
    if (strnlen(cmd,EST_MAX_CMD_LEN) >= EST_MAX_CMD_LEN) {
        CU_FAIL("Command for executing the est_coap_client.py emulator was\n"
                "too long. Add symbolic links to make paths shorter.");
        return;
    }

    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * check that the injected expected path seg was found in the server
     * when the auth cb was called
     */
    CU_ASSERT(auth_cb_called);

    st_proxy_stop();
    
    return;
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us5255_add_suite(void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /*
     * check to see if coap mode support has been compiled in
     */
    if (!coap_mode_supported(US5255_PROXY_CERTKEY, US5255_TRUSTED_CERTS,
                             US5255_CACERTS, US5255_UDP_PROXY_PORT)) {
        printf("CoAP mode is not supported in this build of EST.  Rebuild using --with-libcoap-dir= \n");
        coap_mode_support = 0;
        return 0;
    }
    coap_mode_support = 1;
    
    /* add a suite to the registry */
    pSuite = CU_add_suite("us5255_coap_inject_path_seg",
                          us5255_init_suite,
                          us5255_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (coap_mode_support) {
    
        /* add the tests to the suite */
        if ((NULL == CU_add_test(pSuite, "HTTP Path Seg- not altered",
                                 us5255_test1)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }
        if ((NULL == CU_add_test(pSuite, "HTTP Path Seg- injected",
                                 us5255_test2)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }
        if ((NULL == CU_add_test(pSuite, "CoAP Path Seg- injected",
                                 us5255_test3)))
            {
                CU_cleanup_registry();
                return CU_get_error();
            }
    }
    
    return CUE_SUCCESS;
#endif
}

