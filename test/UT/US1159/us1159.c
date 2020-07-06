/*------------------------------------------------------------------
 * us1159.c - Unit Tests for User Story 1159 - CSR Attributes enforce
 *
 * October, 2014
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
#include <openssl/x509v3.h>
#include "st_server.h"

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

#ifndef WIN32
#define US1159_CACERTS          "CA/estCA/cacert.crt"
#define US1159_CACERT           "CA/estCA/cacert.crt"
#define US1159_SERVER_CERT      "CA/estCA/private/estservercertandkey.pem"
#define US1159_SERVER_KEY       "CA/estCA/private/estservercertandkey.pem"
#else
#define US1159_CACERTS          "CA\\estCA\\cacert.crt"
#define US1159_CACERT           "CA\\estCA\\cacert.crt"
#define US1159_SERVER_CERT      "CA\\estCA\\private\\estservercertandkey.pem"
#define US1159_SERVER_KEY       "CA\\estCA\\private\\estservercertandkey.pem"
#endif
#define US1159_UID              "estuser"
#define US1159_PWD              "estpwd"

#define US1159_SERVER_PORT      15897
#define US1159_SERVER_IP        "127.0.0.1"

#define US1159_ATTR_POP_ONLY    "MAsGCSqGSIb3DQEJBw==\0"
#define US1159_ATTR_CN_ONLY     "MAUGA1UEAw==\0"
#define US1159_ATTR_TEST        "MHEGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEwLAYDiDcCMSUGA4g3AwYDiDcEExlQYXJzZSBTRVQgYXMgMi45OTkuMiBkYXRhBgUrgQQAIgYDVQQDBggqhkjOPQQDAg==\0"

extern EST_CTX *ectx;
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char *attrs;

static unsigned char * handle_csrattrs_request (int *csr_len, char *path_seg,
                                                X509 *peer_cert,
                                                void *app_data)
{
    unsigned char *csr_data;

    *csr_len = strlen(attrs);
    csr_data = malloc(*csr_len + 1);
    strncpy((char *) csr_data, attrs, *csr_len);
    csr_data[*csr_len] = 0;
    return (csr_data);
}

static void us1159_clean (void)
{
}

int us1159_start_server ()
{
    int rv = 0;

    /*
     * Start an EST server acting as the CA
     */
    rv = st_start(US1159_SERVER_PORT,
                  US1159_SERVER_CERT,
                  US1159_SERVER_KEY,
                  "estrealm",
                  US1159_CACERT,
                  "CA/trustedcerts.crt",
                  "CA/estExampleCA.cnf",
                  0, // manual enroll
                  0,  // disable PoP
                  0); // ecdhe nid info
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to start EST server for US1159.\n");
        return rv;
    }

    st_enable_csrattr_enforce();

    rv = est_set_csr_cb(ectx, &handle_csrattrs_request);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to set EST CSR Attributes callback for US1159.\n");
        return (rv);
    }

    SLEEP(1);

    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us1159_init_suite (void)
{
    int rv;

    us1159_clean();

    printf(
        "\nStarting server for CSR attributes enforcement unit tests (US1159).\n");

    attrs = US1159_ATTR_POP_ONLY;
    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1159_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us1159_start_server();

    return rv;
}

void us1159_stop_server ()
{
    st_stop();
    SLEEP(2);
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1159_destroy_suite (void)
{
    us1159_stop_server();
    free(cacerts);
    printf("Completed CSR attributes enforcement unit tests.\n");
    return 0;
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
 * This function generates an EC public/private key
 * pair that will be used with the certificate
 * we provision.
 */
static EVP_PKEY * generate_ec_private_key (int nid)
{
    EC_KEY *eckey;
    EC_GROUP *group = NULL;
    BIO *out;
    unsigned char *tdata;
    unsigned char *key_data;
    int key_len;
    BIO *keyin;
    EVP_PKEY *new_priv_key;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

    /*
     * Generate an EC key
     */
    group = EC_GROUP_new_by_curve_name(nid /*NID_X9_62_prime256v1*/);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
    EC_GROUP_set_point_conversion_form(group, form);
    eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, group);
    if (!EC_KEY_generate_key(eckey)) {
        printf("Failed to generate EC key\n");
        return NULL;
    }
    out = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPKParameters(out, group);
    PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL);
    key_len = BIO_get_mem_data(out, &tdata);
    key_data = malloc(key_len + 1);
    memcpy(key_data, tdata, key_len);
    EC_KEY_free(eckey);
    BIO_free(out);

    /*
     * read it back in to an EVP_PKEY struct
     */
    keyin = BIO_new(BIO_s_mem());
    keyin = BIO_new_mem_buf(key_data, key_len);

    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead.
     */
    new_priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (new_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    BIO_free(keyin);
    free(key_data);

    return (new_priv_key);
}

/*
 * This test attempts does a simple enroll with the
 * client providing no CSR attributes other than
 * challengePassword. The enroll should succeed.
 */
static void us1159_test1 (void)
{
    EST_CTX *ctx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;

    LOG_FUNC_NM
    ;

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ctx, "Test 1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ctx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ctx);
}

/*
 * This routine builds a PKCS10 CSR.
 */
static EST_ERROR populate_x509_request (X509_REQ *req, EVP_PKEY *pkey, char *cn)
{
    X509_NAME *subj;
    int rv;

    /* setup version number */
    rv = X509_REQ_set_version(req, 0L);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_X509_VER);
    }

    /*
     * Add Common Name entry
     */
    subj = X509_REQ_get_subject_name(req);
    rv = X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
        (const unsigned char*) cn, -1, -1, 0);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_X509_CN);
    }

    /*
     * Add serial number Name entry
     */
    rv = X509_NAME_add_entry_by_NID(subj, NID_serialNumber, MBSTRING_ASC,
        (unsigned char*) "12349999B", -1, -1, 0);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_X509_CN);
    }

    /*
     * Add all the other attributes that the server will be expecting
     */
    rv = X509_REQ_add1_attr_by_txt(req, "1.3.6.1.1.1.1.22", MBSTRING_ASC,
        (const unsigned char*) "dummymac", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "2.999.1", MBSTRING_ASC,
        (const unsigned char*) "dummy", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "2.999.2", MBSTRING_ASC,
        (const unsigned char*) "dummy", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "2.999.3", MBSTRING_ASC,
        (const unsigned char*) "dummy", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "2.999.4", MBSTRING_ASC,
        (const unsigned char*) "dummy", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "1.2.840.10045.2.1", MBSTRING_ASC,
        (const unsigned char*) "1.3.132.0.34", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_txt(req, "1.2.840.10045.4.3.3", MBSTRING_ASC,
        (const unsigned char*) "", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    rv = X509_REQ_add1_attr_by_NID(req, NID_serialNumber, MBSTRING_ASC,
        (const unsigned char*) "123456789A", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_UNKNOWN);
    }

    /*
     * Set the public key on the request
     */
    rv = X509_REQ_set_pubkey(req, pkey);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
        return (EST_ERR_X509_PUBKEY);
    }

    X509_REQ_print_fp(stderr, req);

    return (EST_ERR_NONE);
}

#if 0
/*
 * Sign an X509 certificate request using the digest and the key passed.
 * Returns OpenSSL error code from X509_REQ_sign_ctx();
 */
static int sign_X509_REQ(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    int rv;
    EVP_PKEY_CTX *pkctx = NULL;
    EVP_MD_CTX mctx;

    EVP_MD_CTX_init(&mctx);

    if (!EVP_DigestSignInit(&mctx, &pkctx, md, NULL, pkey)) {
        return 0;
    }

    /*
     * Encode using DER (ASN.1)
     *
     * We have to set the modified flag on the X509_REQ because
     * OpenSSL keeps a cached copy of the DER encoded data in some
     * cases.  Setting this flag tells OpenSSL to run the ASN
     * encoding again rather than using the cached copy.
     */
#ifdef HAVE_OLD_OPENSSL
    
    x->req_info->enc.modified = 1; 
#endif
    rv = X509_REQ_sign_ctx(x, &mctx);

    EVP_MD_CTX_cleanup(&mctx);

    return (rv);
}
#endif

/*
 * This test attempts does a simple enroll with the
 * client providing all the required CSR attributes in
 * the CSR. The enroll should succeed.
 */
static void us1159_test2 (void)
{
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    /*
     * This sets the full list of attributes on the server
     */
    attrs = US1159_ATTR_TEST;

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    req = X509_REQ_new();
    CU_ASSERT(req != NULL);

    rv = populate_x509_request(req, key, "Test 2");
    CU_ASSERT(rv == EST_ERR_NONE);

#if 0
    /*
     * Sign the request
     */
    ossl_rv = sign_X509_REQ(req, key, EVP_sha256());
    CU_ASSERT(ossl_rv == 0);
    if (!ossl_rv) {
        ERR_print_errors_fp(stderr);
    }
#endif

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll_csr(ctx, req, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ctx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Cleanup
     */
    if (new_cert)
        free(new_cert);
    if (ctx)
        est_destroy(ctx);
    if (req)
        X509_REQ_free(req);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll with the
 * client providing all the required CSR attributes in
 * the CSR except that the 521-bit curve is used. The enroll
 * should fail since the server CSR attrs specify to
 * use the 384-bit curve.
 */
static void us1159_test3 (void)
{
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    /*
     * This sets the full list of attributes on the server
     */
    attrs = US1159_ATTR_TEST;

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp521r1);
    CU_ASSERT(key != NULL);

    req = X509_REQ_new();
    CU_ASSERT(req != NULL);

    rv = populate_x509_request(req, key, "Test 3");
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll_csr(ctx, req, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_HTTP_BAD_REQ);

    /*
     * Cleanup
     */
    if (ctx)
        est_destroy(ctx);
    if (req)
        X509_REQ_free(req);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll with the
 * client providing all the required CSR attributes in
 * the CSR except that SHA-384 is used for the
 * signature. The enroll should fail since the server
 * CSR attrs require SHA-256.
 */
static void us1159_test4 (void)
{
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    /*
     * This sets the full list of attributes on the server
     */
    attrs = US1159_ATTR_TEST;

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    req = X509_REQ_new();
    CU_ASSERT(req != NULL);

    rv = populate_x509_request(req, key, "Test 3");
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Change to SHA-384 for the signature
     */
    rv = est_client_set_sign_digest(ctx, NID_sha384);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll_csr(ctx, req, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_HTTP_BAD_REQ);

    /*
     * Cleanup
     */
    if (ctx)
        est_destroy(ctx);
    if (req)
        X509_REQ_free(req);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll when the
 * server has no CSR attributes configured to only
 * require the CommonName.  The CSR attributes on
 * the server are configured through the static API,
 * not the callback.
 */
static void us1159_test10 (void)
{
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    /*
     * Disable the CSR attr callback on the server context
     */
    rv = est_set_csr_cb(ectx, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Configure the static CSR attributes value
     */
    rv = est_server_init_csrattrs(ectx, US1159_ATTR_CN_ONLY,
        strlen(US1159_ATTR_CN_ONLY));
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Enroll a new cert
     */
    rv = est_client_enroll(ctx, "Test 10", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    if (ctx)
        est_destroy(ctx);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll with the
 * client providing all the required CSR attributes in
 * the CSR. The client also provides a large
 * quantity of additional attributes.
 */
static void us1159_test20 (void)
{
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    int rv;
    EST_CTX *ctx = NULL;
    int i;
    char t_attr_str[50];

    LOG_FUNC_NM
    ;

    /*
     * This sets the full list of attributes on the server
     */
    attrs = US1159_ATTR_TEST;

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    req = X509_REQ_new();
    CU_ASSERT(req != NULL);

    rv = populate_x509_request(req, key, "Test 20");
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Jam another 25 attributes into the request
     * We could do more, but this causes a failure on the EST server when
     * base64 decoding the CSR due to a safeC constraint.  The max string
     * size in safeC defaults to 4096 bytes.
     */
    for (i = 0; i < 25; i++) {
        sprintf(t_attr_str, "2.899.%d", i);
        rv = X509_REQ_add1_attr_by_txt(req, t_attr_str, MBSTRING_ASC,
            (const unsigned char*) "whatever", -1);
        CU_ASSERT(rv != 0);
        if (!rv) {
            ERR_print_errors_fp(stderr);
        }
    }

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll_csr(ctx, req, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ctx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Cleanup
     */
    if (new_cert)
        free(new_cert);
    if (ctx)
        est_destroy(ctx);
    if (req)
        X509_REQ_free(req);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll with the
 * client providing all the required CSR attributes in
 * the CSR. The client also provides an attribute with
 * a very long name and value.
 */
static void us1159_test21 (void)
{
    X509_REQ *req = NULL;
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    /*
     * This sets the full list of attributes on the server
     */
    attrs = US1159_ATTR_TEST;

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    req = X509_REQ_new();
    CU_ASSERT(req != NULL);

    rv = populate_x509_request(req, key, "Test 21");
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Add an attribute with a long value
     */
    rv =
            X509_REQ_add1_attr_by_txt(req, "2.993.8", MBSTRING_ASC,
                (const unsigned char*) "This is an attribute with a very long value that could potentially cause a problem on the EST server.  0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
    }

    /*
     * Add an attribute with a long name
     */
    rv =
            X509_REQ_add1_attr_by_txt(req,
                "2.993.8.828.85.8142.9999.2.1883.2.993.8.828.85.8142.9999.2.1883.2.993.8.828.85.8142.9999.2.1883.2.993.8.828.85.8142.9999.2.1883.2.993.8.828.85.8142.9999.2.1883.7",
                MBSTRING_ASC, (const unsigned char*) "0123456789", -1);
    CU_ASSERT(rv != 0);
    if (!rv) {
        ERR_print_errors_fp(stderr);
    }
    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll_csr(ctx, req, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_cert = malloc(pkcs7_len);
        CU_ASSERT(new_cert != NULL);
        rv = est_client_copy_enrolled_cert(ctx, new_cert);
        CU_ASSERT(rv == EST_ERR_NONE);
    }

    /*
     * Cleanup
     */
    if (new_cert)
        free(new_cert);
    if (ctx)
        est_destroy(ctx);
    if (req)
        X509_REQ_free(req);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll when the
 * server has no CSR attributes configured with
 * PoP enabled.
 */
static void us1159_test50 (void)
{
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    st_enable_pop();

    /*
     * Disable the CSR attr callback on the server context
     */
    rv = est_set_csr_cb(ectx, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    rv = est_client_force_pop(ctx);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Enroll a new cert
     */
    rv = est_client_enroll(ctx, "Test 50", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    if (ctx)
        est_destroy(ctx);
    if (key)
        EVP_PKEY_free(key);
}

/*
 * This test attempts does a simple enroll when the
 * server has no CSR attributes configured with
 * PoP disabled.
 */
static void us1159_test51 (void)
{
    EVP_PKEY *key = NULL;
    int pkcs7_len = 0;
    int rv;
    EST_CTX *ctx = NULL;

    LOG_FUNC_NM
    ;

    st_disable_pop();

    /*
     * Disable the CSR attr callback on the server context
     */
    rv = est_set_csr_cb(ectx, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * generate a private key
     */
    key = generate_ec_private_key(NID_secp384r1);
    CU_ASSERT(key != NULL);

    /*
     * Create a client context
     */
    ctx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    CU_ASSERT(ctx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ctx, US1159_UID, US1159_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ctx, US1159_SERVER_IP, US1159_SERVER_PORT, NULL);

    /*
     * Enroll a new cert
     */
    rv = est_client_enroll(ctx, "Test 51", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    if (ctx)
        est_destroy(ctx);
    if (key)
        EVP_PKEY_free(key);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us1159_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us1159_csr_attr_enforce",
            us1159_init_suite,
            us1159_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
    if ((NULL == CU_add_test(pSuite, "No attributes required w/pop", us1159_test1)) ||
        (NULL == CU_add_test(pSuite, "All attributes provided w/pop", us1159_test2)) ||
        (NULL == CU_add_test(pSuite, "EC public key wrong curve w/pop", us1159_test3)) ||
        (NULL == CU_add_test(pSuite, "Wrong hash algorithm in signature w/pop", us1159_test4)) ||
        (NULL == CU_add_test(pSuite, "CN only using static config w/pop", us1159_test10)) ||
        (NULL == CU_add_test(pSuite, "A lot of attributes w/pop", us1159_test20)) ||
        (NULL == CU_add_test(pSuite, "Long attribute w/pop", us1159_test21)) ||
        (NULL == CU_add_test(pSuite, "No CSR attrs on server w/pop", us1159_test50)) ||
        (NULL == CU_add_test(pSuite, "No CSR attrs on server w/o pop", us1159_test51)))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

