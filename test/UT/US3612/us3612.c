/*------------------------------------------------------------------
 * us3612.c - Unit Tests for User Story US3612 - Encrypted Private Key Support
 *
 *
 *
 * July, 2016
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
#include "test_utils.h"
#include "st_server.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

static unsigned char *cacerts = NULL;
static char *key_password = NULL;
static int cacerts_len = 0;

#define US3612_SERVER_PORT   29899
#define US3612_SERVER_IP     "127.0.0.1"
#define US3612_UID           "estuser"
#define US3612_PWD           "estpwd"
#define US3612_GOOD_PWD "us3612"
#define US3612_BAD_PWD  "thiscantpossiblywork"
#define RSA_KEYSIZE 4096

/*
 * Key wrap algorithm optionally used to protect private keys
 */
#define EST_PRIVATE_KEY_ENC EVP_aes_128_cbc()

/*
 * The following certs are used for FQDN testing
 */
#ifndef WIN32
#define US3612_CACERTS       "CA/estCA/cacert.crt"
#define US3612_TRUST_CERTS   "CA/trustedcerts.crt"
#define US3612_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
#define US3612_PRIVATE_KEY_FILE "US3612/us3612_key.pem"

#else
#define US3612_CACERTS       "CA\\estCA\\cacert.crt"
#define US3612_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US3612_SERVER_CERTKEY   "CA\\estCA\\private\\estservercertandkey.pem"
#define US3612_PRIVATE_KEY_FILE "US3612\\us3612_key.pem"

static CRITICAL_SECTION logger_critical_section;
static void us3612_logger_stderr (char *format, va_list l)
{
    EnterCriticalSection(&logger_critical_section);
    vfprintf(stderr, format, l);
    fflush(stderr);
    LeaveCriticalSection(&logger_critical_section);
}
#endif

unsigned char *BIO_copy_data(BIO *out, int *data_lenp) {
    unsigned char *data, *tdata;
    int data_len;

    data_len = BIO_get_mem_data(out, &tdata);
    data = malloc(data_len+1);
    if (data) {
        memcpy(data, tdata, data_len);
	data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
	if (data_lenp) {
	    *data_lenp = data_len;
	}
    } else {
        printf("malloc failed");
    }
    return data;
}

char *generate_private_RSA_key (int key_size, pem_password_cb *cb)
{
    char *key_data = NULL;

    RSA *rsa = RSA_new();
    if (!rsa) {
        return NULL;
    }
    BIGNUM *bn = BN_new();
    if (!bn) {
        RSA_free(rsa);
        return NULL;
    }

    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, key_size, bn, NULL);

    do {
        BIO *out = BIO_new(BIO_s_mem());
        if (!out) {
            break;
        }
        PEM_write_bio_RSAPrivateKey(out, rsa, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
        key_data = (char *)BIO_copy_data(out, NULL);
        BIO_free(out);
        if (key_data && !key_data[0]) {
            // happens if passphrase entered via STDIN does not verify or has less than 4 characters
            free(key_data);
            key_data = NULL;
        }
    } while (cb && !key_data);

    RSA_free(rsa);
    BN_free(bn);
    return (key_data);
}

char *generate_private_EC_key (int curve_nid, pem_password_cb *cb)
{
    EC_KEY *eckey;
    EC_GROUP *group = NULL;
    char *key_data = NULL;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

    /*
     * Generate an EC key
     */

    eckey = EC_KEY_new();
    if (!eckey) {
        return NULL;
    }

    group = EC_GROUP_new_by_curve_name(curve_nid);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
    EC_GROUP_set_point_conversion_form(group, form);
    EC_KEY_set_group(eckey, group);
    if (!EC_KEY_generate_key(eckey)) {
        return (NULL);
    }

    do {
        BIO *out = BIO_new(BIO_s_mem());
        if (!out) {
            break;
        }
        PEM_write_bio_ECPKParameters(out, group);
        PEM_write_bio_ECPrivateKey(out, eckey, cb ? EST_PRIVATE_KEY_ENC : NULL, NULL, 0, cb, NULL);
        key_data = (char *)BIO_copy_data(out, NULL);
        BIO_free(out);
        if (key_data && !strstr(key_data, "-----BEGIN EC PRIVATE KEY-----")) {
            // happens if passphrase entered via STDIN does not verify or has less than 4 characters
            free(key_data);
            key_data = NULL;
        }
    } while (cb && !key_data);

    EC_KEY_free(eckey);
    return (key_data);
}

static int string_password_cb (char *buf, int size, int wflag, void *data)
{
    /*
     * Hard code a password for this suite
     */
    strncpy(buf, key_password, size);
    return(strnlen(buf, size));
}


static void us3612_clean (void)
{
}

static int us3612_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US3612_SERVER_PORT,
              US3612_SERVER_CERTKEY,
              US3612_SERVER_CERTKEY,
              "US3612 test realm",
              US3612_CACERTS,
              US3612_TRUST_CERTS,
              "CA/estExampleCA.cnf",
          manual_enroll,
          0,
          nid);
    return rv;
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us3612_init_suite (void)
{
    int rv;

#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us3612_logger_stderr);
#endif

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US3612_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
    return 1;
    }

    us3612_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us3612_start_server(0, 0);

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us3612_destroy_suite (void)
{
    st_stop();
    free(cacerts);
    return 0;
}


/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify(X509 *cur_cert, int openssl_cert_error)
{
    BIO *bio_err;
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;

    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
           __FUNCTION__, openssl_cert_error,
           X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout,cur_cert);
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
 * Simple Enroll b- client
 * Load in a password protected private key with
 * the correct passphrase and attempt to enroll for a certificate
 */
static void us3612_test1 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US3612_UID, US3612_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US3612_SERVER_IP, US3612_SERVER_PORT, NULL);

    /*
     * Read in our test private key
     * generated via the command below:
     *
     * openssl genrsa -aes128 -passout pass:us3612 -out us3612_key.pem 4096
     */

    key_password = US3612_GOOD_PWD;

    key = read_protected_private_key(US3612_PRIVATE_KEY_FILE, string_password_cb);

    CU_ASSERT(key != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, "TCUS3612-1", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

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
    if (new_cert) free(new_cert);
    est_destroy(ectx);
}


/*
 * Simple enroll CSR
 *
 * Load in a password protected private key with the incorrect password
 * and attempt to enroll for a certificate. This will fail.
 */
static void us3612_test2 (void)
{
     EST_CTX *ectx;
     EVP_PKEY *key;
     int rv;
     int pkcs7_len = 0;
     unsigned char *new_cert = NULL;
     unsigned char *attr_data = NULL;
     int attr_len;

     /*
      * Create a client context
      */
     ectx = est_client_init(cacerts, cacerts_len,
                            EST_CERT_FORMAT_PEM,
                            client_manual_cert_verify);
     CU_ASSERT(ectx != NULL);

     /*
      * Set the authentication mode to use a user id/password
      */
     rv = est_client_set_auth(ectx, US3612_UID, US3612_PWD, NULL, NULL);
     CU_ASSERT(rv == EST_ERR_NONE);

     /*
      * Set the EST server address/port
      */
     est_client_set_server(ectx, US3612_SERVER_IP, US3612_SERVER_PORT, NULL);

     /*
      * Read in our test private key
      * generated via the command below:
      *
      * openssl genrsa -aes128 -passout pass:us3612 -out us3612_key.pem 4096
      */

     key_password = US3612_BAD_PWD;

     key = read_protected_private_key(US3612_PRIVATE_KEY_FILE, string_password_cb);

     CU_ASSERT(key == NULL);

     /*
      * Get the latest CSR attributes
      */
     rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
     CU_ASSERT(rv == EST_ERR_NONE);

     /*
      * Use the simplified API to enroll a CSR
      */
     rv = est_client_enroll(ectx, "TC3612-2", &pkcs7_len, key);
     CU_ASSERT(rv != EST_ERR_NONE);

     /*
      * Cleanup
      */
     EVP_PKEY_free(key);
     if (new_cert) free(new_cert);
     est_destroy(ectx);
}


/*
 * Simple enroll CSR
 *
 * Change the password used by the callback after reading
 * in the protected private key file.
 */
static void us3612_test3 (void)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    unsigned char *attr_data = NULL;
    int attr_len;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Set the authentication mode to use a user id/password
     */
    rv = est_client_set_auth(ectx, US3612_UID, US3612_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US3612_SERVER_IP, US3612_SERVER_PORT, NULL);

    /*
     * Read in our test private key
     * generated via the command below:
     *
     * openssl genrsa -aes128 -passout pass:us3612 -out us3612_key.pem 4096
     */

    key_password = US3612_GOOD_PWD;

    key = read_protected_private_key(US3612_PRIVATE_KEY_FILE, string_password_cb);

    CU_ASSERT(key != NULL);

    /*
     * Change out the password, EVP_PKEY should remain unaffected
     */

    key_password = US3612_BAD_PWD;

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, "TCUS3612-3", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

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
    if (new_cert) free(new_cert);
    est_destroy(ectx);
}


/*
 * Test key generation utility functions
 * and associated password callbacks
 */
static void us3612_test4 (void)
{
    char * new_pkey = NULL;

    /*
     * Generate an RSA key without a password
     */

    new_pkey = generate_private_RSA_key(RSA_KEYSIZE, NULL);
    CU_ASSERT(new_pkey != NULL);
    printf("\n%s\n", new_pkey);
    free(new_pkey);
    new_pkey = NULL;

    /*
     * Generate an RSA key with password
     */

    key_password = US3612_GOOD_PWD;

    new_pkey = generate_private_RSA_key(RSA_KEYSIZE, string_password_cb);
    CU_ASSERT(new_pkey != NULL);
    printf("\n%s\n", new_pkey);
    free(new_pkey);
    new_pkey = NULL;

    /*
     * Generate an EC key without a password
     */

    new_pkey = generate_private_EC_key(OBJ_sn2nid((char *) "prime256v1"), NULL);
    CU_ASSERT(new_pkey != NULL);
    printf("\n%s\n", new_pkey);
    free(new_pkey);
    new_pkey = NULL;


    /*
     * Generate an EC key with a password
     */
    new_pkey = generate_private_EC_key(OBJ_sn2nid((char *) "prime256v1"), string_password_cb);
    CU_ASSERT(new_pkey != NULL);
    printf("\n%s\n", new_pkey);
    free(new_pkey);
    new_pkey = NULL;

}

int us3612_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us3612_encrypted_private_keys",
                      us3612_init_suite,
              us3612_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /*
    * Add the tests to the suite
    */
   if ((NULL == CU_add_test(pSuite, "Client simple enroll w/ correct pwd", us3612_test1)) ||
       (NULL == CU_add_test(pSuite, "Client simple enroll w/ incorrect pwd", us3612_test2)) ||
       (NULL == CU_add_test(pSuite, "Client simple enroll w/ incorrect pwd", us3612_test3)) ||
       (NULL == CU_add_test(pSuite, "Keygen Test", us3612_test4)))
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}
