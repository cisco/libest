/*------------------------------------------------------------------
 * us898.c - Unit Tests for User Story 898 - Client re-enroll 
 *
 * October, 2013
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
#include <est_ossl_util.h>
#include "test_utils.h"
#include "st_server.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US898_SERVER_PORT   29898
#define US898_SERVER_IP	    "127.0.0.1"	
#define US898_UID	    "estuser"
#define US898_PWD	    "estpwd"
#ifndef WIN32
#define US898_CACERTS	    "CA/estCA/cacert.crt"
#define US898_TRUST_CERTS   "CA/trustedcerts.crt"
#define US898_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"

#define US898_TC2_CERT_TXT "US898/tc2-new-cert.txt"
#define US898_TC2_CERT_B64 "US898/tc2-new-cert.pkcs7b64"
#define US898_TC2_CERT_PK7 "US898/tc2-new-cert.pkcs7"
#define US898_TC2_CERT_PEM "US898/tc2-new-cert.pem"

#define US898_TC10_CSR	"US898/tc10_csr.pem"
#define US898_TC10_KEY	"US898/tc10_key.pem"
#define US898_TC10_CERT	"US898/tc10_cert.pem"

#define US898_TC11_KEY	"US898/tc11_key.pem"
#define US898_TC11_CERT	"US898/tc11_cert.pem"
#else
  #define US898_CACERTS	    "CA\\estCA\\cacert.crt"
#define US898_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US898_SERVER_CERTKEY   "CA\\estCA\\private\\estservercertandkey.pem"

#define US898_TC2_CERT_TXT "US898\\tc2-new-cert.txt"
#define US898_TC2_CERT_B64 "US898\\tc2-new-cert.pkcs7b64"
#define US898_TC2_CERT_PK7 "US898\\tc2-new-cert.pkcs7"
#define US898_TC2_CERT_PEM "US898\\tc2-new-cert.pem"

#define US898_TC10_CSR	"US898\\tc10_csr.pem"
#define US898_TC10_KEY	"US898\\tc10_key.pem"
#define US898_TC10_CERT	"US898\\tc10_cert.pem"

#define US898_TC11_KEY	"US898\\tc11_key.pem"
#define US898_TC11_CERT	"US898\\tc11_cert.pem"

static CRITICAL_SECTION logger_critical_section;  
static void us898_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}

#endif

static void us898_clean (void)
{
    char cmd[200];

    /*
     * These are all temporary files created 
     * by the various test cases.
     */
#ifndef WIN32
    sprintf(cmd, "rm %s", US898_TC2_CERT_TXT);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC2_CERT_B64);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC2_CERT_PK7);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC2_CERT_PEM);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC10_CERT);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC10_KEY);
    system(cmd);
    sprintf(cmd, "rm %s", US898_TC10_CSR);
    system(cmd);
#else
    sprintf(cmd, "del %s", US898_TC2_CERT_TXT);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC2_CERT_B64);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC2_CERT_PK7);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC2_CERT_PEM);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC10_CERT);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC10_KEY);
    system(cmd);
    sprintf(cmd, "del %s", US898_TC10_CSR);
    system(cmd);
#endif 
}

/*
 * This starts an instance of the EST server running on
 * a separate thread.  We use this to test the
 * client side API in this module.
 */
static int us898_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US898_SERVER_PORT, 
	          US898_SERVER_CERTKEY,
	          US898_SERVER_CERTKEY,
	          "estrealm",
	          US898_CACERTS,
	          US898_TRUST_CERTS,
	          "US898/estExampleCA.cnf",
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
static int us898_init_suite (void)
{
    int rv;

#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us898_logger_stderr);
#endif

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US898_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    us898_clean();

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us898_start_server(0, 0);

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us898_destroy_suite (void)
{
    st_stop();
    free(cacerts);
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
    if (pkey==NULL) {
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
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify(X509 *cur_cert, int openssl_cert_error)
{
    BIO *bio_err;
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    int approve = 0;
    const ASN1_BIT_STRING *cur_cert_sig;
    const X509_ALGOR *cur_cert_sig_alg;
    
    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        return (1);
    }    
    
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

    BIO_free(bio_err);
    
    return approve;
}    

/*
 * This function performs a basic simple enroll using
 * a UID/PWD to identify the client to the server.  This
 * is used for a variet of test cases in this module.
 */
static void us898_test1 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    PKCS7 *p7 = NULL;
    BIO *b64, *out;
    X509 *cert = NULL;
    STACK_OF(X509) *certs = NULL;
    int i;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

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
    if (rv != EST_ERR_NONE) return;

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
    p7 = d2i_PKCS7_bio(out,NULL);
    CU_ASSERT(p7 != NULL);
    BIO_free_all(out);
    i=OBJ_obj2nid(p7->type);
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
    if (!certs) return;
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
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Cleanup
     */
    if (cert) X509_free(cert);
    EVP_PKEY_free(key);
    if (new_cert) free(new_cert);
    est_destroy(ectx);
}


/*
 * This test case uses an existing expired cert and
 * attempts to re-enroll it.  The expired certs contains
 * several X509 extensions. We verify the new issued
 * cert preserves these extensions using grep.  Note, 
 * preserving these extensions requires the OpenSSL CA
 * to enable the "copy_extensions" knob in the OpenSSL
 * config file.  This is why this test suite uses a
 * unique copy of estExampleCA.cnf.
 */
static void us898_test2 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    X509 *cert = NULL;
    BIO *in;
    char cmd[200];
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-expired.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
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
     * Save the cert to a local file
     */
    rv = write_binary_file(US898_TC2_CERT_B64, new_cert, pkcs7_len);
    CU_ASSERT(rv == 1);

    /*
     * Base 64 decode the cert response
     */
    sprintf(cmd, "openssl base64 -d -in %s -out %s", US898_TC2_CERT_B64, US898_TC2_CERT_PK7);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Convert the pkcs7 cert to a PEM cert
     */
    sprintf(cmd, "openssl pkcs7 -in %s -inform DER -print_certs -out %s", US898_TC2_CERT_PK7, US898_TC2_CERT_PEM);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Convert PEM cert to a textual representation of the cert
     */
    sprintf(cmd, "openssl x509 -text -in %s > %s", US898_TC2_CERT_PEM, US898_TC2_CERT_TXT);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Verify the jimbob DNS extension was preserved
     */
    rv = grep(US898_TC2_CERT_TXT, "jimbob");
    CU_ASSERT(rv == 0);

    /*
     * Verify the bobcat DNS extension was preserved
     */
    rv = grep(US898_TC2_CERT_TXT, "bobcat");
    CU_ASSERT(rv == 0);

    /*
     * Verify the IP address extension was preserved
     */
    rv = grep(US898_TC2_CERT_TXT,"172");
    CU_ASSERT(rv == 0);

    /*
     * Verify the Repudiation key usage extension was preserved
     */
    rv = grep(US898_TC2_CERT_TXT,"Repudiation");
    CU_ASSERT(rv == 0);

    /*
     * Verify the public key was preserved
     */
    rv = grep(US898_TC2_CERT_TXT, "00:e3:ca:38:65:fb:9c:46:a6:22:b1:be:17:bc:50");
    CU_ASSERT(rv == 0);

    /*
     * Clean up
     */
    if (new_cert) free(new_cert);
    est_destroy(ectx);
}

/*
 * Test the re-enroll API to ensure it gracefully
 * handles a null X509 cert pointer.
 */
static void us898_test3 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int pkcs7_len = 0;
    int rv;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * re-enroll using a null x509 pointer.
     */
    rv = est_client_reenroll(ectx, NULL, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NO_CERT);

    /*
     * Clean up
     */
    EVP_PKEY_free(key);
    est_destroy(ectx);
}

/*
 * Test the re-enroll API to ensure it gracefully
 * handles a null EVP_PKEY pointer.
 */
static void us898_test4 (void) 
{
    EST_CTX *ectx;
    int pkcs7_len = 0;
    int rv;
    X509 *cert = NULL;
    unsigned char *cert_raw;
    int cert_len;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in an old cert that we can use for re-enroll
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * re-enroll using a null EVP_KEY pointer.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, NULL);
    CU_ASSERT(rv == EST_ERR_NO_KEY);

    /*
     * Clean up
     */
    X509_free(cert);
    est_destroy(ectx);
}

/*
 * This test attempts to re-enroll a corrupted cert
 * The public key in the cert is has been corrupted.
 */
static void us898_test5 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-corrupt.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-corrupt.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_CLIENT_INVALID_KEY);

    /*
     * Clean up
     */
    est_destroy(ectx);
}

/*
 * This test attempts to re-enroll an expired cert
 * while the EST server is configured for manual
 * approval.  The server will send back a retry-after
 * response.
 */
static void us898_test6 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Stop the server.
     */
    st_stop();

    /*
     * Restart the server with manual approval enabled
     */
    rv = us898_start_server(1, 0);
    CU_ASSERT(rv == 0);

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-expired.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_CA_ENROLL_RETRY);

    /*
     * Clean up
     */
    est_destroy(ectx);

    /*
     * Stop the server.
     */
    st_stop();

    /*
     * Restart the server with manual approval disabled
     */
    rv = us898_start_server(0, 0);
    CU_ASSERT(rv == 0);
}

/*
 * Verify that a bogus user ID/password fails when
 * using HTTP basic auth.
 */
static void us898_test7 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

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
    rv = est_client_set_auth(ectx, "hoagie", "chili", NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-expired.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);

    est_destroy(ectx);
}

/*
 * Verify that a good user ID/password passes when
 * using HTTP digest auth.
 */
static void us898_test8 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Enable HTTP digest authentication
     */
    st_enable_http_digest_auth();

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
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-expired.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    est_destroy(ectx);

    /*
     * Re-enable HTTP basic authentication
     */
    st_enable_http_basic_auth();

}

/*
 * Verify that a bogus user ID/password fails when
 * using HTTP digest auth.
 */
static void us898_test9 (void) 
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int rv;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;
    int http_status;

    LOG_FUNC_NM;

    /*
     * Enable HTTP digest authentication
     */
    st_enable_http_digest_auth();

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
    rv = est_client_set_auth(ectx, "jdoe", "panthers", NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file("US898/key-expired.pem", &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file("US898/cert-expired.pem", &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll an expired cert that contains x509 extensions.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);

    /*
     * Check the HTTP status code from the reenroll operation
     */
    http_status = est_client_get_last_http_status(ectx);
    CU_ASSERT(http_status == 401);

    est_destroy(ectx);

    /*
     * Re-enable HTTP basic authentication
     */
    st_enable_http_basic_auth();

}

/*
 * Verify the server fails authentication when the
 * client sends a valid identity cert but doesn't 
 * provide HTTP auth credentials.
 */
static void us898_test10 (void) 
{
    char cmd[200];
    int rv;
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Create a CSR
     */
    sprintf(cmd, "openssl req -new -nodes -out %s -newkey rsa:2048 -keyout %s -subj /CN=127.0.0.1 "
	    "-config CA/estExampleCA.cnf", 
	    US898_TC10_CSR, US898_TC10_KEY);  
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Sign the CSR using our local CA
     */
    sprintf(cmd, "openssl ca -out %s -batch -config CA/estExampleCA.cnf -infiles %s", 
	    US898_TC10_CERT, US898_TC10_CSR);
    rv = system(cmd);
    CU_ASSERT(rv == 0);

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US898_TC10_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US898_TC10_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);


    /*
     * Set the authentication mode to use the certificate 
     * No HTTP auth credentials are provided.
     */
    rv = est_client_set_auth(ectx, NULL, NULL, cert, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Enroll a cert, should fail because we 
     * didn't provide valid HTTP auth credentials
     */
    rv = est_client_enroll(ectx, "TC-US898-10", &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_AUTH_FAIL);

    /*
     * Re-Enroll the cert, should work since
     * we provide a valid cert to identify ourselves
     * and HTTP auth isn't required for re-enroll even when
     * the server has enabled HTTP auth.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    est_destroy(ectx);
}

/*
 * Verify the server fails authentication when the
 * client sends an expired identity cert and uses
 * valid HTTP auth credentials.
 */
static void us898_test11 (void) 
{
    int rv;
    EST_CTX *ectx;
    EVP_PKEY *key;
    unsigned char *key_raw;
    int key_len;
    unsigned char *cert_raw;
    int cert_len;
    int pkcs7_len = 0;
    X509 *cert = NULL;
    BIO *in;
    unsigned char *attr_data = NULL;
    int attr_len;

    LOG_FUNC_NM;

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Read in the private key
     */
    key_len = read_binary_file(US898_TC11_KEY, &key_raw);
    CU_ASSERT(key_len > 0);
    key = est_load_key(key_raw, key_len, EST_FORMAT_PEM);
    CU_ASSERT(key != NULL);
    free(key_raw);

    /*
     * Read in the old cert
     */
    cert_len = read_binary_file(US898_TC11_CERT, &cert_raw);
    CU_ASSERT(cert_len > 0);
    in = BIO_new_mem_buf(cert_raw, cert_len);
    CU_ASSERT(in != NULL);
    if (!in) return;
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    CU_ASSERT(cert != NULL);
    if (!cert) return; 
    BIO_free_all(in);
    free(cert_raw);


    /*
     * Set the authentication mode to use the expired certificate 
     * and valid HTTP auth credentials.
     */
    rv = est_client_set_auth(ectx, US898_UID, US898_PWD, cert, key);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US898_SERVER_IP, US898_SERVER_PORT, NULL);

    /*
     * Get the latest CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);

    /*
     * Re-Enroll the cert 
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);

    est_destroy(ectx);
}


int us898_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us898_client_reenroll", 
	                  us898_init_suite, 
			  us898_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* 
    * Add the tests to the suite 
    */
   if ((NULL == CU_add_test(pSuite, "Simple enroll and re-enroll", us898_test1)) ||
       (NULL == CU_add_test(pSuite, "Re-enroll expired cert with extensions", us898_test2)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll using NULL cert", us898_test3)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll using NULL key", us898_test4)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll using corrupted X509 cert", us898_test5)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll retry-after", us898_test6)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll invalid UID/PWD Basic", us898_test7)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll valid UID/PWD Digest", us898_test8)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll invalid UID/PWD Digest", us898_test9)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll valid certificate no HTTP auth", us898_test10)) || 
       (NULL == CU_add_test(pSuite, "Re-enroll expired certificate with HTTP auth", us898_test11))) 
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}


