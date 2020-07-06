/*------------------------------------------------------------------
 * us4747.c - Unit Tests for User Story 4747 - Encryption of server generated
 * key from server to client
 *
 * October 2017
 *
 * Copyright (c) 2017 by cisco Systems, Inc.
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
static int cacerts_len = 0;

#define US4747_SERVER_PORT   29475
#define US4747_SERVER_IP	    "127.0.0.1"	
#define US4747_UID	    "estuser"
#define US4747_PWD	    "estpwd"

/*
 * The following certs are used for FQDN testing
 */
//#ifndef WIN32
#define US4747_CACERTS	    "CA/estCA/cacert.crt"
#define US4747_TRUST_CERTS   "CA/trustedcerts.crt"
#define US4747_SERVER_CERTKEY   "CA/estCA/private/estservercertandkey.pem"
//
//#define US4747_SERVER_CERT_CN_MISMATCH	    "US4747/cert_cn_mismatch.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH	    "US4747/key_cn_mismatch.pem"
//#define US4747_SERVER_CERT_CN_MISMATCH_IP    "US4747/cert_cn_mismatch_ip.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH_IP	    "US4747/key_cn_mismatch_ip.pem"
//#define US4747_SERVER_CERT_CN_MATCH_WC       "US4747/cert_cn_match_wc.pem"
//#define US4747_SERVER_KEY_CN_MATCH_WC	    "US4747/key_cn_match_wc.pem"
//#define US4747_SERVER_CERT_CN_MISMATCH_WC    "US4747/cert_cn_mismatch_wc.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH_WC	    "US4747/key_cn_mismatch_wc.pem"
//#define US4747_SERVER_CERT_SAN_MATCH	    "US4747/cert_san_match.pem"
//#define US4747_SERVER_KEY_SAN_MATCH	    "US4747/key_san_match.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH	    "US4747/cert_san_mismatch.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH	    "US4747/key_san_mismatch.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH_IP   "US4747/cert_san_mismatch_ip.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH_IP    "US4747/key_san_mismatch_ip.pem"
//#define US4747_SERVER_CERT_SAN_MATCH_IP      "US4747/cert_san_match_ip.pem"
//#define US4747_SERVER_KEY_SAN_MATCH_IP       "US4747/key_san_match_ip.pem"
//#define US4747_SERVER_CERT_SAN_MATCH_WC      "US4747/cert_san_match_wc.pem"
//#define US4747_SERVER_KEY_SAN_MATCH_WC       "US4747/key_san_match_wc.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH_WC   "US4747/cert_san_mismatch_wc.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH_WC    "US4747/key_san_mismatch_wc.pem"
//#else
//#define US4747_CACERTS	    "CA\\estCA\\cacert.crt"
//#define US4747_TRUST_CERTS   "CA\\trustedcerts.crt"
//#define US4747_SERVER_CERTKEY   "CA\\estCA\\private\\estservercertandkey.pem"
//
//#define US4747_SERVER_CERT_CN_MISMATCH	    "US4747\\cert_cn_mismatch.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH	    "US4747\\key_cn_mismatch.pem"
//#define US4747_SERVER_CERT_CN_MISMATCH_IP    "US4747\\cert_cn_mismatch_ip.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH_IP	    "US4747\\key_cn_mismatch_ip.pem"
//#define US4747_SERVER_CERT_CN_MATCH_WC       "US4747\\cert_cn_match_wc.pem"
//#define US4747_SERVER_KEY_CN_MATCH_WC	    "US4747\\key_cn_match_wc.pem"
//#define US4747_SERVER_CERT_CN_MISMATCH_WC    "US4747\\cert_cn_mismatch_wc.pem"
//#define US4747_SERVER_KEY_CN_MISMATCH_WC	    "US4747\\key_cn_mismatch_wc.pem"
//#define US4747_SERVER_CERT_SAN_MATCH	    "US4747\\cert_san_match.pem"
//#define US4747_SERVER_KEY_SAN_MATCH	    "US4747\\key_san_match.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH	    "US4747\\cert_san_mismatch.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH	    "US4747\\key_san_mismatch.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH_IP   "US4747\\cert_san_mismatch_ip.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH_IP    "US4747\\key_san_mismatch_ip.pem"
//#define US4747_SERVER_CERT_SAN_MATCH_IP      "US4747\\cert_san_match_ip.pem"
//#define US4747_SERVER_KEY_SAN_MATCH_IP       "US4747\\key_san_match_ip.pem"
//#define US4747_SERVER_CERT_SAN_MATCH_WC      "US4747\\cert_san_match_wc.pem"
//#define US4747_SERVER_KEY_SAN_MATCH_WC       "US4747\\key_san_match_wc.pem"
//#define US4747_SERVER_CERT_SAN_MISMATCH_WC   "US4747\\cert_san_mismatch_wc.pem"
//#define US4747_SERVER_KEY_SAN_MISMATCH_WC    "US4747\\key_san_mismatch_wc.pem"
//
//static CRITICAL_SECTION logger_critical_section;
//static void us4747_logger_stderr (char *format, va_list l)
//{
//    EnterCriticalSection(&logger_critical_section);
//	vfprintf(stderr, format, l);
//	fflush(stderr);
//    LeaveCriticalSection(&logger_critical_section);
//}
//#endif



#define US4747_VALID_CSR_PEM "-----BEGIN CERTIFICATE REQUEST-----\nMIIBhDCB7gIBADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEh\nMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEB\nAQUAA4GNADCBiQKBgQC13wEG36vBY8Mq+uu80SKvkx0ZCt0lc18kaMSDLwML2IRS\n+SaCLEZbjJYeSxwZ9qXy4Rt1vFDRRTL57/lQTgT5kzKI2D2YUZ+Dg6wQqx/4t99S\naCv/lxcUTfIPiaqATUQxeZA+h7Fo0ti9wLSw6AQft9hibYPRJZ6zHa24lXwd7wID\nAQABoAAwDQYJKoZIhvcNAQEFBQADgYEAjwSjLqFAzoPGa4GKn7AEitepVA+3QjXL\n45LSzrVJMW4Jl8Ovm/aPatnFRQYm82rVKb7Sq4Ddo9nDJ9tgZ450oqIWbujUmGEU\nsUUxJSJ3vGXyQy+8NeTy4GmmsNWIwhSKMkqh7YVlBvgkwGoNFuQ8mD90prFmld+J\nhHBZXCaekrE=\n-----END CERTIFICATE REQUEST-----"


/*
 * Note: this array was generated using:  xdd -i req.der req.c
 */
static unsigned char US4747_VALID_CSR_DER[] = {
  0x30, 0x82, 0x01, 0xa8, 0x30, 0x82, 0x01, 0x11, 0x02, 0x01, 0x00, 0x30,
  0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
  0x02, 0x6e, 0x63, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x07,
  0x0c, 0x03, 0x73, 0x73, 0x73, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
  0x04, 0x0a, 0x0c, 0x03, 0x64, 0x64, 0x64, 0x31, 0x0d, 0x30, 0x0b, 0x06,
  0x03, 0x55, 0x04, 0x0b, 0x0c, 0x04, 0x66, 0x6a, 0x6a, 0x64, 0x31, 0x0c,
  0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x31, 0x32, 0x37,
  0x31, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x09, 0x01, 0x16, 0x04, 0x6e, 0x6f, 0x6e, 0x65, 0x30, 0x81, 0x9f,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
  0x81, 0x00, 0xb9, 0x9f, 0xdd, 0xd0, 0xa4, 0xdf, 0x06, 0x50, 0xf5, 0x4e,
  0x85, 0x80, 0xeb, 0x2a, 0x1e, 0xff, 0x3c, 0x0f, 0x0d, 0x98, 0x6e, 0xfe,
  0x08, 0x74, 0xf4, 0xce, 0xf5, 0xfd, 0xf9, 0x2f, 0x86, 0x20, 0xf7, 0xcc,
  0x08, 0x05, 0xce, 0x98, 0x69, 0x5c, 0x8c, 0xbd, 0x20, 0xa7, 0x28, 0xf7,
  0xe4, 0x22, 0xfa, 0xaf, 0xe4, 0x15, 0xc4, 0xb9, 0x85, 0xcb, 0x0f, 0x11,
  0xc6, 0x55, 0x0d, 0x31, 0x5c, 0xfb, 0x5e, 0xcf, 0x8e, 0xd1, 0xde, 0x77,
  0x15, 0x2c, 0x8c, 0x4e, 0x88, 0x4e, 0x21, 0xb6, 0x69, 0x9c, 0xa7, 0x7d,
  0x06, 0xc5, 0x75, 0x3f, 0xdc, 0x18, 0xf6, 0x00, 0x51, 0xd5, 0x00, 0x47,
  0x62, 0xfc, 0x95, 0xc8, 0xd4, 0xef, 0x31, 0x4a, 0xb0, 0x15, 0xa9, 0x50,
  0x04, 0x6e, 0x13, 0x14, 0xd4, 0xbb, 0x56, 0x22, 0x6f, 0x3b, 0x91, 0xb6,
  0xeb, 0xba, 0x25, 0x8f, 0x12, 0xea, 0xfd, 0xd4, 0xd0, 0x6d, 0x02, 0x03,
  0x01, 0x00, 0x01, 0xa0, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
  0x3b, 0xa5, 0xb4, 0x97, 0x6c, 0xea, 0xe4, 0x9f, 0xeb, 0x56, 0xca, 0x7a,
  0x7f, 0xfa, 0x53, 0x8d, 0xee, 0x6f, 0x7e, 0xa1, 0x08, 0x65, 0xe0, 0x05,
  0x5b, 0x0e, 0x5a, 0x92, 0xdb, 0x3c, 0xc5, 0x6d, 0x0d, 0xcd, 0x2c, 0xcd,
  0x4d, 0x10, 0x2a, 0x92, 0x78, 0x1d, 0xfb, 0x92, 0x66, 0x33, 0x18, 0xdd,
  0xf8, 0x78, 0xc5, 0x1a, 0x03, 0xf9, 0x58, 0x9f, 0x32, 0x49, 0xde, 0xd2,
  0x26, 0x78, 0x80, 0x87, 0x18, 0xf3, 0x6d, 0xc3, 0x35, 0x5d, 0x21, 0x8b,
  0x4c, 0x8c, 0x87, 0xef, 0xb1, 0xfc, 0x2c, 0xec, 0xdb, 0xd6, 0x00, 0xe5,
  0x21, 0xfa, 0x34, 0x5a, 0x3c, 0xc3, 0x82, 0x52, 0x6f, 0x81, 0x2a, 0x05,
  0xcc, 0xdc, 0x8a, 0x51, 0xf6, 0x65, 0x1d, 0xc5, 0x64, 0x86, 0xc1, 0x28,
  0xf5, 0x0c, 0x8f, 0x09, 0xd4, 0x84, 0x8f, 0x69, 0x04, 0x24, 0x65, 0xf4,
  0x47, 0x6c, 0x90, 0x57, 0x3c, 0x04, 0x4d, 0x52
};
static unsigned int US4747_VALID_CSR_DER_LEN = 428;
#if 0
//Leaving this in for now, we may need this for some test cases
static FILE *outfile;
static size_t write_func(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t written;
    written = fwrite(ptr,size,nmemb,outfile);
    return written;
}
#endif

static void us4747_clean (void)
{
}

static int us4747_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US4747_SERVER_PORT, 
	          US4747_SERVER_CERTKEY,
	          US4747_SERVER_CERTKEY,
	          "US4747 test realm",
	          US4747_CACERTS,
	          US4747_TRUST_CERTS,
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
static int us4747_init_suite (void)
{
    int rv;

#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us4747_logger_stderr);
#endif

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US4747_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    us4747_clean();

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us4747_start_server(0, 0);

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us4747_destroy_suite (void)
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

static int populate_x509_csr (X509_REQ *req, EVP_PKEY *pkey, char *cn)
{
    X509_NAME *subj;

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L)) {
	printf("\nUnable to set X509 version#\n");
        return (-1);
    }

    /*
     * Add Common Name entry
     */
    subj = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                    (unsigned char*)cn, -1, -1, 0)) {
	printf("\nUnable to create X509 Common Name entry\n");
        return (-1);
    }

    /*
     * Set the public key on the request
     */
    if (!X509_REQ_set_pubkey(req, pkey)) {
	printf("\nUnable to set X509 public key\n");
        return (-1);
    }

    return (0);
}

/*
 * Sign an X509 certificate request using the digest and the key passed.
 * Returns OpenSSL error code from X509_REQ_sign_ctx();
 */
static int sign_X509_req (X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
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

/*
 * This function performs a basic simple enroll using
 * a UID/PWD to identify the client to the server.  This
 * is used for a variety of test cases in this module.
 */
static void us4747_keygen_simple_enroll(char *cn, char *server, EST_ERROR expected_enroll_rv)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0, pkcs8_len = 0;
    unsigned char *new_cert = NULL, *new_key = NULL;

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
    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ectx, server, US4747_SERVER_PORT, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the encryption mode for the key response
     */
    rv = est_client_set_keygen_enc_mode(ectx, EST_KEYGEN_ENC_AES_256_CBC);
    CU_ASSERT(rv == EST_ERR_NONE);


    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_server_keygen_enroll(ectx, cn, &pkcs7_len, &pkcs8_len, key);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_key = malloc(pkcs8_len);
        CU_ASSERT(new_key != NULL);
        rv = est_client_copy_server_generated_key(ectx, new_key);
        printf("\n###\n%s\n###\n", new_key);
        CU_ASSERT(rv == EST_ERR_NONE);

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
    if (new_key) free(new_key);
    est_destroy(ectx);
}

/*
 * This function performs a basic simple enroll using
 * a UID/PWD to identify the client to the server.  This
 * is used for a variety of test cases in this module.
 */
static void us4747_keygen_regular_enroll(char *csr, char *server, EST_ERROR expected_enroll_rv)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    int rv;
    int pkcs7_len = 0, pkcs8_len = 0;
    unsigned char *new_cert = NULL, *new_key = NULL;

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
    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    rv = est_client_set_server(ectx, server, US4747_SERVER_PORT, NULL);
    CU_ASSERT(rv == EST_ERR_NONE);


    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_server_keygen_enroll(ectx, csr, &pkcs7_len, &pkcs8_len, key);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Retrieve the cert that was given to us by the EST server
     */
    if (rv == EST_ERR_NONE) {
        new_key = malloc(pkcs8_len);
        CU_ASSERT(new_key != NULL);
        rv = est_client_copy_server_generated_key(ectx, new_key);
        CU_ASSERT(rv == EST_ERR_NONE);

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
    if (new_key) free(new_key);
    est_destroy(ectx);
}


/*
 * Simple enroll -  
 *
 * This is a basic test to perform a /simpleenroll using a 
 * user ID and password to identify the client to the server. 
 * No identity certificate is used by the client.
 */
static void us4747_test1 (void) 
{
    LOG_FUNC_NM;

    us4747_keygen_simple_enroll("TC4747-1", US4747_SERVER_IP, EST_ERR_NONE);
}


/*
 * Simple enroll CSR  
 *
 * This is a basic test to perform a /simpleenroll using a 
 * user ID and password to identify the client to the server. 
 * No identity certificate is used by the client.
 * This test case uses the alternate enroll method where the CSR
 * is provided by the application layer rather than having libest
 * generate the CSR.
 */
//static void us4747_test2 (void)
//{
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int rv;
//    int pkcs7_len = 0, pkcs8_len = 0;
//    unsigned char *new_cert = NULL, *new_key = NULL;
//    X509_REQ *csr;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Generate a CSR
//     */
//    csr = X509_REQ_new();
//    CU_ASSERT(csr != NULL);
//    rv = populate_x509_csr(csr, key, "US4747-TC2");
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Use the alternate API to enroll an existing CSR
//     */
//    rv = est_client_server_keygen_enroll_csr(ectx, csr, &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Retrieve the cert that was given to us by the EST server
//     */
//    if (rv == EST_ERR_NONE) {
//        new_key = malloc(pkcs8_len);
//        CU_ASSERT(new_key != NULL);
//        rv = est_client_copy_server_generated_key(ectx, new_key);
//        CU_ASSERT(rv == EST_ERR_NONE);
//
//        new_cert = malloc(pkcs7_len);
//        CU_ASSERT(new_cert != NULL);
//        rv = est_client_copy_enrolled_cert(ectx, new_cert);
//        CU_ASSERT(rv == EST_ERR_NONE);
//    }
//
//    /*
//     * Cleanup
//     */
//    X509_REQ_free(csr);
//    EVP_PKEY_free(key);
//    if (new_cert) free(new_cert);
//    if (new_key) free(new_key);
//
//    est_destroy(ectx);
//}

/*
 * Simple enroll CSR - Null 
 *
 * This is a basic test to perform a /simpleenroll using a 
 * user ID and password to identify the client to the server. 
 * No identity certificate is used by the client.
 * This test case uses the alternate enroll method where the CSR
 * is provided by the application layer rather than having libest
 * generate the CSR.  It attempts to pass in null CSR, which should
 * fail.
 */
//static void us4747_test3 (void)
//{
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int rv;
//    int pkcs7_len = 0, pkcs8_len = 0;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Use the alternate API to enroll a null CSR
//     */
//    rv = est_client_server_keygen_enroll_csr(ectx, NULL, &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_NO_CSR);
//
//    /*
//     * Cleanup
//     */
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//}

/*
 * Simple enroll CSR - corrupted  
 *
 * This test checks the X509_REQ helper function is working properly.
 * edaw 10/12 this is unchagned right now but will be pertinent when
 * the key is encrypted and CSR attributes are added
 */
//static void us4747_test4 (void)
//{
//    X509_REQ *csr;
//    unsigned char badreq[14] = "bogus request";
//
//    LOG_FUNC_NM;
//
//    /*
//     * First try PEM decoding
//     */
//    csr = est_read_x509_request(badreq, 13, EST_CERT_FORMAT_PEM);
//    CU_ASSERT(csr == NULL);
//
//    /*
//     * Next try DER decoding
//     */
//    csr = est_read_x509_request(badreq, 13, EST_CERT_FORMAT_DER);
//    CU_ASSERT(csr == NULL);
//
//    /*
//     * Next try an invalid format
//     */
//    csr = est_read_x509_request(badreq, 13, 999);
//    CU_ASSERT(csr == NULL);
//
//    /*
//     * Next try an invalid csr length
//     */
//    csr = est_read_x509_request(badreq, 999999, EST_CERT_FORMAT_PEM);
//    CU_ASSERT(csr == NULL);
//
//    /*
//     * Next try a valid PEM encoded csr
//     */
//    csr = est_read_x509_request((unsigned char*)US4747_VALID_CSR_PEM, strlen(US4747_VALID_CSR_PEM),
//	                         EST_CERT_FORMAT_PEM);
//    CU_ASSERT(csr != NULL);
//    if (csr) {
//	    X509_REQ_free(csr);
//    }
//
//    /*
//     * Next try a valid DER encoded csr
//     */
//    csr = est_read_x509_request((unsigned char*)US4747_VALID_CSR_DER, US4747_VALID_CSR_DER_LEN,
//	                         EST_CERT_FORMAT_DER);
//    CU_ASSERT(csr != NULL);
//    if (csr) {
//	    X509_REQ_free(csr);
//    }
//}

//C. Attempt to enroll a newly created CSR that's already been signed
//   via est_client_enroll_csr
//static void us4747_test5 (void)
//{
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int rv;
//    int pkcs7_len = 0, pkcs8_len = 0;
//    X509_REQ *csr;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * Generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Generate a new CSR
//     */
//    csr = X509_REQ_new();
//    CU_ASSERT(csr != NULL);
//    rv = populate_x509_csr(csr, key, "US4747-TC5");
//    CU_ASSERT(csr != NULL);
//
//    /*
//     * Sign the CSR
//     */
//
//    rv = sign_X509_req(csr,key,EVP_sha256());
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Use the alternate API to enroll an existing CSR.  This should pass.
//     */
//    rv = est_client_server_keygen_enroll_csr(ectx, csr, &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Cleanup
//     */
//    X509_REQ_free(csr);
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//}

/*
 * Simple enroll - FQDN mismatch hostname in CN 
 *
 * This test confirms that a mismatched host name on
 * the server cert CN will result in an auth failure
 * at the TLS layer on the client side.
 */
//static void us4747_test6 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_CN_MISMATCH,
//	          US4747_SERVER_KEY_CN_MISMATCH,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-6", US4747_SERVER_IP, EST_ERR_FQDN_MISMATCH);
//
//}

/*
 * Simple enroll - FQDN mismatch IPv4 address in CN
 *
 * This test confirms that a mismatched IP address in
 * the server cert CN will result in an auth failure
 * at the TLS layer on the client side.
 * Note: this test may be redundant since the IP address
 *       matching logic only occurs when the dNSName is
 *       used instead of the CommonName.
 */
//static void us4747_test7 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_CN_MISMATCH_IP,
//	          US4747_SERVER_KEY_CN_MISMATCH_IP,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-7", US4747_SERVER_IP, EST_ERR_FQDN_MISMATCH);
//
//}

/*
 * Simple enroll - FQDN matched wildcard in CN 
 *
 * This test confirms that wildcard matching logic
 * in the CN is working. The cert uses a wildcard
 * pattern of *.cisco.com with a server address
 * of localhost.cisco.com.
 */
//static void us4747_test8 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_CN_MATCH_WC,
//	          US4747_SERVER_KEY_CN_MATCH_WC,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-8", "localhost.cisco.com", EST_ERR_NONE);
//
//}

/*
 * Simple enroll - FQDN mismatched wildcard in CN 
 *
 * This test confirms that wildcard matching logic
 * in the CN is working. The cert uses a wildcard
 * pattern of *.google.com with a server address
 * of localhost.cisco.com.
 */
//static void us4747_test9 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_CN_MISMATCH_WC,
//	          US4747_SERVER_KEY_CN_MISMATCH_WC,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-9", "localhost.cisco.com", EST_ERR_FQDN_MISMATCH);
//}

/*
 * Simple enroll - FQDN matched hostname in SubjectAltName 
 *
 * This test confirms that a matched host name on
 * the server cert SubjectAltName ext will result in an auth success. 
 */
//static void us4747_test10 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MATCH,
//	          US4747_SERVER_KEY_SAN_MATCH,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-10", "localhost.cisco.com", EST_ERR_NONE);
//}

/*
 * Simple enroll - FQDN mismatched hostname in SubjectAltName 
 *
 * This test confirms that a mismatched host name on
 * the server cert SubjectAltName ext will result in an auth failure. 
 */
//static void us4747_test11 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MISMATCH,
//	          US4747_SERVER_KEY_SAN_MISMATCH,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-11", "localhost.cisco.com", EST_ERR_FQDN_MISMATCH);
//}

/*
 * Simple enroll - FQDN mismatched IPv4 address in SubjectAltName 
 *
 * This test confirms that a mismatched IPv4 address on
 * the server cert SubjectAltName ext will result in an auth failure. 
 */
//static void us4747_test12 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MISMATCH_IP,
//	          US4747_SERVER_KEY_SAN_MISMATCH_IP,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-12", US4747_SERVER_IP, EST_ERR_FQDN_MISMATCH);
//}

/*
 * Simple enroll - FQDN matched IPv4 address in SubjectAltName 
 *
 * This test confirms that a matched IPv4 address on
 * the server cert SubjectAltName ext will result in an auth success. 
 */
//static void us4747_test13 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MATCH_IP,
//	          US4747_SERVER_KEY_SAN_MATCH_IP,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-13", US4747_SERVER_IP, EST_ERR_NONE);
//}

/*
 * Simple enroll - FQDN matched hostname in SubjectAltName with wildcard 
 *
 * This test confirms that a hostname matches a wildcard pattern in
 * the server cert SubjectAltName ext, which will result in an auth success. 
 */
//static void us4747_test14 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MATCH_WC,
//	          US4747_SERVER_KEY_SAN_MATCH_WC,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-14", "localhost.cisco.com", EST_ERR_NONE);
//}

/*
 * Simple enroll - FQDN mismatched hostname in SubjectAltName with wildcard 
 *
 * This test confirms that a hostname mismatches a wildcard pattern in
 * the server cert SubjectAltName ext, which will result in an auth fail. 
 */
//static void us4747_test15 (void)
//{
//    int rv;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Spin up a new instance of the EST server
//     * using a certificate that contains a
//     * bogus hostname in the CN
//     */
//    rv = st_start(US4747_SERVER_PORT,
//	          US4747_SERVER_CERT_SAN_MISMATCH_WC,
//	          US4747_SERVER_KEY_SAN_MISMATCH_WC,
//	          "US4747 test realm",
//	          US4747_CACERTS,
//	          US4747_TRUST_CERTS,
//	          "CA/estExampleCA.cnf",
//		  0, 0, 0);
//    CU_ASSERT(rv == 0);
//    if (rv) return;
//
//    us4747_keygen_simple_enroll("TC4747-15", "localhost.cisco.com", EST_ERR_FQDN_MISMATCH);
//}


/*
 * Simple enroll - CRL check enabled on client
 *
 * We enable CRL checking on the client side.  We will
 * generate a CRL, but the server cert will not be
 * revoked.  The enroll should succeed.
 */
//static void us4747_test16 (void)
//{
//    int rv;
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int pkcs7_len = 0, pkcs8_len = 0;
//    unsigned char *new_cert = NULL;
//    unsigned char *cacrlcerts = NULL;
//    int cacrlcerts_len = 0;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to use a different cert.
//     */
//    st_stop();
//
//    /*
//     * Now that all the FQDN tests are completed, start
//     * the normal server.
//     */
//    rv = us4747_start_server(0, 0);
//    CU_ASSERT(rv == 0);
//
//    /*
//     * Generate a CRL and append it to the CA chain
//     * we're using on the client side.
//     */
//#ifndef WIN32
//    system("openssl ca -config CA/estExampleCA.cnf -gencrl -out US4747/test16_crl.pem");
//    SLEEP(1);
//    system("cat CA/trustedcerts.crt > US4747/test16trust.crt");
//    SLEEP(1);
//    system("cat US4747/test16_crl.pem >> US4747/test16trust.crt");
//    SLEEP(1);
//#else
//    system("openssl ca -config CA/estExampleCA.cnf -gencrl -out US4747/test16_crl.pem");
//    SLEEP(1);
//    system("type CA\\trustedcerts.crt > US4747\\test16trust.crt");
//    SLEEP(1);
//    system("type US4747\\test16_crl.pem >> US4747\\test16trust.crt");
//    SLEEP(1);
//#endif
//
//    /*
//     * Read in the CA certificates
//     */
//    cacrlcerts_len = read_binary_file("US4747/test16trust.crt", &cacrlcerts);
//    CU_ASSERT(cacrlcerts > 0);
//    if (cacrlcerts_len <= 0) {
//	return;
//    }
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacrlcerts, cacrlcerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Enable CRL checking on the client
//     */
//    rv = est_enable_crl(ectx);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Use the simplified API to enroll a CSR
//     */
//    rv = est_client_server_keygen_enroll(ectx, "TEST16-CN", &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Retrieve the cert that was given to us by the EST server
//     */
//    if (rv == EST_ERR_NONE) {
//        new_cert = malloc(pkcs7_len);
//        CU_ASSERT(new_cert != NULL);
//        rv = est_client_copy_enrolled_cert(ectx, new_cert);
//        CU_ASSERT(rv == EST_ERR_NONE);
//    }
//
//    /*
//     * Cleanup
//     */
//    EVP_PKEY_free(key);
//    if (new_cert) free(new_cert);
//    est_destroy(ectx);
//    free(cacrlcerts);
//}

/*
 * Simple enroll - CRL check enabled on client
 *
 * We enable CRL checking on the client side.  We will
 * generate a CRL, the server cert will  be
 * revoked.  The enroll should fail.
 */
//static void us4747_test17 (void)
//{
//    int rv;
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int pkcs7_len = 0, pkcs8_len;
//    unsigned char *cacrlcerts = NULL;
//    int cacrlcerts_len = 0;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Revoke the server cert, generate a CRL and append it to the CA chain
//     * we're using on the client side.
//     */
//#ifndef WIN32
//    system("cp CA/estCA/index.txt CA/estCA/index.txt.save");
//    SLEEP(1);
//    system("openssl ca -config CA/estExampleCA.cnf -revoke CA/estCA/private/estservercertandkey.pem");
//    SLEEP(1);
//    system("openssl ca -config CA/estExampleCA.cnf -gencrl -out US4747/test17_crl.pem");
//    SLEEP(1);
//    system("cat CA/trustedcerts.crt > US4747/test17trust.crt");
//    SLEEP(1);
//    system("cat US4747/test17_crl.pem >> US4747/test17trust.crt");
//    SLEEP(1);
//    system("cp CA/estCA/index.txt.save CA/estCA/index.txt");
//    SLEEP(1);
//#else
//    system("copy CA\\estCA\\index.txt CA\\estCA\\index.txt.save");
//    SLEEP(1);
//    system("openssl ca -config CA\\estExampleCA.cnf -revoke CA\\estCA\\private\\estservercertandkey.pem");
//	SLEEP(1);
//    system("openssl ca -config CA\\estExampleCA.cnf -gencrl -out US4747\\test17_crl.pem");
//    SLEEP(1);
//    system("type CA\\trustedcerts.crt > US4747\\test17trust.crt");
//    SLEEP(1);
//    system("type US4747\\test17_crl.pem >> US4747\\test17trust.crt");
//    SLEEP(1);
//    system("copy CA\\estCA\\index.txt.save CA\\estCA\\index.txt");
//    SLEEP(1);
//#endif
//
//    /*
//     * Read in the CA certificates
//     */
//    cacrlcerts_len = read_binary_file("US4747/test17trust.crt", &cacrlcerts);
//    CU_ASSERT(cacrlcerts > 0);
//    if (cacrlcerts_len <= 0) {
//	return;
//    }
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacrlcerts, cacrlcerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Enable CRL checking on the client
//     */
//    rv = est_enable_crl(ectx);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);
//
//    /*
//     * Use the simplified API to enroll a CSR
//     */
//    rv = est_client_server_keygen_enroll(ectx, "TEST17-CN", &pkcs7_len, &pkcs8_len,  key);
//    CU_ASSERT(rv == EST_ERR_SSL_CONNECT);
//
//    /*
//     * Cleanup
//     */
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//    free(cacrlcerts);
//}

/*
 * Simple enroll - Receive Retry-After response 
 *
 * Client issues an Enroll request and receives
 * a Retry-After response.  Ensure that the
 * retry after value can be obtained from the client.
 */
//static void us4747_test18 (void)
//{
//    int rv;
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int pkcs7_len = 0, pkcs8_len;
//    int delay_secs = 0;
//    time_t retry_date = 0;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to go into manual enroll mode
//     */
//    st_stop();
//
//    /*
//     * Start the server up in manual enroll mode
//     */
//    rv = us4747_start_server(1, 0);
//    CU_ASSERT(rv == 0);
//
//    /*
//     * Create a client context using the default CA certs
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Use the simplified API to enroll a CSR
//     */
//    rv = est_client_server_keygen_enroll(ectx, "TEST18-CN", &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_CA_ENROLL_RETRY);
//
//    if (rv == EST_ERR_CA_ENROLL_RETRY) {
//        /*
//         * go get the retry duration
//         * make sure it's set to the default value
//         */
//        rv = est_client_copy_retry_after(ectx, &delay_secs, &retry_date);
//        CU_ASSERT(rv == EST_ERR_NONE);
//        CU_ASSERT(delay_secs == 3600);
//    }
//
//    /*
//     * Cleanup
//     */
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//}

/*
 * Simple enroll - Enroll with NULL key
 *
 * Client issues an Enroll request with a NULL key
 */
//static void us4747_test19 (void)
//{
//    int rv;
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int pkcs7_len = 0, pkcs8_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Stop the existing server.  This test case needs
//     * the server to go into manual enroll mode
//     */
//    st_stop();
//
//    /*
//     * Start the server up in manual enroll mode
//     */
//    rv = us4747_start_server(1, 0);
//    CU_ASSERT(rv == 0);
//
//    /*
//     * Create a client context using the default CA certs
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * set private key to NULL
//     */
//    key = NULL;
//
//    /*
//     * Use the simplified API to enroll a CSR
//     */
//    rv = est_client_server_keygen_enroll(ectx, "TEST18-CN", &pkcs7_len, &pkcs8_len, key);
//    CU_ASSERT(rv == EST_ERR_NO_KEY);
//
//    /*
//     * Cleanup
//     */
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//}

/*
 * Regular enroll - Enroll with valid CSR and NULL key
 *
 * Client issues an Enroll request with a NULL key
 */
//static void us4747_test20 (void)
//{
//    EST_CTX *ectx;
//    EVP_PKEY *key;
//    int rv;
//    int pkcs7_len = 0, pkcs8_len = 0;
//    X509_REQ *csr;
//    unsigned char *attr_data = NULL;
//    int attr_len;
//
//    LOG_FUNC_NM;
//
//    /*
//     * Create a client context
//     */
//    ectx = est_client_init(cacerts, cacerts_len,
//                           EST_CERT_FORMAT_PEM,
//                           client_manual_cert_verify);
//    CU_ASSERT(ectx != NULL);
//
//    /*
//     * Set the authentication mode to use a user id/password
//     */
//    rv = est_client_set_auth(ectx, US4747_UID, US4747_PWD, NULL, NULL);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Set the EST server address/port
//     */
//    est_client_set_server(ectx, US4747_SERVER_IP, US4747_SERVER_PORT, NULL);
//
//    /*
//     * Generate a private key
//     */
//    key = generate_private_key();
//    CU_ASSERT(key != NULL);
//
//    /*
//     * Generate a new CSR
//     */
//    csr = X509_REQ_new();
//    CU_ASSERT(csr != NULL);
//    rv = populate_x509_csr(csr, key, "US4747-TC5");
//    CU_ASSERT(csr != NULL);
//
//    /*
//     * Sign the CSR
//     */
//
//    rv = sign_X509_req(csr, key, EVP_sha256());
//
//    /*
//     * Get the latest CSR attributes
//     */
//    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
//    CU_ASSERT(rv == EST_ERR_NONE);
//
//    /*
//     * Use the alternate API to enroll an existing CSR.  This should pass.
//     */
//    rv = est_client_server_keygen_enroll_csr(ectx, csr, &pkcs7_len, &pkcs8_len, NULL);
//    CU_ASSERT(rv == EST_ERR_NO_KEY);
//
//    /*
//     * Cleanup
//     */
//    X509_REQ_free(csr);
//    EVP_PKEY_free(key);
//    est_destroy(ectx);
//}


//TO DO
//
//Auth (HTTP basic auth enabled on server) 
//A. Enroll CSR using valid cert, no UID
//B. Enroll CSR using valid cert, valid UID
//C. Enroll CSR using valid cert, invalid UID
//D. Enroll CSR using invalid cert, no UID
//E. Enroll CSR using invalid cert, valid UID
//F. Enroll CSR using invalid cert, invalid UID
//
//Auth (HTTP digest auth enabled on server) 
//A. Enroll CSR using valid cert, no UID
//B. Enroll CSR using valid cert, valid UID
//C. Enroll CSR using valid cert, invalid UID
//D. Enroll CSR using invalid cert, no UID
//E. Enroll CSR using invalid cert, valid UID
//F. Enroll CSR using invalid cert, invalid UID
//

int us4747_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us4747_keygen_encrypt_key",
	                  us4747_init_suite, 
			  us4747_destroy_suite);
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
   if ( (NULL == CU_add_test(pSuite, "Key gen simple enroll", us4747_test1)) )// ||
//       (NULL == CU_add_test(pSuite, "Enroll CSR", us4747_test2)) ||
//       (NULL == CU_add_test(pSuite, "Enroll null CSR", us4747_test3)) ||
//       (NULL == CU_add_test(pSuite, "Enroll corrupted CSR", us4747_test4)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll signed CSR", us4747_test5)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - hostname mismatch FQDN CN", us4747_test6)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - IPv4 mismatch FQDN CN", us4747_test7)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - wildcard match FQDN CN", us4747_test8)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - wildcard mismatch FQDN CN", us4747_test9)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - hostname match FQDN SAN", us4747_test10)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - hostname mismatch FQDN SAN", us4747_test11)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - IPv4 mismatch FQDN SAN", us4747_test12)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - IPv4 match FQDN SAN", us4747_test13)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - wildcard match FQDN SAN", us4747_test14)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - wildcard mismatch FQDN SAN", us4747_test15)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - CRL enabled, valid server cert", us4747_test16)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - CRL enabled, revoked server cert", us4747_test17)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - Retry-After received", us4747_test18)) ||
//       (NULL == CU_add_test(pSuite, "Simple enroll - Enroll with NULL key", us4747_test19)) ||
//       (NULL == CU_add_test(pSuite, "Regular enroll - Enroll with valid CSR and NULL key", us4747_test20)) )

   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}


