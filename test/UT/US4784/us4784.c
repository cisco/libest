/*------------------------------------------------------------------
 * us4784.c - Unit Tests for serial number verification
 *
 * October, 2017
 *
 * Copyright (c) 2017 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#ifdef ENABLE_BRSKI
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

#include "../../src/est/est_locl.h"

/*
 * max command line length when generating system commands
 */
#define EST_UT_MAX_CMD_LEN 256

/*
 * The CA certificate used to verify the EST server.  Grab it from the server's directory
 */
/* #define CLIENT_UT_CACERT "../../example/server/estCA/cacert.crt" */
/* #define CLIENT_UT_CACERT "CA/masaCA/masa_trust_store.crt" */
/* #define CLIENT_UT_CACERT "CA/estCA/cacert.crt" */
#define CLIENT_UT_CACERT "CA/brski_trustedcerts.crt"
#define CLIENT_UT_PUBKEY "./est_client_ut_keypair"
#define CLIENT_UT_MFG_PRIVKEY "./est_client_ut_mfg_privkey.pem"
#define CLIENT_UT_MFG_CSR "./est_client_ut_mfg_csr.pem"
#define CLIENT_UT_MFG_CERT "./est_client_ut_mfg_cert.pem"

#define US4784_SERVER_PORT   29496
#define US4784_SERVER_IP    "127.0.0.1"	
#define US4784_UIDPWD_GOOD   "estuser:estpwd"
#define US4784_UID           "estuser"
#define US4784_PWD           "estpwd"
#ifndef WIN32
#define US4784_CACERTS	    "CA/estCA/cacert.crt"
#define US4784_TRUST_CERTS   "CA/trustedcerts.crt"
#define US4784_SERVER_CERTKEY "CA/estCA/private/estservercertandkey.pem"
#else
#define US4784_CACERTS	    "CA\\estCA\\cacert.crt"
#define US4784_TRUST_CERTS   "CA\\trustedcerts.crt"
#define US4784_SERVER_CERTKEY "CA\\estCA\\private\\estservercertandkey.pem"

static CRITICAL_SECTION logger_critical_section;  
static void us4784_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}
#endif

#define US4784_ENROLL_URL_BA "https://127.0.0.1:29496/.well-known/est/cacerts-somestring/simpleenroll"
#define US4784_PKCS10_CT	    "Content-Type: application/pkcs10" 

#define US4784_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error);

static void us4784_clean (void)
{
}

static int us4784_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US4784_SERVER_PORT, 
	          US4784_SERVER_CERTKEY,
	          US4784_SERVER_CERTKEY,
	          "US4784 test realm",
	          US4784_CACERTS,
	          US4784_TRUST_CERTS,
	          "CA/estExampleCA.cnf",
		  manual_enroll,
		  0,
		  nid);
    
    SLEEP(1);

    /*
     * If the starting of the single thread server was successful,
     * go ahead and put it into BRSKI mode
     */
    if (!rv) {
        rv = st_set_brski_mode();
        if (rv) {
            printf("Failed to put the server in BRSKI mode\n");
            return(rv);
        }

        /*
         * Initialize the BRSKI server testing modes
         */
        st_set_brski_serial_num_mode(1,0,0);
        st_set_brski_retry_mode(0,5,1);
        st_set_brski_nonce_mode(1,0,0);

        st_set_brski_masa_credentials("CA/masaCA/cacert.crt",
                                      "CA/masaCA/private/cakey.pem");
    }

    return (rv);
}

/*
 * This routine is called when CUnit initializes this test
 * suite. 
 * 1. Generate the keypair to be used for this EST Client UT suite
 */
static int us4784_init_suite (void)
{
    int rv = 0;
   
    char cmd[EST_UT_MAX_CMD_LEN];    
    printf("Starting EST Client BRSKI serial number unit tests.\n");
    
    /*
     * gen the mfg keypair that will be used to simulate what
     * would come from the manufacturer, including a cert request with
     * a hw serial number in the DN.
     *
     * Then, get the CSR signed by the ESTCA used for UT.
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN, "openssl req -nodes -days 365 -sha256 -newkey rsa:2048 "
             " -subj '/CN=www.iotrus.com/O=IOT-R-US, Inc./C=US/ST=NC/L=RTP/serialNumber=IOTRUS-0123456789' "
             " -keyout %s -out %s", CLIENT_UT_MFG_PRIVKEY, CLIENT_UT_MFG_CSR);
    printf("%s\n", cmd);
    rv = system(cmd);

/*     snprintf(cmd, EST_UT_MAX_CMD_LEN, "cd CA/;openssl ca -config ./estExampleCA.cnf -in %s " */
/*              "-extensions v3_ca -out %s -batch;cd ..", "../"CLIENT_UT_MFG_CSR, "../"CLIENT_UT_MFG_CERT); */
    snprintf(cmd, EST_UT_MAX_CMD_LEN, "openssl ca -config CA/estExampleCA.cnf -in %s "
             "-extensions v3_ca -out %s -batch", CLIENT_UT_MFG_CSR, CLIENT_UT_MFG_CERT);
    printf("%s\n", cmd);    
    rv = system(cmd);
    
    /*
     * gen the keypair to be used for EST Client testing
     */
    snprintf(cmd, EST_UT_MAX_CMD_LEN,
             "openssl ecparam -name prime256v1 -genkey -out %s", CLIENT_UT_PUBKEY);
    printf("%s\n", cmd);
    rv = system(cmd);

    /*
     * start the server for the tests that need to talk to a server
     */
    us4784_clean();    
    /*
     * Start an instance of the EST server
     */
    rv = us4784_start_server(0, 0);
    SLEEP(2);
    
    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us4784_destroy_suite (void)
{
    /*
     * Return to a known state just in case
     */
    st_set_brski_serial_num_mode(1,0,0);
    st_set_brski_retry_mode(0,5,1);
    st_set_brski_nonce_mode(1,0,0);    
    
    st_stop();    
    return 0;
}

/*
 * Callback function passed to est_client_init()
 */
static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
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
 * This test performs a voucher request using a cert that does NOT
 * contain a serial number in the DN.  Should return an error.
 */
static void us4784_test1 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    EVP_PKEY *priv_key;
    int voucher_cacert_len = 0;
    int sign_voucher = 0;
    X509 *client_cert;
    BIO *certin;
    EVP_PKEY *client_priv_key;
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

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
    
    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, US4784_SERVER_CERTKEY) <= 0) {
        printf("\nUnable to read client certificate file %s\n", US4784_SERVER_CERTKEY);
        return;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (client_cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n", US4784_SERVER_CERTKEY);
        return;
    }
    client_priv_key = read_private_key(US4784_SERVER_CERTKEY);
    if (client_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", US4784_SERVER_CERTKEY);
        ERR_print_errors_fp(stderr);
        return;
    }        
    rc = est_client_set_auth(ectx, "estuser", "estpwd", client_cert, client_priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);    
        
    rc = est_client_set_server(ectx, US4784_SERVER_IP, US4784_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    rc = est_client_set_brski_mode(ectx);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_brski_get_voucher(ectx, &voucher_cacert_len, sign_voucher);
    CU_ASSERT(rc == EST_ERR_CLIENT_BRSKI_SERIAL_NUM_MISSING);    
    
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
 * This test performs a voucher request using a cert that DOES
 * contain a serial number in the DN.  Should return success.
 */
static void us4784_test2 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    int voucher_cacert_len = 0;
    int sign_voucher = 0;

    X509 *client_cert;
    BIO *certin;
    EVP_PKEY *client_priv_key;
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, CLIENT_UT_MFG_CERT) <= 0) {
        printf("\nUnable to read client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (client_cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    client_priv_key = read_private_key(CLIENT_UT_MFG_PRIVKEY/* client_key_file */);
    if (client_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", CLIENT_UT_MFG_PRIVKEY);
        ERR_print_errors_fp(stderr);
        return;
    }        
    rc = est_client_set_auth(ectx, "estuser", "estpwd", client_cert, client_priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_set_server(ectx, US4784_SERVER_IP, US4784_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    rc = est_client_set_brski_mode(ectx);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_brski_get_voucher(ectx, &voucher_cacert_len, sign_voucher);
    CU_ASSERT(rc == EST_ERR_NONE);
    
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
 * This test sends a voucher that is missing the serial number
 */
static void us4784_test3 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    int voucher_cacert_len = 0;
    int sign_voucher = 0;

    X509 *client_cert;
    BIO *certin;
    EVP_PKEY *client_priv_key;

    st_set_brski_serial_num_mode(0,0,0);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, CLIENT_UT_MFG_CERT) <= 0) {
        printf("\nUnable to read client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (client_cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    client_priv_key = read_private_key(CLIENT_UT_MFG_PRIVKEY/* client_key_file */);
    if (client_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", CLIENT_UT_MFG_PRIVKEY);
        ERR_print_errors_fp(stderr);
        return;
    }        
    rc = est_client_set_auth(ectx, "estuser", "estpwd", client_cert, client_priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_set_server(ectx, US4784_SERVER_IP, US4784_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    rc = est_client_set_brski_mode(ectx);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_brski_get_voucher(ectx, &voucher_cacert_len, sign_voucher);
    CU_ASSERT(rc == EST_ERR_CLIENT_BRSKI_SERIAL_NUM_MISSING);
    
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
 * This test sends a voucher with a serial number that's too long
 */
static void us4784_test4 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    int voucher_cacert_len = 0;
    int sign_voucher = 0;

    X509 *client_cert;
    BIO *certin;
    EVP_PKEY *client_priv_key;

    st_set_brski_serial_num_mode(1,1,0);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, CLIENT_UT_MFG_CERT) <= 0) {
        printf("\nUnable to read client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (client_cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    client_priv_key = read_private_key(CLIENT_UT_MFG_PRIVKEY/* client_key_file */);
    if (client_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", CLIENT_UT_MFG_PRIVKEY);
        ERR_print_errors_fp(stderr);
        return;
    }        
    rc = est_client_set_auth(ectx, "estuser", "estpwd", client_cert, client_priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_set_server(ectx, US4784_SERVER_IP, US4784_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    rc = est_client_set_brski_mode(ectx);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_brski_get_voucher(ectx, &voucher_cacert_len, sign_voucher);
    CU_ASSERT(rc == EST_ERR_CLIENT_BRSKI_SERIAL_NUM_TOO_LARGE);
    
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
 * This test sends a voucher with a mismatching serial number
 */
static void us4784_test5 (void) 
{
    EST_CTX *ectx;
    unsigned char *pkey = NULL;
    unsigned char *cacerts = NULL;
    int cacerts_len = 0;
    EST_ERROR rc = EST_ERR_NONE;
    int voucher_cacert_len = 0;
    int sign_voucher = 0;

    X509 *client_cert;
    BIO *certin;
    EVP_PKEY *client_priv_key;

    st_set_brski_serial_num_mode(1,0,1);
    
    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(CLIENT_UT_CACERT, &cacerts);

    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);

    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, CLIENT_UT_MFG_CERT) <= 0) {
        printf("\nUnable to read client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (client_cert == NULL) {
        printf("\nError while reading PEM encoded client certificate file %s\n", CLIENT_UT_MFG_CERT);
        return;
    }
    client_priv_key = read_private_key(CLIENT_UT_MFG_PRIVKEY/* client_key_file */);
    if (client_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", CLIENT_UT_MFG_PRIVKEY);
        ERR_print_errors_fp(stderr);
        return;
    }        
    rc = est_client_set_auth(ectx, "estuser", "estpwd", client_cert, client_priv_key);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_set_server(ectx, US4784_SERVER_IP, US4784_SERVER_PORT, NULL);
    CU_ASSERT(rc == EST_ERR_NONE);
    
    rc = est_client_set_brski_mode(ectx);
    CU_ASSERT(rc == EST_ERR_NONE);

    rc = est_client_brski_get_voucher(ectx, &voucher_cacert_len, sign_voucher);
    CU_ASSERT(rc == EST_ERR_CLIENT_BRSKI_SERIAL_NUM_MISMATCH);
    
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
int us4784_add_suite (void)
{
    CU_ErrorCode CU_error;
    
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us4784_BRSKI_serial_number_support", 
	                  us4784_init_suite, 
			  us4784_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }
   
#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us4784_logger_stderr);
#endif   
    
    /* add the tests to the suite */
    /* NOTE - ORDER IS IMPORTANT - MUST TEST fread() AFTER fprintf() */
    if (
        (NULL == CU_add_test(pSuite, "Voucher request - no serial number", us4784_test1)) ||
        (NULL == CU_add_test(pSuite, "Voucher request - valid serial number", us4784_test2)) ||
        (NULL == CU_add_test(pSuite, "Voucher request - serial num missing", us4784_test3)) ||
        (NULL == CU_add_test(pSuite, "Voucher request - serial num too long", us4784_test4)) ||
        (NULL == CU_add_test(pSuite, "Voucher request - serial num mismatch", us4784_test5)) 
        ) {
        CU_error = CU_get_error();
        printf("%d\n", CU_error);
        
        CU_cleanup_registry();
        printf("%s\n", CU_get_error_msg());
        return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}
#endif
