/*------------------------------------------------------------------
 * us4020.c - Unit Test for User Story 4020 - Unit test client
 *            proxy mode.  Test the new API function and
 *            verify correct operation of Client proxy modes.
 *
 * October, 2016
 *
 * Copyright (c) 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif 
#include "est.h"
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include "st_server.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif
#include <errno.h>
#include <fcntl.h>

#define MAX_4020_CMDS 1024

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US4020_SERVER_DOMAIN_NAME "localhost.cisco.com"
#define US4020_SERVER_IP        "127.0.0.1"	
#define US4020_SERVER_TCP_PORT	40200

#define US4020_PROXY_IP         "127.0.0.1"	
#define US4020_PROXY_TCP_PORT	40208

#define US4020_UID	    "estuser"
#define US4020_PWD	    "estpwd"

#ifndef WIN32
#define US4020_CACERTS	     "CA/estCA/cacert.crt"
/* #define US4020_CACERT "CA/estCA/cacert.crt" */
/* #define US4020_SERVER_CERT "CA/estCA/private/estservercertandkey.pem" */
/* #define US4020_SERVER_KEY "CA/estCA/private/estservercertandkey.pem" */
/* #define US4020_CLIENT_CERT "CA/estCA/private/estservercertandkey.pem" */
/* #define US4020_CLIENT_KEY  "CA/estCA/private/estservercertandkey.pem" */
#else
#define US4020_CACERTS	     "CA\\estCA\\cacert.crt"
/* #define US4020_CACERT "CA\\estCA\\cacert.crt" */
/* #define US4020_SERVER_CERT "CA\\estCA\\private\\estservercertandkey.pem" */
/* #define US4020_SERVER_KEY "CA\\estCA\\private\\estservercertandkey.pem" */
/* #define US4020_CLIENT_CERT "CA\\estCA\\private\\estservercertandkey.pem" */
/* #define US4020_CLIENT_KEY  "CA\\estCA\\private/estservercertandkey.pem" */

static CRITICAL_SECTION logger_critical_section;  
static void us4020_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}
#endif 

static EVP_PKEY *generate_private_key (void)
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


static void us4020_clean (void)
{
}

int us4020_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US4020_SERVER_TCP_PORT, 
	          "CA/estCA/private/estservercertandkey.pem",
	          "CA/estCA/private/estservercertandkey.pem",
	          "estrealm",
	          "CA/estCA/cacert.crt",
	          "CA/trustedcerts.crt",
	          "CA/estExampleCA.cnf",
		  manual_enroll,
		  0,
		  nid);
    return rv;
}

#define MAX_CMD_BUF 256
#define MAX_PID_BUF 128
static void shutdown_antinat (void)
{
    int fh;
    char read_pid[MAX_PID_BUF];
    pid_t pid;
    int rv = 0;
    
    fh = open ("./antinat-pid", O_RDWR, 0666);
    
    (void)read(fh, read_pid, MAX_PID_BUF);    
    printf("pid read back in = %s\n", read_pid);

    pid = (pid_t) atoi(read_pid);
    /* 
     * Timeout at 1 second
     * check status every 10 msecs
     */
    rv = kill_process(pid, 1000, 10);
    if(rv) {
        printf("Failed to terminate antinat properly.\n");
    }
    return;
}

static void shutdown_haproxy (void)
{
    int fh;
/*     int readbyte_count = 0; */
    char read_pid[MAX_PID_BUF];
    pid_t pid;
    int rv = 0;

    fh = open ("./haproxy.pid", O_RDWR, 0666);
    
    (void)read(fh, read_pid, MAX_PID_BUF);
    printf("pid read back in = %s\n", read_pid);

    pid = (pid_t) atoi(read_pid);
    /* 
     * Timeout at 1 second
     * check status every 10 msecs
     */
    rv = kill_process(pid, 1000, 10);
    if(rv) {
        printf("Failed to terminate haproxy properly.\n");
    }
    return;
}


/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us4020_init_suite (void)
{
    int rv;
#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us4020_logger_stderr);
#else 
    est_init_logger(EST_LOG_LVL_INFO, NULL);
#endif    

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US4020_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    us4020_clean();

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us4020_start_server(0, 0);

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us4020_destroy_suite (void)
{
    st_stop();
    free(cacerts);
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
 * Error check the parameters to the API
 */
static void us4020_test1 (void) 
{
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
     
    LOG_FUNC_NM;

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  Attempt to call the API without a context
     */
    e_rc= est_client_set_proxy(NULL, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");
    CU_ASSERT(e_rc == EST_ERR_NO_CTX);

    /*
     * valid call
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * don't set the server 
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               NULL,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_SERVER_NAME);

    /*
     * server to empty string
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               "",
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_SERVER_NAME);

    /*
     * max server name 
     */
    char * max_server_name = "123456789012345678901234567890123456789012345678901234567890"
                             "123456789012345678901234567890123456789012345678901234567890"
                             "123456789012345678901234567890123456789012345678901234567890"
                             "123456789012345678901234567890123456789012345678901234567890"
                             "123456789012345";
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               max_server_name,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * server name too long
     */
    char * long_server_name = "123456789012345678901234567890123456789012345678901234567890"
                              "123456789012345678901234567890123456789012345678901234567890"
                              "123456789012345678901234567890123456789012345678901234567890"
                              "123456789012345678901234567890123456789012345678901234567890"
                              "1234567890123456";
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               long_server_name,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_SERVER_NAME);

    /*
     * don't set the port
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               0,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_PORT_NUM);

    /* proxy protocol invalid */
    e_rc= est_client_set_proxy(ectx, 25,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_CLIENT_PROXY_PROTOCOL);

    /* proxy protocol invalid */
    e_rc= est_client_set_proxy(ectx, -2,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_CLIENT_PROXY_PROTOCOL);

    /* proxy auth invalid */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               25,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_CLIENT_PROXY_AUTH);

    /*
     * max userid
     */
    char * max_userid = "123456789012345678901234567890123456789012345678901234567890"
                        "123456789012345678901234567890123456789012345678901234567890"
                        "123456789012345678901234567890123456789012345678901234567890"
                        "123456789012345678901234567890123456789012345678901234567890"
                        "123456789012345";
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               max_userid, "estpwd");

    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * userid too long
     */
    char * long_userid = "123456789012345678901234567890123456789012345678901234567890"
                         "123456789012345678901234567890123456789012345678901234567890"
                         "123456789012345678901234567890123456789012345678901234567890"
                         "123456789012345678901234567890123456789012345678901234567890"
                         "1234567890123456";

    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               long_userid, "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_PARAMETERS);

    /*
     * userid is an empty string
     */    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_INVALID_PARAMETERS);

    /*
     * max pwd
     */
    char * max_pwd = "123456789012345678901234567890123456789012345678901234567890"
                     "123456789012345678901234567890123456789012345678901234567890"
                     "123456789012345678901234567890123456789012345678901234567890"
                     "123456789012345678901234567890123456789012345678901234567890"
                     "123456789012345";
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", max_pwd);

    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * pwd too long
     */    
    char * long_pwd = "123456789012345678901234567890123456789012345678901234567890"
                      "123456789012345678901234567890123456789012345678901234567890"
                      "123456789012345678901234567890123456789012345678901234567890"
                      "123456789012345678901234567890123456789012345678901234567890"
                      "1234567890123456";
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", long_pwd);

    CU_ASSERT(e_rc == EST_ERR_INVALID_PARAMETERS);

    /*
     * password is an empty string
     */    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "");

    CU_ASSERT(e_rc == EST_ERR_INVALID_PARAMETERS);    
    
    est_destroy(ectx);
    
}


/*
 * Test for SOCKS 4 mode, no credentials, should pass
 *
 */
static void us4020_test2 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS4,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-2", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_antinat();    
    est_destroy(ectx);
}


/*
 * Test for SOCKS 4 mode, with credentials, should pass
 *
 */
static void us4020_test3 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS4,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-3", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_antinat();    
    est_destroy(ectx);
}


/*
 * Test for SOCKS 5 mode
 *
 */
static void us4020_test4 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS5,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
/*                                "estuser", "estpwd"); */
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-4", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_antinat();    
    est_destroy(ectx);
}


/*
 * Test for SOCKS 4A mode
 *
 */
static void us4020_test5 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS4A,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
/*                                "estuser", "estpwd"); */
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-5", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_antinat();    
    est_destroy(ectx);
}


/*
 * Test for SOCKS 5 mode, with no credentials
 *
 */
static void us4020_test6 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS5,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-6", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);
    
    shutdown_antinat();
    est_destroy(ectx);
}


/*
 * Test for SOCKS 5 mode, with good credentials
 *
 */
static void us4020_test7 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg-goodcred.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS5,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-6", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);
    
    shutdown_antinat();
    est_destroy(ectx);
}


/*
 * Test for SOCKS 5 mode, with good credentials, but forgotten
 *
 */
static void us4020_test8 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg-goodcred.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS5,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-6", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_IP_CONNECT);
    
    shutdown_antinat();
    est_destroy(ectx);
}


/*
 * Test for SOCKS 5 mode, with bad credentials
 *
 */
static void us4020_test9 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg-badcred.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS5,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-6", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_IP_CONNECT);
    
    shutdown_antinat();
    est_destroy(ectx);
}


#if 0
/*
 * could be tested, but needs certificates updated
 */
/*
 * Test for SOCKS 4A mode, with domain name 
 *
 */
static void us4020_test8 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a SOCKS 4 proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "antinat -xcUS4020/antinat-cfg.xml");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    /*
     *  socks4
     */
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_SOCKS4A,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_DOMAIN_NAME, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-7", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_antinat();    
    est_destroy(ectx);
}
#endif

/*
 * Test HTTP proxy mode
 *
 * NOTE: only non-tunnel mode is tested.  tunnel mode does not
 * work with CiscoEST server.
 */
static void us4020_test10 (void) 
{
    int sys_rc = 0;
    EST_ERROR e_rc;
    EST_CTX *ectx = NULL;
    char cmd[MAX_4020_CMDS];
    EVP_PKEY *key;
    int pkcs7_len = 0;
     
    LOG_FUNC_NM;

    /*
     * Set up a HTTP proxy server locally
     */
    snprintf(cmd, MAX_4020_CMDS, "haproxy -D -f US4020/haproxy.cfg -p ./haproxy.pid");

    sys_rc = system(cmd);
    CU_ASSERT(sys_rc == 0);    
    
    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);
    
    e_rc= est_client_set_proxy(ectx, EST_CLIENT_PROXY_HTTP_NOTUNNEL,
                               US4020_PROXY_IP,
                               US4020_PROXY_TCP_PORT,
                               EST_CLIENT_PROXY_AUTH_BASIC,
                               "estuser", "estpwd");

    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the authentication mode to use a user id/password
     */
    e_rc = est_client_set_auth(ectx, US4020_UID, US4020_PWD, NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, US4020_SERVER_IP, US4020_SERVER_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    e_rc = est_client_enroll(ectx, "TC4020-8", &pkcs7_len, key);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    shutdown_haproxy();    
    est_destroy(ectx);
}


/*
 * Indicate whether client proxy support has been built into
 * the library or not
 */
static int client_proxy_enabled (void) 
{
    EST_ERROR e_rc;
    
    e_rc = est_client_set_proxy(NULL, 0, NULL, 0, 0, NULL, NULL);
    if (e_rc == EST_ERR_CLIENT_PROXY_MODE_NOT_SUPPORTED) {
        return 0;
    } else {
        return 1;
    }
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us4020_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us4020_client_proxy", 
	                  us4020_init_suite, 
			  us4020_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }
#ifndef WIN32
   /*
    * client proxy mode is only supported when libcurl has been specified.
    */
   if (client_proxy_enabled()){
       
       /* add the tests to the suite */
       if (
           (NULL == CU_add_test(pSuite, "parameter check API", us4020_test1)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 4 mode", us4020_test2)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 4 mode w/ credentials", us4020_test3)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 5 mode", us4020_test4)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 4A mode", us4020_test5)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 5 mode, no credentials", us4020_test6)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 5 mode, good credentials", us4020_test7)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 5 mode, forgotten credentials", us4020_test8)) ||
           (NULL == CU_add_test(pSuite, "SOCKS 5 mode, bad credentials", us4020_test9)) ||
/*            (NULL == CU_add_test(pSuite, "SOCKS 4A mode with domain name instead of IP address", us4020_test7)) || */
           (NULL == CU_add_test(pSuite, "HTTP proxy", us4020_test10))
           )
           {
               CU_cleanup_registry();
               return CU_get_error();
           }
   }
#endif   
   return CUE_SUCCESS;
#endif
}
