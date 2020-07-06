/*------------------------------------------------------------------
 * us1883.c - Unit Tests for User Story 1883 - Enable token auth mode for
 *            the EST Client.
 *
 * March, 2015
 *
 * Copyright (c) 2015, 2016 by cisco Systems, Inc.
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
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif
#include <errno.h>


static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US1883_SERVER_IP        "127.0.0.1"	
#define US1883_TCP_PORT		29001

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US1883_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"
#define US1883_PKCS10_4096_REQ "MIIEZjCCAk4CAQAwITEPMA0GA1UEAwwGSkpUZXN0MQ4wDAYDVQQFEwUwMDAwMTCC\nAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALfLlHxqzObiKWDfX8saZ4l3\n1JyrCP4xmyQitY2pIIGlLvHT7t1WZ0LO9uo0uB7b/8iGbXki8FgqSm1jROe5lwCN\nDIhTJdG4b705c6XmD3Mh436De9d4gzpjedA2qurSI9+GVNVgU0ZOWJFu9g+y3iRH\ndfsjO9u0E2MfZWWR8M72gBqzvbDDPN4BDwLa9TkQ2Rsxf3h2d7bN2DNShNSYX/dE\nIX89d9uC6FegsHQxHINUOdZzeAn3yuQMBU+FwohEl9Ub8Qu9gub2MJUrYNRQnii7\nduvq5/UjkhjNWzIh7LAbdaM+0wSmCe0ju+wKbayUZZkrqoVK6bWZzFs4dYtn95/S\nVVOv95MD5D1EokXw3Iih7GRJygtWn5e4/YO68LONBF7UE24vgBwEieF6J0bFAlxw\n15s7pIalkGF7CUbitRhbB3kTjGfUDR8YpSsKdqxHNmWBXY7ZVk4T8K7168cNWSOL\netZpTk4BtoUJBnWP8Uq38YOi6389U24gmZtGpSpJEEtDy1MJ8Ha4PZE/VkFtmUWq\nbETOx2kubGwc9vXvWfi5BxE2VvetGNsy2EQEZPVwscYaCy0/yO3fu06coEtr7Ekr\ngapDDEzVtiP9NPe5q18Azu+T9ngoOx3PqrCPG1BDN6z1Ue2tSDdOxKNFMNMwqYIn\nZP9MXh+tz8RaKvsclv9JAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAgEAJMwZ4IUB\nUSH5wQBfsYT4SxtKsZtvun6QX0+7jNMtzzQUOqO79Kx/DKpzsKxLNvHKmFqcxA7g\ngbEwXkAP5+VaMD92DghcNjXOqGKclZdmGj2oREqZwzvTDRo4zP1yen5vgL/Yz7SA\nxze8wPg2WhlV9+qvkVCpHN3EUIfO+rBgi2reo/vF7xq5CAU4UtQ1h4gHax67Yww8\nJmypyGGa0ad0Z8ruiclI/QtluADUxy1YM0Up2FC0s7j72xzrRpEl1fPlOi/bFaZp\nsr4zllOpwnRdxvffXO7gXtXVIr4IHVHNWj6kmDzyk0ovat2Ms5aGUcMDN6Jm8KIB\nNBVH5FgkBVQOPSngkwnEOj0RsaKSxT5EfmOxm9pCrAE3rNdVOgO4t8wZ6DQUqye/\nBUdmgXtWoGsKIg8oR5HAWBER8yw/qdiRlBGgN/PKZdpmYI2TEfZvp/nXwG7QLjGx\nsj5TWeRKNgghUCu3uF+1s0R+gqgY1S9GgiDSifL7+h+bXJ4ncyRGq+XPnrfMiRkB\neSyv3kyIxtZfAB6TjkUbtVfo2KrfqNxu4lbJYE2b6hs1L6t7YPhjubz9aES7wES7\nk+ZZPZn/k/GsqUpsWHnEFEvi5C5WPrnpvVN6rKh0fB+AukGrS+9EK4KNZWfV/yf8\nXN5qWyOtgd4oLUUsgFDJsqNh6A1mlmx6CnY=\n"
#define US1883_ENROLL_URL_BA "https://127.0.0.1:29001/.well-known/est/simpleenroll"
#define US1883_PKCS10_CT     "Content-Type: application/pkcs10" 
#define US1883_UIDPWD_GOOD   "estuser:estpwd"
#ifndef WIN32
#define US1883_CACERTS	     "CA/estCA/cacert.crt"
#define US1883_CACERT "CA/estCA/cacert.crt"
#define US1883_SERVER_CERT "CA/estCA/private/estservercertandkey.pem"
#define US1883_SERVER_KEY "CA/estCA/private/estservercertandkey.pem"
#define US1883_CLIENT_CERT "CA/estCA/private/estservercertandkey.pem"
#define US1883_CLIENT_KEY  "CA/estCA/private/estservercertandkey.pem"
#else
#define US1883_CACERTS	     "CA\\estCA\\cacert.crt"
#define US1883_CACERT "CA\\estCA\\cacert.crt"
#define US1883_SERVER_CERT "CA\\estCA\\private\\estservercertandkey.pem"
#define US1883_SERVER_KEY "CA\\estCA\\private\\estservercertandkey.pem"
#define US1883_CLIENT_CERT "CA\\estCA\\private\\estservercertandkey.pem"
#define US1883_CLIENT_KEY  "CA\\estCA\\private/estservercertandkey.pem"

static CRITICAL_SECTION logger_critical_section;  
static void us1883_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}

#endif 


static void us1883_clean (void)
{
}

static int us1883_start_server (int manual_enroll, int nid)
{
    int rv;

    rv = st_start(US1883_TCP_PORT, 
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

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us1883_init_suite (void)
{
    int rv;
#ifdef WIN32
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &us1883_logger_stderr);
#endif

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US1883_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
	return 1;
    }

    us1883_clean();

    /*
     * Start an instance of the EST server with 
     * automatic enrollment enabled.
     */
    rv = us1883_start_server(0, 0);

    return rv;
}


/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us1883_destroy_suite (void)
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

#define GOOD_TOKEN "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U="
#define DIFFERENT_TOKEN "V2VsbCwgSSd2ZSBnb3QgdG8gcnVuIHRvIGtlZXAgZnJvbSBoaWRpbicNCkFuZCBJJ20gYm91bmQgdG8ga2VlcCBvbiByaWRpbicNCkFuZCBJJ3ZlIGdvdCBvbmUgbW9yZSBzaWx2ZXIgZG9sbGFyDQpCdXQgSSdtIG5vdCBnb25uYSBsZXQgJ2VtIGNhdGNoIG1lLCBubw0KTm90IGdvbm5hIGxldCAnZW0gY2F0Y2ggdGhlIG1pZG5pZ2h0IHJpZGVy"
#define NULL_TOKEN NULL;
#define LONG_TOKEN "SSBjYW4ndCBhZ3JlZSB0byBkaXNhZ3JlZSANCkZpZ2h0aW5nIGxpa2UgSSdtIGZpZ2h0aW5nIGZvciBsaWZlIA0KVGhleSdyZSBvbmx5IHdvcmRzIGJ1dCB0aGV5IGN1dCBsaWtlIGEgYmxhZGUgDQpTd2luZ2luZyB3aWRlIHdpdGggYWxsIG9mIG15IG1pZ2h0IA0KDQpBaCB5ZWFoLCBJIGd1ZXNzIGl0J3MgYWxsIG9mIHRoYXQgY29mZmVlLCB0aGF0J3MgZ290IG15IG1pbmQgaW4gYSB3aGlybCANCkknbSBzdGlsbCBjdXNzaW5nIGFuZCBiaXRjaGluZyBhbmQgdGhlcmUgYWluJ3Qgbm9ib2R5IGhlcmUgDQoNCk9oIHllYWgsIHlvdSBkb24ndCBoYXZlIHRvIGhvbGxlciBJIGhlYXIgeW91IA0KSSdtIHN0YW5kaW5nIHJpZ2h0IGhlcmUgYmVzaWRlIHlvdSANCk9oLCA5OSBzaGFkZXMgb2YgY3JhenksIEknbSA5OSBzaGFkZXMgb2YgY3JhenkgDQpDcmF6eSwgY3JhenksIGNyYXp5LCBjcmF6eSANCg0KUG91ciBhbm90aGVyIGRyaW5rLCBtYWtlIGl0IGEgZG91YmxlIGZvciBtZSANCk1heWJlIEkgY2FuIGRyaW5rIHRoaXMgYXdheSANCkl0J3MgbmV2ZXIgZnVuIHdoZW4gdGhleSBwdWxsIG91dCB0aGUgZ3VuIA0KQmVhdCB5b3UgYmxhY2sgYW5kIGJsdWUsIGJveSANCllvdSBnb3R0YSBwYXksIHlvdSBnb3R0YSBwYXkgDQoNCk9oLCB3aGVyZSB0aGUgaGVsbCBhbSBJPyBJIGhvcGUgYXQgbGVhc3QgSSBoYWQgZnVuIA0KSSdtIHN0dW1ibGluZyB0aHJvdWdoIE5ldyBPcmxlYW5zIG9oLCB0byB0aGUgcmlzaW5nIHN1biANCg0KT2ggeWVhaCwgeW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3UgDQpJJ20gc3RhbmRpbmcgcmlnaHQgaGVyZSBiZXNpZGUgeW91IA0KT2gsIDk5IHNoYWRlcyBvZiBjcmF6eSwgSSdtIDk5IHNoYWRlcyBvZiBjcmF6eSANCkNyYXp5LCBjcmF6eSwgY3JhenksIGNyYXp5IA0KDQpMb3JkIGhhdmUgbWVyY3kgb24gbWUgDQpOb3ZlbnRhIG51ZXZhIHRvbm9zIGRlIGxvY28gDQoNCkkgbmVlZCBzb21lIHBlYWNlLCBqdXN0IHNvbWUgcmVsaWVmIA0KRnJvbSB0aGlzIHZvaWNlLCBraWxsaW5nIG1lIA0KWW91IHN0YXJlIGF0IG1lLCBhbmQgeW91IGdsYXJlIGF0IG1lIA0KQWxsIHRoaXMgcGFpbiBpdCdzIGFsbCB0aGUgc2FtZSwgaXQncyBhbGwgaW5zYW5lIA0KKHlvdSBzZWUpIA0KDQpJcyB0aGlzIHJlYWxseSBoYXBwZW5pbmcgb3IgZGlkIEkgbWFrZSBpdCBhbGwgdXA/IA0KSSdtIGJvdW5kIGZvciBDaGF0dGFob29jaGVlIG9uIGEgdHVybmlwIHRydWNrIA0KDQpPaCB5ZWFoLCB5b3UgZG9uJ3QgaGF2ZSB0byBob2xsZXIgSSBoZWFyIHlvdSANCkknbSBzdGFuZGluZyByaWdodCBoZXJlIGJlc2lkZSB5b3UgDQpPaCwgOTkgc2hhZGVzIG9mIGNyYXp5LCBJJ20gOTkgc2hhZGVzIG9mIGNyYXp5IA0KQ3JhenksIGNyYXp5LCBjcmF6eSwgY3JhenkgDQoNCkFoIHlvdSdyZSBjcmF6eSB5b3UncmUgY3JhenkgDQpIb2xkIG15IGZlZXQsIGZlZXQgdG8gdGhlIGZpcmUgDQpZb3UgaG9sZCBteSBmZWV0IHRvIHRoZSBmaXJlIA0KSSBuZXZlciBzYWlkIEkgd2FzIGRvd24gd2l0aCB5b3U="
char *test_token = "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U=";

int auth_cred_callback_called = 0;
int auth_cred_force_error = 0;

/*
 * auth_credentials_token_cb() is the application layer callback function that will
 * return a token based authentication credential when called.  It's registered
 * with the EST Client using the est_client_set_auth_cred_cb().
 * The test function is required to set some global values in order to make this
 * callback operate the way that the test case wants.
 * - auth_cred_force_error = tell this function to force a response code error
 * - test_token = pointer to a hard coded string that is the token string to return
 *
 * This callback must provide the token credentials in a heap based buffer, and
 * ownership of that buffer is implicitly transferred to the ET client library upon
 * return.
 */
EST_HTTP_AUTH_CRED_RC auth_credentials_token_cb(EST_HTTP_AUTH_HDR *auth_credentials)
{
    char *token_ptr = NULL;
    int token_len = 0;

    CU_ASSERT(auth_credentials->mode == AUTH_TOKEN);

    /*
     * report that the callback has been called.
     */
    auth_cred_callback_called = 1;

    /*
     * See if the test is requesting to force an error response code from the
     * callback
     */
    if (auth_cred_force_error) {
        return(EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
    }
    
    if (auth_credentials->mode == AUTH_TOKEN) {
        /*
         * If the test_token is set to anything, then we need to allocate
         * space from the heap and copy in the value.
         */
        if (test_token != NULL) {
            token_len = strlen(test_token); /* use strlen() so that the string can be as large
                                               as needed to test the EST client */
            if (token_len == 0) {
                printf("\nError determining length of token string used for credentials\n");
                return EST_HTTP_AUTH_CRED_NOT_AVAILABLE;
            }   
            token_ptr = malloc(token_len+1);
            if (token_ptr == NULL){
                printf("\nError allocating token string used for credentials\n");
                return EST_HTTP_AUTH_CRED_NOT_AVAILABLE;
            }   
            strncpy(token_ptr, test_token, strlen(test_token));
            token_ptr[token_len] = '\0';
        }
        /*
         * If we made it this far, token_ptr is pointing to a string
         * containing the token to be returned. Assign it and return success
         */
        auth_credentials->auth_token = token_ptr;
        
        return (EST_HTTP_AUTH_CRED_SUCCESS);
    }
    
    return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
}

/*
 * auth_credentials_basic_cb() is the same as the token based one above, but
 * instead returns the basic credentials of userid and password
 */
EST_HTTP_AUTH_CRED_RC auth_credentials_basic_cb(EST_HTTP_AUTH_HDR *auth_credentials)
{
    CU_ASSERT(auth_credentials->mode == AUTH_BASIC);

    /*
     * report that the callback has been called.
     */
    auth_cred_callback_called = 1;

    /*
     * See if the test is requesting to force an error response code from the
     * callback
     */
    if (auth_cred_force_error) {
        return(EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
    }
    
    if (auth_credentials->mode == AUTH_BASIC) {

        auth_credentials->user = malloc(sizeof("estuser"));
        strncpy(auth_credentials->user, "estuser", sizeof("estuser"));
        auth_credentials->pwd = malloc(sizeof("estpwd"));
        strncpy(auth_credentials->pwd, "estpwd", sizeof("estpwd"));
        
        return (EST_HTTP_AUTH_CRED_SUCCESS);
    }
    
    return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
}


/*
 * auth_credentials_digest_cb() is the same as the basic based one above, but
 * instead verifies that the auth_mode passed is digest
 */
EST_HTTP_AUTH_CRED_RC auth_credentials_digest_cb(EST_HTTP_AUTH_HDR *auth_credentials)
{
    CU_ASSERT(auth_credentials->mode == AUTH_DIGEST);

    /*
     * report that the callback has been called.
     */
    auth_cred_callback_called = 1;

    /*
     * See if the test is requesting to force an error response code from the
     * callback
     */
    if (auth_cred_force_error) {
        return(EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
    }
    
    if (auth_credentials->mode == AUTH_DIGEST) {

        auth_credentials->user = malloc(sizeof("estuser"));
        strncpy(auth_credentials->user, "estuser", sizeof("estuser"));
        auth_credentials->pwd = malloc(sizeof("estpwd"));
        strncpy(auth_credentials->pwd, "estpwd", sizeof("estpwd"));
        
        return (EST_HTTP_AUTH_CRED_SUCCESS);
    }
    
    return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
}


/*
 * Test the est_client_set_auth_cred_cb API
 *
 * Exercise the parameters
 */
static void us1883_test1 (void) 
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

    /* Forgot to specify any parameters. Context will
     * get caught
     */
    e_rc = est_client_set_auth_cred_cb(NULL, NULL);
    CU_ASSERT(e_rc == EST_ERR_NO_CTX);

    /*
     * valid call
     */
    e_rc = est_client_set_auth_cred_cb(ectx, auth_credentials_token_cb);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * attempt to reset the callback function
     */
    e_rc = est_client_set_auth_cred_cb(ectx, NULL);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    est_destroy(ectx);
}

/*
 * us1883_simple_enroll() is used by test cases to perform a simple enroll.
 */
static void us1883_simple_enroll (char *cn, char *server, EST_ERROR expected_enroll_rv, auth_credentials_cb callback)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    EST_ERROR rv;
    int pkcs7_len = 0;
    EST_ERROR e_rc; 

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    e_rc = est_client_set_auth_cred_cb(ectx, callback);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US1883_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);
    
    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, cn, &pkcs7_len, key);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    est_destroy(ectx);
}


/*
 * Perform a simple enroll first in order to get a valid cert, then perform the
 * reenroll.  The simple enroll needs to be successful, so it's currently
 * being done using basic mode because the EST server does not yet have token
 * based support.
 * PDB NOTE:  Once the server side token support have been implemented, this
 * this function can optionally be updated to do token mode on the first enroll,
 * but it's not absolutely necessary since the purpose of this is to test reenroll
 * and the initial enroll is needed just to get the cert.
 */
static
void us1883_simple_reenroll (char *cn, char *server, EST_ERROR expected_enroll_rv, auth_credentials_cb callback)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    EST_ERROR rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;

    PKCS7 *p7 = NULL;
    BIO *b64, *out;
    X509 *cert = NULL;
    STACK_OF(X509) *certs = NULL;
    int i;
    
    EST_ERROR e_rc;    

    /*
     * Create a client context 
     */
    ectx = est_client_init(cacerts, cacerts_len, 
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    /*
     * Make sure the server is currently in  BASIC auth mode
     */
    st_enable_http_basic_auth();
    
    e_rc = est_client_set_auth_cred_cb(ectx, auth_credentials_basic_cb);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US1883_TCP_PORT, NULL);

    /*
     * generate a private key
     */
    key = generate_private_key();
    CU_ASSERT(key != NULL);

    /*
     * Use the simplified API to enroll a CSR
     */
    rv = est_client_enroll(ectx, cn, &pkcs7_len, key);
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

    est_destroy(ectx);
    ectx = NULL;

    /*
     * did we get the cert?
     */
    if (new_cert) {
        
        /*
         * Create a client context 
         */
        ectx = est_client_init(cacerts, cacerts_len, 
                               EST_CERT_FORMAT_PEM,
                               client_manual_cert_verify);
        CU_ASSERT(ectx != NULL);    
        
        /*
         * Now that we have the cert, switch the server over to token mode
         */
        st_enable_http_token_auth();
        
        e_rc = est_client_set_auth_cred_cb(ectx, callback);
        CU_ASSERT(e_rc == EST_ERR_NONE);
        
        /*
         * Set the EST server address/port
         */
        est_client_set_server(ectx, server, US1883_TCP_PORT, NULL);
        
        /*
         * And attempt a reenroll while in token mode
         *
         * Convert the cert to an X509.  Be warned this is
         * pure hackery.
         * PDB: This conversion code comes from other test cases.
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
        if (!certs) {
            EVP_PKEY_free(key);
            est_destroy(ectx);
            return;
        }
        
        /* our new cert should be the one and only
         * cert in the pkcs7 blob.  We shouldn't have to
         * iterate through the full list to find it. */
        cert = sk_X509_value(certs, 0);
        CU_ASSERT(cert != NULL);

        rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
        CU_ASSERT(rv == expected_enroll_rv);
        
        /*
         * Cleanup
         */
        EVP_PKEY_free(key);
        if (new_cert) free(new_cert);
        est_destroy(ectx);
    }
}


/*
 * Test2 - Application layer did not register callback, causing an
 *         HTTP Authentication header with an empty token credential
 *         
 * In this test,
 * - application layer DOES NOT register its callback
 * - EST Client gets the challenge, finds no callback registered and goes with
 *   the credentials it has stored in the Context, which is nothing.
 *   NOTE: This is the way the preloaded credential flow has always worked.
 * - enroll is sent with no token credentials
 * - server fails and does not give a certificate
 */
static void us1883_test2 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     * Pass no callback function to catch and handle the request for a token auth.
     *
     * enroll better fail due to missing credentials
     */
    us1883_simple_enroll("TC1883-2", US1883_SERVER_IP, EST_ERR_AUTH_FAIL, NULL);

    /*
     * callback was never registered, so it should not have been invoked.
     */
    CU_ASSERT(auth_cred_callback_called == 0);
}


/*
 * Test3 - Application layer registers callback, BUT does not set any
 *         credentials when invoked.  Same result as previous test
 *         
 * In this test,
 * - application layer registers its callback
 * - EST Client gets the challenge, calls the callback, gets back an 
 *   empty credential structure and ends up sending an HTTP auth header
 *   with no credentials.
 *   NOTE: This is the way the preloaded credential flow has always worked.
 * - enroll is sent with no token credentials
 * - server fails and does not give a certificate
 */
static void us1883_test3 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = NULL_TOKEN;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     * Register the token based callback, but set it so that it passes back no token.
     *
     * enroll better fail due to missing credentials
     */
    us1883_simple_enroll("TC1883-3", US1883_SERVER_IP, EST_ERR_AUTH_FAIL, auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test4 - Good token is sent to server and is accepted.  Cert should
 * be generated and returned
 *
 * In this test,
 * - application layer registers its callback and responds with a valid token
 * - enroll is sent with this token credential
 * - server is set to match on this token and send back a cert
 */
static void us1883_test4 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Enroll should succeed.
     */
    us1883_simple_enroll("TC1883-4", US1883_SERVER_IP, EST_ERR_NONE, auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test EST client receiving a token auth challenge
 *
 * In this test, the application layer registers its callback and responds
 * with a failing return code.
 */
static void us1883_test5 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();

    auth_cred_callback_called = 0;
    /* Force the callback to give a failing return code */
    auth_cred_force_error = 1;
    test_token = GOOD_TOKEN;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * enroll better fail due to credentials not being supplied by the application layer
     * and eventual failure at the server due to missing credentials.
     */
    us1883_simple_enroll("TC1883-5", US1883_SERVER_IP, EST_ERR_AUTH_FAIL, auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test6 - Sanity test BASIC auth mode
 *
 * In this test,
 * - server into BASIC mode
 * - Client application registers its BASIC based callback
 * - Client should send the estuser/estpwd credentials and get a cert
 */
static void us1883_test6 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to BASIC mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_basic_auth();

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     * Pass a callback function to catch and handle the request for a token auth.
     *
     * enroll should pass because BASIC mode fully works.  Make sure that the
     * callback is called.  This will ensure that the credentials came from
     * the callback.
     */
    us1883_simple_enroll("TC1883-6", US1883_SERVER_IP, EST_ERR_NONE, auth_credentials_basic_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test7 - Make sure re-enroll works with the credential callback flow
 *         to obtain credentials
 *
 * In this test,
 * - server into TOKEN mode
 * - Client application registers its TOKEN based callback
 * - Client should send the valid token credential and get a cert
 */
static void us1883_test7 (void) 
{

    LOG_FUNC_NM;
    
    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Re-enroll should succeed.
     *
     */
    us1883_simple_reenroll("TC1883-7", US1883_SERVER_IP, EST_ERR_NONE, auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test7 - Token credentials that are too long
 *
 * In this test,
 * - server into TOKEN mode and told to match against the GOOD token
 * - Client application registers its TOKEN based callback and is told to
 *   give back a token that is TOO LONG.
 * - Client should send a corrupted token that does not match the GOOD token.
 */
static void us1883_test8 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(GOOD_TOKEN);

    auth_cred_callback_called = 0;
    /* Force the callback to give a failing return code */
    auth_cred_force_error = 0;
    test_token = LONG_TOKEN;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     * Pass a callback function to catch and handle the request for a token auth.
     *
     */
    us1883_simple_enroll("TC1883-8", US1883_SERVER_IP, EST_ERR_AUTH_FAIL,
                         auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test7 - Test DIGEST mode with on demand credential flow
 *
 * In this test,
 * - server into DIGEST mode
 *   NOTE: This means the server is expecting: "estuser"/"estpwd" and "estrealm"
 *         These values are hardcoded into data in the st_server, so st_server
 *         must be started with estrealm so that it returns this realm to client
 *         so that the client returns it in its request.
 * - Client application registers its DIGEST based callback
 * - Client should send a valid DIGEST and get a cert
 */
static void us1883_test9 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to DIGEST mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_digest_auth();

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    
    /*
     * Set up the EST Client and have it perform a simple enroll.
     * Pass a callback function to catch and handle the request for a token auth.
     *
     * enroll should pass because DIGEST mode fully works.  Make sure that the
     * callback is called.  This will ensure that the credentials came from
     * the callback.
     */
    us1883_simple_enroll("TC1883-6", US1883_SERVER_IP, EST_ERR_NONE, auth_credentials_digest_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/*
 * Test4 - Valid token is provided by application callback, but it's the WRONG
 *         token
 *
 * In this test,
 * - application layer registers its callback and responds with a valid token
 * - Server is set up for token mode, but with a different token.
 * - enroll is sent with this token credential
 * - server is set to match on this token and send back a cert
 */
static void us1883_test10 (void) 
{

    LOG_FUNC_NM;

    /*
     * Switch the server over to Token mode.
     * 
     * NOTE: I see the equivalent calls being made in numerous places, and
     * it's probably safe in a test setting, but it's dangerous to change
     * this on the fly in an operational setting.  Also note, no return code
     * for any of these set/enable functions.
     */
    st_enable_http_token_auth();
    /*
     * tell the server which token to check against.
     */
    st_set_token(DIFFERENT_TOKEN);

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;
    test_token = GOOD_TOKEN;

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Enroll should FAIL because the tokens will not match
     */
    us1883_simple_enroll("TC1883-4", US1883_SERVER_IP, EST_ERR_AUTH_FAIL, auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us1883_add_suite (void)
{
#ifdef HAVE_CUNIT
   CU_pSuite pSuite = NULL;

   /* add a suite to the registry */
   pSuite = CU_add_suite("us1883_tok_auth_client", 
	                  us1883_init_suite, 
			  us1883_destroy_suite);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if ((NULL == CU_add_test(pSuite, "parse response", us1883_test1)) ||
       (NULL == CU_add_test(pSuite, "simple enroll no cb", us1883_test2)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb no token", us1883_test3)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb good token", us1883_test4)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb bad rc", us1883_test5)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb basic mode", us1883_test6)) ||
       (NULL == CU_add_test(pSuite, "simple re-enroll reg cb good token", us1883_test7)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb token too long", us1883_test8)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb digest mode", us1883_test9)) ||
       (NULL == CU_add_test(pSuite, "simple enroll reg cb mismatched valid token", us1883_test10))
       )
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   return CUE_SUCCESS;
#endif
}


