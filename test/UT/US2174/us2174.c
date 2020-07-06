/*------------------------------------------------------------------
 * us2174.c - Unit Tests for User Story 2174 - Proxy simple enroll
 *
 * August, 2013
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
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include "st_server.h"
#include "st_proxy.h"
#include <openssl/ssl.h>

#ifdef HAVE_CUNIT
#include "CUnit/Basic.h"
#include "CUnit/Automated.h"
#endif

static unsigned char *cacerts = NULL;
static int cacerts_len = 0;

#define US2174_RETRY_INTERVAL   3600
//#define US2174_TCP_PORT       29001

#define US2174_TCP_SERVER_PORT      52174
#define US2174_TCP_PROXY_PORT       62174

#ifndef WIN32
#define US2174_SERVER_CERT      "CA/estCA/private/estservercertandkey.pem"
#define US2174_SERVER_KEY       "CA/estCA/private/estservercertandkey.pem"
/* #define US2174_PROXY_CERT "CA/estCA/private/estservercertandkey.pem"   */
/* #define US2174_PROXY_KEY "CA/estCA/private/estservercertandkey.pem" */
#define US2174_PROXY_CERT       "US2174/cert.pem"
#define US2174_PROXY_KEY        "US2174/key.pem"
#define US2174_CACERT           "CA/estCA/cacert.crt"
#define US2174_CACERTS          "CA/estCA/cacert.crt"
#define US2174_TRUSTED_CERTS    "CA/trustedcerts.crt"
#define US2174_EXPLICIT_CERT    "US2174/cert-RA.pem"
#define US2174_EXPLICIT_KEY     "US2174/key-RA.pem"

#else
#define US2174_SERVER_CERT      "CA\\estCA\\private\\estservercertandkey.pem"
#define US2174_SERVER_KEY       "CA\\estCA\\private/estservercertandkey.pem"
/* #define US2174_PROXY_CERT "CA/estCA/private/estservercertandkey.pem"   */
/* #define US2174_PROXY_KEY "CA/estCA/private/estservercertandkey.pem" */
#define US2174_PROXY_CERT       "US2174\\cert.pem"
#define US2174_PROXY_KEY        "US2174\\key.pem"
#define US2174_CACERT           "CA\\estCA\\cacert.crt"
#define US2174_CACERTS          "CA\\estCA\\cacert.crt"
#define US2174_TRUSTED_CERTS    "CA\\trustedcerts.crt"
#define US2174_EXPLICIT_CERT    "US2174\\cert-RA.pem"
#define US2174_EXPLICIT_KEY     "US2174\\key-RA.pem"
#endif

#define US2174_SERVER_IP        "127.0.0.1"
#define US2174_TCP_PORT         US2174_TCP_SERVER_PORT

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US2174_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the ec.req file:
 *
 * openssl req -newkey ec:256parms -keyout eckey.pem -keyform PEM -out ec.req -outform PEM
 */
#define US2174_PKCS10_DSA1024 "MIICfjCCAj0CAQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEzARBgNVBAoMCkRTQUNvbXBhbnkxDzANBgNVBAsMBkRTQW9yZzEQMA4G\nA1UEAwwHZHNhIGRvZTEaMBgGCSqGSIb3DQEJARYLZHNhQGRvZS5jb20wggG2MIIB\nKwYHKoZIzjgEATCCAR4CgYEAqIfbyk7rEAaULIPB1GcHHc0ctx6g0dhBfdUdOPNG\nBSE+TP5UF5lw8Qm6oCXstU3nYEJalmMvkjFwbgvBws8aJBnj09dDDn8spKEGcG0M\nZpqdMys6+b4QJjq5YAxEaATVY/1L/rBgGGm1EFDhc/6Ezm2T3CGeQklwo5aBZQCc\naIsCFQDC1olBFuE+phOhjXAwEE5EPJkRJwKBgD+vZ+tLCTjBzVFNjAO8X/SMamwW\noraNfdyZ+ZCEAmYI/D4838nCGAjVRQyDb1q5akkLyxoJX1YV7gNbaBNUys3waqdu\nso1HtuEur2cbhU5iOeKBWpj6MIWlPdD3uCRu4uiBF9XBiANaRID8CT2kchhwy4Ok\nFfQMuYOz4eBhMQqmA4GEAAKBgDuwR7H3U4CfuQjWeTtrI50M1TxhlVZ3TonRtVIx\nEHpuXxAouxATVkthJtaCBKc0EHii1bE/kgNUgGX/ZdFjBUb/XfpkYsRT3QRLF0+s\nPZGY/0TovO9pKjqiw0C10leNKFbEVdlXYtAkjXUbHmyNog3195/t7oKXHMT1A/5p\nhUCRoAAwCQYHKoZIzjgEAwMwADAtAhUAhPCqQG3gKUUPKdwBNCmZfzWDqjsCFAh0\nzn9HujlXNaTA1OhjmPmcJSxT"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the dsa.req file:
 *
 * openssl req -newkey dsa:dsaparms -keyout dsakey.pem -keyform PEM -out dsa.req -outform PEM
 */
#define US2174_PKCS10_ECDSA256 "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ29yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

#define US2174_PKCS10_CORRUPT "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ39yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"

/*
 * The following is a valid CSR that already contains a PoP
 * challengePassword.  This was collected using estserver with
 * the dumpbin() function.  This CSR should never work since
 * the PoP value in it will be stale.
 */
#define US2174_PKCS10_STALE_POP "MIIBcjCB3AIBADARMQ8wDQYDVQQDEwZURVNUQ04wgZ8wDQYJKoZIhvcNAQEBBQAD\ngY0AMIGJAoGBAPDHvrkVB3+rFHl+KuIsrZGixldRYRD50S2vFs8mW5wWVxDS3xFR\nzcKtqg7JUyW8NYOFNWX0ozhCe87XP2h7tUpHyHlL/8N/84zuMtAtKTLU3Bjgq1xg\nuu8a1ht10wiy8u2r/uEKMhQwpvt56UY5pHzuqmqlO0qlmE+M58WN49IhAgMBAAGg\nIjAgBgkqhkiG9w0BCQcxExYRUjdGN1ZUNUwyd2VueWtMcAowDQYJKoZIhvcNAQEF\nBQADgYEAyenrskmfRIXcpeKBvL3VnW5N4HcLTwI9Hcbr744SWFQaw/R+ru+UXd2j\n99AGBr/GvTkTghINWg2C7vzGF/zhIuG6Ok9FtiMnNr9hZ+5SLYhfSFJbuIv65rWH\nvfLR9N9M2Q9jlf7p4AYfWXD2qD2XOTZw2t4trGZGKA2JR/OiB40="

#define US2174_ENROLL_URL_BA    "https://127.0.0.1:62175/.well-known/est/simpleenroll"
#define US2174_PKCS10_CT        "Content-Type: application/pkcs10" 
#define US2174_UIDPWD_GOOD      "estuser:estpwd"

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

#define GOOD_TOKEN "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U="
#define DIFFERENT_TOKEN "V2VsbCwgSSd2ZSBnb3QgdG8gcnVuIHRvIGtlZXAgZnJvbSBoaWRpbicNCkFuZCBJJ20gYm91bmQgdG8ga2VlcCBvbiByaWRpbicNCkFuZCBJJ3ZlIGdvdCBvbmUgbW9yZSBzaWx2ZXIgZG9sbGFyDQpCdXQgSSdtIG5vdCBnb25uYSBsZXQgJ2VtIGNhdGNoIG1lLCBubw0KTm90IGdvbm5hIGxldCAnZW0gY2F0Y2ggdGhlIG1pZG5pZ2h0IHJpZGVy"
#define NULL_TOKEN NULL;
#define LONG_TOKEN "SSBjYW4ndCBhZ3JlZSB0byBkaXNhZ3JlZSANCkZpZ2h0aW5nIGxpa2UgSSdtIGZpZ2h0aW5nIGZvciBsaWZlIA0KVGhleSdyZSBvbmx5IHdvcmRzIGJ1dCB0aGV5IGN1dCBsaWtlIGEgYmxhZGUgDQpTd2luZ2luZyB3aWRlIHdpdGggYWxsIG9mIG15IG1pZ2h0IA0KDQpBaCB5ZWFoLCBJIGd1ZXNzIGl0J3MgYWxsIG9mIHRoYXQgY29mZmVlLCB0aGF0J3MgZ290IG15IG1pbmQgaW4gYSB3aGlybCANCkknbSBzdGlsbCBjdXNzaW5nIGFuZCBiaXRjaGluZyBhbmQgdGhlcmUgYWluJ3Qgbm9ib2R5IGhlcmUgDQoNCk9oIHllYWgsIHlvdSBkb24ndCBoYXZlIHRvIGhvbGxlciBJIGhlYXIgeW91IA0KSSdtIHN0YW5kaW5nIHJpZ2h0IGhlcmUgYmVzaWRlIHlvdSANCk9oLCA5OSBzaGFkZXMgb2YgY3JhenksIEknbSA5OSBzaGFkZXMgb2YgY3JhenkgDQpDcmF6eSwgY3JhenksIGNyYXp5LCBjcmF6eSANCg0KUG91ciBhbm90aGVyIGRyaW5rLCBtYWtlIGl0IGEgZG91YmxlIGZvciBtZSANCk1heWJlIEkgY2FuIGRyaW5rIHRoaXMgYXdheSANCkl0J3MgbmV2ZXIgZnVuIHdoZW4gdGhleSBwdWxsIG91dCB0aGUgZ3VuIA0KQmVhdCB5b3UgYmxhY2sgYW5kIGJsdWUsIGJveSANCllvdSBnb3R0YSBwYXksIHlvdSBnb3R0YSBwYXkgDQoNCk9oLCB3aGVyZSB0aGUgaGVsbCBhbSBJPyBJIGhvcGUgYXQgbGVhc3QgSSBoYWQgZnVuIA0KSSdtIHN0dW1ibGluZyB0aHJvdWdoIE5ldyBPcmxlYW5zIG9oLCB0byB0aGUgcmlzaW5nIHN1biANCg0KT2ggeWVhaCwgeW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3UgDQpJJ20gc3RhbmRpbmcgcmlnaHQgaGVyZSBiZXNpZGUgeW91IA0KT2gsIDk5IHNoYWRlcyBvZiBjcmF6eSwgSSdtIDk5IHNoYWRlcyBvZiBjcmF6eSANCkNyYXp5LCBjcmF6eSwgY3JhenksIGNyYXp5IA0KDQpMb3JkIGhhdmUgbWVyY3kgb24gbWUgDQpOb3ZlbnRhIG51ZXZhIHRvbm9zIGRlIGxvY28gDQoNCkkgbmVlZCBzb21lIHBlYWNlLCBqdXN0IHNvbWUgcmVsaWVmIA0KRnJvbSB0aGlzIHZvaWNlLCBraWxsaW5nIG1lIA0KWW91IHN0YXJlIGF0IG1lLCBhbmQgeW91IGdsYXJlIGF0IG1lIA0KQWxsIHRoaXMgcGFpbiBpdCdzIGFsbCB0aGUgc2FtZSwgaXQncyBhbGwgaW5zYW5lIA0KKHlvdSBzZWUpIA0KDQpJcyB0aGlzIHJlYWxseSBoYXBwZW5pbmcgb3IgZGlkIEkgbWFrZSBpdCBhbGwgdXA/IA0KSSdtIGJvdW5kIGZvciBDaGF0dGFob29jaGVlIG9uIGEgdHVybmlwIHRydWNrIA0KDQpPaCB5ZWFoLCB5b3UgZG9uJ3QgaGF2ZSB0byBob2xsZXIgSSBoZWFyIHlvdSANCkknbSBzdGFuZGluZyByaWdodCBoZXJlIGJlc2lkZSB5b3UgDQpPaCwgOTkgc2hhZGVzIG9mIGNyYXp5LCBJJ20gOTkgc2hhZGVzIG9mIGNyYXp5IA0KQ3JhenksIGNyYXp5LCBjcmF6eSwgY3JhenkgDQoNCkFoIHlvdSdyZSBjcmF6eSB5b3UncmUgY3JhenkgDQpIb2xkIG15IGZlZXQsIGZlZXQgdG8gdGhlIGZpcmUgDQpZb3UgaG9sZCBteSBmZWV0IHRvIHRoZSBmaXJlIA0KSSBuZXZlciBzYWlkIEkgd2FzIGRvd24gd2l0aCB5b3U="
static char *test_token = "WW91IGRvbid0IGhhdmUgdG8gaG9sbGVyIEkgaGVhciB5b3U=";

static int auth_cred_callback_called = 0;
static int auth_cred_force_error = 0;

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
static EST_HTTP_AUTH_CRED_RC auth_credentials_token_cb (
        EST_HTTP_AUTH_HDR *auth_credentials)
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
        return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
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
                printf(
                    "\nError determining length of token string used for credentials\n");
                return EST_HTTP_AUTH_CRED_NOT_AVAILABLE;
            }
            token_ptr = malloc(token_len + 1);
            if (token_ptr == NULL) {
                printf(
                    "\nError allocating token string used for credentials\n");
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
static EST_HTTP_AUTH_CRED_RC auth_credentials_basic_cb (
        EST_HTTP_AUTH_HDR *auth_credentials)
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
        return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
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

#if 0
/*
 * auth_credentials_digest_cb() is the same as the basic based one above, but
 * instead verifies that the auth_mode passed is digest
 */
static
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
#endif

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
 * us2174_simple_enroll() is used by test cases to perform a simple enroll.
 */
static void us2174_simple_enroll (char *cn, char *server,
                                  EST_ERROR expected_enroll_rv,
                                  auth_credentials_cb callback)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    EST_ERROR rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;
    EST_ERROR e_rc;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    e_rc = est_client_set_auth_cred_cb(ectx, callback);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US2174_TCP_PROXY_PORT, NULL);

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
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

static
void us2174_simple_reenroll (char *cn, char *server,
                             EST_ERROR expected_enroll_rv,
                             auth_credentials_cb callback)
{
    EST_CTX *ectx;
    EVP_PKEY *key;
    EST_ERROR rv;
    int pkcs7_len = 0;
    unsigned char *new_cert = NULL;

    PKCS7 *p7 = NULL;
    BIO *b64, *out;
    X509 *cert = NULL;
    STACK_OF(X509) * certs = NULL;
    int i;

    EST_ERROR e_rc;

    /*
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
        client_manual_cert_verify);
    CU_ASSERT(ectx != NULL);

    e_rc = est_client_set_auth_cred_cb(ectx, callback);
    CU_ASSERT(e_rc == EST_ERR_NONE);

    /*
     * Set the EST server address/port
     */
    est_client_set_server(ectx, server, US2174_TCP_PROXY_PORT, NULL);

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
     * Create a client context
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM,
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
    est_client_set_server(ectx, server, US2174_TCP_PORT, NULL);

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
     * PDB NOTE: At the moment, this is expected to fail since
     * the server does not yet understand requests with token authentication.
     * Once 1884 is complete, the below ASSERT will begin to fail and will need
     * to be changed to a passing response.
     */
    rv = est_client_reenroll(ectx, cert, &pkcs7_len, key);
    CU_ASSERT(rv == expected_enroll_rv);

    /*
     * Cleanup
     */
    EVP_PKEY_free(key);
    if (new_cert)
        free(new_cert);
    est_destroy(ectx);
}

static void us2174_clean (void)
{
}

static int us2174_start_server (int manual_enroll, int nid)
{
    int rv = 0;

    /*
     * First we start an EST server acting as the CA
     */
    rv = st_start(US2174_TCP_SERVER_PORT,
                  US2174_SERVER_CERT,
                  US2174_SERVER_KEY,
                  "estrealm",
                  US2174_CACERT,
                  US2174_TRUSTED_CERTS,
                  "US2174/estExampleCA.cnf",
                  manual_enroll, // manual enroll
                  0,  // disable PoP
                  nid); // ecdhe nid info
    SLEEP(1);
    if (rv != EST_ERR_NONE)
        return rv;

    /*
     * Next we start an EST proxy acting as an RA with the server side
     * operating in token auth mode.
     */
    rv = st_proxy_start_token(US2174_TCP_PROXY_PORT,
                              US2174_PROXY_CERT,
                              US2174_PROXY_KEY, "estrealm",
                              US2174_CACERT,
                              US2174_TRUSTED_CERTS,
                              "estuser",
                              "estpwd",
                              "127.0.0.1",
                              US2174_TCP_SERVER_PORT,
                              0); //  disable PoP

    SLEEP(1);

    return rv;
}

void us2174_stop_server ()
{
    st_stop();
    st_proxy_stop();
    SLEEP(2);
}

/*
 * This routine is called when CUnit initializes this test
 * suite.  This can be used to allocate data or open any
 * resources required for all the test cases.
 */
static int us2174_init_suite (void)
{
    int rv;

    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(US2174_CACERTS, &cacerts);
    if (cacerts_len <= 0) {
        return 1;
    }

    us2174_clean();

    /*
     * Start an instance of the EST server with
     * automatic enrollment enabled.
     */
    rv = us2174_start_server(0, 0);

    return rv;
}

/*
 * This routine is called when CUnit uninitializes this test
 * suite.  This can be used to deallocate data or close any
 * resources that were used for the test cases.
 */
static int us2174_destroy_suite (void)
{
    us2174_stop_server();
    free(cacerts);
    return 0;
}

#if 0
/*
 * Simple enroll -
 * proxy - BASIC
 * server - BASIC
 *
 * Make sure token auth mode did not break anything.
 *
 */
static void us2174_test1(void)
{
    long rv;

    LOG_FUNC_NM;

    rv = curl_http_post(US2174_ENROLL_URL_BA, US2174_PKCS10_CT,
            US2174_PKCS10_RSA2048,
            US2174_UIDPWD_GOOD, US2174_CACERTS, CURLAUTH_BASIC,
            NULL, NULL, NULL);
    /*
     * Since we passed in a valid userID/password,
     * we expect the server to respond with 200
     */
    CU_ASSERT(rv == 200);
}
#endif

/*
 * Simple enroll -
 * proxy - TOKEN
 * server - TOKEN
 *
 */
static void us2174_test2 (void)
{
    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;

    /*
     * set server to do token auth challenges
     * tell the server which tokens to accept
     */
    st_enable_http_token_auth();
    st_set_token(GOOD_TOKEN);
    /*
     * set the proxy to do token auth challenges and
     * tell it what tokens to accept.
     */
    st_proxy_enable_http_token_auth();
    st_proxy_set_srv_valid_token(GOOD_TOKEN);
    /*
     * tell the client side of proxy which token credential to
     * use
     */
    st_proxy_set_clnt_token_cred(GOOD_TOKEN);

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Enroll should succeed.
     */
    us2174_simple_enroll("TC2174-4", US2174_SERVER_IP, EST_ERR_NONE,
        auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}

/*
 * Simple enroll -
 * proxy - TOKEN
 * server - BASIC
 */
static void us2174_test3 (void)
{
    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;

    /*
     * set server to do BASIC auth challenges
     */
    st_enable_http_basic_auth();
    /*
     * set the proxy to do token auth challenges and
     * tell it what tokens to accept.
     */
    st_proxy_enable_http_token_auth();
    st_proxy_set_srv_valid_token(GOOD_TOKEN);
    /*
     * tell the client side of proxy which token credential to
     * use
     */
    st_proxy_set_clnt_token_cred(GOOD_TOKEN);

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Enroll should succeed.
     */
    us2174_simple_enroll("TC2174-4", US2174_SERVER_IP, EST_ERR_NONE,
        auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}

/*
 * Simple enroll -
 * proxy - BASIC
 * server - TOKEN
 */
static void us2174_test4 (void)
{
    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;

    /*
     * set server to do token auth challenges
     * tell the server which tokens to accept
     */
    st_enable_http_token_auth();
    st_set_token(GOOD_TOKEN);
    /*
     * set the proxy to do BASIC auth challenges and
     * tell it what tokens to accept.
     */
    st_proxy_enable_http_basic_auth();
    /*     st_proxy_set_srv_valid_token(GOOD_TOKEN); */
    /*
     * tell the client side of proxy which token credential to
     * use
     */
    st_proxy_set_clnt_token_cred(GOOD_TOKEN);

    /*
     * Set up the EST Client and have it perform a simple enroll.
     *
     * Enroll should succeed.
     */
    us2174_simple_enroll("TC2174-4", US2174_SERVER_IP, EST_ERR_NONE,
        auth_credentials_basic_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}

/*
 * Simple RE-enroll -
 * proxy - TOKEN
 * server - TOKEN
 *
 */
static void us2174_test5 (void)
{
    LOG_FUNC_NM
    ;

    auth_cred_callback_called = 0;
    auth_cred_force_error = 0;

    /*
     * set server to do token auth challenges
     * tell the server which tokens to accept
     */
    st_enable_http_token_auth();
    st_set_token(GOOD_TOKEN);
    /*
     * set the proxy to do token auth challenges and
     * tell it what tokens to accept.
     */
    st_proxy_enable_http_token_auth();
    st_proxy_set_srv_valid_token(GOOD_TOKEN);
    /*
     * tell the client side of proxy which token credential to
     * use
     */
    st_proxy_set_clnt_token_cred(GOOD_TOKEN);

    /*
     * Set up the EST Client and have it perform a simple RE-enroll.
     *
     * RE-enroll should succeed.
     */
    us2174_simple_reenroll("TC2174-4", US2174_SERVER_IP, EST_ERR_NONE,
        auth_credentials_token_cb);

    /*
     * callback should have been called
     */
    CU_ASSERT(auth_cred_callback_called == 1);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int us2174_add_suite (void)
{
#ifdef HAVE_CUNIT
    CU_pSuite pSuite = NULL;

    /* add a suite to the registry */
    pSuite = CU_add_suite("us2174_token_proxy",
            us2174_init_suite,
            us2174_destroy_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if (/* (NULL == CU_add_test(pSuite, "Proxy Enroll basic sanity test", us2174_test1)) || */
        (NULL == CU_add_test(pSuite, "Proxy Enroll token auth, both proxy and server", us2174_test2)) ||
        (NULL == CU_add_test(pSuite, "Proxy Enroll token auth, proxy token/server basic", us2174_test3)) ||
        (NULL == CU_add_test(pSuite, "Proxy Enroll token auth, proxy basic/server token", us2174_test4)) ||
        (NULL == CU_add_test(pSuite, "Proxy RE-Enroll token auth, proxy basic/server token", us2174_test5))
        )
    {
       CU_cleanup_registry();
       return CU_get_error();
    }

    return CUE_SUCCESS;
#endif
}

