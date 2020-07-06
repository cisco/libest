/*------------------------------------------------------------------
 * perftest.c - This is a simple performance test tool to be
 *              used against example/server/estserver listening
 *              on port 8085.
 *
 * August, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#include <stdio.h>
#include <unistd.h>
#include <est.h>
#include <curl/curl.h>
#include "curl_utils.h"
#include "test_utils.h"
#include <openssl/ssl.h>
#include <pthread.h>



/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the rsa.req file:
 *
 * openssl req -newkey rsa:2048 -keyout rsakey.pem -keyform PEM -out rsa.req -outform PEM
 */
#define US903_PKCS10_RSA2048 "MIICvTCCAaUCAQAweDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEjAQBgNVBAoMCVJTQWNlcnRjbzEMMAoGA1UECwwDcnNhMRAwDgYDVQQD\nDAdyc2EgZG9lMRowGAYJKoZIhvcNAQkBFgtyc2FAZG9lLmNvbTCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAN6pCTBrK7T029Bganq0QHXHyNL8opvxc7JY\nXaQz39R3J9BoBE72XZ0QXsBtUEYGNhHOLaISASNzs2ZKWpvMHJWmPYNt39OCi48Y\nFOgLDbAn83mAOKSfcMLbibCcsh4HOlhaaFrWskRTAsew16MUOzFu6vBkw/AhI82J\nKPYws0dYOxuWFIgE1HL+m/gplbzq7FrBIdrqkNL+ddgyXoDd5NuLMJGDAK7vB1Ww\n9/Baw/6Ai9V5psye1v8fWDr6HW2gg9XnVtMwB4pCg1rl1lSYstumTGYbM6cxJywe\nLuMnDjj1ZwDsZ1wIXaBAXZaxEIS/rXOX0HnZMTefxY/gpFk1Kv0CAwEAAaAAMA0G\nCSqGSIb3DQEBBQUAA4IBAQB6rIwNjE8l8jFKR1hQ/qeSvee/bAQa58RufZ4USKuK\nlsih7UCf8bkQvgljnhscQuczIbnJzeqEPqSdnomFW6CvMc/ah+QfX87FGYxJgpwF\nutnUifjDiZhrWgf/jNNbtHrkecw/Zex4sZ/HC127jtE3cyEkDsrA1oBxYRCq93tC\nW2q9PLVmLlyjcZcS1KHVD2nya79kfS0YGMocsw1GelVL2iz/ocayAS5GB9Y2sEBw\nRkCaYZw6vhj5qjpCUzJ3E8Cl3VD4Kpi3j3bZGDJA9mdmd8j5ZyPY56eAuxarWssD\nciUM/h6E99w3tmrUZbLljkjJ7pBXRnontgm5WZmQFH4X"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the ec.req file:
 *
 * openssl req -newkey ec:256parms -keyout eckey.pem -keyform PEM -out ec.req -outform PEM
 */
#define US903_PKCS10_DSA1024 "MIICfjCCAj0CAQAwfDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMQwwCgYDVQQH\nDANSVFAxEzARBgNVBAoMCkRTQUNvbXBhbnkxDzANBgNVBAsMBkRTQW9yZzEQMA4G\nA1UEAwwHZHNhIGRvZTEaMBgGCSqGSIb3DQEJARYLZHNhQGRvZS5jb20wggG2MIIB\nKwYHKoZIzjgEATCCAR4CgYEAqIfbyk7rEAaULIPB1GcHHc0ctx6g0dhBfdUdOPNG\nBSE+TP5UF5lw8Qm6oCXstU3nYEJalmMvkjFwbgvBws8aJBnj09dDDn8spKEGcG0M\nZpqdMys6+b4QJjq5YAxEaATVY/1L/rBgGGm1EFDhc/6Ezm2T3CGeQklwo5aBZQCc\naIsCFQDC1olBFuE+phOhjXAwEE5EPJkRJwKBgD+vZ+tLCTjBzVFNjAO8X/SMamwW\noraNfdyZ+ZCEAmYI/D4838nCGAjVRQyDb1q5akkLyxoJX1YV7gNbaBNUys3waqdu\nso1HtuEur2cbhU5iOeKBWpj6MIWlPdD3uCRu4uiBF9XBiANaRID8CT2kchhwy4Ok\nFfQMuYOz4eBhMQqmA4GEAAKBgDuwR7H3U4CfuQjWeTtrI50M1TxhlVZ3TonRtVIx\nEHpuXxAouxATVkthJtaCBKc0EHii1bE/kgNUgGX/ZdFjBUb/XfpkYsRT3QRLF0+s\nPZGY/0TovO9pKjqiw0C10leNKFbEVdlXYtAkjXUbHmyNog3195/t7oKXHMT1A/5p\nhUCRoAAwCQYHKoZIzjgEAwMwADAtAhUAhPCqQG3gKUUPKdwBNCmZfzWDqjsCFAh0\nzn9HujlXNaTA1OhjmPmcJSxT"

/*
 * The following CSR was generated using the following openssl command and then
 * using cat on the dsa.req file:
 *
 * openssl req -newkey dsa:dsaparms -keyout dsakey.pem -keyform PEM -out dsa.req -outform PEM
 */
#define US903_PKCS10_ECDSA256 "MIIBMTCB2gIBADB4MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxDDAKBgNVBAcM\nA1JUUDESMBAGA1UECgwJRUNDb21wYW55MQ4wDAYDVQQLDAVFQ29yZzEPMA0GA1UE\nAwwGRUMgZG9lMRkwFwYJKoZIhvcNAQkBFgplY0Bkb2UuY29tMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEO1uszCKdXNFzygNLNeS8azQKod1516GT9qdDddt9iJN4\nLpBTnv+7K7+tji5kts1kWSYyvqLxvnq8Q/TU1iQJ56AAMAkGByqGSM49BAEDRwAw\nRAIgP6qda+0TEKZFPopgUfwFMRsxcNmuQUe2yuz16460/SQCIBfLvmuMeyYOqbbD\nX0Ifde9yzkROVBCEPvK0hcU5KsTO"



#define US903_ENROLL_URL_BA "https://127.0.0.1:8085/.well-known/est/simpleenroll"
#define US903_PKCS10_CT     "Content-Type: application/pkcs10"
#define US903_UIDPWD_GOOD   "estuser:estpwd"
#define US903_CACERTS       "../../../example/server/estCA/cacert.crt"


static int stop_flag;
static long auth_mode = CURLAUTH_BASIC;
static int rsa_cnt = 0;
static int dsa_cnt = 0;
static int ecdsa_cnt = 0;


/*
 * Simple enroll - RSA 2048
 *
 * This test case uses libcurl to test simple
 * enrollment of a 2048 bit RSA CSR.  HTTP Basic
 * authentication is used.
 */
static void * us903_test1 (void *arg)
{
    long rv;

    while (!stop_flag) {
        rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                            US903_PKCS10_RSA2048,
                            US903_UIDPWD_GOOD, US903_CACERTS, auth_mode,
                            NULL, NULL, NULL);
        /*
         * Since we passed in a valid userID/password,
         * we expect the server to respond with 200
         */
        if (rv != 200) {
            fprintf(stderr, "Unable to enroll RSA cert\n");
        }
	rsa_cnt++;
    }
    return NULL;
}

/*
 * Simple enroll - EC prime 256
 *
 * This test case uses libcurl to test simple
 * enrollment of a 256 bit EC CSR.  HTTP Basic
 * authentication is used.
 */
static void * us903_test2 (void *arg)
{
    long rv;

    while (!stop_flag) {
        rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                            US903_PKCS10_ECDSA256,
                            US903_UIDPWD_GOOD, US903_CACERTS, auth_mode,
                            NULL, NULL, NULL);
        /*
         * Since we passed in a valid userID/password,
         * we expect the server to respond with 200
         */
        if (rv != 200) {
            fprintf(stderr, "Unable to enroll ECDSA cert\n");
        }
	ecdsa_cnt++;
    }
    return NULL;
}

/*
 * Simple enroll - DSA prime 1024
 *
 * This test case uses libcurl to test simple
 * enrollment of a 1024 bit DSA CSR.  HTTP Basic
 * authentication is used.
 */
static void * us903_test3 (void *arg)
{
    long rv;

    while (!stop_flag) {
        rv = curl_http_post(US903_ENROLL_URL_BA, US903_PKCS10_CT,
                            US903_PKCS10_DSA1024,
                            US903_UIDPWD_GOOD, US903_CACERTS, auth_mode,
                            NULL, NULL, NULL);
        /*
         * Since we passed in a valid userID/password,
         * we expect the server to respond with 200
         */
        if (rv != 200) {
            fprintf(stderr, "Unable to enroll DSA cert\n");
        }
	dsa_cnt++;
    }
    return NULL;
}


/*
 * Simple routine to spin up 3 threads and continuously
 * send enrollment requests on each thread.  We do
 * RSA, DSA, and ECDSA on each of the 3 threads.
 * If the server is using Digest authentication, then add
 * the -digest option.
 */
int main (int argc, char *argv[])
{
    pthread_t threads[3];
    void *rv;

    if (argc == 2 && !strcmp(argv[1], "-digest")) {
	auth_mode = CURLAUTH_DIGEST;
    }

    stop_flag = 0;
    pthread_create(&threads[0], NULL, us903_test1, NULL);
    pthread_create(&threads[1], NULL, us903_test2, NULL);
    pthread_create(&threads[2], NULL, us903_test3, NULL);

    getchar();
    stop_flag = 1;

    pthread_join(threads[0], &rv);
    pthread_join(threads[1], &rv);
    pthread_join(threads[2], &rv);

    printf("\n\nTotal enrollment requests sent\n");
    printf("     RSA: %d\n", rsa_cnt);
    printf("     DSA: %d\n", dsa_cnt);
    printf("     ECDSA: %d\n", ecdsa_cnt);

    return 0;
}

