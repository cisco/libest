/*------------------------------------------------------------------
 * estclient-simple.c - Example application that utilizes libest.so for
 *               EST client operations.  This module utilizes OpenSSL
 *               for SSL and crypto services. 
 *
 *
 * October, 2013
 *
 * Copyright (c) 2013, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#include "stdio.h"
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#ifndef WIN32
#include <strings.h>
#endif
#include <stdlib.h>
#include <est.h>
#include "../util/utils.h"

#define MAX_SERVER_LEN 32
#define MAX_FILENAME_LEN 255

#ifdef WIN32
static CRITICAL_SECTION logger_critical_section;  
static void windows_logger_stderr (char *format, va_list l) 
{
    EnterCriticalSection(&logger_critical_section);
	vfprintf(stderr, format, l);
	fflush(stderr);
    LeaveCriticalSection(&logger_critical_section); 
}
#endif

/*
 * Global variables to hold command line options
 */
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char est_http_uid[MAX_UID_LEN];
static char est_http_pwd[MAX_PWD_LEN];
static char est_srp_uid[MAX_UID_LEN];
static char est_srp_pwd[MAX_PWD_LEN];
static char est_server[MAX_SERVER_LEN];
static char est_auth_token[MAX_AUTH_TOKEN_LEN];
static int est_port;
static int srp = 0;
static int token_auth_mode = 0;

#define cert_file_name	"cert-b64.pkcs7"
#define ca_file_name	"newcacerts.pkcs7"


static void print_version () 
{
    printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
}


static void show_usage_and_exit (void) 
{
    printf("estclient \n");
    printf("Usage:\n");
    printf("\nAvailable client OPTIONS\n"
	"  -s <server>       Enrollment server IP address\n"
	"  -p <port#>        TCP port# for enrollment server\n"
	"  -u                Specify user name for HTTP authentication.\n"
	"  -h                Specify password for HTTP authentication.\n"
	"  --srp                       Enable TLS-SRP cipher suites.  Use with --srp-user and --srp-password options.\n"
	"  --srp-user     <string>     Specify the SRP user name.\n"
	"  --srp-password <string>     Specify the SRP password.\n"
	"  --auth-token   <string>     Specify the token to be used with HTTP token authentication.\n"
	"\n");
    exit(255);
}

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
static
EST_HTTP_AUTH_CRED_RC auth_credentials_token_cb(EST_HTTP_AUTH_HDR *auth_credentials)
{
    char *token_ptr = NULL;
    int token_len = 0;

    printf("\nHTTP Token authentication credential callback invoked from EST client library\n");
    
    if (auth_credentials->mode == AUTH_TOKEN) {
        /*
         * If the test_token is set to anything, then we need to allocate
         * space from the heap and copy in the value.
         */
        if (est_auth_token[0] != '\0') {
            token_len = strlen(est_auth_token);

            if (token_len == 0) {
                printf("\nError determining length of token string used for credentials\n");
                return EST_HTTP_AUTH_CRED_NOT_AVAILABLE;
            }   
            token_ptr = malloc(token_len+1);
            if (token_ptr == NULL){
                printf("\nError allocating token string used for credentials\n");
                return EST_HTTP_AUTH_CRED_NOT_AVAILABLE;
            }   
            strncpy(token_ptr, est_auth_token, strlen(est_auth_token));
            token_ptr[token_len] = '\0';
        }
        /*
         * If we made it this far, token_ptr is pointing to a string
         * containing the token to be returned. Assign it and return success
         */
        auth_credentials->auth_token = token_ptr;

        printf("Returning access token = %s\n\n", auth_credentials->auth_token);
        
        return (EST_HTTP_AUTH_CRED_SUCCESS);
    }
    
    return (EST_HTTP_AUTH_CRED_NOT_AVAILABLE);
}


/*
 * This routine intializes an EST context, which can later
 * be used to issue commands to an EST server.
 */
static EST_CTX * setup_est_context (void)
{
    EST_CTX *ectx;
    EST_ERROR rv;

    /*
     * Initialize an EST context.  We must provide the trust
     * anchor certs at this time.
     */
    ectx = est_client_init(cacerts, cacerts_len, EST_CERT_FORMAT_PEM, NULL);
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        exit(1);
    }
        
    /*
     * Set the local authentication credentials.  We're not using
     * a certificate to identify ourselves to the server.  We're 
     * simply hard-coding the userID and password, which will be
     * used for HTTP authentication.
     */
    rv = est_client_set_auth(ectx, est_http_uid, est_http_pwd, NULL, NULL);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure client authentication.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }        

    if (srp) {
	rv = est_client_enable_srp(ectx, SRP_MINIMAL_N, est_srp_uid, est_srp_pwd);
	if (rv != EST_ERR_NONE) {
	    printf("\nUnable to enable SRP.  Aborting!!!\n");
	    exit(1);
	}        
    }

    if (token_auth_mode) {
        rv = est_client_set_auth_cred_cb(ectx, auth_credentials_token_cb);
        if (rv != EST_ERR_NONE) {
            printf("\nUnable to register token auth callback.  Aborting!!!\n");
            exit(1);
        }        
    }
    
    /*
     * Specify the EST server address and TCP port#
     */
    rv = est_client_set_server(ectx, est_server, est_port, NULL);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure server address.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }        

    return (ectx);
}



int main (int argc, char **argv) 
{
    EST_ERROR rv;
    char c;
    char *key_data;
    EVP_PKEY *key;
    char *trustanchor_file;
    EST_CTX *ectx;
    int p7_len;
    int ca_certs_len;
    unsigned char *new_client_cert;
    unsigned char *new_certs;
    static struct option long_options[] = {
        {"srp", 0, 0, 0},
        {"srp-user", 1, 0, 0},
        {"srp-password", 1, 0, 0},
        {"auth-token", 1, 0, 0},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;

    est_http_uid[0] = 0x0;
    est_http_pwd[0] = 0x0;

    while ((c = getopt_long(argc, argv, "s:p:u:h:", long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
		if (!strncmp(long_options[option_index].name,"srp", strlen("srp"))) {
		    srp = 1;
		}
		if (!strncmp(long_options[option_index].name,"srp-user", strlen("srp-user"))) {
		    strncpy(est_srp_uid, optarg, MAX_UID_LEN);
		}
		if (!strncmp(long_options[option_index].name,"srp-password", strlen("srp-password"))) {
		    strncpy(est_srp_pwd, optarg, MAX_PWD_LEN);
		}
		if (!strncmp(long_options[option_index].name,"auth-token", strlen("auth-token"))) {
		    strncpy(est_auth_token, optarg, MAX_AUTH_TOKEN_LEN);
                    token_auth_mode = 1;
		}
                break;
            case 'u':
		strncpy(est_http_uid, optarg, MAX_UID_LEN);
                break;
            case 'h':
		strncpy(est_http_pwd, optarg, MAX_PWD_LEN);
                break;
            case 's':
		strncpy(est_server, optarg, MAX_SERVER_LEN);
                break;
            case 'p':
		est_port = atoi(optarg);
                break;
            default:
                show_usage_and_exit();
                break;
        }
    }
    if (optind < argc) {
        printf ("non-option ARGV-elements: ");
        while (optind < argc)
            printf ("%s ", argv[optind++]);
        printf ("\n");
    }    
    argc -= optind;
    argv += optind;

    if (est_http_uid[0] && !est_http_pwd[0]) {
	printf ("Error: The password for HTTP authentication must be specified when the HTTP user name is set.\n");
	exit(1);
    }

    /*
     * Initialize the library, including OpenSSL
     */
    est_apps_startup();
        
    print_version();
    printf("\nUsing EST server %s:%d", est_server, est_port);

    /*
     * Read in the trusted certificates, which are used by
     * libEST to verify the identity of the EST server.
     */
    trustanchor_file = getenv("EST_OPENSSL_CACERT");
    cacerts_len = read_binary_file(trustanchor_file, &cacerts);
    if (cacerts_len <= 0) {
        printf("\nTrusted certs file could not be read.  Did you set EST_OPENSSL_CACERT?\n");
        exit(1);
    }
    
    /*
     * This is not required, but we'll enable full debugs
     */
#ifndef WIN32
    /* Initialize the EST logging */
    est_init_logger(EST_LOG_LVL_INFO, NULL);
#else
    InitializeCriticalSection (&logger_critical_section);
    est_init_logger(EST_LOG_LVL_INFO, &windows_logger_stderr);
#endif 

    /*
     * Create a public/private key pair that will be used for 
     * the enrollment.  We'll write this out to a local
     * file called new_key.pem.
     */
    key_data = generate_private_RSA_key(2048, NULL/* no password_cb */);

    write_binary_file("./new_key.pem", (unsigned char *)key_data, strlen(key_data));

    /*
     * Use the load_clear macro to load in an unencrypted key
     */
    key = load_clear_private_key_PEM(key_data);

    if(!key) {
        printf("\nUnable to load newly created key from PEM file\n");
        exit(1);
    }
    memset(key_data, 0, strlen(key_data));
    free(key_data);
    key_data = NULL;

    ectx = setup_est_context();
    if (!ectx) {
	printf("\nUnable to create EST client context\n");
	exit(1);
    }
    
    /*
     * Attempt to provision a new cert
     */
    rv = est_client_provision_cert(ectx, "localhost", &p7_len, &ca_certs_len, key);
    if (rv != EST_ERR_NONE) {
	printf("\nProvisioning failed with error %s\n", EST_ERR_NUM_TO_STR(rv));
	exit(1);
    } 
    EVP_PKEY_free(key);

    /*
     * Retrieve a copy of the cert
     */
    new_client_cert = malloc(p7_len);
    if (new_client_cert == NULL){
	printf("\nFailed to allocate memory for the newly provisioned cert\n");
	exit(1);
    }                    
    rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to copy new cert with code %d (%s)\n", 
            rv, EST_ERR_NUM_TO_STR(rv));
	exit(1);
    }

    /*
     * Save the cert to local storage
     */
    write_binary_file(cert_file_name, new_client_cert, p7_len);
    free(new_client_cert);

    /*
     * Retrieve a copy of the new trust anchor
     */
    new_certs = malloc(ca_certs_len);
    rv = est_client_copy_cacerts(ectx, new_certs);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to copy new CA certs with code %d (%s)\n", 
            rv, EST_ERR_NUM_TO_STR(rv));
	exit(1);
    }

    /*
     * Your applications should save the CA certs to local storage in case
     * they're needed for future use.
     */
    write_binary_file(ca_file_name, new_certs, ca_certs_len); 
    free(new_certs);

    printf("\n\nSuccess!!!\n");
   
    free(cacerts);
    est_destroy(ectx);

    est_apps_shutdown();

    printf("\n");
    return 0;
}

