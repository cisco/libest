/*------------------------------------------------------------------
 * estclient-simple.c - Simple example application that utilizes libest for
 *               EST client operations.  This module utilizes OpenSSL
 *               for SSL and crypto services. 
 *
 *
 * October, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 *------------------------------------------------------------------
 */

// 2015-08-28 minor bug corrections w.r.t long options and stability improvements

#include <est.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include "../util/utils.h"

#define MAX_SERVER_LEN 32
#define MAX_FILENAME_LEN 255

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
static int est_port = 8085;
static int srp = 0;
static int token_auth_mode = 0;

#define cert_file_name	"cert-b64.pkcs7"
#define ca_file_name	"newcacerts.pkcs7"


static void print_version () 
{
    // printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
}


static void show_usage_and_exit (void) 
{
    printf("Usage:\n");
    printf("\nAvailable client OPTIONS\n"
	"  -s <server>       Enrollment server name or IP address; default: 127.0.0.1\n"
	"  -p <port>         TCP port number of enrollment server; default: 8085\n"
	"  -u                Specify user name for HTTP authentication.\n"
	"  -h                Specify password for HTTP authentication.\n"
	"  -?                Print this help message and exit\n"
	"  --srp                       Enable TLS-SRP cipher suites.  Use with --srp-user and --srp-password options.\n"
	"  --srp-user     <string>     Specify the SRP user name.\n"
	"  --srp-password <string>     Specify the SRP password.\n"
	"  --auth-token   <string>     Specify the token to be used with HTTP token authentication.\n"
	"\n");
    exit(255);
}


/*
 * This function generates an EC public/private key
 * pair that will be used with the certificate
 * we provision.
 */
static EVP_PKEY * generate_private_key (void)
{
    EC_KEY *eckey;
    EC_GROUP *group = NULL;
    BIO *out;
    unsigned char *tdata;
    unsigned char *key_data;
    char file_name[MAX_FILENAME_LEN] = "./new_key.pem";
    int key_len;
    BIO *keyin;
    EVP_PKEY *new_priv_key;
    int	asn1_flag = OPENSSL_EC_NAMED_CURVE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

    /*
     * Generate an EC key
     */

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP_set_asn1_flag(group, asn1_flag);
    EC_GROUP_set_point_conversion_form(group, form);
    eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, group); 
    if (!EC_KEY_generate_key(eckey)) {
	printf("\nFailed to generate EC key\n");
        exit(1);
    }
    out = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPKParameters(out, group);
    PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL);
    key_len = BIO_get_mem_data(out, &tdata);
    key_data = (unsigned char *)malloc(key_len+1);
    memcpy(key_data, tdata, key_len);
    EC_KEY_free(eckey);
    BIO_free(out);


    /*
     * We'll write this out to a local file called new_key.pem.
     * Your application should persist the key somewhere safe.
     */
    if (write_binary_file(file_name, key_data, key_len) < 0) {
	exit(1);
    }
    free(key_data);
    
    /*
     * read it back in to an EVP_PKEY struct
     */
    keyin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(keyin, file_name) <= 0) {
        printf("\nUnable to read newly generated client private key file %s\n", file_name);
        exit(1);
    }

    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead. 
     */
    new_priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (new_priv_key == NULL) {
        printf("\nError while reading PEM encoded private key file %s\n", file_name);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    BIO_free(keyin);

    return (new_priv_key);
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

    printf("HTTP Token authentication credential callback invoked from EST client library\n");
    
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
            token_ptr = (char *)malloc(token_len+1);
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

        printf("Returning access token = %s\n", auth_credentials->auth_token);
        
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
    rv = est_client_set_server(ectx, est_server, est_port);
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
        {"help", 0, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;

    strncpy(est_server, "127.0.0.1", MAX_SERVER_LEN);

    est_http_uid[0] = 0x0;
    est_http_pwd[0] = 0x0;

    while ((c = getopt_long(argc, argv, "?s:p:u:h:", long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
		// the following uses of strncmp() MUST use strlen(...)+1, otherwise only prefix is compared.
		if (!strncmp(long_options[option_index].name,"srp", strlen("srp")+1)) {
		    srp = 1;
		} else
		if (!strncmp(long_options[option_index].name,"srp-user", strlen("srp-user")+1)) {
		    strncpy(est_srp_uid, optarg, MAX_UID_LEN);
		} else
		if (!strncmp(long_options[option_index].name,"srp-password", strlen("srp-password")+1)) {
		    strncpy(est_srp_pwd, optarg, MAX_PWD_LEN);
		} else
		if (!strncmp(long_options[option_index].name,"auth-token", strlen("auth-token")+1)) {
		    strncpy(est_auth_token, optarg, MAX_AUTH_TOKEN_LEN);
                    token_auth_mode = 1;
		} else show_usage_and_exit();
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
            case '?':
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
	printf ("\nError: The password for HTTP authentication must be specified when the HTTP user name is set.\n");
	exit(1);
    }

    /*
     * Initialize the library, including OpenSSL
     */
    est_apps_startup();
        
    print_version();
    printf("Using EST server %s:%d\n", est_server, est_port);

    /*
     * Read in the trusted certificates, which are used by
     * libest to verify the identity of the EST server.
     */
    trustanchor_file = getenv("EST_OPENSSL_CACERT");
    if (!trustanchor_file) {
	printf("\nCACERT file not set, set EST_OPENSSL_CACERT to resolve\n");
	exit(1);
    }
    cacerts_len = read_binary_file(trustanchor_file, &cacerts);
    if (cacerts_len <= 0) {
        printf("\nTrusted certs file %s could not be read.\n", trustanchor_file);
        exit(1);
    }
    
    /*
     * This is not required, but we'll enable full debugs
     */
    est_init_logger(EST_LOG_LVL_INFO, NULL);

    /*
     * Create a public/private key pair that will be used for 
     * the enrollment.  We'll write this out to a local
     * file called new_key.pem.
     */
    key = generate_private_key();

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
    new_client_cert = (unsigned char *)malloc(p7_len);
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
    if (write_binary_file(cert_file_name, new_client_cert, p7_len) < 0) {
	exit(1);
    }
    free(new_client_cert);

    /*
     * Retrieve a copy of the new trust anchor
     */
    new_certs = (unsigned char *)malloc(ca_certs_len);
    rv = est_client_copy_cacerts(ectx, new_certs);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to copy new CA certs with code %d (%s)\n", 
            rv, EST_ERR_NUM_TO_STR(rv));
	exit(1);
    }

    /*
     * Your appliations should save the CA certs to local storage in case
     * they're needed for future use.
     */
    if (write_binary_file(ca_file_name, new_certs, ca_certs_len) < 0) {
	exit(1);
    }
    free(new_certs);

    // printf("\nSuccess!!!\n");
   
    free(cacerts);
    est_destroy(ectx);

    est_apps_shutdown();

    return 0;
}

