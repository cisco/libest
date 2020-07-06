/*------------------------------------------------------------------
 * estclient-brski.c - Example application that utilizes libest.so for
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
#include "../util/jsmn.h"

#if ENABLE_BRSKI

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
static char est_http_uid[MAX_UID_LEN+1];
static char est_http_pwd[MAX_PWD_LEN+1];
static char est_srp_uid[MAX_UID_LEN];
static char est_srp_pwd[MAX_PWD_LEN];
static char est_server[MAX_SERVER_LEN];
static char est_auth_token[MAX_AUTH_TOKEN_LEN];
static int est_port;
static int srp = 0;
static char client_key_file[MAX_FILENAME_LEN];
static char client_cert_file[MAX_FILENAME_LEN];
static int token_auth_mode = 0;
static int force_voucher_failure = 0;
static int force_enroll_failure = 0;
static int force_pop = 0;
static int sign_voucher = 0;
static pem_password_cb *priv_key_cb = NULL;
static char *est_path_seg = NULL;

static EVP_PKEY *client_priv_key;
static X509 *client_cert;


#define cert_file_name  "cert-b64.pkcs7"
#define ca_file_name    "newcacerts.pkcs7"


static void print_ssl_version () 
{
    printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
}


static void show_usage_and_exit (void) 
{
    printf("estclient: BRSKI bootstrapping\n");
    printf("Usage:\n");
    printf("\nAvailable client OPTIONS\n"
        "  -s <server>       Enrollment server IP address\n"
        "  -p <port#>        TCP port# for enrollment server\n"
        "  -z                Force binding the PoP by including the challengePassword in the CSR\n"
        "  -u                Specify user name for HTTP authentication.\n"
        "  -h                Specify password for HTTP authentication.\n"
        "  -f                Runs EST BRSKI Client in FIPS MODE = ON\n"
        "  -c <certfile>     Identity certificate to use for the TLS session\n"
        "  -k <keyfile>      Use with -c option to specify private key for the identity cert\n"
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
static EST_CTX *setup_est_context (void)
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
    rv = est_client_set_auth(ectx, est_http_uid, est_http_pwd, client_cert, client_priv_key);
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
    rv = est_client_set_server(ectx, est_server, est_port, est_path_seg);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure server address.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }        

    return (ectx);
}

typedef enum {
    EST_BRSKI_SUCCESS = 0,
    EST_BRSKI_INVALID_PARAMETER,
    EST_BRSKI_MISSING_NONCE,
    EST_BRSKI_MISSING_CACERTS,    
    EST_BRSKI_FAILURE,
} EST_BRSKI_RC;

static EST_ERROR send_brski_voucher_req (EST_CTX *ectx, int *cacert_len)
{
    EST_ERROR rv = EST_ERR_NONE;

    /*
     * enable proof of possession
     */
    if (force_pop) {
        rv =  est_client_force_pop(ectx);
        if (rv != EST_ERR_NONE) {
            printf("\nFailed to enable force PoP");
            return(rv);
        }
    }

    /*
     * issue the request
     */
    rv = est_client_brski_get_voucher(ectx, cacert_len, sign_voucher);

    return (rv);
}

static EST_ERROR send_brski_voucher_status_ind (EST_CTX *ectx)
{
    EST_ERROR rv = EST_ERR_NONE;
    int http_status;
    EST_BRSKI_STATUS_VALUE status;
    char *reason;
    
    status = force_voucher_failure?EST_BRSKI_STATUS_FAIL:EST_BRSKI_STATUS_SUCCESS;
    reason = force_voucher_failure?"Voucher rejected":"Voucher Accepted";
    
    /*
     * send the status indication
     */    
    rv = est_client_brski_send_voucher_status(ectx, status, reason);
    if (rv != EST_ERR_NONE) {
        printf("Error: Unable to send voucher status. rv = %d (%s)\n",
                rv, EST_ERR_NUM_TO_STR(rv));
        return (rv);
    }

    /*
     * HTTP response should be ignored by the client (draft 7, section 3.5)
     * But get it anyway and print it out.
     */
    http_status = est_client_get_last_http_status(ectx);
    printf("HTTP status from voucher status indication = %d\n", http_status);
    
    return (rv);
}

static EST_ERROR send_brski_enrollment_status_ind (EST_CTX *ectx,
                                                   unsigned char *subject_key_id)
{
    EST_ERROR rv = EST_ERR_NONE;
    EST_BRSKI_STATUS_VALUE status;
    char *reason;
    int http_status;    

    status = force_enroll_failure?EST_BRSKI_STATUS_FAIL:EST_BRSKI_STATUS_SUCCESS;
    reason = force_enroll_failure?"Enrollent Rejected":"";
    
    /*
     * send the status indication
     */    
    rv = est_client_brski_send_enroll_status(ectx, status, reason, subject_key_id);
    if (rv != EST_ERR_NONE) {
        printf("Error: Unable to send enroll status. rv = %d (%s)\n",
                rv, EST_ERR_NUM_TO_STR(rv));
        return (rv);
    }

    /*
     * HTTP response should be ignored by the client
     */
    http_status = est_client_get_last_http_status(ectx);
    printf("HTTP status from enroll status indication = %d\n", http_status);
    
    return (rv);
}

int main (int argc, char **argv) 
{
    EST_ERROR rv;
    char c;
    char *key_data;
    EVP_PKEY *key;
    char *trustanchor_file;
    EST_CTX *ectx;
#if 1
    int p7_len;
    int ca_certs_len;
    unsigned char *new_client_cert;
    unsigned char *new_certs;
#endif
    BIO *certin;    
    int cacert_len = 0;
    int set_fips_return = 0;
    unsigned char returned_cacerts[EST_BRSKI_MAX_VOUCHER_LEN+1];
    
    static struct option long_options[] = {
        {"srp", 0, 0, 0},
        {"srp-user", 1, 0, 0},
        {"srp-password", 1, 0, 0},
        {"auth-token", 1, 0, 0},
        {"path-seg", 1, 0, 0},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;

    memset(client_key_file, 0, 1);
    memset(client_cert_file, 0, 1);
    memset(est_http_uid, 0, MAX_UID_LEN+1);
    memset(est_http_pwd, 0, MAX_PWD_LEN+1);

    while ((c = getopt_long(argc, argv, "?zfs:p:u:h:c:k:", long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
                if (!strncmp(long_options[option_index].name,"sign-voucher", strlen("sign_voucher"))) {
                    sign_voucher = 1;
                }
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
		if (!strncmp(long_options[option_index].name,"path-seg", strlen("path-seg"))) {
                    est_path_seg = calloc(EST_MAX_PATH_SEGMENT_LEN+1, sizeof(char));
		    strncpy(est_path_seg, optarg, EST_MAX_PATH_SEGMENT_LEN);
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
            case 'k':
                strncpy(client_key_file, optarg, MAX_FILENAME_LEN);
                break;
            case 'c':
                strncpy(client_cert_file, optarg, MAX_FILENAME_LEN);
                break;
            case 'z':
                force_pop = 1;
                break;
            case 'f':
                /* Turn FIPS on if requested and exit if failure */
                set_fips_return = FIPS_mode_set(1);
                if (!set_fips_return) {
                    printf("\nERROR setting FIPS MODE ON ...\n");
                    ERR_load_crypto_strings();
                    ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
                    exit(1);
                } else {
                    printf("\nRunning EST BRSKI Client with FIPS MODE = ON\n");
                };
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
    
    print_ssl_version();
    printf("\nUsing EST server %s:%d", est_server, est_port);

    if (client_cert_file[0]) printf("\nUsing identity client cert file %s", client_cert_file);
    if (client_key_file [0]) printf("\nUsing identity private key file %s", client_key_file);

    /*
     * Read in the current client certificate
     */
    if (client_cert_file[0]) {
        certin = BIO_new(BIO_s_file());
        if (BIO_read_filename(certin, client_cert_file) <= 0) {
            printf("\nUnable to read client certificate file %s\n", client_cert_file);
            exit(1);
        }
        /*
         * This reads the file, which is expected to be PEM encoded.  If you're using
         * DER encoded certs, you would invoke d2i_X509_bio() instead.
         */
        client_cert = PEM_read_bio_X509(certin, NULL, NULL, NULL);
        if (client_cert == NULL) {
            printf("\nError while reading PEM encoded client certificate file %s\n", client_cert_file);
            exit(1);
        }
        BIO_free(certin);
    }

    /*
     * Read in the client's private key
     */
    if (client_key_file[0]) {
        client_priv_key = read_private_key(client_key_file, priv_key_cb);
        if (client_priv_key == NULL) {
            printf("\nError while reading PEM encoded private key file %s\n", client_key_file);
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }

    /*
     * Read in the trusted certificates, which are used by
     * libEST to verify the identity of the EST server.
     *
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
     * BRSKI API usage
     */
    
    /*
     * Put the EST library into BRSKI mode
     */
    rv = est_client_set_brski_mode(ectx);
    if (rv != EST_ERR_NONE) {
        printf("\nEST Client: BRSKI: failed to configure BRSKI mode with error %s\n",
               EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }

    /*
     * Call to request that the voucher request is sent.
     */
    rv = send_brski_voucher_req(ectx, &cacert_len);
    if (rv != EST_ERR_NONE) {
        printf("Failed to send BRSKI request voucher. error = %d (%s)\n",
               rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }

    /*
     * Retrieve the PKI domain CA Cert from the received voucher
     */
    memset(returned_cacerts, 0, EST_BRSKI_MAX_VOUCHER_LEN+1);
    rv = est_client_brski_copy_cacert(ectx, &returned_cacerts[0]);
    if (rv != EST_ERR_NONE) {
        printf("Failed to retrieve CA cert from voucher.\n");
        exit(1);
    }
    
    printf("Returned domain CA certs = %s \n", returned_cacerts);

    /*
     * Send the Voucher status indication.  This indicates that we've received
     * and accepted the voucher from the Registrar
     */
    rv = send_brski_voucher_status_ind(ectx);
    if (rv != EST_ERR_NONE) {
        printf("Failed to send BRSKI voucher status. error = %d (%s)\n",
               rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }
    
#if 1
    /*
     * Attempt to provision a new cert
     */
    rv = est_client_provision_cert(ectx, "localhost", &p7_len, &ca_certs_len, key);
    if (rv != EST_ERR_NONE) {
        printf("Provisioning failed with error %s\n", EST_ERR_NUM_TO_STR(rv));
        exit(1);
    } 
    EVP_PKEY_free(key);

    /*
     * Retrieve a copy of the cert
     */
    new_client_cert = malloc(p7_len);
    if (new_client_cert == NULL){
        printf("Failed to allocate memory for the newly provisioned cert\n");
        exit(1);
    }                    
    rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
    if (rv != EST_ERR_NONE) {
        printf("Failed to copy new cert with code %d (%s)\n", 
            rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }
#endif
    /*
     * PDB TODO: Need to figure out the "SubjectKeyIdentifier"
     * value that needs to be passed back when the enrollment fails.
     */
#if 0 /* Need to obtain the SubjectKeyIdentifier from the new cert */    
    {
        int new_client_cert_pem_len = 0;
        unsigned char *new_client_cert_pem = NULL;
        ASN1_OCTET_STRING *skid;

        new_client_cert_pem_len = est_convert_p7b64_to_pem(new_client_cert, p7_len,
                                                           &new_client_cert_pem);

        skid = X509_get_ext_d2i(x, NID_subject_key_identifier, NULL, NULL);
        printf(" PDB: new_client_cert Subject Key Identifier: %s\n", skid->data;
    }
#endif

/* PDB: 20 byte hex string.  Needs to be extracted from the enrolled cert */
/* #define key_subject "12345678901234567890" */
    unsigned char *subject_key_id = (unsigned char *)"12345678901234567890";

#if 0
    {
        
        int i;
    
/*     i = EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos); */

        BIGNUM *bn = NULL;

        bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
        if (!bn)
            goto err;
        if (BN_is_zero(bn))
            row[DB_serial] = BUF_strdup("00");
        else
            row[DB_serial] = BN_bn2hex(bn);
        BN_free(bn);

        i = X509_NAME_get_index_by_NID(subj, NID_subject_key_identifier, -1);
        if (i == -1) {
            EST_LOG_ERR("Serial Number element not defined in certificate subject attribute");
            return (NULL);
        }
    
    }
    
#endif    

    /*
     * Send the enrollment status indication
     */
    rv = send_brski_enrollment_status_ind(ectx, (unsigned char *) subject_key_id);
    if (rv != EST_ERR_NONE) {
        printf("\nEST Client: BRSKI: failed to send BRSKI voucher status. error = %d (%s)\n",
               rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }
#if 1
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
#endif
    printf("\n\nSuccess!!!\n");
   
    free(cacerts);
    est_destroy(ectx);

    est_apps_shutdown();

    printf("\n");
    return 0;
}
#else
int main (int argc, char **argv) 
{
    printf("libEST was not built with BRSKI support.  Rebuild libEST with --enable-brski configure option.\n");
    exit (1);
}
#endif
