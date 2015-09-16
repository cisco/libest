/*------------------------------------------------------------------
 * estproxy.c -  Example application that utilizes libest.so for
 *               EST proxy operations.  libest does not manage
 *               sockets and pthreads.  This responsibility is
 *               placed on the application.  This module shows
 *               a fairly trivial example of how to setup a
 *               listening socket and serve EST requests.
 *
 * May, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-28 minor bug corrections w.r.t long options and stability improvements; added -o option
// 2015-08-07 completed use of DISABLE_PTHREADS

/* Main routine */
#include <est.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <sys/types.h>
#include "../util/utils.h"
#include "../util/simple_server.h"


#define MAX_SERVER_LEN 32
#define PROXY_PORT 8086  

/*
 * The OpenSSL CA needs this BIO to send errors to
 */
BIO *bio_err = NULL;

static char est_server[MAX_SERVER_LEN];
static char est_auth_token[MAX_AUTH_TOKEN_LEN+1];
static int est_server_port = 8085;
static int listen_port = PROXY_PORT;
static int verbose = 0;
static int pop = 0;
static int v6 = 0;
static int srp = 0;
static int client_token_auth_mode = 0;
static int http_auth_disable = 0;
static int disable_forced_http_auth = 0;
static int http_digest_auth = 0;
static int http_basic_auth = 0;
static int server_http_token_auth = 0;
static int set_fips_return = 0;
static unsigned long set_fips_error = 0;

EST_CTX *ectx;
char certfile[EST_MAX_FILE_LEN];
char keyfile[EST_MAX_FILE_LEN];
char realm[MAX_REALM];
unsigned char *cacerts_raw = NULL;
int cacerts_len = 0;
unsigned char *trustcerts = NULL;
int trustcerts_len = 0;

SRP_VBASE *srp_db = NULL;

static char valid_token_value[MAX_AUTH_TOKEN_LEN];

static void print_version (FILE *fp)
{
    // fprintf(fp, "Using %s\n", SSLeay_version(SSLEAY_VERSION));
}

static void show_usage_and_exit (void)
{
    fprintf(stderr, "\nAvailable EST proxy options\n"
            "  -v           Verbose operation\n"
            "  -n           Disable HTTP authentication\n"
            "  -o           Do not require HTTP authentication when TLS client auth succeeds\n"
            "  -h           Use HTTP Digest auth instead of Basic auth\n"
            "  -t           Enable PoP check of TLS UID\n"
            "  -c <file>    PEM file to use for server cert\n"
            "  -k <file>    PEM file to use for server key\n"
            "  -s <server>  Upstream server name or IP address\n"
            "  -p <port>    Upstream server TCP port number; default: 8085\n"
	    "  -l <port>    Downstream client TCP port number to listen on; default: 8086\n"
            "  -r <value>   HTTP realm to present to clients\n"
#ifndef DISABLE_PTHREADS
	    "  -d <seconds> Sleep timer to auto-shut the server\n"
#endif
	    "  -f           Runs EST Proxy in FIPS MODE = ON\n"
	    "  -6           Enable IPv6\n"
	    "  --srp <file> Enable TLS-SRP authentication of client using the specified SRP parameters file\n"
            "  -?           Print this help message and exit\n"
            "\n");
    exit(255);
}

static char digest_user[3][34] =
    {
	"estuser", 
	"estrealm", 
	"36807fa200741bb0e8fb04fcf08e2de6" //This is the HA1 precaculated value
    };

int process_http_auth (EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah, X509 *peer_cert,
	               void *app_data)
{
    int user_valid = 0; 
    char *digest;

    switch (ah->mode) {
    case AUTH_BASIC:
	/*
	 * this is where we might hook into a Radius server
	 * or some external database to authenticate a 
	 * userID/password.  But for this example code,
	 * we just hard-code a local user for testing
	 * the libest API.
	 */
	if (!strcmp(ah->user, "estuser") && !strcmp(ah->pwd, "estpwd")) {
	    /* The user is valid */
	    user_valid = 1;
	} 
	break;
    case AUTH_DIGEST:
	/*
	 * Check the user's name
	 */
	if (strcmp(ah->user, digest_user[0])) {
	    return 0;
	}

	/*
	 * Call the helper function to calculate the digest,
	 * This is then compared against the digest provided
	 * by the client.
	 */
	digest = est_server_generate_auth_digest(ah, digest_user[2]);
	if (!strncmp(digest, ah->response, 32)) {
	    user_valid = 1;
	}
	free(digest);
	break;
    case AUTH_TOKEN:
	/*
         * The bearer token has just been passed up from the EST Server
         * library.  Assuming it's an OAuth 2.0 based access token, it would
         * now be sent along to the OAuth Authorization Server.  The
         * Authorization Server would return either a success or failure
         * response.
	 */
        printf("Configured for HTTP Token Authentication\n");
        printf("Configured access token = %s \nClient access token received = %s\n",
               ah->auth_token, valid_token_value);

	if (!strcmp(ah->auth_token, valid_token_value)) {
	    /* The token is currently valid */
	    user_valid = 1;
	} 
	break;        
    case AUTH_FAIL:
    case AUTH_NONE:
    default:
	return 0;
	break;
    }
    return user_valid;
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
EST_HTTP_AUTH_CRED_RC auth_credentials_token_cb (EST_HTTP_AUTH_HDR *auth_credentials)
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
 * This callback is issued during the TLS-SRP handshake.  
 * We can use this to get the userid from the TLS-SRP handshake.
 * If a verifier file as provided, we must pull the SRP verifier 
 * parameters and invoke SSL_set_srp_server_param() with these
 * values to allow the TLS handshake to succeed.  If the application
 * layer wants to use their own verifier store, they would
 * hook into it here.  They would lookup the verifier parameters
 * based on the userid and return those parameters by invoking
 * SSL_set_srp_server_param().
 */
static int process_ssl_srp_auth (SSL *s, int *ad, void *arg) {

    char *login = SSL_get_srp_username(s);
    SRP_user_pwd *user;

    if (!login) return (-1);

    printf("SRP username = %s\n", login);

    user = SRP_VBASE_get_by_user(srp_db, login); 

    if (user == NULL) {
	printf("\nUser %s doesn't exist in SRP database\n", login);
	return SSL3_AL_FATAL;
    }

    /*
     * Get the SRP parameters for the user from the verifier database.
     * Provide these parameters to TLS to complete the handshake
     */
    if (SSL_set_srp_server_param(s, user->N, user->g, user->s, user->v, user->info) < 0) {
	*ad = SSL_AD_INTERNAL_ERROR;
	return SSL3_AL_FATAL;
    }
		
    printf("SRP parameters set: username = \"%s\" info=\"%s\" \n", login, user->info);

    user = NULL;
    login = NULL;
    fflush(stdout);
    return SSL_ERROR_NONE;
}

#ifndef DISABLE_PTHREADS
/*
 * We're using OpenSSL, both as the CA and libest
 * requires it.  OpenSSL requires these platform specific
 * locking callbacks to be set when multi-threaded support
 * is needed.  
 */
static pthread_mutex_t *ssl_mutexes;
static void ssl_locking_callback (int mode, int mutex_num, const char *file,
                                  int line)
{
    if (mode & CRYPTO_LOCK) {
        (void)pthread_mutex_lock(&ssl_mutexes[mutex_num]);
    } else {
        (void)pthread_mutex_unlock(&ssl_mutexes[mutex_num]);
    }
}
static unsigned long ssl_id_callback (void)
{
#ifndef _WIN32
    return (unsigned long)pthread_self();
#else
    return (unsigned long)pthread_self().p;
#endif
}
#endif

void cleanup (void)
{
#ifndef DISABLE_PTHREADS
    int i;

    /*
     * Tear down the mutexes used by OpenSSL
     */
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    free(ssl_mutexes);
#endif

    est_proxy_stop(ectx);
    est_destroy(ectx);
    if (srp_db) {
	SRP_VBASE_free(srp_db);
    }
    BIO_free(bio_err);
    if (cacerts_raw)
	free(cacerts_raw);
    if (trustcerts)
	free(trustcerts);
    est_apps_shutdown();
}

int main (int argc, char **argv)
{
    signed char c;
    EVP_PKEY *priv_key;
    BIO *certin, *keyin;
    X509 *x;
    EST_ERROR rv;
    int sleep_delay = 0;
    char vfile[255];
    int option_index = 0;
    static struct option long_options[] = {
        {"srp", 1, NULL, 0},
        {"token", 1, 0, 0},
        {"auth-token", 1, 0, 0},
        {"help", 0, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    
    strncpy(est_server, "127.0.0.1", MAX_SERVER_LEN);

    while ((c = getopt_long(argc, argv, "?vt6nohfr:c:k:s:p:l:d:", long_options, &option_index)) != -1) {
        switch (c) {
	case 0:
	    // the following uses of strncmp() MUST use strlen(...)+1, otherwise only prefix is compared.
            if (!strncmp(long_options[option_index].name,"srp", strlen("srp")+1)) {
		srp = 1;
                strncpy(vfile, optarg, 255);
            } else
            if (!strncmp(long_options[option_index].name,"token", strlen("token")+1)) {
		server_http_token_auth = 1;
                strncpy(&(valid_token_value[0]), optarg, MAX_AUTH_TOKEN_LEN);
            } else
            if (!strncmp(long_options[option_index].name,"auth-token", strlen("auth-token")+1)) {
                strncpy(est_auth_token, optarg, MAX_AUTH_TOKEN_LEN);
                client_token_auth_mode = 1;
            } else show_usage_and_exit();
	    break;
        case 'v':
            verbose = 1;
            break;
        case 't':
            pop = 1;
            break;
        case '6':
            v6 = 1;
            break;
        case 'h':
            http_digest_auth = 1;
            break;
        case 'b':
            http_basic_auth = 1;
            break;
        case 'n':
            http_auth_disable = 1;
            break;
        case 'o':
            disable_forced_http_auth = 1;
            break;
        case 'c':
	    strncpy(certfile, optarg, EST_MAX_FILE_LEN);
            break;
        case 'k':
	    strncpy(keyfile, optarg, EST_MAX_FILE_LEN);
            break;
        case 'r':
	    strncpy(realm, optarg, MAX_REALM);
            break;
        case 's':
            strncpy(est_server, optarg, MAX_SERVER_LEN);
            break;
#ifndef DISABLE_PTHREADS
        case 'd':
	    sleep_delay = atoi(optarg);
            break;
#endif
        case 'p':
            est_server_port = atoi(optarg);
            break;
        case 'l':
            listen_port = atoi(optarg);
            break;
        case 'f':
           /*
            * Turn FIPS on if user requested it and exit if failure
            */
            set_fips_return = FIPS_mode_set(1);
            if (set_fips_return != 1) {
              set_fips_error = ERR_get_error();
              printf("\nERROR WHILE SETTING FIPS MODE ON exiting ....\n");
              exit(1);
            } else {
              printf("Running EST Sample Proxy with FIPS MODE = ON !\n");
            };
            break;
        case '?':
        default:
            show_usage_and_exit();
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (verbose) {
        print_version(stdout);
        fprintf(stdout, "EST Proxy start up values:\n");
	fprintf(stdout, "Using EST server %s:%d\n", est_server, est_server_port);
	fprintf(stdout, "Listening on port: %d\n", listen_port);
	fprintf(stdout, "Using identity cert file: %s\n", certfile);
	fprintf(stdout, "Using identity private key file: %s\n", keyfile);
	fprintf(stdout, "Using realm value: %s\n", realm);
        fflush(stdout);
    }

    if (!getenv("EST_TRUSTED_CERTS")) {
        printf("\nEST_TRUSTED_CERTS file not set, set this env variable to resolve\n");
        exit(1);
    }

    /*
     * Read in the CA certificates
     */
    if (getenv("EST_CACERTS_RESP")) {
        cacerts_len = read_binary_file(getenv("EST_CACERTS_RESP"), &cacerts_raw);
        if (cacerts_len <= 0) {
            printf("\nEST_CACERTS_RESP file could not be read\n");
            exit(1);
        }
    }
    /*
     * Read in the trusted CA certificates for the local TLS context
     */
    if (getenv("EST_TRUSTED_CERTS")) {
        trustcerts_len = read_binary_file(getenv("EST_TRUSTED_CERTS"), &trustcerts);
        if (trustcerts_len <= 0) {
            printf("\nEST_TRUSTED_CERTS file could not be read\n");
            exit(1);
        }
    }

    est_apps_startup();

    /*
     * Read in the local server certificate 
     */
    certin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(certin, certfile) <= 0) {
	printf("\nUnable to read server certificate file %s\n", certfile);
	exit(1);
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using 
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
	printf("\nError while reading PEM encoded server certificate file %s\n", certfile);
	exit(1);
    }
    BIO_free(certin);

    /* 
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(keyin, keyfile) <= 0) {
	printf("\nUnable to read server private key file %s\n", keyfile);
	exit(1);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead. 
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
	printf("\nError while reading PEM encoded private key file %s\n", keyfile);
	ERR_print_errors_fp(stderr);
	exit(1);
    }
    BIO_free(keyin);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!bio_err) {
        printf("\nBIO not working\n");
        exit(1);
    }

    if (verbose) {
	est_init_logger(EST_LOG_LVL_INFO, NULL);
	est_enable_backtrace(1);
    }

    /*
     * Initialize EST context from libest
     */
    ectx = est_proxy_init(trustcerts, trustcerts_len,
                          cacerts_raw, cacerts_len, EST_CERT_FORMAT_PEM,
                          realm, x, priv_key, "estuser", "estpwd");
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        exit(1);
    }
    if (!http_auth_disable) {
	if (est_set_http_auth_cb(ectx, &process_http_auth)) {
	    printf("\nUnable to set EST HTTP AUTH callback.  Aborting!!!\n");
	    exit(1);
	}    
    }
    if (disable_forced_http_auth) {
        if (verbose) {
	    printf("Not requiring HTTP authentication when TLS client auth succeeds\n");
	}
	if (est_set_http_auth_required(ectx, HTTP_AUTH_NOT_REQUIRED)) {
	    printf("\nUnable to disable required HTTP auth.  Aborting!!!\n");
	    exit(1);
	}
    }

    if (http_digest_auth) {
	rv = est_proxy_set_auth_mode(ectx, AUTH_DIGEST);
	if (rv != EST_ERR_NONE) {
            printf("\nUnable to enable HTTP digest authentication.  Aborting!!!\n");
            exit(1);
	}
    }

    if (http_basic_auth) {
	rv = est_server_set_auth_mode(ectx, AUTH_BASIC);
	if (rv != EST_ERR_NONE) {
            printf("\nUnable to enable HTTP basic authentication.  Aborting!!!\n");
            exit(1);
	}
    }
    
    if (server_http_token_auth) {
	rv = est_server_set_auth_mode(ectx, AUTH_TOKEN);
	if (rv != EST_ERR_NONE) {
            printf("\nUnable to enable HTTP token authentication.  Aborting!!!\n");
            exit(1);
	}
    }

    if (!pop) {
	printf("Disabling PoP check\n");
	est_server_disable_pop(ectx);
    }

    est_proxy_set_server(ectx, est_server, est_server_port);

    if (srp) {
	srp_db = SRP_VBASE_new(NULL);
	if (!srp_db) {
	    printf("\nUnable allocate SRP verifier database.  Aborting!!!\n");
	    exit(1); 
	}
	if (SRP_VBASE_init(srp_db, vfile) != SRP_NO_ERROR) {
	    printf("\nUnable initialize SRP verifier database.  Aborting!!!\n");
	    exit(1); 
	}
	
	if (est_server_enable_srp(ectx, &process_ssl_srp_auth)) { 
	    printf("\nUnable to enable SRP.  Aborting!!!\n");
	    exit(1);
	}
    }

    if (client_token_auth_mode) {
        rv = est_proxy_set_auth_cred_cb(ectx, auth_credentials_token_cb);
        if (rv != EST_ERR_NONE) {
            printf("\nUnable to register token auth callback.  Aborting!!!\n");
            exit(1);
        }        
    }            
    
#ifndef DISABLE_PTHREADS
    /*
     * Install thread locking mechanism for OpenSSL
     */
    int size = sizeof(pthread_mutex_t) * CRYPTO_num_locks();
    if ((ssl_mutexes = (pthread_mutex_t*)malloc((size_t)size)) == NULL) {
        printf("\nCannot allocate mutexes\n");
	exit(1);
    }   

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&ssl_mutexes[i], NULL);
    }
    CRYPTO_set_locking_callback(&ssl_locking_callback);
    CRYPTO_set_id_callback(&ssl_id_callback);
#endif

    printf("Launching EST proxy...\n");

    rv = est_proxy_start(ectx);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to init mg (rv=%d)\n", rv);
        exit(1);
    }

    /*
     * Start the simple server, which opens a TCP
     * socket, waits for incoming connections, and
     * invokes the EST handler for each connection.
     */
    start_simple_server(ectx, listen_port, sleep_delay, v6);

    cleanup();
    return 0;
}

