/*------------------------------------------------------------------
 * estclient.c - Example application that utilizes libest.a for
 *               EST client operations.  This module utilizes OpenSSL
 *               for SSL and crypto services.
 *
 *
 * November, 2012
 *
 * Copyright (c) 2012-2013 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */

/* Main routine */
#include "stdio.h"
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pem.h> // for PEM_def_callback
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <est.h>
#include "../util/utils.h"

#define EST_UT_MAX_CMD_LEN 255
#define MAX_SERVER_LEN 255
#define MAX_FILENAME_LEN 255
#define MAX_CN 64
#define PRIV_KEY_PASS "pass:"

/*
 * Global variables to hold command line options
 */
static char est_http_uid[MAX_UID_LEN];
static char est_http_pwd[MAX_PWD_LEN];
static char est_srp_uid[MAX_UID_LEN];
static char est_srp_pwd[MAX_PWD_LEN];
static char subj_cn[MAX_CN];
static char est_server[MAX_SERVER_LEN];
static char est_auth_token[MAX_AUTH_TOKEN_LEN+1];
static int est_port;
static int verbose = 0;
static int srp = 0;
static int token_auth_mode = 0;
static int pem_out = 0;
static char csr_file[MAX_FILENAME_LEN];
static char priv_key_file[MAX_FILENAME_LEN];
static char client_key_file[MAX_FILENAME_LEN];
static char client_cert_file[MAX_FILENAME_LEN];
static int read_timeout = EST_SSL_READ_TIMEOUT_DEF;
static unsigned char *cacerts = NULL;
static int cacerts_len = 0;
static char out_dir[MAX_FILENAME_LEN];
static int enroll = 0;
static int getcsr = 0;
static int getcert = 0;
static int reenroll = 0;
static int force_pop = 0;
static unsigned char *c_cert = NULL;
static unsigned char *c_key = NULL;
static int c_cert_len = 0;
static int c_key_len = 0;

static char priv_key_pwd[MAX_PWD_LEN];
static pem_password_cb *priv_key_cb = NULL;
EVP_PKEY *priv_key = NULL;
EVP_PKEY *client_priv_key = NULL;
X509 *client_cert = NULL;

/*
 * This is a simple callback used to override the default
 * logging facility in libest.
 */
static void test_logger_stdout (char *format, va_list l)
{
    vprintf(format, l);
    fflush(stdout);
}


static void print_version ()
{
    printf("Using %s\n", SSLeay_version(SSLEAY_VERSION));
}


static void show_usage_and_exit (void)
{
    printf("estclient \n");
    printf("Usage:\n");
    fprintf(stderr, "\nAvailable EST client options\n"
            "  -v                Verbose operation\n"
            "  -g                Get CA certificate from EST server\n"
            "  -e                Enroll with EST server and request a cert\n"
            "  -a                Get CSR attributes from EST server\n"
            "  -z                Force binding the PoP by including the challengePassword in the CSR\n"
            "  -r                Re-enroll with EST server and request a cert, must use -c option\n"
            "  -c <certfile>     Identity certificate to use for the TLS session, also the cert that will\n"
	    "                    be used when doing a re-enroll operation\n"
            "  -k <keyfile>      Use with -c option to specify private key for the identity cert\n"
            "  -x <keyfile>      Use existing private key in the given file for signing the CSR\n"
            "  -y <csrfile>      Use existing CSR in the given file\n"
            "  -s <server>       Enrollment server IP address\n"
            "  -p <port>         TCP port number for enrollment server\n"
            "  -o <dir>          Directory where pkcs7 certs will be written\n"
            "  -w <count>        Timeout in seconds to wait for server response (default=10)\n" //EST_SSL_READ_TIMEOUT_DEF
            "  -f                Runs EST Client in FIPS MODE = ON\n"
            "  -u <string>       Specify user name for HTTP authentication\n"
            "  -h <string>       Specify password for HTTP authentication\n"
            "  -?                Print this help message and exit\n"
            "  --common-name  <string>     Specify the common name to use in the Suject Name field of the new certificate.\n"
            "                              127.0.0.1 will be used if this option is not specified\n"
            "  --pem-output                Convert the new certificate to PEM format\n"
            "  --keypass stdin|"PRIV_KEY_PASS"<string>  Specify en-/decryption of private key, password read from STDIN or argument\n"
            "  --srp                       Enable TLS-SRP cipher suites.  Use with --srp-user and --srp-password options\n"
            "  --srp-user     <string>     Specify the SRP user name\n"
            "  --srp-password <string>     Specify the SRP password\n"
            "  --auth-token   <string>     Specify the token to be used with HTTP token authentication.\n"
            "\n");
    exit(255);
}


/*
 * Takes as input the name of the file to write the cert to on the
 * local file system (full path name expected).
 * The cert_data argument should contain the PKCS7 base64 encoded
 * certificate, with the cert_len argument specifying the length
 * of the cert.  This routine will either write the cert to the
 * local file system "as is", or it will convert the cert to
 * PEM format and write it as a PEM file.
 */
static void save_cert (char *file_name, unsigned char *cert_data, int cert_len)
{
    int pem_len;
    unsigned char *pem;
    char full_file_name[MAX_FILENAME_LEN];

    if (pem_out) {
	pem_len = est_convert_p7b64_to_pem(cert_data, cert_len, &pem);
	if (pem_len > 0) {
	    snprintf(full_file_name, MAX_FILENAME_LEN, "%s.%s", file_name, "pem");
	    write_binary_file(full_file_name, pem, pem_len);
	    free(pem);
	}
    } else {
	snprintf(full_file_name, MAX_FILENAME_LEN, "%s.%s", file_name, "pkcs7");
        write_binary_file(full_file_name, cert_data, cert_len);
    }
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

static int client_manual_cert_verify (X509 *cur_cert, int openssl_cert_error)
{
    if (openssl_cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
        return 1; // accepted
    }

    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    int approve = 0;

    /*
     * Print out the specifics of this cert
     */
    printf("%s: OpenSSL/EST server cert verification failed with the following error: openssl_cert_error = %d (%s)\n",
           __FUNCTION__, openssl_cert_error,
           X509_verify_cert_error_string(openssl_cert_error));

    printf("Failing Cert:\n");
    X509_print_fp(stdout, cur_cert);
    /*
     * Next call prints out the signature which can be used as the fingerprint
     * This fingerprint can be checked against the anticipated value to determine
     * whether or not the server's cert should be approved.
     */
    X509_signature_print(bio_err, cur_cert->sig_alg, cur_cert->signature);

    BIO_free(bio_err);

    return approve;
}


/*  read_csr() is a helper function that reads a PEM encoded
    CSR from a file and converts its contents to an OpenSSL X509_REQ.

    The csr_file argument is the name of the file containing the PEM encoded CSR.

    This function reads the given file and converts its PEM encoded contents to
    the OpenSSL X509_REQ structure.  This function will return NULL if the PEM/DER
    data is corrupted or unable to be parsed by the OpenSSL library.
    This function will allocate memory for the X509_REQ data.  You must free the
    memory in your application when it's no longer needed by calling X509_REQ_free().
    See also the more general est_read_x509_request function.

    returns X509_REQ*
 */
static X509_REQ *read_csr (char *csr_file)
{
    BIO *csrin;
    X509_REQ *csr;

    /*
     * Read in the csr
     */
    csrin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(csrin, csr_file) <= 0) {
        printf("\nUnable to read CSR file %s\n", csr_file);
        return (NULL);
    }
    /*
     * This reads in the csr file, which is expected to be PEM encoded
     */
    csr = PEM_read_bio_X509_REQ(csrin, NULL, NULL, NULL);
    if (csr == NULL) {
        printf("\nError while reading PEM encoded CSR file %s\n", csr_file);
        ERR_print_errors_fp(stderr);
        return (NULL);
    }
    BIO_free(csrin);

    return (csr);
}

static int simple_enroll_attempt (EST_CTX *ectx)
{
    int pkcs7_len = 0;
    int rv;
    char file_name[MAX_FILENAME_LEN];
    unsigned char *new_client_cert;
    X509_REQ *csr = NULL;

    if (force_pop) {
        rv =  est_client_force_pop(ectx);
        if (rv != EST_ERR_NONE) {
            printf("\nFailed to enable force PoP");
        }
    }

    if (csr_file[0]) {
        csr = read_csr(csr_file);
        if (csr == NULL) {
            rv = EST_ERR_PEM_READ;
        }else  {
            rv = est_client_enroll_csr(ectx, csr, &pkcs7_len, NULL);
        }
    }else  {
        rv = est_client_enroll(ectx, subj_cn, &pkcs7_len, priv_key);
    }
    if (csr) {
        X509_REQ_free(csr);
    }
    if (verbose) {
        printf("\nenrollment rv = %d (%s) with pkcs7 length = %d\n",
               rv, EST_ERR_NUM_TO_STR(rv), pkcs7_len);
    }
    if (rv == EST_ERR_NONE) {
        /*
         * client library has obtained the new client certificate.
         * now retrieve it from the library
         */
        new_client_cert = malloc(pkcs7_len);
        if (new_client_cert == NULL) {
            if (verbose) {
                printf("\nmalloc of destination buffer for enrollment cert failed\n");
            }
            return (EST_ERR_MALLOC);
        }

        rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
        if (verbose) {
            printf("\nenrollment copy rv = %d\n", rv);
        }
        if (rv == EST_ERR_NONE) {
            /*
             * Enrollment copy worked, dump the pkcs7 cert to stdout
             */
            if (verbose) {
                dumpbin(new_client_cert, pkcs7_len);
            }
        }

        snprintf(file_name, MAX_FILENAME_LEN, "%s/newcert", out_dir);
        save_cert(file_name, new_client_cert, pkcs7_len);
        free(new_client_cert);
    }

    return (rv);
}


/*
 * Routine used to CSR for est_client_enroll_csr testcases
 */
static int populate_x509_csr (X509_REQ *req, EVP_PKEY *pkey, char *cn)
{
    X509_NAME *subj;

    /* Setup version number */
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

static int regular_csr_attempt (EST_CTX *ectx)
{
    int rv;
    unsigned char *attr_data = NULL;
    int attr_len;
    char file_name[MAX_FILENAME_LEN];

    /*
     * Just get the CSR attributes
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    if (rv != EST_ERR_NONE) {
        printf("\nWarning: CSR attributes were not available");
    } else {
        snprintf(file_name, MAX_FILENAME_LEN, "%s/csr.base64", out_dir);
        write_binary_file(file_name, attr_data, attr_len);
    }
    return (rv);
}

static int regular_enroll_attempt (EST_CTX *ectx)
{
    int pkcs7_len = 0;
    int rv;
    char file_name[MAX_FILENAME_LEN];
    unsigned char *new_client_cert;
    unsigned char *attr_data = NULL;
    unsigned char *der_ptr = NULL;
    int attr_len, der_len, nid;
    X509_REQ *csr;

    /*
     * We need to get the CSR attributes first, which allows libest
     * to know if the challengePassword needs to be included in the
     * CSR.
     */
    rv = est_client_get_csrattrs(ectx, &attr_data, &attr_len);
    if (rv != EST_ERR_NONE) {
        printf("\nWarning: CSR attributes were not available");
        return (rv);
    }

    /* Generate a CSR */
    csr = X509_REQ_new();

    if (csr == NULL) {
        printf("\nFailed to get X509_REQ");
        return (EST_ERR_NO_CSR);
    }
    rv = populate_x509_csr(csr, priv_key, "EST-client");

    if (rv) {
        printf("\nFailed to populate X509_REQ");
        return (EST_ERR_X509_PUBKEY);
    }


    rv = est_decode_attributes_helper((char*)attr_data, attr_len, &der_ptr, &der_len);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to decode attributes");
        return (rv);
    }

    while (der_len) {
        rv = est_get_attributes_helper(&der_ptr, &der_len, &nid);

        if (rv == EST_ERR_NONE) {
            /*
             * This switch can be enhanced to include all NID values
             * of interest by the client/server.  In addition the last
             * parameter can be enhanced to provide the character string
             * type information that is included with the NID.
             *
             * Presently only character string types are supported, but at
             * some point OID or groups of strings/OIDs may need to be
             * supported.
             *
             * Note that challenge password should not be included here
             * as it is handled by libest client code.
             */
            switch (nid) {
            case NID_commonName:
                /* add the attribute to the request */
                rv = est_add_attributes_helper(csr, nid, "test\n", 0);
                break;
            case NID_pkcs9_emailAddress:
                /* add the attribute to the request */
                rv = est_add_attributes_helper(csr, nid, "bubba@notmyemail.com\0", 0);
                break;
            case NID_undef:
                printf("\nNID is undefined; skipping it\n");
                break;
            default:
                rv = est_add_attributes_helper(csr, nid, "", 0);
                break;
            }
            if (rv != EST_ERR_NONE) {
                printf("\n Error adding NID=%d", nid);
            }
        }
    }

    X509_REQ_print_fp(stderr, csr);

    rv = est_client_enroll_csr(ectx, csr, &pkcs7_len, priv_key);

    if (verbose) {
        printf("\nenrollment rv = %d (%s) with pkcs7 length = %d\n",
               rv, EST_ERR_NUM_TO_STR(rv), pkcs7_len);
    }
    if (rv == EST_ERR_NONE) {
        /*
         * client library has obtained the new client certificate.
         * now retrieve it from the library
         */
        new_client_cert = malloc(pkcs7_len);
        if (new_client_cert == NULL) {
            if (verbose) {
                printf("\nmalloc of destination buffer for enrollment cert failed\n");
            }
            return (EST_ERR_MALLOC);
        }

        rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
        if (verbose) {
            printf("\nenrollment copy rv = %d\n", rv);
        }
        if (rv == EST_ERR_NONE) {
            /*
             * Enrollment copy worked, dump the pkcs7 cert to stdout
             */
            if (verbose) {
                dumpbin(new_client_cert, pkcs7_len);
            }
        }

        snprintf(file_name, MAX_FILENAME_LEN, "%s/newcert", out_dir);
        save_cert(file_name, new_client_cert, pkcs7_len);
        free(new_client_cert);
    }

    return (rv);
}


static void retry_enroll_delay (int retry_delay, time_t retry_time)
{

    if (retry_delay != 0) {
        if (verbose) {
            printf("\nwaiting for retry period specified by server\n");
        }
        if (verbose) {
            printf("\nduration can be set on estserver with -m <retry-period> (min is 60 seconds)\n");
        }
        sleep(retry_delay);
    } else {
        /*
         * received a time_t value instead.  Calculate the amount of time to wait.
         * If it's in the past, then indicate that and proceed to the retry.
         * If it's within 2 minutes from now, then go ahead and wait.
         * If it's beyond 2 minutes from not, print out the date that was received and exit.
         * If both values returned (retry_delay and retry_time) are both zero, this is
         * incorrect.  Output an message and exit.
         */
        if (retry_time != 0) {

            time_t current_time;
            double secs_to_wait;

            time(&current_time);
            secs_to_wait = difftime(retry_time, current_time);

            if (secs_to_wait <= 0) {
                if (verbose) {
                    printf("\nSpecified delay time is in the past. Proceed on to retry \n");
                }
            } else if (secs_to_wait <= 60 * 2) {
                if (verbose) {
                    printf("\nSpecified delay time is 2 minutes or less. Wait the specified time before retry \n");
                }
                sleep(secs_to_wait);
            } else {
                if (verbose) {
                    printf("\nSpecified delay time is more than 2 minutes in the future.  printing out the delay time and terminating\n");
                }
                printf(" Delay time received from the server is: %s \n", ctime(&retry_time));
                return;
            }
        } else {
            if (verbose) {
                printf("\nERROR: both retry after values returned are zero\n");
            }
            return;
        }
    }
}


static void do_operation ()
{
    EST_CTX *ectx;
    unsigned char *pkcs7;
    int pkcs7_len = 0;
    int rv;
    char file_name[MAX_FILENAME_LEN];
    unsigned char *new_client_cert;
    int retry_delay = 0;
    time_t retry_time = 0;
    char *operation;

    ectx = est_client_init(cacerts, cacerts_len,
                           EST_CERT_FORMAT_PEM,
                           client_manual_cert_verify);
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        exit(1);
    }

    rv = est_client_set_read_timeout(ectx, read_timeout);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure read timeout from server.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }

    rv = est_client_set_auth(ectx, est_http_uid, est_http_pwd, client_cert, client_priv_key);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure client authentication.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }


    if (srp) {
        rv = est_client_enable_srp(ectx, 1024, est_srp_uid, est_srp_pwd);
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

    est_client_set_server(ectx, est_server, est_port);

    if (getcert) {
        operation = "Get CA Cert";

        rv = est_client_get_cacerts(ectx, &pkcs7_len);
        if (rv == EST_ERR_NONE) {
            if (verbose) {
                printf("\nGet CA Cert success\n");
            }

            /*
             * allocate a buffer to retrieve the CA certs
             * and get them copied in
             */
            pkcs7 = malloc(pkcs7_len);
            rv = est_client_copy_cacerts(ectx, pkcs7);

            /*
             * Dump the retrieved cert to stdout
             */
            if (verbose) {
                dumpbin(pkcs7, pkcs7_len);
            }

            /*
             * Generate the output file name, which contains the thread ID
             * and iteration number.
             */
            snprintf(file_name, MAX_FILENAME_LEN, "%s/cacert.pkcs7", out_dir);
            write_binary_file(file_name, pkcs7, pkcs7_len);

            free(pkcs7);

        }
    }

    if (enroll && getcsr) {
        operation = "Regular enrollment with server-defined attributes";

        rv = regular_enroll_attempt(ectx);

        if (rv == EST_ERR_CA_ENROLL_RETRY) {

            /*
             * go get the retry period
             */
            rv = est_client_copy_retry_after(ectx, &retry_delay, &retry_time);
            if (verbose) {
                printf("\nretry after period copy rv = %d "
                       "Retry-After delay seconds = %d "
                       "Retry-After delay time = %s\n",
                       rv, retry_delay, ctime(&retry_time) );
            }
            if (rv == EST_ERR_NONE) {
                retry_enroll_delay(retry_delay, retry_time);
            }
            /*
             * now that we're back, try to enroll again
             */
            rv = regular_enroll_attempt(ectx);

        }

    } else if (enroll && !getcsr) {
        operation = "Simple enrollment without server-defined attributes";

        rv = simple_enroll_attempt(ectx);

        if (rv == EST_ERR_CA_ENROLL_RETRY) {

            /*
             * go get the retry period
             */
            rv = est_client_copy_retry_after(ectx, &retry_delay, &retry_time);
            if (verbose) {
                printf("\nretry after period copy rv = %d "
                       "Retry-After delay seconds = %d "
                       "Retry-After delay time = %s\n",
                       rv, retry_delay, ctime(&retry_time) );
            }
            if (rv == EST_ERR_NONE) {
                retry_enroll_delay(retry_delay, retry_time);
            }

            /*
             * now that we're back, try to enroll again
             */
            rv = simple_enroll_attempt(ectx);
        }

    } else if (!enroll && getcsr) {
        operation = "Get CSR attribues";

        rv = regular_csr_attempt(ectx);

    }

    /* Split reenroll from enroll to allow both messages to be sent */
    if (reenroll) {
        operation = "Re-enrollment";

        rv = est_client_reenroll(ectx, client_cert, &pkcs7_len, client_priv_key);
        if (verbose) {
            printf("\nreenroll rv = %d (%s) with pkcs7 length = %d\n",
                   rv, EST_ERR_NUM_TO_STR(rv), pkcs7_len);
        }
        if (rv == EST_ERR_NONE) {
            /*
             * client library has obtained the new client certificate.
             * now retrieve it from the library
             */
            new_client_cert = malloc(pkcs7_len);
            if (new_client_cert == NULL) {
                if (verbose) {
                    printf("\nmalloc of destination buffer for reenroll cert failed\n");
                }
            }

            rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
            if (verbose) {
                printf("\nreenroll copy rv = %d\n", rv);
            }
            if (rv == EST_ERR_NONE) {
                /*
                 * Enrollment copy worked, dump the pkcs7 cert to stdout
                 */
                if (verbose) {
                    dumpbin(new_client_cert, pkcs7_len);
                }
            }

            /*
             * Generate the output file name, which contains the thread ID
             * and iteration number.
             */
            snprintf(file_name, MAX_FILENAME_LEN, "%s/newcert", out_dir);
            save_cert(file_name, new_client_cert, pkcs7_len);
            free(new_client_cert);
        }
    }

    if (rv != EST_ERR_NONE) {
        /*
         * something went wrong.
         */
        printf("\n%s failed with code %d (%s)\n",
               operation, rv, EST_ERR_NUM_TO_STR(rv));
    }

    est_destroy(ectx);

    ERR_clear_error();
    ERR_remove_thread_state(NULL);
}


static int string_password_cb(char *buf, int size, int wflag, void *data)
{
    strncpy(buf, priv_key_pwd, size);
    // printf("string_password_cb: wflag=%d, password=%.*s\n", wflag, size, buf);
    return(strnlen(buf, size));
}

int main (int argc, char **argv)
{
    signed char c;
    int set_fips_return = 0;
    char file_name[MAX_FILENAME_LEN];
    BIO *certin;
    static struct option long_options[] = {
        { "trustanchor",  1, 0,    0 },
        { "srp",          0, 0,    0 },
        { "srp-user",     1, 0,    0 },
        { "srp-password", 1, 0,    0 },
        { "auth-token",   1, 0,    0 },
        { "common-name",  1, 0,    0 },
        { "pem-output",   0, 0,    0 },
        { "keypass",      1, 0,    0 },
        { NULL,           0, NULL, 0 }
    };
    int option_index = 0;
    int trustanchor = 1; /* default to require a trust anchor */
    char *trustanchor_file = NULL;

    est_http_uid[0] = 0x0;
    est_http_pwd[0] = 0x0;

    /*
     * Set the default common name to put into the Subject field
     */
    strncpy(subj_cn, "127.0.0.1", MAX_CN);

    memset(csr_file, 0, 1);
    memset(priv_key_file, 0, 1);
    memset(client_key_file, 0, 1);
    memset(client_cert_file, 0, 1);
    memset(out_dir, 0, 1);

    while ((c = getopt_long(argc, argv, "?zfvagerx:y:k:s:p:o:c:w:u:h:", long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
#if 0
            printf("option %s", long_options[option_index].name);
            if (optarg) {
                printf(" with arg %s", optarg);
            }
            printf("\n");
#endif
            if (!strncmp(long_options[option_index].name, "trustanchor", strlen("trustanchor"))) {
                if (!strncmp(optarg, "no", strlen("no"))) {
                    trustanchor = 0;
                } else {
                    trustanchor_file = optarg;
                }
            }
            if (!strncmp(long_options[option_index].name, "srp", strlen("srp"))) {
                srp = 1;
            }
            if (!strncmp(long_options[option_index].name, "srp-user", strlen("srp-user"))) {
                strncpy(est_srp_uid, optarg, MAX_UID_LEN);
            }
            if (!strncmp(long_options[option_index].name, "srp-password", strlen("srp-password"))) {
                strncpy(est_srp_pwd, optarg, MAX_PWD_LEN);
            }
	    if (!strncmp(long_options[option_index].name,"auth-token", strlen("auth-token"))) {
		strncpy(est_auth_token, optarg, MAX_AUTH_TOKEN_LEN);
                token_auth_mode = 1;
	    }
            if (!strncmp(long_options[option_index].name, "common-name", strlen("common-name"))) {
                strncpy(subj_cn, optarg, MAX_CN);
            }
            else if (!strcmp(long_options[option_index].name, "keypass")) {
                if (!strcmp(optarg, "stdin")) {
		    priv_key_cb = PEM_def_callback;
		} else if (!strncmp(optarg, PRIV_KEY_PASS, strlen(PRIV_KEY_PASS))) {
		    strncpy(priv_key_pwd, optarg+strlen(PRIV_KEY_PASS), MAX_PWD_LEN);
		    priv_key_cb = string_password_cb;
		} else {
		    printf("Error: The --keypass option takes as argument either \'stdin\' or \'pass:\' immediately followed by a string.\n");
		    exit(1);
		}
            }
            if (!strncmp(long_options[option_index].name, "pem-output", strlen("pem-output"))) {
                pem_out = 1;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'z':
            force_pop = 1;
            break;
        case 'a':
            getcsr = 1;
            break;
        case 'g':
            getcert = 1;
            break;
        case 'e':
            enroll = 1;
            break;
        case 'r':
            reenroll = 1;
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
        case 'x':
            strncpy(priv_key_file, optarg, MAX_FILENAME_LEN);
            break;
        case 'y':
            strncpy(csr_file, optarg, MAX_FILENAME_LEN);
            break;
        case 'k':
            strncpy(client_key_file, optarg, MAX_FILENAME_LEN);
            break;
        case 'c':
            strncpy(client_cert_file, optarg, MAX_FILENAME_LEN);
            break;
        case 'o':
            strncpy(out_dir, optarg, MAX_FILENAME_LEN);
            break;
        case 'p':
            est_port = atoi(optarg);
            break;
        case 'f':
            /* Turn FIPS on if requested and exit if failure */
            set_fips_return = FIPS_mode_set(1);
            if (!set_fips_return) {
                printf("\nERROR setting FIPS MODE ON ...\n");
                ERR_load_crypto_strings();
                ERR_print_errors(BIO_new_fp(stderr, BIO_NOCLOSE));
                exit(1);
            } else {
                printf("\nRunning EST Sample Client with FIPS MODE = ON\n");
            };
            break;
        case 'w':
            read_timeout = atoi(optarg);
            if (read_timeout > EST_SSL_READ_TIMEOUT_MAX) {
                printf("\nMaxium number of seconds to wait is %d, ", EST_SSL_READ_TIMEOUT_MAX);
                printf("please use a lower value with the -w option\n");
                exit(1);
            }
            break;
        default:
            show_usage_and_exit();
            break;
        }
    }
    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc) {
            printf("%s ", argv[optind++]);
        }
        printf("\n");
    }
    argc -= optind;
    argv += optind;

    if (est_http_uid[0] && !est_http_pwd[0]) {
        printf("Error: The password for HTTP authentication must be specified when the HTTP user name is set.\n");
        exit(1);
    }

    if (csr_file[0] && getcsr) {
        printf("\nError: The -a option (CSR attributes) does not make sense with a pre-defined CSR\n");
        exit(1);
    }
    if (csr_file[0] && priv_key_file[0]) {
        printf("\nError: The -x option (private key for CSR) does not make sense with a pre-defined CSR\n");
        exit(1);
    }
    if (csr_file[0] && force_pop) {
        printf("\nError: The -z option (PoP) does not make sense with a pre-defined CSR\n");
        exit(1);
    }
    if (reenroll & csr_file[0]) {
        printf("\nError: The -y option (predefined CSRs) does not make sense for re-enrollment\n");
        exit(1);
    }

    if (verbose) {
        print_version();
        printf("\nUsing EST server %s:%d", est_server, est_port);
        if (csr_file        [0]) {
            printf("\nUsing CSR file %s", csr_file);
        }
        if (priv_key_file   [0]) {
            printf("\nUsing identity private key file %s", priv_key_file);
        }
        if (client_cert_file[0]) {
            printf("\nUsing identity client cert file %s", client_cert_file);
        }
        if (client_key_file [0]) {
            printf("\nUsing identity private key file %s", client_key_file);
        }
    }

    if (enroll && reenroll) {
        printf("\nThe enroll and reenroll operations can not be used together\n");
        exit(1);
    }

    if (!out_dir[0]) {
        printf("\nOutput directory must be specified with -o option\n");
        exit(1);
    }

    if (trustanchor) {
        if (!trustanchor_file) {
            /*
             * Get the trust anchor filename from the environment var
             */
            if (!getenv("EST_OPENSSL_CACERT")) {
                printf("\nCACERT file not set, set EST_OPENSSL_CACERT to resolve");
                exit(1);
            }
            trustanchor_file = getenv("EST_OPENSSL_CACERT");
        }

        /*
         * Read in the CA certificates
         */
        cacerts_len = read_binary_file(trustanchor_file, &cacerts);
        if (cacerts_len <= 0) {
            printf("\nCACERT file could not be read\n");
            exit(1);
        }
    }

    est_apps_startup(); // need to do this before decrypting private keys

#if DEBUG_OSSL_LEAKS
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif

    /*
     * Read in the current client certificate
     */
    if (client_cert_file[0]) {
        certin = BIO_new(BIO_s_file_internal());
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
        client_priv_key = ossl_read_private_key(client_key_file, priv_key_cb);
        if (client_priv_key == NULL) {
            printf("\nError while reading PEM encoded private key file %s\n", client_key_file);
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }

    if (verbose) {
        est_init_logger(EST_LOG_LVL_INFO, &test_logger_stdout);
        est_enable_backtrace(1);
    } else {
        est_init_logger(EST_LOG_LVL_ERR, &test_logger_stdout);
    }

    if (!priv_key_file[0] && enroll && !csr_file[0]) {
	printf("A private key is required for enrolling.  Creating a new RSA key pair since you didn't provide a key using the -x option.\n");
        /*
         * Create a private key that will be used for the
         * enroll operation.
         */
        char *new_pkey = ossl_generate_private_RSA_key(SRP_MINIMAL_N, priv_key_cb);
        if (new_pkey == NULL) {
            printf("\nError creating key pair\n");
            exit(1);
        }
        snprintf(file_name, MAX_FILENAME_LEN, "%s/newkey.pem", out_dir);
        write_binary_file(file_name, (unsigned char *)new_pkey, strlen(new_pkey));
        free(new_pkey);

        /*
         * prepare to read it back in to an EVP_PKEY struct
         */
        strncpy(priv_key_file, file_name, MAX_FILENAME_LEN);

    }

    if (enroll && !csr_file[0]) {
	/* Read in the private key file */
	priv_key = ossl_read_private_key(priv_key_file, priv_key_cb);
        if (priv_key == NULL) {
            printf("\nError reading CSR private key from file %s\n", priv_key_file);
            exit(1);
        }
    }


    do_operation();

    if (priv_key) {
        EVP_PKEY_free(priv_key);
    }
    if (client_priv_key) {
        EVP_PKEY_free(client_priv_key);
    }
    if (client_cert) {
        X509_free(client_cert);
    }

    free(cacerts);
    if (c_cert_len) {
        free(c_cert);
    }
    if (c_key_len) {
        free(c_key);
    }

    est_apps_shutdown();

#if DEBUG_OSSL_LEAKS
    BIO *bio_err;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
#endif

    printf("\n");
    return 0;
}

