/*------------------------------------------------------------------
 * estserver.c - Example application that utilizes libest.so for
 *               EST server operations.  libest does not manage
 *               sockets and pthreads.  This responsibility is
 *               placed on the application.  This module shows
 *               a fairly trivial example of how to set up a
 *               listening socket and handle EST requests.
 *
 * November, 2012
 *
 * Copyright (c) 2012-2013 by cisco Systems, Inc.
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-28 minor bug corrections w.r.t long options and stability improvements
// 2015-08-19 added missing cleanup for search tree
// 2015-08-07 re-added -e option; fixed potential NULL free()
// 2015-08-07 completed use of DISABLE_PTHREADS; improved diagnostic output
// 2014-06-26 improved -e option; enhanced code for -m and -o options
// 2014-04-23 added -e option for enrollment by an external CA
// 2014-04-23 added -o option for not requring HTTP authentication
// 2014-04-23 improved usage hints; corrected and extended logging

#include <est.h>
#include <stdio.h>
#include <sys/stat.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
#ifndef DISABLE_TSEARCH
#include <search.h>
#endif
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include "../util/ossl_srv.h"
#include "../util/utils.h"
#include "../util/simple_server.h"

#define MAX_FILENAME_LEN 255
#define TEMP_CSR_FILE  "csr.p10"
#define TEMP_CERT_FILE "cert.cer"

/*
 * The OpenSSL CA needs this BIO to send errors too
 */
BIO *bio_err = NULL;

/*
 * These are the command line options with defaults provided below
 */
static int verbose = 0;
static int write_csr = 0;
static int crl = 0;
static int pop = 0;
static int v6 = 0;
static int srp = 0;
static int enforce_csr = 0;
#ifndef DISABLE_TSEARCH
static int simulate_manual_enroll = 0;
#endif
static int external_enroll = 0;
static int tcp_port = 8085;
static int http_digest_auth = 0;
static int http_basic_auth = 0;
static int http_token_auth = 0;
static int http_auth_disable = 0;
static int disable_forced_http_auth = 0;
static int set_fips_return = 0;
static unsigned long set_fips_error = 0;
static int test_app_data = 0xDEADBEEF;  // TODO: remove

char certfile[EST_MAX_FILE_LEN];
char keyfile[EST_MAX_FILE_LEN];
char realm[MAX_REALM];
unsigned char *cacerts_raw = NULL;
int cacerts_len = 0;
unsigned char *trustcerts = NULL;
int trustcerts_len = 0;

SRP_VBASE *srp_db = NULL;

static char valid_token_value[MAX_AUTH_TOKEN_LEN+1];

/*
 * This is the single EST context we need for operating
 * the EST server.  Only a single context is required.
 */
EST_CTX *ectx;


/*
 * We hard-code the DH parameters here.  THIS SHOULD NOT
 * be done in a real application.  The DH parameters need
 * to be generated at the time of product installation so
 * that every instance of the product in the field has
 * unique parameters.  Otherwise DH key exchange would be
 * vulnerable to attack.
 * See the OpenSSL documentation on generating DH parameters
 * for more information.
 */
static DH *get_dh1024dsa()
{
    static unsigned char dh1024_p[]={
	0xC8,0x00,0xF7,0x08,0x07,0x89,0x4D,0x90,0x53,0xF3,0xD5,0x00,
	0x21,0x1B,0xF7,0x31,0xA6,0xA2,0xDA,0x23,0x9A,0xC7,0x87,0x19,
	0x3B,0x47,0xB6,0x8C,0x04,0x6F,0xFF,0xC6,0x9B,0xB8,0x65,0xD2,
	0xC2,0x5F,0x31,0x83,0x4A,0xA7,0x5F,0x2F,0x88,0x38,0xB6,0x55,
	0xCF,0xD9,0x87,0x6D,0x6F,0x9F,0xDA,0xAC,0xA6,0x48,0xAF,0xFC,
	0x33,0x84,0x37,0x5B,0x82,0x4A,0x31,0x5D,0xE7,0xBD,0x52,0x97,
	0xA1,0x77,0xBF,0x10,0x9E,0x37,0xEA,0x64,0xFA,0xCA,0x28,0x8D,
	0x9D,0x3B,0xD2,0x6E,0x09,0x5C,0x68,0xC7,0x45,0x90,0xFD,0xBB,
	0x70,0xC9,0x3A,0xBB,0xDF,0xD4,0x21,0x0F,0xC4,0x6A,0x3C,0xF6,
	0x61,0xCF,0x3F,0xD6,0x13,0xF1,0x5F,0xBC,0xCF,0xBC,0x26,0x9E,
	0xBC,0x0B,0xBD,0xAB,0x5D,0xC9,0x54,0x39,
	};
    static unsigned char dh1024_g[]={
	0x3B,0x40,0x86,0xE7,0xF3,0x6C,0xDE,0x67,0x1C,0xCC,0x80,0x05,
	0x5A,0xDF,0xFE,0xBD,0x20,0x27,0x74,0x6C,0x24,0xC9,0x03,0xF3,
	0xE1,0x8D,0xC3,0x7D,0x98,0x27,0x40,0x08,0xB8,0x8C,0x6A,0xE9,
	0xBB,0x1A,0x3A,0xD6,0x86,0x83,0x5E,0x72,0x41,0xCE,0x85,0x3C,
	0xD2,0xB3,0xFC,0x13,0xCE,0x37,0x81,0x9E,0x4C,0x1C,0x7B,0x65,
	0xD3,0xE6,0xA6,0x00,0xF5,0x5A,0x95,0x43,0x5E,0x81,0xCF,0x60,
	0xA2,0x23,0xFC,0x36,0xA7,0x5D,0x7A,0x4C,0x06,0x91,0x6E,0xF6,
	0x57,0xEE,0x36,0xCB,0x06,0xEA,0xF5,0x3D,0x95,0x49,0xCB,0xA7,
	0xDD,0x81,0xDF,0x80,0x09,0x4A,0x97,0x4D,0xA8,0x22,0x72,0xA1,
	0x7F,0xC4,0x70,0x56,0x70,0xE8,0x20,0x10,0x18,0x8F,0x2E,0x60,
	0x07,0xE7,0x68,0x1A,0x82,0x5D,0x32,0xA2,
	};
    DH *dh;

    if ((dh=DH_new()) == NULL) {
	return(NULL);
    }
    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) { 
	DH_free(dh); return(NULL); 
    }
    dh->length = 160;
    return(dh);
}

static void print_version (FILE *fp)
{
    // fprintf(fp, "Using %s\n", SSLeay_version(SSLEAY_VERSION));
}

static void show_usage_and_exit (void)
{
    fprintf(stderr, "\nAvailable EST server options\n"
            "  -v           Verbose operation\n"
            "  -c <file>    PEM file to use for server cert\n"
            "  -k <file>    PEM file to use for server key\n"
            "  -r <value>   HTTP realm to present to clients\n"
            "  -l           Enable CRL checks\n"
            "  -t           Enable check for binding client PoP to the TLS UID\n"
#ifndef DISABLE_TSEARCH
            "  -m <seconds> Simulate manual CA enrollment after the given number of seconds\n"
            "  -e <seconds> "
#else
            "  -e           "
#endif
                           "External CA enrollment: delete and await new '" TEMP_CERT_FILE "' file for manual CA enrollment, implies -w\n"
#ifndef DISABLE_TSEARCH
            "               The client shall wait for the given number of seconds before re-trying the request\n"
#else
            "               The server postpones its response until the cert file appears\n"
#endif
            "  -n           Disable HTTP authentication (TLS client auth required)\n"
            "  -o           Do not require HTTP authentication when TLS client auth succeeds\n"
            "  -h           Use HTTP Digest auth instead of Basic auth\n"
            "  -b           Use HTTP Basic auth.  Causes explicit call to set Basic auth\n"
            "  -p <num>     TCP port number to listen on; default: 8085\n"
#ifndef DISABLE_PTHREADS
	    "  -d <seconds> Sleep timer to auto-shut the server\n"
#endif
	    "  -f           Runs EST Server in FIPS MODE = ON\n"
	    "  -6           Enable IPv6\n"
	    "  -w           Dump the CSR to '" TEMP_CSR_FILE "' allowing for manual attribute capture and external CA enrollment on server\n"
	    "  -?           Print this help message and exit\n"
	    "  --srp <file> Enable TLS-SRP authentication of client using the specified SRP parameters file\n"
	    "  --enforce-csr  Enable CSR attributes enforcement. The client must provide all the attributes in the CSR.\n"
	    "  --token <value> Use HTTP Bearer Token auth.\n"
            "\n");
    exit(255);
}


#ifndef DISABLE_TSEARCH
/*
 * The functions in this section implement a simple lookup table
 * to correlate incoming cert requests after a retry operation.
 * We use this for (simulation of) manual-enrollment mode on the CA.
 */
typedef struct {
    unsigned char  *data;  //this will hold the pub key from the cert request
    int		    length;
} LOOKUP_ENTRY;
LOOKUP_ENTRY *lookup_root = NULL;

static void free_lookup (void *node)
{
    LOOKUP_ENTRY *n = (LOOKUP_ENTRY *)node;
    if (n->data) free(n->data);
    free(n);
}

/*
 * Used to compare two entries in the lookup table to correlate
 * incoming cert reqeuests in the case of a retry operation.
 * We use the public key from the cert as the index into the 
 * lookup table.
 */
int compare (const void *pa, const void *pb)
{
    LOOKUP_ENTRY *a = (LOOKUP_ENTRY *)pa;
    LOOKUP_ENTRY *b = (LOOKUP_ENTRY *)pb;
    if (a->length > b->length) return 1;
    if (a->length < b->length) return -1;
    return (memcmp(a->data, b->data, a->length));
}

/*
 * We use a simple lookup table for (simulation of) manual enrollment
 * of certs by the CA.  This is the case where an operator
 * needs to review each cert request and approve it (e.g.
 * auto-enrollment is off).  
 *
 * Return 1 if a match was found, and optionally delete the entry.
 * Return 0 if no match was found, in which
 * case we'll add the public key from the cert request into
 * our lookup table so it can be correlated later.
 */
int lookup_pkcs10_request(unsigned char *pkcs10, int p10_len, int delete_on_match)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    BIO *b64;
    EVP_PKEY *pkey;
    BUF_MEM *bptr;
    int rv;
    LOOKUP_ENTRY *l;
    LOOKUP_ENTRY *n;

    /*
     * Decode the request into an X509_REQ structure
     */
    b64 = BIO_new(BIO_f_base64());
    in = BIO_new_mem_buf(pkcs10, p10_len);
    in = BIO_push(b64, in);
    if ((req = d2i_X509_REQ_bio(in, NULL)) == NULL) {
	/* Unable to parse the request, just let this fall through
	 * and the enrollment will fail */
	rv = 1;
	goto DONE;
    }

    /*
     * Get the public key from the request, this will be our index into
     * the lookup table.  Frankly, I'm not sure how a real CA
     * would do this lookup.  But this should be good enough for
     * testing the retry-after logic.
     */
    pkey = X509_PUBKEY_get(req->req_info->pubkey);
    if (!pkey) {
	rv = 1;
	goto DONE;
    }
    out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(out, pkey);
    BIO_get_mem_ptr(out, &bptr);

    /*
     * see if we can find a match for this public key
     */
    n = (LOOKUP_ENTRY *)malloc(sizeof(LOOKUP_ENTRY));
    n->data = (unsigned char *)malloc(bptr->length);
    n->length = bptr->length;
    memcpy(n->data, bptr->data, n->length);
    l = (LOOKUP_ENTRY *)tfind(n, (void **)&lookup_root, compare);
    if (l) {
	/* We have a match */
	rv = 1;	
	if (verbose && !delete_on_match) {
	    printf("\nFound key in lookup table:");
	    dumpbin((unsigned char*)n->data, n->length);
	}
	if (delete_on_match) {
	    if (verbose) {
		printf("\nRemoving key from lookup table:");
		dumpbin((unsigned char*)n->data, n->length);
	    }
	    tdelete(n, (void **)&lookup_root, compare);
	    free(n->data);
	    free(n);
	}
    } else {
	/* Not a match, add it to the list and return */
	l = (LOOKUP_ENTRY *)tsearch(n, (void **)&lookup_root, compare);
	rv = 0;
	if (verbose) {
	    printf("\nAdding key to lookup table:");
	    dumpbin((unsigned char*)n->data, n->length);
	}
    }
DONE:
    if (out) BIO_free_all(out);
    if (in) BIO_free_all(in);
    if (req) X509_REQ_free(req);
    if (pkey) EVP_PKEY_free(pkey);

    return (rv);
}
#endif

/*
 * Trivial utility function to extract the string
 * value of the subject name from a cert.
 */
static void extract_sub_name(X509 *cert, char *name, unsigned int len)
{
    X509_NAME *subject_nm;
    BIO *out;
    BUF_MEM *bm;

    subject_nm = X509_get_subject_name(cert);

    out = BIO_new(BIO_s_mem());

    X509_NAME_print_ex(out, subject_nm, 0, XN_FLAG_SEP_SPLUS_SPC);
    BIO_get_mem_ptr(out, &bm);
    strncpy(name, bm->data, len);
    if (bm->length < len) {
        name[bm->length]=0;
    } else {
        name[len]=0;
    }

    BIO_free(out);
}

int file_exists(char *fileName)
{
   struct stat buf;
   return (0 == stat(fileName, &buf));
}

void wait_for_file(char *file) {
	printf("\nWaiting for file '%s' to appear..", file);
	fflush(stdout);
	while(!file_exists(file)) {
	    sleep(3);
	    printf(".");
	    fflush(stdout);
	}
	printf(" got it!\n");
	fflush(stdout);
}

/*
 * Dump out pkcs10 to a file, this will contain a list of the OIDs in the CSR.
*/
void write_csr_file(unsigned char * pkcs10, int p10_len) {
    char *filename = TEMP_CSR_FILE;
    FILE *fp = fopen(filename, "w");
    if (!fp) {
	fprintf(stderr, "Unable to open %s for writing\n;", filename);
	return;
    }
    if (fprintf(fp, "-----BEGIN CERTIFICATE REQUEST-----\n"
		"%.*s-----END CERTIFICATE REQUEST-----\n", p10_len, pkcs10) < 0) {
	fprintf(stderr, "Error writing file %s\n", filename);
    }
    fclose(fp);
}

/****************************************************************************************
 * The following functions are the callbacks used by libest to bind
 * the EST stack to the HTTP/SSL layer and the CA server.
 ***************************************************************************************/

#ifndef DISABLE_PTHREADS
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
#endif
#define MAX_CERT_LEN 8192
/*
 * Callback function used by EST stack to process a PKCS10
 * enrollment request with the CA.  The parameters are:
 *
 *   pkcs10	Contains the CSR that should be sent to
 *              the CA to be signed.
 *   pkcs10_len Length of the CSR char array
 *   pcks7	Should contain the signed PKCS7 certificate
 *              from the CA server.  You'll need allocate
 *              space and copy the cert into this char array.
 *   pkcs7_len  Length of the pkcs7 char array, you will set this.
 *   user_id    If HTTP authentication was used to identify the
 *              EST client, this will contain the user ID supplied
 *              by the client.
 *   peer_cert  If the EST client presented a certificate to identify
 *              itself during the TLS handshake, this parameter will
 *              contain that certificate.
 */
EST_ERROR process_pkcs10_enrollment (unsigned char * pkcs10, int p10_len,
                               unsigned char **pkcs7, int *pkcs7_len,
			       char *user_id, X509 *peer_cert,
			       void *app_data)
{
    BIO *result = NULL;
    char *buf;
    char sn[64];

    if (verbose) {
	/*
	 * Informational only
	 */
	if (user_id) {
	    printf("%s - User ID is %s\n", __FUNCTION__, user_id);
	}
	if (peer_cert) {
	    memset(sn, 0, 64);
	    extract_sub_name(peer_cert, sn, 64);
	    printf("%s - Peer cert CN is %s\n", __FUNCTION__, sn);
	}
	if (app_data) {
	    printf("ex_data value is %x\n", *((unsigned int *)app_data));
	}
    }

#ifndef DISABLE_TSEARCH
    /*
     * If we're simulating manual certificate enrollment, 
     * the CA will not automatically sign the cert request.
     * We'll attempt to lookup in our local table if this
     * cert has already been sent to us, if not, add it
     * to the table and send the 'retry' message back to the
     * client.  But if this cert request has been seen in the
     * past, then we'll continue with the enrollment.
     * To summarize, we're simulating manual enrollment by
     * forcing the client to request twice, and we'll automatically
     * enroll on the second request.
     */
    if (simulate_manual_enroll) {
	if (lookup_pkcs10_request(pkcs10, p10_len, 1)) {
	    /*
	     * We've seen this cert request in the past.  
	     * Remove it from the lookup table and allow
	     * the enrollment to continue.  
	     * Fall-thru to enrollment logic below
	     */
	} else {
	    /* 
	     * Couldn't find this request, it's the first time
	     * we've seen it.  Therefore, send the retry
	     * response.
	     */
	    return (EST_ERR_CA_ENROLL_RETRY);
	}

    }
#endif

    if (external_enroll) {
	/*
	 * If we're doing manual certificate enrollment, we write out the CSR to a temp file
	 * and wait for the CA to sign the cert request and put the cert in another temp file.
	 */
#ifndef DISABLE_TSEARCH
	if (lookup_pkcs10_request(pkcs10, p10_len, 0)) {
	    /*
	     * We've seen this cert request in the past.  
	     * Check if the cert file has become available. 
	     * If so, remove the request from the lookup table,
	     * read the cert file and the enrollment to continue. 
	     * Otherwise, keep waiting, sending the retry response.
	     */
	    if (file_exists(TEMP_CERT_FILE)) {
		remove(TEMP_CSR_FILE);
		lookup_pkcs10_request(pkcs10, p10_len, 1); // delete entry
		result = read_cert_pkcs7(TEMP_CERT_FILE);
	    }
	    else {
		return (EST_ERR_CA_ENROLL_RETRY);
	    }
	} else {
	    /*
	     * Couldn't find this request, so it's the first time
	     * we've seen it. Therefore, prepare to wait for cert
	     * file to (re-)appear and send the retry response.
	     */
	    remove(TEMP_CERT_FILE);
	    write_csr_file(pkcs10, p10_len);
	    return (EST_ERR_CA_ENROLL_RETRY);
	}
#else
	remove(TEMP_CERT_FILE);
	write_csr_file(pkcs10, p10_len);
	wait_for_file(TEMP_CERT_FILE);
	remove(TEMP_CSR_FILE);
	result = read_cert_pkcs7(TEMP_CERT_FILE);
#endif
    } else {
#ifndef DISABLE_PTHREADS
	int rc = pthread_mutex_lock(&m);
	if (rc) {
	    printf("\nmutex lock failed rc=%d", rc);
	    exit(1);
	}
#endif

	if (write_csr) {
	    /*
	     * Dump out pkcs10 to a file, this will contain a list of the OIDs in the CSR.
	     */
	    write_csr_file(pkcs10, p10_len);
	}
	result = ossl_simple_enroll(pkcs10, p10_len, NULL);

#ifndef DISABLE_PTHREADS
	rc = pthread_mutex_unlock(&m);
	if (rc) {
	    printf("\nmutex unlock failed rc=%d", rc);
	    exit(1);
	}
#endif
    }
    if (result == NULL) {
	fprintf(stderr, "ossl_simple_enroll was unsuccessful\n");
	return EST_ERR_CA_ENROLL_FAIL;
    }

    /*
     * The result is a BIO containing the pkcs7 signed certificate
     * Need to convert it to char and copy the results so we can
     * free the BIO.
     */
    *pkcs7_len = BIO_get_mem_data(result, (char**)&buf);
    if (*pkcs7_len > 0 && *pkcs7_len < MAX_CERT_LEN) {
        *pkcs7 = (unsigned char *)malloc(*pkcs7_len);
        memcpy(*pkcs7, buf, *pkcs7_len);
    }

    BIO_free_all(result);
    return EST_ERR_NONE;
}

//The following is a default CSR attributes response that also
//contains challengePassword
#define TEST_CSR "MCYGBysGAQEBARYGCSqGSIb3DQEJAQYFK4EEACIGCWCGSAFlAwQCAg=="
unsigned char * process_csrattrs_request (int *csr_len, void *app_data)
{
    unsigned char *csr_data;
    char *t = NULL;
    int t_len;

    t = getenv("EST_CSR_ATTR");
    if (t) {
        t_len = strlen(t);
        csr_data = (unsigned char *)malloc(t_len + 1);
        strncpy((char *)csr_data, t, t_len);
	*csr_len = t_len;
    } else {
        *csr_len = sizeof(TEST_CSR);
        csr_data = (unsigned char *)malloc(*csr_len + 1);
        strcpy((char *)csr_data, TEST_CSR);
    }
    return (csr_data);
}

static char digest_user[3][34] =
    {
	"estuser", 
	"estrealm", 
	"36807fa200741bb0e8fb04fcf08e2de6" //This is the SHA1 pre-calculated value
    };
/*
 * This callback is invoked by libest when performing
 * HTTP authentication of the EST client.  libest will
 * parse the auth credentials from the HTTP header.  We
 * must validate the user ourselves since libest does
 * not maintain a user database.  This allows us to hook
 * into a Radius server, or some other external user
 * database.
 *
 * For this example code, we simply have a local hard-coded
 * user database.
 *
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
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

/*
 * This routine destroys the EST context and frees 
 * up other resources to prevent a memory leak.
 */
void cleanup (void)
{
    est_server_stop(ectx);
    est_destroy(ectx);

#ifndef DISABLE_TSEARCH
    /*
     * Free the lookup table used to simulate
     * manual cert approval
     */
    if (lookup_root) {
        tdestroy((void *)lookup_root, free_lookup);
	lookup_root = NULL;
    }
#endif

    if (srp_db) {
	SRP_VBASE_free(srp_db);
    }

#ifndef DISABLE_PTHREADS
    /*
     * Tear down the mutexes used by OpenSSL
     */
    CRYPTO_set_locking_callback(NULL);
    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    free(ssl_mutexes);
    pthread_mutex_destroy(&m);
#endif

    BIO_free(bio_err);
    if (cacerts_raw)
	free(cacerts_raw);
    if (trustcerts)
	free(trustcerts);
    est_apps_shutdown();
}


/*
 * This is the main entry point into the example EST server.
 * This routine parses the command line options, reads in the
 * cert chains, creates an EST context, initializes the HTTP
 * layer (mongoose), and starts a simple TCP server to accept
 * incoming EST requests.
 */
int main (int argc, char **argv)
{
    char c;
    X509 *x;
    EVP_PKEY *priv_key;
    BIO *certin, *keyin;
    DH *dh;
    EST_ERROR rv;
    int sleep_delay = 0;
    int retry_period = 300;
    char vfile[255];
    int option_index = 0;
    static struct option long_options[] = {
        {"srp", 1, NULL, 0},
        {"enforce-csr", 0, NULL, 0},
        {"token", 1, NULL, 0},
        {"help", 0, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    
    while ((c = getopt_long(argc, argv, "?fhbwnovr:c:k:m:e"
#ifndef DISABLE_TSEARCH
":"
#else
""
#endif
                                        "p:d:lt6", long_options, &option_index)) != -1) {
        switch (c) {
	case 0:
#if 0
            printf("option %s", long_options[option_index].name);
            if (optarg) {
                printf (" with arg %s", optarg);
	    }
            printf ("\n");
#endif
	    // the following uses of strncmp() MUST use strlen(...)+1, otherwise only prefix is compared.
            if (!strncmp(long_options[option_index].name,"srp", strlen("srp")+1)) {
		srp = 1;
                strncpy(vfile, optarg, 255);
            }
            else if (!strncmp(long_options[option_index].name,"enforce-csr", strlen("enforce-csr")+1)) {
		enforce_csr = 1;
            }
            else if (!strncmp(long_options[option_index].name,"token", strlen("token")+1)) {
		http_token_auth = 1;
                memset(valid_token_value, 0, MAX_AUTH_TOKEN_LEN+1); 
                strncpy(&(valid_token_value[0]), optarg, MAX_AUTH_TOKEN_LEN);
            }
	    else show_usage_and_exit();
	    break;
#ifndef DISABLE_TSEARCH
        case 'm':
            simulate_manual_enroll = 1;
            retry_period = atoi(optarg);
            break;
#endif
        case 'e':
            external_enroll = 1;
#ifndef DISABLE_TSEARCH
	    retry_period = atoi(optarg);
#endif
            break;
        case 'h':
            http_digest_auth = 1;
            break;
        case 'b':
            http_basic_auth = 1;
            break;
        case 'w':
            write_csr = 1;
            break;
        case 'n':
            http_auth_disable = 1;
            break;
        case 'o':
            disable_forced_http_auth = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'l':
            crl = 1;
            break;
        case 't':
            pop = 1;
            break;
        case '6':
            v6 = 1;
            break;
#ifndef DISABLE_PTHREADS
        case 'd':
	    sleep_delay = atoi(optarg);
            break;
#endif
        case 'p':
	    tcp_port = atoi(optarg);
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
	case 'f':
	   /* turn FIPS on if user requested it
	    * and exit if failure.
	   */
	    set_fips_return = FIPS_mode_set(1);
	    if (set_fips_return != 1) { 
	      set_fips_error = ERR_get_error();
	      printf("\nERROR WHILE SETTING FIPS MODE ON exiting ....\n"); 
	      exit(1);
	    } else {
	      printf("Running EST Sample Server with FIPS MODE = ON !\n");
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
    }

    if (getenv("EST_CSR_ATTR")) {
	printf("Using CSR Attributes: %s\n", getenv("EST_CSR_ATTR"));
    }

    if (!getenv("EST_CACERTS_RESP")) {
        printf("\nEST_CACERTS_RESP file not set, set this env variable to resolve\n");
        exit(1);
    }
    if (!getenv("EST_TRUSTED_CERTS")) {
        printf("\nEST_TRUSTED_CERTS file not set, set this env variable to resolve\n");
        exit(1);
    }

    /*
     * Read in the CA certificates
     */
    cacerts_len = read_binary_file(getenv("EST_CACERTS_RESP"), &cacerts_raw);
    if (cacerts_len <= 0) {
        printf("\nEST_CACERTS_RESP file could not be read\n");
        exit(1);
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
    } else {
	est_init_logger(EST_LOG_LVL_ERR, NULL);
    }
    ectx = est_server_init(trustcerts, trustcerts_len,
	    cacerts_raw, cacerts_len,  
	    EST_CERT_FORMAT_PEM, realm, x, priv_key);
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        exit(1);
    }
    est_set_ex_data(ectx, &test_app_data);

    if (enforce_csr) {
	est_server_enforce_csrattr(ectx);
    }

    /*
     * Change the retry-after period.  This is not
     * necessary, it's only shown here as an example.
     */
    if (verbose) printf("Retry period being set to: %d \n", retry_period);
    est_server_set_retry_period(ectx, retry_period);

    if (crl) {
	est_enable_crl(ectx);
    }
    if (!pop) {
	if (verbose) printf("Disabling PoP check\n");
	est_server_disable_pop(ectx);
    }

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

    if (est_set_ca_enroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("\nUnable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        exit(1);
    }
    /*
     * We use the same handler for re-enrollment.  Our little toy
     * CA doesn't do anything special for re-enrollment.  A real 
     * CA would need to implement the requirements in section
     * 4.2 of the EST draft.
     */
    if (est_set_ca_reenroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("\nUnable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        exit(1);
    }
    if (est_set_csr_cb(ectx, &process_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        exit(1);
    }
    if (http_auth_disable) {
        if (verbose) {
	    printf("\nDisabling HTTP authentication\n");
	}
    } else {
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
	rv = est_server_set_auth_mode(ectx, AUTH_DIGEST);
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
    
    if (http_token_auth) {
	rv = est_server_set_auth_mode(ectx, AUTH_TOKEN);
	if (rv != EST_ERR_NONE) {
            printf("\nUnable to enable HTTP token authentication.  Aborting!!!\n");
            exit(1);
	}
    }

    /*
     * Set DH parameters for TLS
     */
    dh = get_dh1024dsa();
    if (dh) {
	est_server_set_dh_parms(ectx, dh);
    }
    DH_free(dh);

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

    printf("Launching EST server...\n");

    rv = est_server_start(ectx);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to init mg (rv=%d)\n", rv);
        exit(1);
    }

    /*
     * Start the simple server, which opens a TCP
     * socket, waits for incoming connections, and
     * invokes the EST handler for each connection.
     */
    start_simple_server(ectx, tcp_port, sleep_delay, v6);

    cleanup();
    EVP_PKEY_free(priv_key);
    X509_free(x);
    return 0;
}

