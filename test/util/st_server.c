/*------------------------------------------------------------------
 * st_server.c - Simple single-threaded EST server that can be
 *               used for testing.  This server can only handle
 *               a single EST request at any given time.  Attempting
 *               to send multiple requests to it will result in
 *               undetermined results.
 *
 * August, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-14 sharing master_thread() with unit tests, more efficient synchronization
// 2015-08-14 using start_single_server() and stop_single_server() of simple_server.c

#include <est.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#define __USE_GNU
#include <search.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "../../example/util/ossl_srv.h"
#include "../../example/util/simple_server.h"
#include "test_utils.h"
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#endif

BIO *bio_err = NULL;
static int manual_enroll = 0;
void *server_data = NULL;
unsigned char *cacerts_raw = NULL;
int cacerts_len = 0;
EST_CTX *ectx;
SRP_VBASE *srp_db = NULL;
unsigned char *trustcerts = NULL;
int trustcerts_len = 0;
static char conf_file[255];
static char *csr_attr_value = NULL;

static char valid_token_value[MAX_AUTH_TOKEN_LEN+1];

extern void dumpbin(char *buf, size_t len);

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


/*
 * The functions in this section implement a simple lookup table
 * to correlate incoming cert requests after a retry operation.
 * We use this to simulate the manual-enrollment mode on the CA.
 *
 * FIXME: we need a cleanup routine to clear the tree when this
 *        server shuts down.  Currently any remaining entries
 *        in the table will not be released, resulting in a memory
 *        leak in the valgrind output.
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
static int compare (const void *pa, const void *pb)
{
    LOOKUP_ENTRY *a = (LOOKUP_ENTRY *)pa;
    LOOKUP_ENTRY *b = (LOOKUP_ENTRY *)pb;
    if (a->length > b->length) return 1;
    if (a->length < b->length) return -1;
    return (memcmp(a->data, b->data, a->length));
}

/*
 * We use a simple lookup table to simulate manual enrollment
 * of certs by the CA.  This is the case where an operator
 * needs to review each cert request and approve it (e.g.
 * auto-enrollment is off).  
 *
 * Return 1 if a match was found and the enrollment operation
 * should proceed.  Return 0 if no match was found, in which
 * case we'll add the public key from the cert request into
 * our lookup table so it can be correlated later.
 */
static int lookup_pkcs10_request(unsigned char *pkcs10, int p10_len)
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
	/* We have a match, allow the enrollment */
	rv = 1;	
	tdelete(n, (void **)&lookup_root, compare);
	printf("Removing key from lookup table:\n");
	dumpbin((char*)n->data, n->length);
	free(n->data);
	free(n);
    } else {
	/* Not a match, add it to the list and return */
	l = (LOOKUP_ENTRY *)tsearch(n, (void **)&lookup_root, compare);
	rv = 0;
	printf("Adding key to lookup table:\n");
	dumpbin((char*)n->data, n->length);
    }
DONE:
    if (out) BIO_free_all(out);
    if (in) BIO_free_all(in);
    if (req) X509_REQ_free(req);
    if (pkey) EVP_PKEY_free(pkey);

    return (rv);
}


/****************************************************************************************
 * The following funcitons are the callbacks used by libest.a to bind
 * the EST stack to the HTTP/SSL layer and the CA server.
 ***************************************************************************************/
#define MAX_CERT_LEN 8192
/*
 * Callback function used by EST stack to process a PKCS10
 * enrollment request with the CA.
 */
static EST_ERROR process_pkcs10_enrollment (unsigned char * pkcs10, int p10_len, 
                               unsigned char **cert, int *cert_len,
			       char *uid, X509 *peercert, void *app_data)
{
    BIO *result = NULL;
    char *buf;

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
    if (manual_enroll) {
	if (lookup_pkcs10_request(pkcs10, p10_len)) {
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

    result = ossl_simple_enroll(pkcs10, p10_len, conf_file);

    /*
     * The result is a BIO containing the pkcs7 signed certificate
     * Need to convert it to char and copy the results so we can
     * free the BIO.
     */
    *cert_len = BIO_get_mem_data(result, (char**)&buf);
    if (*cert_len > 0 && *cert_len < MAX_CERT_LEN) {
        *cert = (unsigned char *)malloc(*cert_len);
        memcpy(*cert, buf, *cert_len);
    }

    BIO_free_all(result);
    return EST_ERR_NONE;
}

//This CSR attributes contains the challengePassword OID and others
#define TEST_CSR "MCYGBysGAQEBARYGCSqGSIb3DQEJBwYFK4EEACIGCWCGSAFlAwQCAg==\0"

static unsigned char * process_csrattrs_request (int *csr_len, void *app_data)
{
    unsigned char *csr_data;

    if (csr_attr_value) {
	*csr_len = strlen(csr_attr_value);
	csr_data = (unsigned char *)malloc(*csr_len + 1);
	strncpy((char *)csr_data, csr_attr_value, *csr_len+1);
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
	"36807fa200741bb0e8fb04fcf08e2de6" //This is the HA1 precaculated value
    };

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int process_http_auth (EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah, 
	                      X509 *peer_cert, void *app_data)
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
	free(digest);
      }
      break;
    case AUTH_TOKEN:
	/*
         * The bearer token has just been passed up from the EST Server
         * library.  Assuming it's an OAuth 2.0 based access token, it would
         * now be sent along to the OAuth Authorization Server.  The
         * Authorization Server would return either a success or failure
         * response.
	 */
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
static int ssl_srp_server_param_cb (SSL *s, int *ad, void *arg) {

    char *login = SSL_get_srp_username(s);
    SRP_user_pwd *user;

    if (!login) return (-1);

    printf("SRP username = %s\n", login);

    user = SRP_VBASE_get_by_user(srp_db, login); 

    if (user == NULL) {
	printf("User %s doesn't exist in SRP database\n", login);
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

static void cleanup() 
{
    est_server_stop(ectx);
    est_destroy(ectx);
    BIO_free(bio_err);
    free(cacerts_raw);
    free(trustcerts);
    
    /*
     * Free the lookup table used to simulate
     * manual cert approval
     */
    if (lookup_root) {
        tdestroy((void *)lookup_root, free_lookup);
	lookup_root = NULL;
    }

    if (srp_db) {
	SRP_VBASE_free(srp_db);
	srp_db = NULL;
    }

    //We don't shutdown here because there
    //may be other unit test cases in this process
    //the occur later.
    //est_apps_shutdown();
}

/*
 * Call this function to stop the single-threaded simple EST server
 */
void st_stop ()
{
    stop_single_server(server_data);
    cleanup();
    printf("Stopped EST server.\n");
    fflush(stdout);
}

/*
 * Call this to start a simple EST server.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  certfile:	    PEM encoded certificate used for server's identity
 *  keyfile:	    Private key associated with the certfile
 *  realm:	    HTTP realm to present to the client
 *  ca_chain_file:  PEM encoded certificates to use in the /cacerts
 *                  response to the client. 
 *  trusted_certs_file: PEM encoded certificates to use for authenticating
 *                  the EST client at the TLS layer. 
 *  ossl_conf_file: Configuration file that specifies the OpenSSL
 *                  CA to use.
 *  simulate_manual_enroll: Pass in a non-zero value to have the EST
 *                  simulate manual approval at the CA level.  This
 *                  is used to test the retry-after logic.
 *  ec_nid:         Openssl NID value for ECDHE curve to use during
 *                  TLS handshake.  Take values from <openssl/obj_mac.h>
 */
static int st_start_internal (
    int listen_port,
    char *certfile,
    char *keyfile,
    char *realm,
    char *ca_chain_file,
    char *trusted_certs_file,
    char *ossl_conf_file,
    int simulate_manual_enroll,
    int enable_pop,
    int ec_nid,
    int enable_srp,
    char *srp_vfile)
{
    X509 *x;
    EVP_PKEY *priv_key;
    BIO *certin, *keyin;
    DH *dh;
    EST_ERROR rv;

    printf("\nLaunching EST server...\n");
    fflush(stdout);
    est_set_log_source(EST_SERVER);

    manual_enroll = simulate_manual_enroll;

    /*
     * Read in the CA certificates
     * This is the explicit chain
     */
    cacerts_len = read_binary_file(ca_chain_file, &cacerts_raw);
    if (cacerts_len <= 0) {
        printf("CA chain file %s file could not be read\n", ca_chain_file);
        return (-1);
    }
    /*
     * Read in the external CA certificates
     * This is the implicit chain
     */
    if (trusted_certs_file) {
        trustcerts_len = read_binary_file(trusted_certs_file, &trustcerts);
        if (trustcerts_len <= 0) {
            printf("Trusted certs file %s could not be read\n", trusted_certs_file);
            return (-1);
        }
    }

    /*
     * Copy in the name of the OpenSSL conf file.  This is used for
     * the OpenSSL test CA.  The conf file specifies how the CA is
     * configured.
     */
    if (ossl_conf_file) {
	strncpy(conf_file, ossl_conf_file, 255);
    }

    /*
     * Read in the local server certificate 
     */
    certin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(certin, certfile) <= 0) {
	printf("Unable to read server certificate file %s\n", certfile);
	return (-1);
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using 
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
	printf("Error while reading PEM encoded server certificate file %s\n", certfile);
	return (-1);
    }
    BIO_free(certin);


    /* 
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file_internal());
    if (BIO_read_filename(keyin, keyfile) <= 0) {
	printf("Unable to read server private key file %s\n", keyfile);
	return (-1);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead. 
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
	printf("Error while reading PEM encoded private key file %s\n", certfile);
	return (-1);
    }
    BIO_free(keyin);

    //We don't startup here, it's expected the test harness
    //will call this.
    //est_apps_startup();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!bio_err) {
        printf("BIO not working\n");
        return (-1);
    }

    ectx = est_server_init(trustcerts, trustcerts_len, 
                           cacerts_raw, cacerts_len, 
	                   EST_CERT_FORMAT_PEM, realm, x, priv_key);
    if (!ectx) {
        printf("Unable to initialize EST context.  Aborting!!!\n");
        return (-1);
    }

    if (ec_nid) {
	est_server_set_ecdhe_curve(ectx, ec_nid);
    }

    if (!enable_pop) {
	est_server_disable_pop(ectx);
    }

    if (est_set_ca_enroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("Unable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_ca_reenroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("Unable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_csr_cb(ectx, &process_csrattrs_request)) {
        printf("Unable to set EST CSR Attributes callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_http_auth_cb(ectx, &process_http_auth)) {
        printf("Unable to set EST HTTP AUTH callback.  Aborting!!!\n");
        return (-1);
    }    

    /*
     * Set DH parameters for TLS
     */
    dh = get_dh1024dsa();
    if (dh) {
	est_server_set_dh_parms(ectx, dh);
    }
    DH_free(dh);

    /*
     * Do we need to enable SRP?
     */
    if (enable_srp) {
	srp_db = SRP_VBASE_new(NULL);
	if (!srp_db) {
	    printf("Unable allocate SRP verifier database.  Aborting!!!\n");
	    return(-1); 
	}
	if (SRP_VBASE_init(srp_db, srp_vfile) != SRP_NO_ERROR) {
	    printf("Unable initialize SRP verifier database %s.  Aborting!!!\n", srp_vfile);
	    return(-1); 
	}
	
	if (est_server_enable_srp(ectx, &ssl_srp_server_param_cb)) { 
	    printf("Unable to enable SRP.  Aborting!!!\n");
	    return(-1);
	}
    }

    rv = est_server_start(ectx);
    if (rv != EST_ERR_NONE) {
        printf("Failed to init mg\n");
        return (-1);
    }

    // Start master (listening) thread
    server_data = start_single_server (ectx, listen_port, 0/* better IP v4, not v6 */);
    /*
     * clean up
     */
    EVP_PKEY_free(priv_key);
    X509_free(x);

    est_set_log_source(EST_CLIENT);
    return 0;
}

/*
 * Call this to start a simple EST server.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:	    PEM encoded certificate used for server's identity
 *  keyfile:	    Private key associated with the certfile
 *  realm:	    HTTP realm to present to the client
 *  ca_chain_file:  PEM encoded certificates to use in the /cacerts
 *                  response to the client. 
 *  trusted_certs_file: PEM encoded certificates to use for authenticating
 *                  the EST client at the TLS layer. 
 *  ossl_conf_file: Configuration file that specifies the OpenSSL
 *                  CA to use.
 *  simulate_manual_enroll: Pass in a non-zero value to have the EST
 *                  simulate manual approval at the CA level.  This
 *                  is used to test the retry-after logic.
 *  ec_nid:         Openssl NID value for ECDHE curve to use during
 *                  TLS handshake.  Take values from <openssl/obj_mac.h>
 */
int st_start (int listen_port,
	      char *certfile,
	      char *keyfile,
	      char *realm,
	      char *ca_chain_file,
	      char *trusted_certs_file,
	      char *ossl_conf_file,
              int simulate_manual_enroll,
	      int enable_pop,
	      int ec_nid)
{
    int rv;

    rv = st_start_internal(listen_port, certfile, keyfile, realm, ca_chain_file,
	      trusted_certs_file, ossl_conf_file, simulate_manual_enroll,
	      enable_pop, ec_nid, 0, NULL);

    return (rv);
}

/*
 * Call this to start a simple EST server with SRP.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:	    PEM encoded certificate used for server's identity
 *  keyfile:	    Private key associated with the certfile
 *  realm:	    HTTP realm to present to the client
 *  ca_chain_file:  PEM encoded certificates to use in the /cacerts
 *                  response to the client. 
 *  trusted_certs_file: PEM encoded certificates to use for authenticating
 *                  the EST client at the TLS layer. 
 *  ossl_conf_file: Configuration file that specifies the OpenSSL
 *                  CA to use.
 *  enable_pop:     Set to non-zero value to require Proof-of-possession check.
 *  vfile:          Full path name of OpenSSL SRP verifier file
 */
int st_start_srp (int listen_port,
	          char *certfile,
	          char *keyfile,
	          char *realm,
	          char *ca_chain_file,
	          char *trusted_certs_file,
	          char *ossl_conf_file,
	          int enable_pop,
		  char *vfile)
{
    int rv;

    rv = st_start_internal(listen_port, certfile, keyfile, realm, ca_chain_file,
	      trusted_certs_file, ossl_conf_file, 0, enable_pop, 0, 1, vfile);

    return (rv);
}

/*
 * Note: Many of the following functions are not following
 *       EST API guidelines.  Specifically, some of these calls
 *       into the API should not occur on a running server.
 *       DO NOT follow this code as an example for production
 *       code.  This is here for testing only, supporting negative
 *       test cases in some scenarios.
 */
void st_disable_csr_cb ()
{
    est_set_csr_cb(ectx, NULL);
}

void st_set_csrattrs (char *value)
{
    csr_attr_value = value;
}

void st_disable_http_auth ()
{
    est_set_http_auth_cb(ectx, NULL);
}

void st_enable_http_auth ()
{
    est_set_http_auth_cb(ectx, &process_http_auth);
}

void st_enable_http_digest_auth ()
{
    est_server_set_auth_mode(ectx, AUTH_DIGEST);
}

void st_enable_http_basic_auth ()
{
    est_server_set_auth_mode(ectx, AUTH_BASIC);
}

void st_enable_http_token_auth ()
{
    est_server_set_auth_mode(ectx, AUTH_TOKEN);
}

void st_set_token (char *value)
{
    memset(valid_token_value, MAX_AUTH_TOKEN_LEN+1, 0);
    strncpy(&(valid_token_value[0]), value, MAX_AUTH_TOKEN_LEN);
}

void st_enable_pop ()
{
    est_server_enable_pop(ectx);
}

void st_disable_pop ()
{
    est_server_disable_pop(ectx);
}

void st_set_http_auth_optional ()
{
    est_set_http_auth_required(ectx, HTTP_AUTH_NOT_REQUIRED);
}

void st_set_http_auth_required ()
{
    est_set_http_auth_required(ectx, HTTP_AUTH_REQUIRED);
}

void st_enable_csrattr_enforce ()
{
    est_server_enforce_csrattr(ectx);
}


