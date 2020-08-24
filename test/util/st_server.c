/*------------------------------------------------------------------
 * st_server.c - Simple single-threaded EST server that can be
 *               used for testing.  This server can only handle
 *               a single EST request at any given time.  Attempting
 *               to send multiple requests to it will result in
 *               undetermined results.
 *
 * August, 2013
 *
 * Copyright (c) 2013, 2016, 2017, 2018 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#define __USE_GNU
#include <search.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <est.h>
#include "ossl_srv.h"
#include "test_utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <jsmn.h>
#include "st_server.h"
#define MAX_CERT_LEN 8192
#define MAX_FILENAME_LEN 255

BIO *bio_err = NULL;
static int tcp_port;
static int manual_enroll = 0;
volatile int stop_flag = 0;
static int coap_enabled;
unsigned char *cacerts_raw = NULL;
int cacerts_len = 0;
EST_CTX *ectx;
SRP_VBASE *srp_db = NULL;
unsigned char *trustcerts = NULL;
int trustcerts_len = 0;
static char conf_file[MAX_FILENAME_LEN];
static char *csr_attr_value = NULL;
int write_csr = 0;
static char csr_filename[MAX_FILENAME_LEN];

X509 *x;
EVP_PKEY *priv_key;

static char valid_token_value[MAX_AUTH_TOKEN_LEN+1];

extern void dumpbin(char *buf, size_t len);

char tst_srvr_path_seg_auth[EST_MAX_PATH_SEGMENT_LEN+1];

char tst_srvr_path_seg_enroll[EST_MAX_PATH_SEGMENT_LEN+1];
char tst_srvr_path_seg_cacerts[EST_MAX_PATH_SEGMENT_LEN+1];
char tst_srvr_path_seg_csrattrs[EST_MAX_PATH_SEGMENT_LEN+1];

#if ENABLE_BRSKI
static int brski_retry_enabled = 0;
static int brski_retry_delay = 0;
static int brski_retry_count = 0;
static int brski_retry_running_count = 0;

static int brski_send_nonce = 1;
static int brski_nonce_too_long = 0;
static int brski_nonce_mismatch = 0;

static int brski_send_serial_num = 1;
static int brski_serial_num_too_long = 0;
static int brski_serial_num_mismatch = 0;

static X509 *masa_ca_root;
static EVP_PKEY *masa_ca_priv_key;
static int masa_ca_enabled = 0;
#endif

unsigned char *p7_ca_certs = NULL;
int   p7_ca_certs_len = 0;

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
#ifndef HAVE_OLD_OPENSSL
    BIGNUM *p, *g;
#endif

    if ((dh=DH_new()) == NULL) {
	return(NULL);
    }
#ifdef HAVE_OLD_OPENSSL    
    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL)) { 
	DH_free(dh); return(NULL); 
    }
    dh->length = 160;
    return(dh);
#else    
    p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
    if ((p == NULL) || (g == NULL)) {
        DH_free(dh);
        return (NULL);
    }
    DH_set0_pqg(dh, p, NULL, g);
    return (dh);
#endif    
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
static int lookup_pkcs10_request (unsigned char *pkcs10, int p10_len)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    BIO *b64;
    EVP_PKEY *pkey = NULL;
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
#ifdef HAVE_OLD_OPENSSL
     pkey = X509_PUBKEY_get(req->req_info->pubkey);
#else
    pkey = X509_PUBKEY_get(X509_REQ_get_X509_PUBKEY(req));
#endif
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
    n = malloc(sizeof(LOOKUP_ENTRY));
    n->data = malloc(bptr->length);
    n->length = bptr->length;
    memcpy(n->data, bptr->data, n->length);
    l = tfind(n, (void **)&lookup_root, compare);
    if (l) {
	/* We have a match, allow the enrollment */
	rv = 1;	
	tdelete(n, (void **)&lookup_root, compare);
	printf("\nRemoving key from lookup table:\n");
	dumpbin((char*)n->data, n->length);
	free(n->data);
	free(n);
    } else {
	/* Not a match, add it to the list and return */
	l = tsearch(n, (void **)&lookup_root, compare);
	rv = 0;
	printf("\nAdding key to lookup table:\n");
	dumpbin((char*)n->data, n->length);
    }
DONE:
    if (out) BIO_free_all(out);
    if (in) BIO_free_all(in);
    if (req) X509_REQ_free(req);
    if (pkey) EVP_PKEY_free(pkey);

    return (rv);
}

/*
 * Trivial utility function to extract the string
 * value of the subject name from a cert.
 */
static void extract_sub_name (X509 *cert, char *name, int len)
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
        name[bm->length] = 0;
    } else {
        name[len] = 0;
    }

    BIO_free(out);
}

#ifndef WIN32
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
#endif
/*
 * Callback function used by EST to generate a private key
 *
 * priv_key  contains a pointer to the key we will populate
 * priv_key_len  contains a pointer to an integer for the
 *               length of the new key
 */
static int generate_private_key(EVP_PKEY **p_priv_key)
{
    EVP_PKEY *priv_key = NULL;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    BIO *out = NULL;
    int rv = EST_ERR_NONE;

    if (!p_priv_key) {
        rv = EST_ERR_INVALID_PARAMETERS;
        goto end;
    }

    rsa = RSA_new();
    if (!rsa) {
        rv = EST_ERR_MALLOC;
        printf("***ESTCLIENT [ERROR][generate_private_key]--> Failed to allocate RSA struct");
        goto end;
    }
    bn = BN_new();
    if (!bn) {
        rv = EST_ERR_MALLOC;
        printf("***ESTCLIENT [ERROR][generate_private_key]--> Failed to allocate BN struct");
        goto end;
    }

    BN_set_word(bn, 0x10001);

    RSA_generate_key_ex(rsa, 4096, bn, NULL);
    out = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(out,rsa,NULL,NULL,0,NULL,NULL);

    priv_key = PEM_read_bio_PrivateKey(out, NULL, NULL, NULL);
    if (priv_key == NULL) {
        rv = EST_ERR_PEM_READ;
        printf("Error while reading PEM encoded private key BIO: ");
        goto end;
    }
    *p_priv_key = priv_key;

    end:
    if (out) {
        BIO_free(out);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    if (bn) {
        BN_free(bn);
    }
    return rv;
}

static char *print_est_auth_status (EST_AUTH_STATE rv)
{
    switch (rv) {
    case EST_UNAUTHORIZED:
        return ("EST_UNAUTHORIZED");
        break;
    case EST_CSR_PARSE_FAIL:
        return ("EST_CSR_PARSE_FAIL");
        break;
    case EST_HTTP_AUTH:
        return ("EST_HTTP_AUTH");
        break;
    case EST_HTTP_AUTH_PENDING:
        return("EST_HTTP_AUTH_PENDING");
        break;
    case EST_CERT_AUTH:
        return("EST_CERT_AUTH");
        break;
    case EST_SRP_AUTH:
        return("EST_SRP_AUTH");
        break;
    default:
        return("Invalid Enhanced Auth State value");
    }
}

static char *print_est_enhanced_auth_state (EST_ENHANCED_AUTH_TS_AUTH_STATE enh_auth_ts_state)
{
    switch (enh_auth_ts_state) {
    case EST_ENHANCED_AUTH_TS_VALIDATED:
        return("EST_ENHANCED_AUTH_TS_VALIDATED");
        break;
    case EST_ENHANCED_AUTH_TS_NOT_VALIDATED:
        return("EST_ENHANCED_AUTH_TS_NOT_VALIDATED");
        break;
    default:
        return("Invalid Enhanced Auth State value");
    }
}

static void st_notify_est_err_cb (char *format, va_list arg_list) {


    /*
     * Print the incoming EST error message.
     */
    fprintf(stderr, "***SRVR EVENT [%s]--> EST Internal Error-> ",
                    __FUNCTION__);

    vfprintf(stderr, format, arg_list);

    return;
}

static void st_notify_ssl_proto_err_cb (char *err_msg) {

    if (err_msg == NULL) {
        err_msg = "NULL err_msg";
    }

    /*
     * Print the incoming SSL protocol error message.
     */
    fprintf(stderr, "***SRVR EVENT [%s]--> SSL Protocol Error-> %s\n",
                    __FUNCTION__, err_msg);

    return;
}

static void st_notify_enroll_req_cb (char *id_cert_subj, X509 *peer_cert,
                                     char *csr_subj, X509_REQ *csr_x509,
                                     char *ipstr, int port,
                                     char *path_seg, EST_ENROLL_REQ_TYPE enroll_req)
{
    char *req;

    /*
     * Display information about this enroll request event.
     */
    if (enroll_req == SIMPLE_ENROLL_REQ) {
        req = "Enroll";
    } else if (enroll_req == REENROLL_REQ) {
        req = "Re-enroll";
    } else if (enroll_req == SERVERKEYGEN_REQ) {
        req = "Server-Side KeyGen";
    } else {
        req = "Unknown request";
    }
    fprintf(stderr, "***SRVR EVENT [%s]--> EST %s Request-> "
                    "TLS ID cert subject: \"%s\", "
                    "CSR subject: \"%s\", "
                    "IP address: \"%s\",  Port: %d, "
                    "path segment: \"%s\"\n",
                    __FUNCTION__, req,
                    id_cert_subj, csr_subj, ipstr, port, path_seg);
    return;
}

static void st_notify_enroll_rsp_cb (char *id_cert_subj, X509 *peer_cert,
                                     char *csr_subj, X509_REQ *csr,
                                     char *ip_addr, int port,
                                     unsigned char *returned_cert, int returned_cert_len,
                                     char *path_seg, EST_ENROLL_REQ_TYPE enroll_req, EST_ERROR rc) {

    char *rsp;

    /*
     * Display information about this enroll response event.
     */
    if (enroll_req == SIMPLE_ENROLL_REQ) {
        rsp = "Enroll";
    } else if (enroll_req == REENROLL_REQ) {
        rsp = "Re-enroll";
    } else if (enroll_req == SERVERKEYGEN_REQ) {
        rsp = "Server-Side KeyGen";
    } else {
        rsp = "Unknown request";
    }
    /*
     * The newly enrolled cert could be accessed through calls to OpenSSL.
     * First convert it into an X509 structure and then use various get
     * functions to retrieve fields from the cert; such as the subject field,
     * issuer, not before/not after, etc
     *
     * Below, we just print the pointer and length to prove that the
     * buffer has been passed up.
     */
    fprintf(stderr, "***SRVR EVENT [%s]--> EST %s Response-> "
                    "TLS ID cert subject: \"%s\", "
                    "CSR subject: \"%s\", "
                    "IP address: \"%s\",  Port: %d, "
                    "path segment: \"%s\", "
                    "Returned cert: \"%s\", returned cert length: %d, "
                    "status of the enroll: \"%s\"\n",
                    __FUNCTION__, rsp,
                    id_cert_subj, csr_subj, ip_addr, port, path_seg,
                    returned_cert, returned_cert_len,
                    EST_ERR_NUM_TO_STR(rc));

    return;
}

static void st_notify_enroll_auth_result_cb (X509 *peer_cert, char *path_seg,
                                             EST_ENROLL_REQ_TYPE enroll_req,
                                             EST_ENHANCED_AUTH_TS_AUTH_STATE state,
                                             EST_AUTH_STATE rv) {
    char *rsp;

    /*
     * Display information about this enroll authentication response event.
     */
    if (enroll_req == SIMPLE_ENROLL_REQ) {
        rsp = "Enroll";
    } else if (enroll_req == REENROLL_REQ) {
        rsp = "Re-enroll";
    } else if (enroll_req == SERVERKEYGEN_REQ) {
        rsp = "Server-Side KeyGen";
    } else {
        rsp = "Unknown request";
    }
    /*
     * The attributes from the peer cert can be obtained through calls
     * to openssl X509 get functions.
     *
     * The Auth state (status of the auth check) can be checked against
     * enums defined in est.h
     */
/*
    fprintf(stderr, "***SRVR EVENT [%s]--> EST %s Authentication Response-> "
                    "Peer cert: %p, "
                    "path_seq: %p, "
                    "Enhanced auth Trust store state: %d (%s), "
                    "auth-state: %d (%s)\n",
                    __FUNCTION__, rsp,
                    peer_cert, path_seg,
                    state, print_est_enhanced_auth_state(state),
                    rv, print_est_auth_status(rv));
*/
    fprintf(stderr, "***SRVR EVENT [%s]--> EST %s Authentication Response-> "
                    "Peer cert: %p, "
                    "path_seq: %p, "
                    "Enhanced auth Trust store state: %d (%s), "
                    "auth-state: %d (%s)\n",
                    __FUNCTION__, rsp,
                    peer_cert, path_seg,
                    state, print_est_enhanced_auth_state(state),
                    rv, print_est_auth_status(rv));
    return;
}

static void st_notify_endpoint_req_cb (char *id_cert_subj, X509 *peer_cert,
                                       const char *uri, char *ip_addr, int port,
                                       EST_ENDPOINT_EVENT_TYPE event_type)
{
    pthread_t tid = pthread_self();

    /*
     * Display information about this endpoint request event.  Note that
     * the assumption is that uri is printable if not null.
     */
    if (uri == NULL) {
        uri = "<URI null>";
    }

    fprintf(stderr, "***SRVR EVENT [%s]--> EST Endpoint Request-> %s %lu "
                    "TLS ID cert subject: \"%s\", "
                    "uri: \"%s\", "
                    "IP address: \"%s\",  Port: %d\n",
                    __FUNCTION__,
                    (event_type == EST_ENDPOINT_REQ_START?"start of request":"end of request"),
                    tid, id_cert_subj, uri, ip_addr, port);
    return;
}


/*
 * st_notify_event_plugin_config
 *
 * This data structure contains the notify-specific event plugin module
 * data.
 */
static st_est_event_cb_table_t  st_est_default_event_cb_table = {

    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when EST errors occur.
     */
    st_notify_est_err_cb,

    /*
     * Address of the notify-specific event callback function that
     * is registered with EST and called when SSL protocol errors occur.
     */
   st_notify_ssl_proto_err_cb,

   /*
    * Address of the notify-specific event callback function that
    * is registered with EST and called when EST enroll or re-enroll
    * requests are made.
    */
   st_notify_enroll_req_cb,

   /*
    * Address of the notify-specific event callback function that
    * is registered with EST and called when EST enroll or re-enroll
    * responses are received.
    */
   st_notify_enroll_rsp_cb,

   /*
    * Address of the notify-specific event callback function that
    * is registered with EST and called when EST enroll or re-enroll
    * authentication results are received.
    */
   st_notify_enroll_auth_result_cb,

   /*
    * Address of the notify-specific event callback function that
    * is registered with EST and called when EST endpoint requests
    * are received.
    */
   st_notify_endpoint_req_cb
};

/*
 * st_internal_set_est_event_callbacks
 *
 * Sets callbacks for all of the EST event callbacks for
 * the specified EST_CTX to the callback functions
 * pointed to by event_cb_ptr.
 */
static
void st_internal_set_est_event_callbacks (EST_CTX * libest_ctx,
                                          st_est_event_cb_table_t *event_cb_ptr) {

    if (event_cb_ptr != NULL) {

        est_set_est_err_event_cb(event_cb_ptr->est_err_event_cb);
        est_set_ssl_proto_err_event_cb(event_cb_ptr->ssl_proto_err_event_cb);
        est_set_enroll_req_event_cb(libest_ctx,
                                    event_cb_ptr->enroll_req_event_cb);
        est_set_enroll_rsp_event_cb(libest_ctx,
                                    event_cb_ptr->enroll_rsp_event_cb);
        est_set_enroll_auth_result_event_cb(libest_ctx,
                                            event_cb_ptr->enroll_auth_result_event_cb);
        est_set_endpoint_req_event_cb(libest_ctx,
                                      event_cb_ptr->endpoint_req_event_cb);
    } else {

        est_set_est_err_event_cb(NULL);
        est_set_ssl_proto_err_event_cb(NULL);
        est_set_enroll_req_event_cb(libest_ctx, NULL);
        est_set_enroll_rsp_event_cb(libest_ctx, NULL);
        est_set_enroll_auth_result_event_cb(libest_ctx, NULL);
        est_set_endpoint_req_event_cb(libest_ctx, NULL);
    }

    return;
}

/*
 * st_set_default_est_event_callbacks
 *
 * Sets callbacks for all of the EST event callbacks for
 * the specified EST_CTX to the callback functions
 * specified in st_est_default_event_cb_table.
 */
void st_set_est_event_callbacks (st_est_event_cb_table_t *event_callbacks) {

    st_internal_set_est_event_callbacks(ectx, event_callbacks);

    return;
}

/*
 * st_set_default_est_event_callbacks
 *
 * Sets callbacks for all of the EST event callbacks for
 * the specified EST_CTX to the callback functions
 * specified in st_est_default_event_cb_table.
 */
void st_set_default_est_event_callbacks () {

    st_internal_set_est_event_callbacks(ectx, &st_est_default_event_cb_table);

    return;
}

/*
 * st_disable_est_event_callbacks
 *
 * Disable callbacks for all of the EST event callbacks for
 * the specified EST_CTX to the callback functions.
 */
void st_disable_est_event_callbacks() {
    st_internal_set_est_event_callbacks(ectx, NULL);

    return;
}

/*
 * Callback function used by EST stack to process a PKCS10
 * enrollment request with the CA.  The parameters are:
 *
 *   pkcs10  Contains the CSR that should be sent to
 *              the CA to be signed.
 *   pkcs10_len Length of the CSR char array
 *   pcks7   Should contain the signed PKCS7 certificate
 *              from the CA server.  You'll need allocate
 *              space and copy the cert into this char array.
 *   pkcs7_len  Length of the pkcs7 char array, you will set this.
 *   user_id    If HTTP authentication was used to identify the
 *              EST client, this will contain the user ID supplied
 *              by the client.
 *   peer_cert  If the EST client presented a certificate to identify
 *              itself during the TLS handshake, this parameter will
 *              contain that certificate.
 *   path_seg   If the incoming request contains a path segment it
 *              is extracted from the URI and passed here.  Typically
 *              used to mux between multiple CAs or to identify a
 *              specific profile to use by the CA.
 *   app_data   an optional pointer to information that is to be
 *              used by the application layer.
 *
 */
int process_srvr_side_keygen_pkcs10_enrollment (unsigned char * pkcs10, int p10_len,
                                                unsigned char **pkcs7, int *pkcs7_len,
                                                unsigned char **pkcs8, int *pkcs8_len,
                                                char *user_id, X509 *peer_cert, char *path_seg,
                                                void *app_data)
{
    BIO *result = NULL;
    char *buf;
#ifndef WIN32
    int rc;
#endif
    char sn[64];
    char file_name[MAX_FILENAME_LEN];

    /*
     * Informational only
     */
    if (user_id) {
        /*
         * Should be safe to log the user ID here since HTTP auth
         * has succeeded at this point.
         */
        printf("\n%s - User ID is %s\n", __FUNCTION__, user_id);
    }
    if (peer_cert) {
        memset(sn, 0, 64);
        extract_sub_name(peer_cert, sn, 64);
        printf("\n%s - Peer cert CN is %s\n", __FUNCTION__, sn);
    }
    if (app_data) {
        printf("ex_data value is %x\n", *((unsigned int *) app_data));
    }
    if (path_seg) {
        printf("\nPath segment was included in enrollment URI. "
                       "Path Segment = %s\n", path_seg);
    }

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

#ifndef WIN32
    rc = pthread_mutex_lock(&m);
    if (rc) {
        printf("\nmutex lock failed rc=%d", rc);
        exit(1);
    }
#else
    EnterCriticalSection(&enrollment_critical_section);
#endif

    if (write_csr) {
        /*
         * Dump out pkcs10 to a file, this will contain a list of the OIDs in the CSR.
         */
        snprintf(file_name, MAX_FILENAME_LEN, "/tmp/csr.p10");
        write_binary_file(file_name, pkcs10, p10_len);
    }

    result = ossl_simple_enroll(pkcs10, p10_len, conf_file);
#ifndef WIN32
    rc = pthread_mutex_unlock(&m);
    if (rc) {
        printf("\nmutex unlock failed rc=%d", rc);
        exit(1);
    }
#else
    LeaveCriticalSection(&enrollment_critical_section);
#endif

    /*
     * The result is a BIO containing the pkcs7 signed certificate
     * Need to convert it to char and copy the results so we can
     * free the BIO.
     */
    *pkcs7_len = BIO_get_mem_data(result, (char**) &buf);
    if (*pkcs7_len > 0 && *pkcs7_len < MAX_CERT_LEN) {
        *pkcs7 = malloc(*pkcs7_len);
        memcpy(*pkcs7, buf, *pkcs7_len);
    }

    BIO_free_all(result);
    return EST_ERR_NONE;
}

/******************************************************************************
 * The following functions are the callbacks used by libest.so to bind
 * the EST stack to the HTTP/SSL layer and the CA server.
 ******************************************************************************/

/*
 * Callback function used by EST stack to process a PKCS10
 * enrollment request with the CA.
 */
static int process_pkcs10_enrollment (unsigned char * pkcs10, int p10_len, 
                                      unsigned char **cert, int *cert_len,
                                      char *uid, X509 *peercert,
                                      char *path_seg, void *app_data)
{
    BIO *result = NULL;
    char *buf;
    
    if (path_seg){
        printf("\n %s: Path segment in the enroll request is: %s\n",
               __FUNCTION__, path_seg);
        strcpy(tst_srvr_path_seg_enroll, path_seg);
    }
    
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

    /*
     * Dump out pkcs10 to a file,
     * this will contain a list of the OIDs in the CSR.
     */
    if (write_csr) {
        write_binary_file(csr_filename, pkcs10, p10_len);
    }

    result = ossl_simple_enroll(pkcs10, p10_len, conf_file);

    /*
     * The result is a BIO containing the pkcs7 signed certificate
     * Need to convert it to char and copy the results so we can
     * free the BIO.
     */
    *cert_len = BIO_get_mem_data(result, (char**)&buf);
    if (*cert_len > 0 && *cert_len < MAX_CERT_LEN) {
        *cert = calloc(*cert_len, sizeof(char));
        memcpy(*cert, buf, *cert_len);
    }

    BIO_free_all(result);
    return EST_ERR_NONE;
}

//This CSR attributes contains the challengePassword OID and others
#define TEST_CSR "MCYGBysGAQEBARYGCSqGSIb3DQEJBwYFK4EEACIGCWCGSAFlAwQCAg==\0"

static unsigned char * process_csrattrs_request (int *csr_len, char *path_seg,
                                                 X509 *peer_cert,
                                                 void *app_data)
{
    unsigned char *csr_data;

    if (path_seg){
        printf("\n %s: Path segment in the casrattrs request is: %s\n",
               __FUNCTION__, path_seg);
        strcpy(tst_srvr_path_seg_csrattrs, path_seg);
    }    
    
    if (csr_attr_value) {
	*csr_len = strlen(csr_attr_value);
	csr_data = malloc(*csr_len + 1);
	strncpy((char *)csr_data, csr_attr_value, *csr_len+1);
    } else {
	*csr_len = sizeof(TEST_CSR);
	csr_data = malloc(*csr_len + 1);
	strcpy((char *)csr_data, TEST_CSR);
    }
    return (csr_data);
}


/*
 * This function can be used to output the OpenSSL
 * error buffer.  This is useful when an OpenSSL
 * API call fails and you'd like to provide some
 * detail to the user regarding the cause of the
 * failure.
 */
void st_ossl_dump_ssl_errors ()
{
    BIO		*e = NULL;
    BUF_MEM	*bptr = NULL;

    e = BIO_new(BIO_s_mem());
    if (!e) {
	printf("BIO_new failed\n");
	return;
    }
    ERR_print_errors(e);
    (void)BIO_flush(e);
    BIO_get_mem_ptr(e, &bptr);
    if (bptr->data) {
        bptr->data[bptr->length] = '\0';
    }
    printf("OSSL error: %s\n", bptr->data); 
    BIO_free_all(e);
}


/*
 * This function is used to read the CERTS in a BIO and build a
 * stack of X509* pointers.  This is used during the PEM to
 * PKCS7 conversion process.
 */
static int add_certs_from_BIO (STACK_OF(X509) *stack, BIO *in)
{
    int count = 0;
    int ret = -1;

    STACK_OF(X509_INFO) * sk = NULL;
    X509_INFO *xi;


    /* This loads from a file, a stack of x509/crl/pkey sets */
    sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (sk == NULL) {
        printf("Unable to read certs from PEM encoded data\n");
        return (ret);
    }

    /* scan over it and pull out the CRL's */
    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack, xi->x509);
            xi->x509 = NULL;
            count++;
        }
        X509_INFO_free(xi);
    }

    ret = count;

    /* never need to OPENSSL_free x */
    if (sk != NULL) {
        sk_X509_INFO_free(sk);
    }
    return (ret);
}


static BIO *get_certs_pkcs7 (BIO *in, int do_base_64)
{
    STACK_OF(X509) * cert_stack = NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    BIO *b64;
    int buflen = 0;


    /*
     * Create a PKCS7 object 
     */
    if ((p7 = PKCS7_new()) == NULL) {
        printf("pkcs7_new failed\n");
	goto cleanup;
    }
    /*
     * Create the PKCS7 signed object
     */
    if ((p7s = PKCS7_SIGNED_new()) == NULL) {
        printf("pkcs7_signed_new failed\n");
	goto cleanup;
    }
    /*
     * Set the version
     */
    if (!ASN1_INTEGER_set(p7s->version, 1)) {
        printf("ASN1_integer_set failed\n");
	goto cleanup;
    }

    /*
     * Create a stack of X509 certs
     */
    if ((cert_stack = sk_X509_new_null()) == NULL) {
        printf("stack malloc failed\n");
	goto cleanup;
    }

    /*
     * Populate the cert stack
     */
    if (add_certs_from_BIO(cert_stack, in) < 0) {
        printf("Unable to load certificates\n");
	st_ossl_dump_ssl_errors();
	goto cleanup;
    }

    /*
     * Create the BIO which will receive the output
     */
    out = BIO_new(BIO_s_mem());
    if (!out) {
        printf("BIO_new failed\n");
	goto cleanup;
    }

    /*
     * Add the base64 encoder if needed
     */
    if (do_base_64) {
	b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL) {
            printf("BIO_new failed while attempting to create base64 BIO\n");
            st_ossl_dump_ssl_errors();
            goto cleanup;
        }    
	out = BIO_push(b64, out);
    }

    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign = p7s;
    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
    p7s->cert = cert_stack;

    /*
     * Convert from PEM to PKCS7
     */
    buflen = i2d_PKCS7_bio(out, p7);
    if (!buflen) {
        printf("PEM_write_bio_PKCS7 failed\n");
	st_ossl_dump_ssl_errors();
	BIO_free_all(out);
        out = NULL;
	goto cleanup;
    }
    (void)BIO_flush(out);

cleanup:
    /* 
     * Only need to cleanup p7.  This frees up the p7s and
     * cert_stack allocations for us since these are linked
     * to the p7.
     */
    if (p7) {
        PKCS7_free(p7);
    }

    return out;
}


/*
 * Takes in a PEM based buffer and length containing the CA certificates trust
 * chain, reads the data in and loads the certificates into a global buffer
 * which is used to respond to the /cacerts callback requests.
 */
static int load_ca_certs (EST_CTX *ctx, unsigned char *pem_cacerts, int pem_cacerts_len)
{
    BIO *cacerts_bio = NULL;
    BIO *in_bio;
    unsigned char *retval;

    in_bio = BIO_new_mem_buf(pem_cacerts, pem_cacerts_len);
    if (in_bio == NULL) {
        printf("Unable to open the raw cert buffer\n");
        return (-1);
    }

    /*
     * convert the CA certs to PKCS7 encoded char array
     * This is used by an EST server to respond to the
     * cacerts request.
     */
    cacerts_bio = get_certs_pkcs7(in_bio, 1);
    if (!cacerts_bio) {
        printf("get_certs_pkcs7 failed\n");
        BIO_free(in_bio);
        return (-1);
    }

    p7_ca_certs_len = (int) BIO_get_mem_data(cacerts_bio, (char**)&retval);
    if (p7_ca_certs_len <= 0) {
        printf("Failed to copy PKCS7 data\n");
        BIO_free_all(cacerts_bio);
        BIO_free(in_bio);
        return (-1);
    }

    p7_ca_certs = calloc(p7_ca_certs_len+1, sizeof(char));
    if (!p7_ca_certs) {
        printf("malloc failed\n");
        BIO_free_all(cacerts_bio);
        BIO_free(in_bio);
        return (-1);
    }
    memcpy(p7_ca_certs, retval, p7_ca_certs_len);
    BIO_free_all(cacerts_bio);
    BIO_free(in_bio);
    return (0);
}


static unsigned char * process_cacerts_request (int *cacerts_len, char *path_seg,
                                                void *app_data)
{

    if (path_seg){
        printf("\n %s: Path segment in the cacerts request is: %s\n",
               __FUNCTION__, path_seg);
        strcpy(tst_srvr_path_seg_cacerts, path_seg);
    }
    
    /*
     * return the preloaded cacerts chain buffer
     */
    *cacerts_len = p7_ca_certs_len;
    
    return (p7_ca_certs);
}

static unsigned char * process_null_return (int *cacerts_len, char *path_seg,
                                            void *app_data)
{
    return (NULL);
}

static char digest_user[3][32] = 
    {
	"estuser", 
	"estrealm", 
	"36807fa200741bb0e8fb04fcf08e2de6" //This is the HA1 precaculated value
    };

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int process_http_auth (EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah, 
	                      X509 *peer_cert, char *path_seg, void *app_data)
{
    int user_valid = 0; 
    char *digest;
    
    if (path_seg){
        printf("\n %s: Path segment in the authenticate callback is: %s\n",
               __FUNCTION__, path_seg);
        strcpy(tst_srvr_path_seg_auth, path_seg);
    }

    switch (ah->mode) {
    case AUTH_BASIC:
	/*
	 * this is where we might hook into a Radius server
	 * or some external database to authenticate a 
	 * userID/password.  But for this example code,
	 * we just hard-code a local user for testing
	 * the CiscoEST API.
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

    user = SRP_VBASE_get1_by_user(srp_db, login);

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
        SRP_user_pwd_free(user);
	return SSL3_AL_FATAL;
    }
		
    printf("SRP parameters set: username = \"%s\" info=\"%s\" \n", login, user->info);

    user = NULL;
    login = NULL;
    fflush(stdout);
    SRP_user_pwd_free(user);    
    return SSL_ERROR_NONE;
}

static void cleanup() 
{
    est_server_stop(ectx);
    est_destroy(ectx);
    BIO_free(bio_err);
    free(cacerts_raw);
    free(trustcerts);
    EVP_PKEY_free(priv_key);
    X509_free(x);
    
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

static void* master_thread (void *arg)
{
    int sock;                 
    struct sockaddr_in6 addr;
    int on = 1;
    int rc;
    int flags;
    int new;
    int unsigned len;
#ifdef HAVE_LIBCOAP
    unsigned char recv_char;
#endif

    memset(&addr, 0x0, sizeof(struct sockaddr_in6));
    addr.sin6_family = AF_INET6;
//    addr.sin6_family = AF_INET;
    addr.sin6_port = htons((uint16_t)tcp_port);
    if (coap_enabled) {
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
    } else {
        sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);        
    }
    if (sock == -1) {
        fprintf(stderr, "\nsocket call failed\n");
        exit(1);
    }
    // Needs to be done to bind to both :: and 0.0.0.0 to the same port
    int no = 0;
    setsockopt(sock, SOL_SOCKET, IPV6_V6ONLY, (void *)&no, sizeof(no));

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    rc = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (rc == -1) {
        fprintf(stderr, "\nbind call failed\n");
        exit(1);
    }
    listen(sock, SOMAXCONN);
    stop_flag = 0;

    while (stop_flag == 0) {
        if (coap_enabled) {
#ifdef HAVE_LIBCOAP
            rc = recv(sock, (void *) &recv_char, 1, MSG_PEEK);
#else       
            fprintf(stderr, "\nLibCoAP is not included in this build\n");
            exit(1);
#endif
        } else {
            len = sizeof(addr);
            rc = accept(sock, (struct sockaddr*)&addr, &len);
        }
        if (rc < 0) {
	    /*
	     * this is a bit cheesy, but much easier to implement than using select()
	     */
            usleep(100);
        } else {
            if (stop_flag == 0) {
                if (coap_enabled) {
#ifdef HAVE_LIBCOAP
                    est_server_handle_request(ectx, sock);
#endif
                } else {
                    new = rc;
                    est_server_handle_request(ectx, new);
                    close(new);
                }
            }
        }
    }
    close(sock);
    cleanup();
    return NULL;
}


/*
 * Call this function to stop the single-threaded simple EST server
 */
void st_stop ()
{
    stop_flag = 1;
    sleep(2);
}

/*
 * Call this to start a simple EST server.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
 *  ca_chain_file:  PEM encoded certificates to use in the /cacerts
 *                  response to the client. 
 *  trusted_certs_file: PEM encoded certificates to use for authenticating
 *                  the EST client at the TLS layer. 
 *  ossl_conf_file: Configuration file that specifies the OpenSSL
 *                  CA to use.
 *  simulate_manual_enroll: Pass in a non-zero value to have the EST
 *                  simulate manual approval at the CA level.  This
 *                  is used to test the retry-after logic.
 *  enable_pop:     Enable PoP support.
 *  ec_nid:         Openssl NID value for ECDHE curve to use during
 *                  TLS handshake.  Take values from <openssl/obj_mac.h>
 *  enable_tls10    Enable TLS 1.0 support
 *  disable_cacerts_response: Do not pass down the CA certs response chain
 *                  to the library.
 *  enable_crl:     Enable CRL checks
 *  enable_events:  Enable EST event callbacks
 *  enable_coap:    Flag for enabling the use of EST over CoAP on server
 *  coap_server_addr: Address for the EST CoAP server to listen on
 *
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
    char *srp_vfile,
    int enable_tls10,
    int disable_cacerts_response,
    int enable_crl,
    int enable_events,
    int enable_coap,
    int coap_max_sessions)
{
    BIO *certin, *keyin;
    DH *dh;
    EST_ERROR rv;
    pthread_t thread;
    int rc;
#ifdef HAVE_LIBCOAP
    int coap_port;
#endif
    
    manual_enroll = simulate_manual_enroll;
    
    /*
     * Read in the CA certificates
     * This is the explicit chain
     */
    cacerts_len = read_binary_file(ca_chain_file, &cacerts_raw);
    if (cacerts_len <= 0) {
        printf("\nCA chain file %s file could not be read\n", ca_chain_file);
        return (-1);
    }

    /*
     * Read in the external CA certificates
     * This is the implicit chain
     */
    if (trusted_certs_file) {
        trustcerts_len = read_binary_file(trusted_certs_file, &trustcerts);
        if (trustcerts_len <= 0) {
            printf("\nTrusted certs file %s could not be read\n", 
		    trusted_certs_file);
            return (-1);
        }
    }

    /*
     * Copy in the name of the OpenSSL conf file.  This is used for
     * the OpenSSL test CA.  The conf file specifies how the CA is
     * configured.
     */
    if (ossl_conf_file) {
	strncpy(conf_file, ossl_conf_file, MAX_FILENAME_LEN);
    }

    /*
     * Build out a default file name used to write out CSRs received
     */
#ifdef WIN32
    snprintf(csr_filename, MAX_FILENAME_LEN, "%s\\%s", getenv(TEMP), "csr.p10");
#else
    strncpy(csr_filename, "/tmp/csr.p10", MAX_FILENAME_LEN);
#endif

    /*
     * Read in the local server certificate 
     */
    certin = BIO_new(BIO_s_file());
    if (BIO_read_filename(certin, certfile) <= 0) {
	printf("\nUnable to read server certificate file %s\n", certfile);
	return (-1);
    }
    /*
     * This reads the file, which is expected to be PEM encoded.  If you're using 
     * DER encoded certs, you would invoke d2i_X509_bio() instead.
     */
    x = PEM_read_bio_X509(certin, NULL, NULL, NULL);
    if (x == NULL) {
	printf("\nError while reading PEM encoded server certificate file %s\n", certfile);
	return (-1);
    }
    BIO_free(certin);


    /* 
     * Read in the server's private key
     */
    keyin = BIO_new(BIO_s_file());
    if (BIO_read_filename(keyin, keyfile) <= 0) {
	printf("\nUnable to read server private key file %s\n", keyfile);
	return (-1);
    }
    /*
     * This reads in the private key file, which is expected to be a PEM
     * encoded private key.  If using DER encoding, you would invoke
     * d2i_PrivateKey_bio() instead. 
     */
    priv_key = PEM_read_bio_PrivateKey(keyin, NULL, NULL, NULL);
    if (priv_key == NULL) {
	printf("\nError while reading PEM encoded private key file %s\n", certfile);
	return (-1);
    }
    BIO_free(keyin);

    //We don't startup here, it's expected the test harness
    //will call this.
    //est_apps_startup();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!bio_err) {
        printf("\nBIO not working\n");
        return (-1);
    }

    if (disable_cacerts_response) {
        ectx = est_server_init(trustcerts, trustcerts_len, 
                               NULL, 0, 
                               EST_CERT_FORMAT_PEM, realm, x, priv_key);
    } else {
        ectx = est_server_init(trustcerts, trustcerts_len, 
                               cacerts_raw, cacerts_len, 
                               EST_CERT_FORMAT_PEM, realm, x, priv_key);
    }
    
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        return (-1);
    }

    /*
     * Install event callbacks
     */
    if (enable_events) {
        st_set_default_est_event_callbacks(ectx);
    }

    if (ec_nid) {
	est_server_set_ecdhe_curve(ectx, ec_nid);
    }

    if (!enable_pop) {
	est_server_disable_pop(ectx);
    }

    if (enable_tls10) {
	est_server_enable_tls10(ectx);
    }

    if (enable_crl) {
        est_enable_crl(ectx);
    }

    if (est_set_ca_enroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("\nUnable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_ca_reenroll_cb(ectx, &process_pkcs10_enrollment)) {
        printf("\nUnable to set EST pkcs10 enrollment callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_csr_cb(ectx, &process_csrattrs_request)) {
        printf("\nUnable to set EST CSR Attributes callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_http_auth_cb(ectx, &process_http_auth)) {
        printf("\nUnable to set EST HTTP AUTH callback.  Aborting!!!\n");
        return (-1);
    }
    /*
     * Set server-side key generation callback
     */
    if (est_server_set_key_generation_cb(ectx, &generate_private_key)) {
        printf("\nUnable to set EST server side key generation callback.  Aborting!!!\n");
        return (-1);
    }
    if (est_set_server_side_keygen_enroll_cb(ectx, &process_srvr_side_keygen_pkcs10_enrollment)) {
        printf(
                "\nUnable to set EST server-side keygen enrollment callback.  Aborting!!!\n");
        return (-1);
    }

    /*
     * If we've been told to not pass down the CA certs response chain
     * to the library then we need to set them up and register the call
     * back to provide them at the app layer
     */
    if (disable_cacerts_response) {

        /*
         * Convert the PEM encoded buffer previously read the file into the
         * PKCS7 buffer used for responding to /cacerts requests
         */
        rc = load_ca_certs(ectx, cacerts_raw, cacerts_len);
        if (rc != 0) {
            printf("\nUnable to convert CA certs chain in PEM format to PKCS7."
                   " Aborting!!!\n");
            return (-1);
        }            
        
        if (est_set_cacerts_cb(ectx, &process_cacerts_request)) {
            printf("\nUnable to set EST CACerts callback.  Aborting!!!\n");
            return (-1);
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

    /*
     * Do we need to enable SRP?
     */
    if (enable_srp) {
	srp_db = SRP_VBASE_new(NULL);
	if (!srp_db) {
	    printf("\nUnable allocate SRP verifier database.  Aborting!!!\n");
	    return(-1); 
	}
	if (SRP_VBASE_init(srp_db, srp_vfile) != SRP_NO_ERROR) {
	    printf("\nUnable initialize SRP verifier database %s.  Aborting!!!\n", srp_vfile);
	    return(-1); 
	}
	
	if (est_server_enable_srp(ectx, &ssl_srp_server_param_cb)) { 
	    printf("\nUnable to enable SRP.  Aborting!!!\n");
	    return(-1);
	}
    }

    coap_enabled = enable_coap;
    if (enable_coap) {
#ifdef HAVE_LIBCOAP
        if (est_server_set_dtls_session_max(ectx, coap_max_sessions)) {
            printf("\nUnable to set DTLS maximum sessions. Aborting!!!\n");
            return(-1);
        }

        printf("\nLaunching EST over CoAP server...\n");
        coap_port = 0;
        rv = est_server_coap_init_start(ectx, coap_port);
        if (rv != 0) {
            printf("\nFailed to init the coap library into server mode\n");
            return (-1);
        }
#else
        printf("\nCan't launch st_server in coap mode when est isn't built with"
               " libcoap\n");
        return (-1);
#endif
    } else {
        printf("\nLaunching EST server...\n");

        rv = est_server_start(ectx);
        if (rv != EST_ERR_NONE) {
            printf("\nFailed to init mg\n");
            return (-1);
        }
    }
    // Start master (listening) thread
    tcp_port = listen_port;
    pthread_create(&thread, NULL, master_thread, NULL);

    sleep(2);
    /*
     * clean up
     */

    return 0;
}

/*
 * Call this to start a simple EST server with legacy TLS 1.0
 * support enabled, which is not compliant.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_tls10 (int listen_port,
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
	                       trusted_certs_file, ossl_conf_file, 
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           1, 0, 0, 0, 0, 0);

    return (rv);
}

/*
 * Call this to start a simple EST server with CRL check enabled,
 * This server will not be thread safe.  It can only handle a single
 * EST request on the listening socket at any given time.
 * This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_crl (int listen_port,
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
	                       trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 1, 0, 0, 0);

    return (rv);
}

/*
 * Call this to start a simple EST server.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 0, 0, 0, 0);

    return (rv);
}

/*
 * Call this to start an EST over CoAP server.  This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_coap (int listen_port,
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
                           trusted_certs_file, ossl_conf_file, 
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 0, 0, 1, EST_DTLS_SESSION_MAX_DEF);

    return (rv);
}

/*
 * Call this to start an EST over CoAP server with the non-default number
 * of maximum sessions.  This server will not be thread safe.  It can only
 * handle a single EST request on the listening socket at any given time.
 * This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
 *  max_sessions:   Maximum number of DTLS sessions supported.
 */
int st_start_coap_sessions (int listen_port,
                            char *certfile,
                            char *keyfile,
                            char *realm,
                            char *ca_chain_file,
                            char *trusted_certs_file,
                            char *ossl_conf_file,
                            int simulate_manual_enroll,
                            int enable_pop,
                            int ec_nid,
                            int max_sessions)
{
    int rv;

    rv = st_start_internal(listen_port, certfile, keyfile, realm, ca_chain_file,
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 0, 0, 1, max_sessions);

    return (rv);
}

/*
 * Call this to start a simple EST server where the CAcerts are responded to
 * through the callback up to the application layer.  This server will not be
 * thread safe.  It can only handle a single EST request on the listening
 * socket at any given time.  This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_nocacerts (int listen_port,
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
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 1, 0, 0, 0, 0);

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
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
                           trusted_certs_file, ossl_conf_file, 0, enable_pop,
                           0, 1, vfile, 0, 0, 0, 0, 0, 0);

    return (rv);
}

/*
 * Call this to start a simple EST server with SRP *and* TLS1.0.
 * This server will not
 * be thread safe.  It can only handle a single EST request on
 * the listening socket at any given time.  This server will run
 * until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
 *  ca_chain_file:  PEM encoded certificates to use in the /cacerts
 *                  response to the client. 
 *  trusted_certs_file: PEM encoded certificates to use for authenticating
 *                  the EST client at the TLS layer. 
 *  ossl_conf_file: Configuration file that specifies the OpenSSL
 *                  CA to use.
 *  enable_pop:     Set to non-zero value to require Proof-of-possession check.
 *  vfile:          Full path name of OpenSSL SRP verifier file
 */
int st_start_srp_tls10 (int listen_port,
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
    /* Note here that the third to last parm turns on tls1.0 */
    rv = st_start_internal(listen_port, certfile, keyfile, realm, ca_chain_file,
                           trusted_certs_file, ossl_conf_file, 0, enable_pop, 0,
                           1, vfile, 1, 0, 0, 0, 0, 0);

    return (rv);
}

/*
 * Call this to start a simple EST server with event callbacks.
 * This server will not be thread safe.  It can only handle a single
 * EST request on the listening socket at any given time.
 * This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_events (int listen_port,
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
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 0, 1, 0, 0);
    return (rv);
}

/*
 * Call this to start a simple EST server using CoAP with event callbacks.
 * This server will not be thread safe.  It can only handle a single
 * EST request on the listening socket at any given time.
 * This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_coap_events (int listen_port,
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
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 0, 0, 1, 1, EST_DTLS_SESSION_MAX_DEF);
    return (rv);
}

/*
 * Call this to start a simple EST/CoAP server where the CAcerts are responded
 * to through the callback up to the application layer.  This server will not be
 * thread safe.  It can only handle a single EST request on the listening
 * socket at any given time.  This server will run until st_stop() is invoked.
 *
 * Parameters:
 *  listen_port:    Port number to listen on
 *  certfile:       PEM encoded certificate used for server's identity
 *  keyfile:        Private key associated with the certfile
 *  realm:          HTTP realm to present to the client
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
int st_start_coap_nocacerts (int listen_port,
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
                           trusted_certs_file, ossl_conf_file,
                           simulate_manual_enroll, enable_pop, ec_nid, 0, NULL,
                           0, 1, 0, 0, 1, EST_DTLS_SESSION_MAX_DEF);
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

void st_disable_cacerts_cb ()
{
    est_set_cacerts_cb(ectx, NULL);
}

void st_null_cacerts_cb ()
{
    est_set_cacerts_cb(ectx, &process_null_return);
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
    memset(valid_token_value, 0, MAX_AUTH_TOKEN_LEN+1);
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

void st_enable_crl ()
{
    est_enable_crl(ectx);
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

void st_set_read_timeout (int timeout)
{
    est_server_set_read_timeout(ectx, timeout);
}

/*
 * Call to enable or disable the writing of the CSR to a file
 * 1 = write, 0 = do NOT write (default)
 */
void st_write_csr (int state)
{
    write_csr = state;
}

/*
 * Change the default filename used when writing out the CSR to a file
 */
void st_csr_filename (char *incoming_name)
{
    if (incoming_name == NULL) {
#ifdef WIN32
        snprintf(csr_filename, MAX_FILENAME_LEN, "%s\\%s",
                 getenv(TEMP), "csr.p10");
#else
        snprintf(csr_filename, MAX_FILENAME_LEN, "%s", "/tmp/csr.p10");
#endif
    } else {
        snprintf(csr_filename, MAX_FILENAME_LEN, "%s", incoming_name);
    }
}

#if ENABLE_BRSKI
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
        if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
                        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
                return 0;
        }
        return -1;
}

static int dump(const char *js, jsmntok_t *t, size_t count, int indent) {
        int i, j, k;
        if (count == 0) {
                return 0;
        }
        if (t->type == JSMN_PRIMITIVE) {
                printf("%.*s", t->end - t->start, js+t->start);
                return 1;
        } else if (t->type == JSMN_STRING) {
                printf("'%.*s'", t->end - t->start, js+t->start);
                return 1;
        } else if (t->type == JSMN_OBJECT) {
                printf("\n");
                j = 0;
                for (i = 0; i < t->size; i++) {
                        for (k = 0; k < indent; k++) printf("  ");
                        j += dump(js, t+1+j, count-j, indent+1);
                        printf(": ");
                        j += dump(js, t+1+j, count-j, indent+1);
                        printf("\n");
                }
                return j+1;
        } else if (t->type == JSMN_ARRAY) {
                j = 0;
                printf("\n");
                for (i = 0; i < t->size; i++) {
                        for (k = 0; k < indent-1; k++) printf("  ");
                        printf("   - ");
                        j += dump(js, t+1+j, count-j, indent+1);
                        printf("\n");
                }
                return j+1;
        }
        return 0;
}

/*   { */
/*      "ietf-voucher:voucher": { */
/*        "nonce": "62a2e7693d82fcda2624de58fb6722e5", */
/*        "assertion": "logging" */
/*        "pinned-domain-cert": "<base64 encoded certificate>" */
/*        "serial-number": "JADA123456789" */
/*      } */
/*    } */
#define BRSKI_DEVICE_SERIAL_NUM "F7BE0D"
#define VOUCHER "{\n\r\"ietf-voucher:voucher\":{\n\r\"nonce\":\"%s\",\n\r\"assertion\":\"logging\",\n\r\"pinned-domain-cert\":\"%s\",\n\r\"serial-number\":\"%s\"}\n\r}"
#define VOUCHER_NONONCE "{\n\r\"ietf-voucher:voucher\":{\n\r\"assertion\":\"logging\",\n\r\"pinned-domain-cert\":\"%s\",\n\r\"serial-number\":\"%s\"}\n\r}"
#define VOUCHER_NOSERIAL "{\n\r\"ietf-voucher:voucher\":{\n\r\"assertion\":\"logging\",\n\r\"pinned-domain-cert\":\"%s\",\n\r}\n\r}"

#define EST_BRSKI_MAX_NONCE_LEN 256
#define EST_BRSKI_MAX_SERIAL_NUM_LEN 256

#define NONCE_TEMPLATE "\"nonce\":\"%s\""
#define SERIAL_NUM_TEMPLATE "\"serial-number\":\"%s\""
#define VOUCHER_TEMPLATE "{\n\r\"ietf-voucher:voucher\":{\n\r%s,\n\r\"assertion\":\"logging\",\n\r\"pinned-domain-cert\":\"%s\",\n\r%s}\n\r}"


/*
 * Callback function used by EST stack to process a BRSK 
 * voucher request.  The parameters are:
 *
 *   voucher_req Contains the voucher request from the client
 *   voucher_req_len Length of the voucher request
 *   voucher     Pointer to a buffer pointer that will contain
 *               the voucher to be returned
 *   voucher_len Pointer to an integer that will be set to the length
 *               of the returned voucher.
 *   peer_cert - client certificate, if available, in internal X509
 *               structure format
 */
static
EST_BRSKI_CALLBACK_RC
process_brski_voucher_request (char *voucher_req, int voucher_req_len,
                               char **voucher, int *voucher_len, X509 *peer_cert)
{
    char *voucher_buf = NULL;
    jsmn_parser p;
    jsmntok_t *tok;
    size_t tokcount = 100;
    int parser_resp;
    int i;
    int nonce_found = 0;
    int incoming_server_cert_found = 0;
    char incoming_nonce[EST_BRSKI_VOUCHER_REQ_NONCE_SIZE+1];
    char incoming_server_cert[EST_BRSKI_MAX_CACERT_LEN+1];
    char *ser_num_str = NULL;

    char *nonce_buf = NULL;
    char *serial_num_buf = NULL;

    char *signed_voucher_buf;    
    BUF_MEM *buf_mem_ptr;

    BIO *voucher_bio = NULL;
#ifdef CMS_SIGNING
    BIO *cms_bio_out = NULL;
    CMS_ContentInfo *voucher_cms = NULL;
#else
    PKCS7 *voucher_p7 = NULL;
    BIO *out = NULL;
#ifdef BASE64_ENCODE_VOUCHERS
    BIO *b64 = NULL;
#endif /* BASE64_ENCODE_VOUCHERS */
#endif            
    int rc;    
    
    memset(incoming_nonce, 0, EST_BRSKI_VOUCHER_REQ_NONCE_SIZE+1);

    printf("BRSKI voucher request received\n");
    printf(" voucher_req = %s\n voucher_req_len = %d\n",
           voucher_req, voucher_req_len);

    /*
     * If configured to perform retries, alternate between
     * sending the retry and sending the voucher response.
     * Unlike simple enroll retry processing, there is nothing
     * in the voucher request to key off of to determine if
     * the voucher request has been seen before, so the only
     * option is to toggle based on time.  This can be more
     * error prone if the test code gets out of sync with
     * this toggling.
     */
    if (brski_retry_enabled) {
        if (brski_retry_running_count) {
            brski_retry_running_count--; 
            return (EST_BRSKI_CB_RETRY);
        } else {
            brski_retry_running_count = brski_retry_count;            
            /*
             * Continue on with sending the voucher response
             */
        }
    }
    
    /*
     * Parse the voucher request and obtain the nonce
     */
    jsmn_init(&p);
    tok = calloc(tokcount, sizeof(*tok));
    if (tok == NULL) {
        printf("calloc(): errno=%d\n", errno);
        return 3;
    }
    parser_resp = jsmn_parse(&p, (char *)voucher_req, (size_t)voucher_req_len,
                             tok, tokcount);
    if (parser_resp < 0) {
        printf("Voucher request parse failed. parse error = %d\n", parser_resp);
    } else {
        dump((char *)voucher_req, tok, p.toknext, 0);
        printf("Voucher request parsed\n");
    }
    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(voucher_req, &tok[i], "nonce") == 0) {
            sprintf(incoming_nonce, "%.*s", tok[i+1].end-tok[i+1].start,
                    voucher_req + tok[i+1].start);            
            printf("Found nonce %s\n", incoming_nonce);
            nonce_found = 1;
            break;
        }
    }
    if (!nonce_found) {
        printf("Nonce missing from voucher request\n");
        return (EST_BRSKI_CB_FAILURE);
    }

    /*
     * Now look for the Registrar's cert
     */
    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(voucher_req, &tok[i], "proximity-registrar-cert") == 0) {
            sprintf(incoming_server_cert, "%.*s", tok[i+1].end-tok[i+1].start,
                    voucher_req + tok[i+1].start);            
            printf("Found proximity registrar cert %s\n", incoming_server_cert);
            incoming_server_cert_found = 1;
            break;
        }
    }
    if (!incoming_server_cert_found) {
        printf("Proximity registrar cert missing from voucher request\n");
        return (EST_BRSKI_CB_FAILURE);
    }

    free(tok);
    
    /*
     * Obtain the serial number of the pledge device from its ID cert
     */
    ser_num_str = est_find_ser_num_in_subj(peer_cert);
    if (ser_num_str == NULL) {
        char *subj;

        printf("Pledge MFG cert does not contain a serial number.");

        subj = X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0);
        printf("Client MFG cert subject: %s", subj);
        OPENSSL_free(subj);
        
        return (EST_ERR_CLIENT_BRSKI_SERIAL_NUM_MISSING);        
    }
    
    voucher_buf = calloc(EST_BRSKI_MAX_VOUCHER_LEN, sizeof(char));
    if (voucher_buf) {
        
        if (brski_send_nonce) {

            nonce_buf = calloc(EST_BRSKI_MAX_NONCE_LEN+1, sizeof(char));
            
            if (brski_nonce_too_long) {

                snprintf(nonce_buf, EST_BRSKI_MAX_NONCE_LEN, NONCE_TEMPLATE,
                         "123456789012345678901234567890123");
                
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         "123456789012345678901234567890123", p7_ca_certs, */
/*                                         ser_num_str); */
            } else if (brski_nonce_mismatch) {
                snprintf(nonce_buf, EST_BRSKI_MAX_NONCE_LEN, NONCE_TEMPLATE,
                         "12345678901234567890123456789012");
                
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         "12345678901234567890123456789012", p7_ca_certs, */
/*                                         ser_num_str); */
            } else {
                snprintf(nonce_buf, EST_BRSKI_MAX_NONCE_LEN, NONCE_TEMPLATE,
                         incoming_nonce);
                
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         incoming_nonce, p7_ca_certs, */
/*                                         ser_num_str); */
            }
        } else {
/*             *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER_NONONCE, */
/*                                     p7_ca_certs, */
/*                                     ser_num_str);             */
        }

        
        if (brski_send_serial_num) {

            serial_num_buf = calloc(EST_BRSKI_MAX_NONCE_LEN+1, sizeof(char));
            if (serial_num_buf == NULL) {
                printf("calloc(): errno=%d\n", errno);
                return 3;
            }
            
            if (brski_serial_num_too_long) {
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         "123456789012345678901234567890123", p7_ca_certs, */
/*                                         ser_num_str); */
                snprintf(serial_num_buf, EST_BRSKI_MAX_SERIAL_NUM_LEN, SERIAL_NUM_TEMPLATE,
                         "SERIAL-NUM-TOO-LONG0123456789012345678901234567890123456789012345");
            } else if (brski_serial_num_mismatch) {
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         "12345678901234567890123456789012", p7_ca_certs, */
/*                                         ser_num_str); */
                snprintf(serial_num_buf, EST_BRSKI_MAX_SERIAL_NUM_LEN, SERIAL_NUM_TEMPLATE,
                         "SERIAL-NUM-MISMATCH012345678901234567890123456789012345678901234");
            } else {
/*                 *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER, */
/*                                         incoming_nonce, p7_ca_certs, */
/*                                         ser_num_str); */
                snprintf(serial_num_buf, EST_BRSKI_MAX_SERIAL_NUM_LEN, SERIAL_NUM_TEMPLATE,
                         ser_num_str);
            }
        } else {
/*             *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER_NONONCE, */
/*                                     p7_ca_certs, */
/*                                     ser_num_str);             */
        }
        
/*         *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER_TEMPLATE, */
/*                                 nonce_buf, p7_ca_certs, serial_num_buf); */
        *voucher_len = snprintf(voucher_buf, EST_BRSKI_MAX_VOUCHER_LEN, VOUCHER_TEMPLATE,
                                nonce_buf, p7_ca_certs, serial_num_buf);
        *voucher = voucher_buf;
        
        free(nonce_buf);
        free(serial_num_buf);
        
        /*
         * If the MASA CA has been enabled then sign the voucher with the MASA's
         * signing key
         */
        if (masa_ca_enabled) {

            signed_voucher_buf = calloc(EST_BRSKI_MAX_VOUCHER_LEN, sizeof(char));
            if (signed_voucher_buf == NULL) {
                printf("calloc(): errno=%d\n", errno);
                return (EST_BRSKI_CB_FAILURE);
            }
            
            voucher_bio = BIO_new_mem_buf(voucher_buf, *voucher_len);
            if (voucher_bio == NULL) {
                printf("Unable to assign voucher to BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#ifdef CMS_SIGNING
            voucher_cms = CMS_sign(masa_ca_root, masa_ca_priv_key, NULL, voucher_bio,
                                   (CMS_BINARY|CMS_NOSMIMECAP));
            if (voucher_cms == NULL) {
                printf("Unable to sign voucher");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#else       
            voucher_p7 = PKCS7_sign(masa_ca_root, masa_ca_priv_key, NULL, voucher_bio,
                                    (PKCS7_BINARY|PKCS7_NOSMIMECAP));
            if (voucher_p7 == NULL) {
                printf("Unable to sign voucher");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#endif

/*
 * For now, this is not going to be set.  It eventually needs to be set to
 * the OID that has been reserved that represents "JSON-encoded voucher" per
 * voucher profile 06, "An eContentType of TBD1 indicates the content is a JSON-
 * encoded voucher."
 */
#if 0
            /* Set inner content type to signed PKCS7 receipt */
            /* PDB NOTE: probably not needed.  It appears that it's already set to
             * this contentType */
            if (!CMS_set1_eContentType(voucher_cms, OBJ_nid2obj(NID_pkcs7_signed))) {
                printf("Unable to assign ContentType to CMS structure");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#endif
#ifdef CMS_SIGNING
            /*
             * convert it into something that can be sent in the voucher
             * response
             */
            cms_bio_out = BIO_new(BIO_s_mem());
            if (cms_bio_out == NULL) {
                printf("Unable to create output BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
            
            rc = PEM_write_bio_CMS(cms_bio_out, voucher_cms);
            
            if (rc == 0) {
                printf("Unable to assign voucher to output BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }                

            char buf[1024*20];
            
            memset(&buf[0], 0, 1024*20);
            BIO_get_mem_ptr(cms_bio_out, &buf_mem_ptr);
            memcpy(signed_voucher_buf, buf_mem_ptr->data, buf_mem_ptr->length);

/*             len = BIO_get_mem_data(cms_bio_out, (char**) &buf); */
/*             printf("%d\n", len); */
            
/*             rc = PEM_write_bio_CMS_stream(cms_bio_out, voucher_cms,  ); */
/*             if (!rc) { */
/*                 printf("Error in PEM_write_bio_PKCS7"); */
/*                 st_ossl_dump_ssl_errors(); */
/*                 return (EST_BRSKI_CB_FAILURE); */
/*             }             */       
#else
#ifdef BASE64_ENCODE_VOUCHERS        
            b64 = BIO_new(BIO_f_base64());
            if (!b64) {
                printf("BIO_new failed for b64 output BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#endif /* BASE64_ENCODE_VOUCHERS */
            out = BIO_new(BIO_s_mem());
            if (!out) {
                printf("BIO_new failed for output BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
#ifdef BASE64_ENCODE_VOUCHERS        
            out = BIO_push(b64, out);
#endif /* BASE64_ENCODE_VOUCHERS */
            rc = i2d_PKCS7_bio(out, voucher_p7);
            (void)BIO_flush(out);
            if (!rc) {
                printf("Unable to assign voucher to output BIO");
                st_ossl_dump_ssl_errors();
                return (EST_BRSKI_CB_FAILURE);
            }
            
            BIO_get_mem_ptr(out, &buf_mem_ptr);
            memcpy(signed_voucher_buf, buf_mem_ptr->data, buf_mem_ptr->length);

            /*
             * Return the signed voucher
             */
            *voucher = signed_voucher_buf;
            *voucher_len = buf_mem_ptr->length;
            
            if (voucher_p7 != NULL) {
                PKCS7_free(voucher_p7);
            }
#endif
        }
        
        printf("Voucher to be returned =\n%s\n", *voucher);
        
    } else {
        *voucher = NULL;
        *voucher_len = 0;
        return (EST_BRSKI_CB_FAILURE);
    }

    return EST_BRSKI_CB_SUCCESS;
}

/*
 * Callback function used by EST stack to process a BRSKI
 * voucher status indication.  The parameters are:
 *
 *   voucher_status Contains the voucher status from the client
 *   voucher_status_len Length of the voucher status
 *   peer_cert - client certificate, if available, in internal X509
 *               structure format
 *
 */
static EST_BRSKI_CALLBACK_RC
process_brski_voucher_status (char *voucher_status, int voucher_status_len, X509 *peer_cert)
{
    jsmn_parser p;
    jsmntok_t *tok;
    size_t tokcount = 100;
    int parser_resp;
    int i;
    int status_found = 0;
    char incoming_status[5+1];
    int reason_found = 0;
    char incoming_reason[EST_BRSKI_MAX_REASON_LEN];
    
    memset(incoming_status, 0, 5+1);

    printf("BRSKI voucher status received\n");
    printf(" voucher_status = %s\n voucher_status_len = %d\n",
           voucher_status, voucher_status_len);
    
    /*
     * Parse the voucher response and obtain the status and reason
     */
    jsmn_init(&p);
    tok = calloc(tokcount, sizeof(*tok));
    if (tok == NULL) {
        printf("calloc(): errno=%d\n", errno);
        return 3;
    }
    parser_resp = jsmn_parse(&p, (char *)voucher_status, (size_t)voucher_status_len,
                             tok, tokcount);
    if (parser_resp < 0) {
        printf("Voucher response parse failed. parse error = %d\n", parser_resp);
    } else {
        dump((char *)voucher_status, tok, p.toknext, 0);
        printf("Voucher status parsed\n");
    }
    
    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(voucher_status, &tok[i], "Status") == 0) {
            sprintf(incoming_status, "%.*s", tok[i+1].end-tok[i+1].start,
                    voucher_status + tok[i+1].start);            
            printf("Found status %s\n", incoming_status);
            status_found = 1;
            break;
        }
    }
    if (!status_found) {
        printf("Status value missing from voucher status\n");
        return (EST_BRSKI_CB_FAILURE);
    }

    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(voucher_status, &tok[i], "Reason") == 0) {
            sprintf(incoming_reason, "%.*s", tok[i+1].end-tok[i+1].start,
                    voucher_status + tok[i+1].start);            
            printf("Found reason: %s\n", incoming_reason);
            reason_found = 1;
            break;
        }
    }
    if (!reason_found) {
        printf("Reason value missing from voucher status\n");
        return (EST_BRSKI_CB_FAILURE);
    }
    
    free(tok);
    return EST_BRSKI_CB_SUCCESS;
}

/*
 * Callback function used by EST stack to process a BRSK 
 * enrollment status.  The parameters are:
 *
 *   voucher_req Contains the voucher request from the client
 *   voucher_req_len Length of the voucher request
 *   voucher     Pointer to a buffer pointer that will contain
 *               voucher/
 *   voucher_len Pointer to an integer that will be set to the length
 *               of the returned voucher.
 *
 */
static EST_BRSKI_CALLBACK_RC 
process_brski_enroll_status (char *enroll_status, int enroll_status_len, X509 *peer_cert)
{
    jsmn_parser p;
    jsmntok_t *tok;
    size_t tokcount = 100;
    int parser_resp;
    int i;
    int status_found = 0;
    char incoming_status[5+1];
    int reason_found = 0;
    char incoming_reason[EST_BRSKI_MAX_REASON_LEN];
    
    memset(incoming_status, 0, 5+1);

    printf("BRSKI enroll status received\n");
    printf(" enroll_status = %s\n enroll_status_len = %d\n",
           enroll_status, enroll_status_len);

    /*
     * Parse the voucher response and obtain the status and reason
     */
    jsmn_init(&p);
    tok = calloc(tokcount, sizeof(*tok));
    if (tok == NULL) {
        printf("calloc(): errno=%d\n", errno);
        return 3;
    }
    parser_resp = jsmn_parse(&p, (char *)enroll_status, (size_t)enroll_status_len,
                             tok, tokcount);
    if (parser_resp < 0) {
        printf("Enroll response parse failed. parse error = %d\n", parser_resp);
    } else {
        dump((char *)enroll_status, tok, p.toknext, 0);
        printf("Enroll status parsed\n");
    }
    
    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(enroll_status, &tok[i], "Status") == 0) {
            sprintf(incoming_status, "%.*s", tok[i+1].end-tok[i+1].start,
                    enroll_status + tok[i+1].start);            
            printf("Found status %s\n", incoming_status);
            status_found = 1;
            break;
        }
    }
    if (!status_found) {
        printf("Status value missing from enroll status\n");
        return (EST_BRSKI_CB_FAILURE);
    }

    for (i = 1; i < parser_resp; i++) {
        if (jsoneq(enroll_status, &tok[i], "Reason") == 0) {
            sprintf(incoming_reason, "%.*s", tok[i+1].end-tok[i+1].start,
                    enroll_status + tok[i+1].start);            
            printf("Found reason: %s\n", incoming_reason);
            reason_found = 1;
            break;
        }
    }
    if (!reason_found) {
        printf("Reason value missing from enroll status\n");
        return (EST_BRSKI_CB_FAILURE);
    }

    free(tok);
    return EST_BRSKI_CB_SUCCESS;    
}

int st_set_brski_mode (void)
{
    int rc;
    
    if (est_set_brski_voucher_req_cb(ectx, &process_brski_voucher_request)) {
        printf(
            "\nUnable to set EST BRSKI voucher request callback.  Aborting!!!\n");
        return(-1);
    }
    if (est_set_brski_voucher_status_cb(ectx, &process_brski_voucher_status)) {
        printf(
            "\nUnable to set EST BRSKI voucher request callback.  Aborting!!!\n");
        return(-1);
    }
    if (est_set_brski_enroll_status_cb(ectx, &process_brski_enroll_status)) {
        printf(
            "\nUnable to set EST BRSKI voucher request callback.  Aborting!!!\n");
        return(-1);
    }

    /*
     * For EST /cacerts, the CA certs response can be processed two ways,
     * they can be provided to the EST library and the library repsonds
     * directly, or the application layer can provide a call back and
     * it provides the response buffer containing the CA certs.  The estserver
     * test app does it the first way, so the EST library responds directly.
     * With BRSKI, this response of the CA certs is contained in the voucher, so
     * the application layer needs to be responsible for preparing the response.
     * The following code is replicated from the EST library.
     */
    /*
     * Convert the PEM encoded buffer previously read the file into the
     * PKCS7 buffer used for responding to /cacerts requests
     */
    rc = load_ca_certs(ectx, cacerts_raw, cacerts_len);
    if (rc != 0) {
        printf("\nUnable to convert CA certs chain in PEM format to PKCS7."
               " Aborting!!!\n");
        return (-1);
    }
    return (0);
}

/*
 * Used to control the retry-after mode of the voucher request processing
 */
int st_set_brski_retry_mode (int enable_retry, int retry_delay, int retry_count)
{    
    /*
     * reset the retry-after logic
     */
    brski_retry_delay = retry_delay;
    if (EST_ERR_NONE != est_server_set_brski_retry_period(ectx, brski_retry_delay)) {
        printf("\nFailed to set retry period in context\n");
        return (-1);
    }    
    brski_retry_running_count = brski_retry_count = retry_count;
    brski_retry_enabled = enable_retry;

    printf("\nSetting retry mode to:\n"
           "  retry_enabled = %d\n"
           "  retry_delay = %d\n"
           "  retry_count = %d\n",
           brski_retry_enabled,
           brski_retry_delay,
           brski_retry_count);
    
    return (0);
}

/*
 * Used to control the nonce error processing
 */
int st_set_brski_nonce_mode (int send_nonce, int nonce_too_long,
                             int nonce_mismatch)
{    
    /*
     * set the retry-after testing logic
     */
    brski_send_nonce = send_nonce;
    brski_nonce_too_long = nonce_too_long;
    brski_nonce_mismatch = nonce_mismatch;

    printf("\nSetting nonce mode to:\n"
           "  send_nonce = %d\n"
           "  send_nonce_too_long = %d\n"
           "  send_nonce_mismatch = %d\n",
           brski_send_nonce,
           brski_nonce_too_long,
           brski_nonce_mismatch);
    
    return (0);
}

/*
 * Used to control the serial number error processing
 */
int st_set_brski_serial_num_mode (int send_serial_num, int serial_num_too_long,
                                  int serial_num_mismatch)
{    
    /*
     * set the serial number testing logic
     */
    brski_send_serial_num = send_serial_num;
    brski_serial_num_too_long = serial_num_too_long;
    brski_serial_num_mismatch = serial_num_mismatch;

    printf("\nSetting serial_num mode to:\n"
           "  send_serial_num = %d\n"
           "  send_serial_num_too_long = %d\n"
           "  send_serial_num_mismatch = %d\n",
           brski_send_serial_num,
           brski_serial_num_too_long,
           brski_serial_num_mismatch);
    
    return (0);
}


/*
 * Used to set up the MASA credentials to be used to sign vouchers
 */
int st_set_brski_masa_credentials (char *masa_root_ca_file, char *masa_priv_key_file)
{
    BIO *certin;    

    /*
     * read in the MASA CA root cert
     */
    if (masa_root_ca_file[0]) {
        certin = BIO_new(BIO_s_file());
        if (certin == NULL) {
            printf("Unable to create BIO");
            return (-1);
        }
        if (BIO_read_filename(certin, masa_root_ca_file) <= 0) {
            printf("\nUnable to read MASA root CA certificate file %s\n", masa_root_ca_file);
            return (-1);
        }
        /*
         * This reads the file, which is expected to be PEM encoded. 
         */
        masa_ca_root = PEM_read_bio_X509(certin, NULL, NULL, NULL);
        if (masa_ca_root == NULL) {
            printf("\nError while reading PEM encoded MASA CA Root certificate file %s\n", masa_root_ca_file);
            return (-1);
        }
        BIO_free(certin);
    }

    /*
     * read in the matching MASA private key
     */
    if (masa_priv_key_file[0]) {
        masa_ca_priv_key = read_private_key(masa_priv_key_file);
        if (masa_ca_priv_key == NULL) {
            printf("\nError while reading PEM encoded MASA CA private key file %s\n",
                   masa_priv_key_file);
            return (-1);
        }
    }

    masa_ca_enabled = 1;
    
    return (0);
}
#endif

/* Used to enable Enhanced Cert Auth mode on the st server */
int st_enable_enhanced_cert_auth (int nid, char *ah_pwd,
                                  EST_ECA_CSR_CHECK_FLAG csr_check_flag)
{
    return est_server_enable_enhanced_cert_auth(ectx, nid, ah_pwd,
                                                csr_check_flag);
}

/* Used to add manufacturer info to the mfg_info_list when using st server */
int st_enhanced_cert_auth_add_mfg_info (char *mfg_name, int mfg_subj_field_nid,
                                        unsigned char *truststore_buf,
                                        int truststore_buf_len)
{
    return est_server_enhanced_cert_auth_add_mfg_info(
        ectx, mfg_name, mfg_subj_field_nid, truststore_buf, truststore_buf_len);
}

/* Used to disable Enhanced Cert Auth mode on the st server */
int st_disable_enhanced_cert_auth (void)
{
    return est_server_disable_enhanced_cert_auth(ectx);
}

int st_server_set_http_auth_cb (int (*cb)(EST_CTX *ctx,
                                          EST_HTTP_AUTH_HDR *ah,
                                          X509 *peer_cert,
                                          char *path_seg,
                                          void *app_data))
{
    return est_set_http_auth_cb(ectx, cb);
}

void st_set_dtls_handshake_timeout (int timeout)
{
    est_server_set_dtls_handshake_timeout(ectx, timeout);
}

EST_ERROR st_server_enable_performance_timers() 
{
    return est_enable_performance_timers(ectx);
}

EST_ERROR st_server_disable_performance_timers() 
{
    return est_disable_performance_timers(ectx);
}
