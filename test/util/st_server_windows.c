/*------------------------------------------------------------------
 * st_server_windows.c - Windows port of st_server test utility.
 *                       Does not support dual stack IPv6 sockets
 *
 * March, 2016
 *
 * Copyright (c) 2016, 2017 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 */

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <WS2tcpip.h>
#include <string.h>
#include <windows.h> 
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#include <search.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <est.h>
#include "ossl_srv.h"
#include "test_utils.h"

#ifdef WIN32
#define close(socket) closesocket(socket)
#define snprintf _snprintf
#endif 

#pragma comment(lib, "Ws2_32.lib")

#define NON_BLOCKING_SOCKET 1
#define MAX_CERT_LEN 8192
#define MAX_FILENAME_LEN 255

WSADATA wsaData;

BIO *bio_err = NULL;
static int tcp_port;
static int manual_enroll = 0;
volatile int stop_flag = 0;
int ipv6_flag = 0;
unsigned char *cacerts_raw = NULL;
int cacerts_len = 0;
EST_CTX *ectx;
SRP_VBASE *srp_db = NULL;
unsigned char *trustcerts = NULL;
int trustcerts_len = 0;
static char conf_file[255];
static char *csr_attr_value = NULL;
int write_csr = 0;
static char csr_filename[MAX_FILENAME_LEN];

static char valid_token_value[MAX_AUTH_TOKEN_LEN + 1];

extern void dumpbin(char *buf, size_t len);

char tst_srvr_path_seg_auth[EST_MAX_PATH_SEGMENT_LEN + 1];

char tst_srvr_path_seg_enroll[EST_MAX_PATH_SEGMENT_LEN + 1];
char tst_srvr_path_seg_cacerts[EST_MAX_PATH_SEGMENT_LEN + 1];
char tst_srvr_path_seg_csrattrs[EST_MAX_PATH_SEGMENT_LEN + 1];

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
    static unsigned char dh1024_p[] = {
            0xC8, 0x00, 0xF7, 0x08, 0x07, 0x89, 0x4D, 0x90, 0x53, 0xF3, 0xD5, 0x00,
            0x21, 0x1B, 0xF7, 0x31, 0xA6, 0xA2, 0xDA, 0x23, 0x9A, 0xC7, 0x87, 0x19,
            0x3B, 0x47, 0xB6, 0x8C, 0x04, 0x6F, 0xFF, 0xC6, 0x9B, 0xB8, 0x65, 0xD2,
            0xC2, 0x5F, 0x31, 0x83, 0x4A, 0xA7, 0x5F, 0x2F, 0x88, 0x38, 0xB6, 0x55,
            0xCF, 0xD9, 0x87, 0x6D, 0x6F, 0x9F, 0xDA, 0xAC, 0xA6, 0x48, 0xAF, 0xFC,
            0x33, 0x84, 0x37, 0x5B, 0x82, 0x4A, 0x31, 0x5D, 0xE7, 0xBD, 0x52, 0x97,
            0xA1, 0x77, 0xBF, 0x10, 0x9E, 0x37, 0xEA, 0x64, 0xFA, 0xCA, 0x28, 0x8D,
            0x9D, 0x3B, 0xD2, 0x6E, 0x09, 0x5C, 0x68, 0xC7, 0x45, 0x90, 0xFD, 0xBB,
            0x70, 0xC9, 0x3A, 0xBB, 0xDF, 0xD4, 0x21, 0x0F, 0xC4, 0x6A, 0x3C, 0xF6,
            0x61, 0xCF, 0x3F, 0xD6, 0x13, 0xF1, 0x5F, 0xBC, 0xCF, 0xBC, 0x26, 0x9E,
            0xBC, 0x0B, 0xBD, 0xAB, 0x5D, 0xC9, 0x54, 0x39,
    };
    static unsigned char dh1024_g[] = {
            0x3B, 0x40, 0x86, 0xE7, 0xF3, 0x6C, 0xDE, 0x67, 0x1C, 0xCC, 0x80, 0x05,
            0x5A, 0xDF, 0xFE, 0xBD, 0x20, 0x27, 0x74, 0x6C, 0x24, 0xC9, 0x03, 0xF3,
            0xE1, 0x8D, 0xC3, 0x7D, 0x98, 0x27, 0x40, 0x08, 0xB8, 0x8C, 0x6A, 0xE9,
            0xBB, 0x1A, 0x3A, 0xD6, 0x86, 0x83, 0x5E, 0x72, 0x41, 0xCE, 0x85, 0x3C,
            0xD2, 0xB3, 0xFC, 0x13, 0xCE, 0x37, 0x81, 0x9E, 0x4C, 0x1C, 0x7B, 0x65,
            0xD3, 0xE6, 0xA6, 0x00, 0xF5, 0x5A, 0x95, 0x43, 0x5E, 0x81, 0xCF, 0x60,
            0xA2, 0x23, 0xFC, 0x36, 0xA7, 0x5D, 0x7A, 0x4C, 0x06, 0x91, 0x6E, 0xF6,
            0x57, 0xEE, 0x36, 0xCB, 0x06, 0xEA, 0xF5, 0x3D, 0x95, 0x49, 0xCB, 0xA7,
            0xDD, 0x81, 0xDF, 0x80, 0x09, 0x4A, 0x97, 0x4D, 0xA8, 0x22, 0x72, 0xA1,
            0x7F, 0xC4, 0x70, 0x56, 0x70, 0xE8, 0x20, 0x10, 0x18, 0x8F, 0x2E, 0x60,
            0x07, 0xE7, 0x68, 0x1A, 0x82, 0x5D, 0x32, 0xA2,
    };
    DH *dh;

    if ((dh = DH_new()) == NULL) {
        return(NULL);
    }
    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
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
struct lookup_entry{
    unsigned char  *data;  //this will hold the pub key from the cert request
    int		    length;
    struct lookup_entry * next;
};

typedef struct lookup_entry LOOKUP_ENTRY;

/*
 * This is the head of our linked list
 */
struct lookup_entry *lookup_root = NULL;

static int compare(const void *pa, const void *pb)
{
    LOOKUP_ENTRY *a = (LOOKUP_ENTRY *)pa;
    struct lookup_entry *b = (LOOKUP_ENTRY *)pb;
    if (a->length > b->length) {
        return 1;
    }
    if (a->length < b->length) {
        return -1;
    }
    return (memcmp(a->data, b->data, a->length));
}

static void free_lookup(void *node)
{
    LOOKUP_ENTRY *n = (LOOKUP_ENTRY *)node;
    if (n->data) free(n->data);
    free(n);
}


static LOOKUP_ENTRY * search_list(LOOKUP_ENTRY *head, LOOKUP_ENTRY* target){

    LOOKUP_ENTRY * tmp = head;
    LOOKUP_ENTRY * tmp_prev = NULL;

    while (tmp && compare(tmp, target)){
        tmp_prev = tmp;
        tmp = tmp->next;
    }

    if (tmp == NULL){
        return NULL;
    }

    return tmp;
}

static LOOKUP_ENTRY * delete_lookup_entry(LOOKUP_ENTRY *head, LOOKUP_ENTRY * target)
{
    LOOKUP_ENTRY *tmp = head;
    LOOKUP_ENTRY *tmp_prev = NULL;

    /* look for the node that matches d, but also remember the node
	that points to it, tmp_prev, so that we can create a new link
     */

    while (tmp && compare(tmp, target))
    {
        tmp_prev = tmp;
        tmp = tmp->next;
    }

    /* did we fail to find the node? */
    if (tmp == NULL)
        return NULL;

    /* otherwise, remove the node */

    if (tmp == head)
    {
        /* remove head of list */
        head = head->next;
    }
    else
    {
        tmp_prev->next = tmp->next;
    }

    /* free matching node */
    free_lookup(tmp);
    return head;
}

static void add_entry(LOOKUP_ENTRY * head, LOOKUP_ENTRY *new_node){

    LOOKUP_ENTRY * tmp = head;

    if (tmp->next == NULL){
        tmp->next = new_node;
    }
    else {
        while (TRUE){
            if (tmp->next == NULL){
                tmp->next = new_node;
                break;
            }
            tmp = tmp->next;
        }

    }

}

static void destroy_lookup_table(LOOKUP_ENTRY * head){

    LOOKUP_ENTRY * tmp;

    while (head) {
        tmp = head;
        head = head->next;
        free_lookup(tmp);
    }

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
 *
 * Windows: Rewriting to forgo the use of search.h API
 * lookup table will be implemented as a basic linked list
 */
static int lookup_pkcs10_request(unsigned char *pkcs10, int p10_len)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    BIO *b64;
    EVP_PKEY *pkey = NULL;
    BUF_MEM *bptr;
    int rv;
    LOOKUP_ENTRY  *l;
    LOOKUP_ENTRY  *n;

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
    n = malloc(sizeof(LOOKUP_ENTRY));
    n->data = malloc(bptr->length);
    n->length = bptr->length;
    memcpy(n->data, bptr->data, n->length);
    n->next = NULL;
    l = search_list(lookup_root, n);
    if (l) {
        /* We have a match, allow the enrollment */
        rv = 1;
        lookup_root = delete_lookup_entry(lookup_root, n);
        printf("\nRemoving key from lookup table:\n");
        dumpbin((char*)n->data, n->length);
        free(n->data);
        free(n);
    }
    else {
        /* Not a match, add it to the list and return */

        if (lookup_root == NULL){
            /*
             * Initialize the list
             */
            lookup_root = n;
        }
        else {
            add_entry(lookup_root, n);
        }
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


/****************************************************************************************
 * The following funcitons are the callbacks used by libest.a to bind
 * the EST stack to the HTTP/SSL layer and the CA server.
 ***************************************************************************************/
#define MAX_CERT_LEN 8192
/*
 * Callback function used by EST stack to process a PKCS10
 * enrollment request with the CA.
 */
static int process_pkcs10_enrollment(unsigned char * pkcs10, int p10_len,
                                     unsigned char **cert, int *cert_len,
                                     char *uid, X509 *peercert, char *path_seg, void *app_data)
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
        }
        else {
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
        *cert = malloc(*cert_len);
        memcpy(*cert, buf, *cert_len);
    }

    BIO_free_all(result);
    return EST_ERR_NONE;
}

//This CSR attributes contains the challengePassword OID and others
#define TEST_CSR "MCYGBysGAQEBARYGCSqGSIb3DQEJBwYFK4EEACIGCWCGSAFlAwQCAg==\0"

static unsigned char * process_csrattrs_request(int *csr_len, char *path_seg,
                                                X509 *peer_cert, void *app_data)
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
        strncpy((char *)csr_data, csr_attr_value, *csr_len + 1);
    }
    else {
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
void ossl_dump_ssl_errors()
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
    printf("OSSL error: %s\n", bptr->data);
    BIO_free_all(e);
}


/*
 * This function is used to read the CERTS in a BIO and build a
 * stack of X509* pointers.  This is used during the PEM to
 * PKCS7 conversion process.
 */
static int add_certs_from_BIO(STACK_OF(X509) *stack, BIO *in)
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


static BIO *get_certs_pkcs7(BIO *in, int do_base_64)
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
        ossl_dump_ssl_errors();
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
            ossl_dump_ssl_errors();
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
        ossl_dump_ssl_errors();
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
static int load_ca_certs(EST_CTX *ctx, unsigned char *pem_cacerts, int pem_cacerts_len)
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

    p7_ca_certs_len = (int)BIO_get_mem_data(cacerts_bio, (char**)&retval);
    if (p7_ca_certs_len <= 0) {
        printf("Failed to copy PKCS7 data\n");
        BIO_free_all(cacerts_bio);
        BIO_free(in_bio);
        return (-1);
    }

    p7_ca_certs = malloc(p7_ca_certs_len);
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


static unsigned char * process_cacerts_request(int *cacerts_len, char *path_seg,
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

static char digest_user[3][32] =
{
        "estuser",
        "estrealm",
        "36807fa200741bb0e8fb04fcf08e2de6" //This is the HA1 precaculated value
};

/*
 * Return 1 to signal the user is valid, 0 to fail the auth
 */
static int process_http_auth(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah,
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
static int ssl_srp_server_param_cb(SSL *s, int *ad, void *arg) {

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
        destroy_lookup_table(lookup_root);
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

static DWORD WINAPI master_thread_v4(LPVOID lpParam)
{
    int sock;
    struct sockaddr_in addr;
    int on = 1;
    int rc;
    int new;
    int unsigned len;

    u_long iMode = NON_BLOCKING_SOCKET;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(tcp_port);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        fprintf(stderr, "\nsocket call failed\n");
        exit(1);
    }
    // Needs to be done to bind to both :: and 0.0.0.0 to the same port

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));

    /*
	Replace POSIX code with Windows equivalent for setting non-blocking socket
     */
    ioctlsocket(sock, FIONBIO, &iMode);

    rc = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (rc == -1) {
        fprintf(stderr, "\nbind call failed\n");
        exit(1);
    }
    listen(sock, SOMAXCONN);
    stop_flag = 0;

    while (stop_flag == 0) {
        len = sizeof(addr);
        new = accept(sock, (struct sockaddr*)&addr, &len);
        if (new < 0) {
            /*
             * this is a bit cheesy, but much easier to implement than using select()
             */

            SLEEP(1);
        }
        else {
            if (stop_flag == 0) {
                est_server_handle_request(ectx, new);
                close(new);
            }
        }
    }
    close(sock);
    cleanup();
    return 0;
}

static DWORD WINAPI master_thread_v6(LPVOID lpParam)
{
    int sock;
    struct sockaddr_in6 addr;
    int on = 1;
    int rc;
    int new;
    int unsigned len;

    u_long iMode = NON_BLOCKING_SOCKET;

    memset(&addr, 0x0, sizeof(struct sockaddr_in6));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)tcp_port);

    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        fprintf(stderr, "\nsocket call failed\n");
        exit(1);
    }
    // Needs to be done to bind to both :: and 0.0.0.0 to the same port
    int no = 0;
    setsockopt(sock, SOL_SOCKET, IPV6_V6ONLY, (void *)&no, sizeof(no));

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));

    /*
	Replace POSIX code with Windows equivalent for setting non-blocking socket
     */
    ioctlsocket(sock, FIONBIO, &iMode);

    rc = bind(sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (rc == -1) {
        fprintf(stderr, "\nbind call failed\n");
        exit(1);
    }
    listen(sock, SOMAXCONN);
    stop_flag = 0;

    while (stop_flag == 0) {
        len = sizeof(addr);
        new = accept(sock, (struct sockaddr*)&addr, &len);
        if (new < 0) {
            /*
             * this is a bit cheesy, but much easier to implement than using select()
             */

            SLEEP(1);
        }
        else {
            if (stop_flag == 0) {
                est_server_handle_request(ectx, new);
                close(new);
            }
        }
    }
    close(sock);
    cleanup();
    return 0;
}


/*
 * Call this function to stop the single-threaded simple EST server
 */
void st_stop()
{
    stop_flag = 1;
    SLEEP(2);
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
static int st_start_internal(
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
        int enable_crl)
{
    X509 *x;
    EVP_PKEY *priv_key;
    BIO *certin, *keyin;
    DH *dh;
    EST_ERROR rv;

    HANDLE mThread;
    DWORD mThreadID;
    int rc;

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
        strncpy(conf_file, ossl_conf_file, 255);
    }

    /*
     * Read in the local server certificate
     */
    certin = BIO_new(BIO_s_file_internal());
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
    keyin = BIO_new(BIO_s_file_internal());
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

    ectx = est_server_init(trustcerts, trustcerts_len,
        cacerts_raw, cacerts_len,
        EST_CERT_FORMAT_PEM, realm, x, priv_key);
    if (!ectx) {
        printf("\nUnable to initialize EST context.  Aborting!!!\n");
        return (-1);
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

    printf("\nLaunching EST server...\n");

    rv = est_server_start(ectx);
    if (rv != EST_ERR_NONE) {
        printf("\nFailed to init mg\n");
        return (-1);
    }

    // Start master (listening) thread
    tcp_port = listen_port;

    if (ipv6_flag) {
        mThread = CreateThread(NULL, 0, master_thread_v6, NULL, 0, &mThreadID);
    }
    else {
        mThread = CreateThread(NULL, 0, master_thread_v4, NULL, 0, &mThreadID);
    }

    SLEEP(2);
    /*
     * clean up
     */
    EVP_PKEY_free(priv_key);
    X509_free(x);

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
int st_start_tls10(int listen_port,
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
        enable_pop, ec_nid, 0, NULL, 1, 0, 0);

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
int st_start_crl(int listen_port,
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
        enable_pop, ec_nid, 0, NULL, 0, 0, 1);

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
int st_start(int listen_port,
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
        enable_pop, ec_nid, 0, NULL, 0, 0, 0);

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
int st_start_nocacerts(int listen_port,
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
        enable_pop, ec_nid, 0, NULL, 0, 1, 0);
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
int st_start_srp(int listen_port,
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
        0, 1, vfile, 0, 0, 0);

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
int st_start_srp_tls10(int listen_port,
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
    /* Note here that the last parm turns on tls1.0 */
    rv = st_start_internal(listen_port, certfile, keyfile, realm, ca_chain_file,
        trusted_certs_file, ossl_conf_file, 0, enable_pop, 0,
        1, vfile, 1, 0, 0);
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
void st_disable_csr_cb()
{
    est_set_csr_cb(ectx, NULL);
}

void st_set_csrattrs(char *value)
{
    csr_attr_value = value;
}

void st_disable_http_auth()
{
    est_set_http_auth_cb(ectx, NULL);
}

void st_enable_http_auth()
{
    est_set_http_auth_cb(ectx, &process_http_auth);
}

void st_enable_http_digest_auth()
{
    est_server_set_auth_mode(ectx, AUTH_DIGEST);
}

void st_enable_http_basic_auth()
{
    est_server_set_auth_mode(ectx, AUTH_BASIC);
}

void st_enable_http_token_auth()
{
    est_server_set_auth_mode(ectx, AUTH_TOKEN);
}

void st_set_token(char *value)
{
    memset(valid_token_value, 0, MAX_AUTH_TOKEN_LEN + 1);
    strncpy(&(valid_token_value[0]), value, MAX_AUTH_TOKEN_LEN);
}

void st_enable_pop()
{
    est_server_enable_pop(ectx);
}
void st_toggle_ipv6()
{
    ipv6_flag = !ipv6_flag;
}

void st_disable_pop()
{
    est_server_disable_pop(ectx);
}

void st_set_http_auth_optional()
{
    est_set_http_auth_required(ectx, HTTP_AUTH_NOT_REQUIRED);
}

void st_set_http_auth_required()
{
    est_set_http_auth_required(ectx, HTTP_AUTH_REQUIRED);
}

void st_enable_csrattr_enforce()
{
    est_server_enforce_csrattr(ectx);
}

void st_set_read_timeout(int timeout)
{
    est_server_set_read_timeout(ectx,timeout);
}

void st_enable_crl()
{
    est_enable_crl(ectx);
}

/*
 * Call to enable or disable the writing of the CSR to a file
 * 1 = write, 0 = do NOT write (default)
 */
void st_write_csr(int state)
{
    write_csr = state;
}

/*
 * Change the default filename used when writing out the CSR to a file
 */
void st_csr_filename(char *incoming_name)
{
    if (incoming_name == NULL) {
#ifdef WIN32
        snprintf(csr_filename, MAX_FILENAME_LEN, "%s\\%s",
            getenv("TEMP"), "csr.p10");
#else
        snprintf(csr_filename, MAX_FILENAME_LEN, "/tmp/csr.p10");
#endif
    }
    else {
        snprintf(csr_filename, MAX_FILENAME_LEN, incoming_name);
    }
}


