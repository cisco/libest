/** @file */
/*------------------------------------------------------------------
 * est/est_proxy.c - EST Proxy specific code
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       modulue.
 *
 * May, 2013
 *
 * Copyright (c) 2013, 2016, 2017, 2018, 2019 by Cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#ifdef WIN32 
#include <WS2tcpip.h>
#endif 
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include "est.h"
#include "est_server_http.h"
#include "est_locl.h"
#include "est_server.h"


/*
 * Since we hijack the OpenSSL BUF_MEM with our
 * own data, this utility function allows us
 * to free the BUF_MEM without freeing the
 * underlying data.
 */
static void est_proxy_free_ossl_bufmem (BUF_MEM *b)
{
    b->data = NULL;
    BUF_MEM_free(b);
}

/*
 * The following code implements the lookup operation for obtaining the client
 * context pointers when calling into the EST client code to communicate with
 * the upstream server.
 */

static int cur_max_ctx_array = INITIAL_PROXY_CLIENT_CTXS;


/*
 * bsearch_compare is used by the bsearch function to perform the
 * comparison of the nodes within the client context array.
 */
static int bsearch_compare(const void *pa, const void *pb)
{
    int result;
    CLIENT_CTX_LU_NODE_T *a = (CLIENT_CTX_LU_NODE_T *)pa;
    CLIENT_CTX_LU_NODE_T *b = (CLIENT_CTX_LU_NODE_T *)pb;
    
    if (a->threadid > b->threadid) {
        result = 1;
    } else if (a->threadid < b->threadid) {
        result = -1;
    } else {
        result = 0;
    }
    return (result);
}

/*
 * get_client_ctx() performs a search through a ordered array.
 * The key for the search is the current thread id and the value returned
 * is the client context that's been created for this thread.  If no
 * entry exists in the array for this thread id, a new one is created.
 */
static EST_CTX *get_client_ctx (EST_CTX *p_ctx) 
{
    EST_CTX *c_ctx = NULL;
    EST_ERROR rv;
    unsigned long cur_threadid = 0;
    unsigned long cur_pid = GETPID();
    CLIENT_CTX_LU_NODE_T *found_node;
    unsigned long zero_threadid = 0x0;
    CLIENT_CTX_LU_NODE_T *empty_node;
    int empty_index;

    /*
     * Windows TODO: This will likely need to be replaced with
     * GetCurrentThreadId()
     * In addition, this is really returning a pointer to an opaque value, so
     * what's being used here is typically a pointer in pthread based
     * environments and not the actual pthread id.  The only helper API to
     * access the actual id is pthread_equal().  If this must be used, then
     * the array search would best be changed to a linear search.
     * We mix in the PID of the current process with the thread ID in
     * case the application is forking new processes (e.g. NGINX).  
     */
#ifndef DISABLE_PTHREADS
    cur_threadid = (unsigned long) pthread_self();
#endif
    cur_threadid += cur_pid;

    found_node = (CLIENT_CTX_LU_NODE_T *) bsearch(&cur_threadid,
                                                  p_ctx->client_ctx_array,
                                                  cur_max_ctx_array,
                                                  sizeof(CLIENT_CTX_LU_NODE_T),
                                                  bsearch_compare);
    if (found_node == NULL) {
        
        /*
         * need to allocate a context and get it ready to be used.
         */
        c_ctx = est_client_init(p_ctx->ca_chain_raw, p_ctx->ca_chain_raw_len,
                                EST_CERT_FORMAT_PEM, NULL);
        if (c_ctx == NULL) {
            EST_LOG_ERR("Unable to allocate and initialize EST client context for Proxy use");
            return (NULL);
        }

        /*
         * The name is a bit misleading.  The identity cert and private
         * key used for proxy mode are the ones stored in the server_cert and
         * server_priv_key, however they are used in both directions, so here
         * when setting up the client side, it looks mixed up.  Might want to
         * change the name in context to hold these.
         */
        rv = est_client_set_auth(c_ctx, p_ctx->userid, p_ctx->password,
                                 p_ctx->server_cert, p_ctx->server_priv_key);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to set authentication configuration in the client context for Proxy use");
	    est_destroy(c_ctx);
            return (NULL);
	}        

        rv = est_client_set_auth_cred_cb(c_ctx, p_ctx->auth_credentials_cb);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to register authentication credential callback.");
            return (NULL);
        }

        /*
         * wrt path segment, unlike true client mode, the path segment will
         * be changing on every request going upstream, so no need to
         * obtain it locally at a proxy and set it one time, so it
         * should be left NULL.
         */
	rv = est_client_set_server(c_ctx, p_ctx->est_server, p_ctx->est_port_num, NULL);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to set the upstream server configuration in the client context for Proxy use");
	    est_destroy(c_ctx);
            return (NULL);
	}

        rv = est_client_set_read_timeout(c_ctx, p_ctx->read_timeout);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to set the SSL read timeout in the client context");
	    est_destroy(c_ctx);
            return (NULL);
	}        

        /*
         * make sure there's room for another entry
         */
        empty_node = (CLIENT_CTX_LU_NODE_T *) bsearch(&zero_threadid,
                                                      p_ctx->client_ctx_array,
                                                      cur_max_ctx_array,
                                                      sizeof(CLIENT_CTX_LU_NODE_T),
                                                      bsearch_compare);

        if (empty_node == NULL) {
            /*
             * we're out of space.  allocate a new array and copy over what's
             * already there.  Double the size of the current one.
             */
            CLIENT_CTX_LU_NODE_T *temp_array;
            
            cur_max_ctx_array *= 2;
            temp_array = (CLIENT_CTX_LU_NODE_T *) malloc(sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);
            memzero_s(temp_array, sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array); 
            memcpy_s(temp_array, sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array,
                     p_ctx->client_ctx_array,sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array/2);
            free(p_ctx->client_ctx_array);
            p_ctx->client_ctx_array = temp_array;
            
            qsort(p_ctx->client_ctx_array, cur_max_ctx_array,
                  sizeof(CLIENT_CTX_LU_NODE_T), 
                  bsearch_compare);

            empty_node = (CLIENT_CTX_LU_NODE_T *) bsearch(&zero_threadid,
                                                          p_ctx->client_ctx_array,
                                                          cur_max_ctx_array,
                                                          sizeof(CLIENT_CTX_LU_NODE_T),
                                                          bsearch_compare);
        }
        empty_index = (int) (empty_node - p_ctx->client_ctx_array);

        /*
         * add to the array and sort it into its proper place
         */
        p_ctx->client_ctx_array[empty_index].threadid = cur_threadid;
        p_ctx->client_ctx_array[empty_index].client_ctx = c_ctx;
        
        qsort(p_ctx->client_ctx_array, cur_max_ctx_array,
              sizeof(CLIENT_CTX_LU_NODE_T), 
              bsearch_compare);
    } else {
        /*
         * the entry was found in the tree, return the client context for this
         * pid
         */
        c_ctx = found_node->client_ctx;
    }
    
    return(c_ctx);   
}        

/*
 * proxy_cleanup() is invoked from est_destroy when the
 * current context is for proxy mode.
 */
void proxy_cleanup (EST_CTX *p_ctx) 
{
    int i;
    
    if (p_ctx->client_ctx_array == NULL) {
        return;
    }

    for (i=0; i<cur_max_ctx_array; i++) {
        if (p_ctx->client_ctx_array[i].client_ctx) {
            est_destroy(p_ctx->client_ctx_array[i].client_ctx);
        }
    }
    free(p_ctx->client_ctx_array);
    p_ctx->client_ctx_array = NULL;
}

/*****************************************************************************
* EST proxy operations
*****************************************************************************/

/*
 * This routine will send a PKCS7 encoded certificate to
 * the EST client via HTTP. 
 */
static EST_ERROR est_proxy_propagate_pkcs7 (void *http_ctx, unsigned char *pkcs7, int pkcs7_len)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;

    /*
     * Send HTTP header
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
             EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_PKCS7_CO, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CE,
             EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
             pkcs7_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
            return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send the signed PKCS7 certificate in the body
     */
    if (!mg_write(http_ctx, pkcs7, pkcs7_len)) {
        EST_LOG_ERR("HTTP write error while propagating pkcs7");
        return (EST_ERR_HTTP_WRITE);
    }
    return (EST_ERR_NONE);
}

/*
 * This routine will send multipart key and cert response to the
 * client via HTTP
 */
static EST_ERROR est_proxy_propagate_keygen_rsp (void *http_ctx,
                                                 unsigned char *key, int key_len,
                                                 unsigned char *pkcs7, int pkcs7_len)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;

    /*
     * Send HTTP header
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200, EST_HTTP_HDR_EOL,
             EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s; boundary=%s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_MULTI_MIXED, EST_HTTP_BOUNDARY,EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
             key_len+pkcs7_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "\n--%s%s", EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL);

    /*
     * private key header info
     */
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_PKCS8, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s%s", EST_HTTP_HDR_CE,
             EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);

    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send the PKCS8 private key in the body
     */
    if (!mg_write(http_ctx, key, key_len)) {
        EST_LOG_ERR("HTTP write error while propogating server generated key");
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Write boundary for multipart/mixed content-types
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s--%s%s", EST_HTTP_HDR_EOL, EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL);
    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send certificate header info
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_PKCS7_CO, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s%s", EST_HTTP_HDR_CE,
             EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);

    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send the signed PKCS7 certificate in the body
     */
    if (!mg_write(http_ctx, pkcs7, pkcs7_len)) {
        EST_LOG_ERR("HTTP write error while propagating pkcs7");
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Write boundary for multipart/mixed content-types
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s--%s--%s%s", EST_HTTP_HDR_EOL, EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        return (EST_ERR_HTTP_WRITE);
    }

    return (EST_ERR_NONE);
}


/*
 * est_proxy_retrieve_cacerts() issues a request to the server to obtain the
 * CA Certs chain to be used for Get CA Certs requests from clients.
 * The CA Cert chain returned from the server are passed back to the caller.
 *
 * It's the responsibility of the caller to free up this buffer.
 */
EST_ERROR est_proxy_retrieve_cacerts (EST_CTX *ctx, unsigned char **cacerts_rtn,
                                      int *cacerts_rtn_len)
{
    EST_CTX *client_ctx;
    EST_ERROR rv;
    int rcvd_cacerts_len;
    unsigned char *rcvd_cacerts;

    if (ctx == NULL) {
        EST_LOG_ERR("Ctx not passed to %s", __FUNCTION__);
        return (EST_ERR_NO_CTX);
    }
    if (cacerts_rtn == NULL || cacerts_rtn_len == NULL) {
        EST_LOG_ERR("Ctx not passed to %s", __FUNCTION__);
        return (EST_ERR_INVALID_PARAMETERS);        
    }
    
    *cacerts_rtn = NULL;
    *cacerts_rtn_len = 0;

    /*
     * Get the client context for this thread
     */
    client_ctx = get_client_ctx(ctx);
    if (!client_ctx) {
        EST_LOG_ERR("Unable to obtain client context for proxy operation");
        return (EST_ERR_NO_CTX);
    }

    rv = est_client_get_cacerts(client_ctx, &rcvd_cacerts_len);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to retrieve CA Certs from upstream server RC = %s",
                    EST_ERR_NUM_TO_STR(rv));
        return (rv);
    }
    
    /*
     * Allocate a buffer to retrieve the CA certs
     * and get them copied in
     */
    rcvd_cacerts = malloc(rcvd_cacerts_len);
    if (rcvd_cacerts == NULL) {
        EST_LOG_ERR("Unable to malloc buffer for cacerts received from server");
        return (EST_ERR_MALLOC);
    }
    
    rv = est_client_copy_cacerts(client_ctx, rcvd_cacerts);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to copy CA Certs from upstream server RC = %s",
                    EST_ERR_NUM_TO_STR(rv));
        free(rcvd_cacerts);
        return (rv);
    }

    /*
     * The retrieving of the CA certs through the normal client
     * interface causes the client to go back into an uninitialized state.
     * In this case though, we're getting it just for passing it back
     * to the downstream clients, so we're going to put this client
     * context back into the initialized state
     */
    client_ctx->est_client_initialized = 1;
    
    *cacerts_rtn = rcvd_cacerts;
    *cacerts_rtn_len = rcvd_cacerts_len;
    return (EST_ERR_NONE);
}


/*
 * This routine will connect to the EST server and attempt
 * to enroll the CSR in the *pkcs10 buffer. Upon success
 * it will return the X509 cert in the *pkcs7 buffer.  The
 * length of the returned cert will be in *pkcs7_len.  
 * The *pkcs7 buffer should be allocated by the caller.
 */
static EST_ERROR est_proxy_send_enroll_request (EST_CTX *clnt_ctx, 
	                                        BUF_MEM *pkcs10, unsigned char *pkcs7,
						int *pkcs7_len, int reenroll)
{
    EST_ERROR rv;
    SSL *ssl_client;

    /*
     * Connect to the server
     */
    rv = est_client_connect(clnt_ctx, &ssl_client);
    if (rv != EST_ERR_NONE) {
        return (rv);
    }

    /*
     * Send the enroll request
     */
    rv = est_client_send_enroll_request(clnt_ctx, ssl_client,
                                        pkcs10, pkcs7, pkcs7_len, reenroll);

    /*
     * Disconnect from the server
     */
    est_client_disconnect(clnt_ctx, &ssl_client);

    return (rv);
}

/*
 * This routine will connect to the EST server and attempt
 * to enroll the CSR in the *pkcs10 buffer as well as collect
 * a new private key that will be generated by the server and
 * added to the CSR before the enrollment. Upon success
 * it will return the X509 cert in the *pkcs7 buffer and an
 * RSA key in the *key buffer.  The respectives lengths
 * will be in *pkcs7_len and *key_len. The *pkcs7 buffer and
 * *key buffer should be allocated by the caller.
 */
static EST_ERROR est_proxy_send_keygen_request (EST_CTX *clnt_ctx,
                                                BUF_MEM *pkcs10,
                                                unsigned char *key,
                                                int *key_len,
                                                unsigned char *pkcs7,
                                                int *pkcs7_len)
{
    EST_ERROR rv;
    SSL *ssl_client;

    /*
     * Connect to the server
     */
    rv = est_client_connect(clnt_ctx, &ssl_client);
    if (rv != EST_ERR_NONE) {
        return (rv);
    }

    /*
     * Send the server-side keygen request
     */
    rv = est_client_send_keygen_request(clnt_ctx, ssl_client,
                                        pkcs10, key, key_len,
                                        pkcs7, pkcs7_len);

    /*
     * Disconnect from the server
     */
    est_client_disconnect(clnt_ctx, &ssl_client);

    return (rv);
}

/*
 * Ensure the length of the given path segment is valid 
 * and store it in the context (ctx->uri_path_segment).
 * This function is available externally.
 */
EST_ERROR est_proxy_store_path_segment (EST_CTX *ctx, char *path_seg)
{
#ifdef HAVE_URIPARSER
    int path_seg_len;
    EST_ERROR rc;

    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (ctx->est_mode != EST_PROXY) {
        EST_LOG_ERR("Invalid context. Expected %d, received %d.",
                    EST_PROXY, ctx->est_mode);
        return EST_ERR_BAD_MODE;
    }

    if (path_seg != NULL) {

        if (*path_seg == '\0') {
            EST_LOG_ERR("Invalid injected path segment. Below minimum size.");
            return EST_ERR_HTTP_INVALID_PATH_SEGMENT;
        }
        
        /*
         * Make sure it's not too long
         */
        path_seg_len = strnlen_s(path_seg, EST_MAX_PATH_SEGMENT_LEN+1);
        if (path_seg_len > EST_MAX_PATH_SEGMENT_LEN) {
            EST_LOG_ERR("Invalid injected path segment. Exceeded "
                        "maximum size of %d bytes", EST_MAX_PATH_SEGMENT_LEN);
            return EST_ERR_HTTP_INVALID_PATH_SEGMENT;
        }

        /*
         * Ensure it is a valid path segment value
         */
        rc = est_parse_path_seg(path_seg);
        if (rc != EST_ERR_NONE) {
             EST_LOG_ERR("Invalid injected path segment '%s'. Failed "
                         "parsing requirements.", path_seg);
            return EST_ERR_HTTP_INVALID_PATH_SEGMENT;
        }

        /*
         * store it away in the context
         */
        rc = est_store_path_segment(ctx, path_seg, path_seg_len);
        if (rc != EST_ERR_NONE) {
            EST_LOG_ERR("Failed to store proxy path segment.");
            return (rc);
        }

        EST_LOG_INFO("URI path segment stored in context as \"%s\"", ctx->uri_path_segment);
        
    }
    return EST_ERR_NONE;
#else
    EST_LOG_ERR("Could not parse injected path seg without URIPARSER");
    return EST_ERR_HTTP_PATH_SEGMENT_NOT_SUPPORTED;
#endif
}

/*
 * Length checks the given path segment and stores it in the
 * client context of the est in proxy mode.
 */
static EST_ERROR est_proxy_set_path_segment (EST_CTX *client_ctx,
                                             char *path_segment)
{
    int path_segment_len;
    EST_ERROR rc;

    path_segment_len = strnlen_s(path_segment, EST_MAX_PATH_SEGMENT_LEN);
    
    rc = est_store_path_segment(client_ctx, path_segment, path_segment_len);
    if (rc != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to store URI path segment.");
        return (rc);
    }
    return EST_ERR_NONE;
}

/*
 * This function is used by the server side of the EST proxy to respond to an
 * incoming Simple Enroll request.  This function is similar to the Client API
 * function, est_client_enroll_req(), except it bypasses some things that are
 * not done when functioning as a proxy, such as signing the CSR, not
 * inserting the TLS unique id and instead including the id-kp-cmcRA usage
 * extension.
 */
EST_ERROR est_proxy_handle_simple_enroll (EST_CTX *ctx, void *http_ctx,
                                          SSL *ssl, const char *ct, 
                                          char *body, int body_len, 
                                          char *path_seg, int reenroll, 
                                          unsigned char **returned_cert, 
                                          int *returned_cert_len)
{
    EST_ERROR rv;
    BUF_MEM *pkcs10;
    unsigned char *pkcs7;
    int pkcs7_len = 0;
   
    X509_REQ *csr = NULL;
    EST_CTX *client_ctx;

    /* Performance Timers */
    EST_TIMER send_to_server_timer;

    if (ctx->transport_mode == EST_HTTP) {
        int diff;
        errno_t safec_rc;

        /*
        * Make sure the client has sent us a PKCS10 CSR request if in HTTP
        */

        safec_rc = memcmp_s(ct, sizeof("application/pkcs10"), "application/pkcs10",
            sizeof("application/pkcs10"), &diff);

        if (safec_rc != EOK) {
            EST_LOG_INFO("memcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            return (EST_ERR_BAD_CONTENT_TYPE);
        }
    }

    /*
     * Authenticate the client
     */
    switch (est_enroll_auth(ctx, http_ctx, ssl, path_seg, reenroll, body,
                            body_len, &csr)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
        break;
    case EST_HTTP_AUTH_PENDING:
        return (EST_ERR_AUTH_PENDING);
    case EST_CSR_PARSE_FAIL:
        return (EST_ERR_BAD_PKCS10);
    case EST_UNAUTHORIZED:
    default:
        return (EST_ERR_AUTH_FAIL);
    }

    /*
     * Parse the PKCS10 CSR from the client
     */
    if (!csr) {
        csr = est_server_parse_csr((unsigned char *)body, body_len,
                                   EST_CSR_DECODE);
        if (!csr) {
            EST_LOG_ERR("Unable to parse the PKCS10 CSR sent by the client");
            return (EST_ERR_BAD_PKCS10);
        }
    }

    /*
     * Perform a sanity check on the CSR
     */
    if (est_server_check_csr(csr)) {
        EST_LOG_ERR("PKCS10 CSR sent by the client failed sanity check");
        X509_REQ_free(csr);
        return (EST_ERR_BAD_PKCS10);
    }

    /*
     * Do the PoP check (Proof of Possession).  The challenge password
     * in the pkcs10 request should match the TLS unique ID.
     */
    rv = est_tls_uid_auth(ctx, ssl, csr);
    X509_REQ_free(csr);

    if (rv != EST_ERR_NONE) {
        return (EST_ERR_AUTH_FAIL_TLSUID);
    }

    /*
     * body now points to the pkcs10 data, pass
     * this to the enrollment routine.  Need to hi-jack
     * a BUF_MEM.  Attach the body to a new BUF_MEM
     */
    pkcs10 = BUF_MEM_new();
    pkcs10->data = body;
    pkcs10->length = body_len;
    pkcs10->max = body_len;

    /*
     * get the client context for this thread
     */
    client_ctx = get_client_ctx(ctx);
    if (!client_ctx) {
        EST_LOG_ERR("Unable to obtain client context for proxy operation");
        est_proxy_free_ossl_bufmem(pkcs10);
        return (EST_ERR_NO_CTX);
    }

    /*
     * path_segment.  The path seg value is coming in from the
     * downstream client on this request.  It's already been validated,
     * place it in ctx for use by client code.
     */

    /* 
     * If no path segment was given by the client, set it to
     * the path segment that may already be stored in the proxy context
     */
    if (path_seg == NULL) {
        /* TODO: this will need to be altered when coap can handle path segments */
        path_seg = ctx->uri_path_segment;
    }

    /* store the proxy path segment in the client context */
    if (path_seg != NULL) {
        rv = est_proxy_set_path_segment(client_ctx, path_seg);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Could not store path_seg into client context.");
            est_proxy_free_ossl_bufmem(pkcs10);
            return rv;
        }
    }

    /*
     * Allocate some space to hold the cert that we
     * expect to receive from the EST server.
     */
    pkcs7 = malloc(EST_CA_MAX);

    if (pkcs7 == NULL) {
        EST_LOG_ERR("Malloc failed for pkcs7 buffer");
        return (EST_ERR_MALLOC);
    }
try_again:
    /*
     * Attempt to enroll the CSR from the client
     */
    start_timer(&send_to_server_timer, ctx,
                "HTTPS proxy est_proxy_send_enroll_request");
    rv = est_proxy_send_enroll_request(client_ctx, pkcs10, pkcs7, &pkcs7_len,
                                       reenroll);
    stop_timer(&send_to_server_timer);
    ctx->retry_after_delay = client_ctx->retry_after_delay;

    /*
     * Handle any errors that likely occurred
     */
    switch (rv) {
    case EST_ERR_NONE:
        break;
    /*
     * Something went wrong with the upstream request to the
     * server.
     */
    case EST_ERR_IP_GETADDR:
    case EST_ERR_IP_CONNECT:
    case EST_ERR_SSL_READ:
        /* This section will map to a 504 repsonse */
        EST_LOG_ERR("Proxy: Server not reachable %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_IP_CONNECT;
        break;
    case EST_ERR_SSL_CONNECT:
    case EST_ERR_FQDN_MISMATCH:
    case EST_ERR_SSL_WRITE:
    case EST_ERR_ZERO_LENGTH_BUF:
    case EST_ERR_MULTIPART_PARSE:
    case EST_ERR_UNKNOWN:
    case EST_ERR_BUF_EXCEEDS_MAX_LEN:
    case EST_ERR_HTTP_UNSUPPORTED:
        /* This section will map to a 502 repsonse */
        EST_LOG_ERR(
            "Proxy: Error while communicating with upstream server %s (%d)",
            EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_HTTP_UNSUPPORTED;
        break;
    case EST_ERR_HTTP_BAD_REQ:
    case EST_ERR_HTTP_NO_CONTENT:
    case EST_ERR_HTTP_NOT_FOUND:
    case EST_ERR_HTTP_LOCKED:
    case EST_ERR_CA_ENROLL_RETRY:
        /* This section will pass through the response code from the server */
        EST_LOG_ERR("Proxy: Passing through error response code from upstream "
                    "server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        break;
    case EST_ERR_AUTH_FAIL:
        /* Try one more time if proxy has auth creds */
        if ((ctx->auth_mode == AUTH_DIGEST || ctx->auth_mode == AUTH_BASIC ||
             ctx->auth_mode == AUTH_TOKEN) &&
            client_ctx->auth_mode != AUTH_FAIL) {
            EST_LOG_INFO(
                "HTTP Auth failed, trying again with HTTP Auth parameters");
            goto try_again;
        }
        break;
    default:
        /* This section will map to a 500 repsonse */
        EST_LOG_ERR("Proxy: Unhandled error occured while communicating with "
                    "the upstream server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_UNKNOWN;
        break;
    }

    client_ctx->auth_mode = AUTH_NONE;
    
    /*
     * Prevent OpenSSL from freeing our data
     */
    est_proxy_free_ossl_bufmem(pkcs10);

    /*
     * If we have a cert response from the EST server, we pass it
     * back to the caller.  In HTTP mode we propogate it back right
     * here and pass it back so it can be passed in the event notification
     * handler, if needed.  In CoAP mode, we just pass it back to the
     * caller (the CoAP handler) and have the caller send it back and
     * also log it with the event handler, if needed.
     *
     * If there was no cert, log this error condition.
     */    
    if (pkcs7_len > 0) {

        /*
         * It's assumed the caller wants access to the returned cert
         * so pass it back.
         */
        if (returned_cert == NULL || returned_cert_len == NULL) {
            EST_LOG_ERR("Null pointers for return cert values");
            free(pkcs7);
            return (EST_ERR_INVALID_PARAMETERS);
        }
        *returned_cert = pkcs7;
        *returned_cert_len = pkcs7_len;

        /*
         * If HTTP mode, we also need to send it right now to the client
         */
        if (ctx->transport_mode == EST_HTTP) {
            rv = est_proxy_propagate_pkcs7(http_ctx, pkcs7, pkcs7_len);
        }
    } else {
        EST_LOG_ERR("No certificate returned from server.");
        if (pkcs7) {
            free(pkcs7);
        }
    }
    return (rv);
}


/*
 * This function is used by the server side of the EST proxy to respond to an
 * incoming Server-side key generation enrollment request.  This function is
 * similar to the Client API function, est_client_enroll_req() which is leveraged
 * by est_client_send_keygen_req(), except it bypasses some things that are
 * not done when functioning as a proxy, such as signing the CSR, not
 * inserting the TLS unique id and instead including the id-kp-cmcRA usage
 * extension.
 */
EST_ERROR est_proxy_handle_server_keygen (EST_CTX *ctx, void *http_ctx,
                                                 SSL *ssl, const char *ct,
                                                 char *body, int body_len,
                                                 char *path_seg,
                                                 unsigned char **returned_cert, 
                                                 int *returned_cert_len,
                                                 unsigned char **returned_key,
                                                 int *returned_key_len)
{
    EST_ERROR rv;
    BUF_MEM *pkcs10;
    unsigned char *pkcs7, *key;
    int pkcs7_len = 0, key_len = 0;
    int diff;
    X509_REQ *csr = NULL;
    EST_CTX *client_ctx;
    errno_t safec_rc;

    /* Performance Timers */
    EST_TIMER send_to_server_timer;

    /*
     * Make sure the client has sent us a PKCS10 CSR request
     * This check happens in the coap handler functions for CoAP mode and
     * therefore doesn't hae to be done here.
     */
    if (ctx->transport_mode == EST_HTTP) {
        safec_rc = memcmp_s(ct, sizeof("application/pkcs10"), "application/pkcs10",
                            sizeof("application/pkcs10"), &diff);

        if (safec_rc != EOK) {
            EST_LOG_INFO("memcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            return (EST_ERR_BAD_CONTENT_TYPE);
        }
    }

    /*
     * Authenticate the client
     */
    switch (est_enroll_auth(ctx, http_ctx, ssl, path_seg, SERVERKEYGEN_REQ, body, body_len,
                            &csr)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
        break;
    case EST_HTTP_AUTH_PENDING:
        if(csr) X509_REQ_free(csr);
        return (EST_ERR_AUTH_PENDING);
    case EST_CSR_PARSE_FAIL:
        if(csr) X509_REQ_free(csr);
        return (EST_ERR_BAD_PKCS10);
    case EST_UNAUTHORIZED:
    default:
        if(csr) X509_REQ_free(csr);
        return (EST_ERR_AUTH_FAIL);
    }

    /*
     * Parse the PKCS10 CSR from the client
     */
    if (!csr) {
        csr = est_server_parse_csr((unsigned char *)body, body_len,
                                   EST_CSR_DECODE);
        if (!csr) {
            EST_LOG_ERR("Unable to parse the PKCS10 CSR sent by the client");
            return (EST_ERR_BAD_PKCS10);
        }
    }

    /*
     * Perform a sanity check on the CSR
     */
    if (est_server_check_csr(csr)) {
        EST_LOG_ERR("PKCS10 CSR sent by the client failed sanity check");
        X509_REQ_free(csr);
        return (EST_ERR_BAD_PKCS10);
    }

    /*
     * Do the PoP check (Proof of Possession).  The challenge password
     * in the pkcs10 request should match the TLS unique ID.
     */
    rv = est_tls_uid_auth(ctx, ssl, csr);
    X509_REQ_free(csr);

    if (rv != EST_ERR_NONE) {
        return (EST_ERR_AUTH_FAIL_TLSUID);
    }

    /*
     * body now points to the pkcs10 data, pass
     * this to the enrollment routine.  Need to hi-jack
     * a BUF_MEM.  Attach the body to a new BUF_MEM
     */
    pkcs10 = BUF_MEM_new();
    pkcs10->data = body;
    pkcs10->length = body_len;
    pkcs10->max = body_len;

    /*
     * get the client context for this thread
     */
    client_ctx = get_client_ctx(ctx);
    if (!client_ctx) {
        EST_LOG_ERR("Unable to obtain client context for proxy operation");
        est_proxy_free_ossl_bufmem(pkcs10);
        return (EST_ERR_NO_CTX);
    }

    /*
     * path_segment.  The path seg value is coming in from the
     * downstream client on this request.  It's already been validated,
     * place it in ctx for use by client code.
     */

    /* 
     * If no path segment was given by the client, set it to
     * the path segment that may already be stored in the proxy context
     */
    if (path_seg == NULL) {
        /* TODO: this will need to be altered when coap can handle path segments */
        path_seg = ctx->uri_path_segment;
    }

    /* store the proxy path segment in the client context */
    if (path_seg != NULL) {
        rv = est_proxy_set_path_segment(client_ctx, path_seg);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Could not store path_seg into client context.");
            est_proxy_free_ossl_bufmem(pkcs10);
            return rv;
        }
    }

    /*
     * Allocate some space to hold the cert that we
     * expect to receive from the EST server.
     */
    pkcs7 = malloc(EST_CA_MAX);
    key = malloc(EST_MAX_CLIENT_PKEY_LEN);

try_again:
    /*
     * Attempt to enroll the CSR from the client
     */
    start_timer(&send_to_server_timer, ctx,
                "HTTPS proxy est_proxy_send_keygen_request");
    rv = est_proxy_send_keygen_request(client_ctx, pkcs10, key, &key_len, pkcs7, &pkcs7_len);
    stop_timer(&send_to_server_timer);
    ctx->retry_after_delay = client_ctx->retry_after_delay;

    /*
     * Handle any errors that likely occurred
     */
    switch (rv) {
    case EST_ERR_NONE:
        break;
    /*
     * Something went wrong with the upstream request to the
     * server.
     */
    case EST_ERR_IP_GETADDR:
    case EST_ERR_IP_CONNECT:
    case EST_ERR_SSL_READ:
        /* This section will map to a 504 repsonse */
        EST_LOG_ERR("Proxy: Server not reachable %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_IP_CONNECT;
        break;
    case EST_ERR_SSL_CONNECT:
    case EST_ERR_FQDN_MISMATCH:
    case EST_ERR_SSL_WRITE:
    case EST_ERR_ZERO_LENGTH_BUF:
    case EST_ERR_MULTIPART_PARSE:
    case EST_ERR_UNKNOWN:
    case EST_ERR_BUF_EXCEEDS_MAX_LEN:
    case EST_ERR_HTTP_UNSUPPORTED:
        /* This section will map to a 502 repsonse */
        EST_LOG_ERR(
            "Proxy: Error while communicating with upstream server %s (%d)",
            EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_HTTP_UNSUPPORTED;
        break;
    case EST_ERR_HTTP_BAD_REQ:
    case EST_ERR_HTTP_NO_CONTENT:
    case EST_ERR_HTTP_NOT_FOUND:
    case EST_ERR_HTTP_LOCKED:
    case EST_ERR_CA_ENROLL_RETRY:
        /* This section will pass through the response code from the server */
        EST_LOG_ERR("Proxy: Passing through error response code from upstream "
                    "server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        break;
    case EST_ERR_AUTH_FAIL:
        /* Try one more time if proxy has auth creds */
        if ((ctx->auth_mode == AUTH_DIGEST || ctx->auth_mode == AUTH_BASIC ||
             ctx->auth_mode == AUTH_TOKEN) &&
            client_ctx->auth_mode != AUTH_FAIL) {
            EST_LOG_INFO(
                "HTTP Auth failed, trying again with HTTP Auth parameters");
            goto try_again;
        }
        break;
    default:
        /* This section will map to a 500 repsonse */
        EST_LOG_ERR("Proxy: Unhandled error occured while communicating with "
                    "the upstream server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        rv = EST_ERR_UNKNOWN;
        break;
    }

    client_ctx->auth_mode = AUTH_NONE;

    /*
     * Prevent OpenSSL from freeing our data
     */
    est_proxy_free_ossl_bufmem(pkcs10);

    /*
     * If we have a response from the EST server, we pass it
     * back to the caller.  In HTTP mode we propogate it back right
     * here and pass it back so it can be passed in the event notification
     * handler, if needed.  In CoAP mode, we just pass it back to the
     * caller (the CoAP handler) and have the caller send it back and
     * also log it with the event handler, if needed.
     *
     * If we have a response from the EST server, let's forward
     * it back to the EST client
     */
    if (pkcs7_len > 0 && key_len > 0) {
        /*
         * It's assumed the caller wants access to the returned cert
         * and key so pass it back.
         */
        if (returned_cert == NULL || returned_cert_len == NULL
            || returned_key == NULL || returned_key_len == NULL) {
            EST_LOG_ERR("Null pointers for return cert or key values");
            free(pkcs7);
            memzero_s(key, key_len);
            free(key);
            return (EST_ERR_INVALID_PARAMETERS);
        }
        *returned_cert = pkcs7;
        *returned_cert_len = pkcs7_len;
        *returned_key = key;
        *returned_key_len = key_len;

        /*
         * If HTTP mode, we also need to send it right now to the client
         */
        if (ctx->transport_mode == EST_HTTP) {
            rv = est_proxy_propagate_keygen_rsp(http_ctx, key, key_len, pkcs7, pkcs7_len);
        }
    } else {
        EST_LOG_ERR("No certificate or key returned from server.");
        memzero_s(key, EST_MAX_CLIENT_PKEY_LEN);
        free(key);
        free(pkcs7);
    }

    return (rv);
}

/*
 * This function is used by the server side of the EST proxy to respond to an
 * incoming cacerts request.  If the CA certs response has been set locally
 * then respond with this locally set buffer.  If not set, then issue a
 * request to the upstream server.
 */
EST_ERROR est_proxy_handle_cacerts (EST_CTX *ctx, void *http_ctx, char *path_seg)
{
    EST_ERROR rv = EST_ERR_NONE;
    EST_CTX *client_ctx;
    int cacerts_len;

    /* Performance Timers */
    EST_TIMER send_to_server_timer;

    /*
     * If the certs are stored locally then send them back to the client
     */
    if (ctx->ca_certs != NULL) {
        EST_LOG_INFO("Proxy: CA certs set locally, responding with locally "
                     "set CA certs response");
                     
        if (ctx->transport_mode == EST_HTTP) {
            rv = est_handle_cacerts(ctx, ctx->ca_certs, ctx->ca_certs_len,
                                  http_ctx, path_seg);
        } else if (ctx->transport_mode == EST_COAP) {
            /* 
             * since the certs are already in the context,
             * there is nothing to do here (the coap crts
             * handler uses the certs stored in the context)
             */
            rv = EST_ERR_NONE;
        } else {
            EST_LOG_ERR("EST in improper transport mode. Cannot forward "
                        "cacerts to client.");
            rv = EST_ERR_BAD_MODE;
        }
    /*
     * If the certs are not stored locally then attempt to retrieve them
     * from the upstream server
     */
    } else {
        
        /*
         * get the client context for this thread
         */
        client_ctx = get_client_ctx(ctx);
        if (!client_ctx) {
            EST_LOG_ERR("Unable to obtain client context for proxy operation");
            return (EST_ERR_NO_CTX);
        }

        /*
         * path_segment.  The path seg value is coming in from the
         * downstream client on this request.  It's already been validated,
         * place it in ctx for use by client code.
         */

        /* 
         * If no path segment was given by the client, set it to
         * the path segment that may already be stored in the proxy context
         */
        if (path_seg == NULL) {
            /* TODO: this will need to be altered when coap can handle path segments */
            path_seg = ctx->uri_path_segment;
        }

        /* store the proxy path segment in the client context */
        if (path_seg != NULL) {
            rv = est_proxy_set_path_segment(client_ctx, path_seg);
            if (rv != EST_ERR_NONE) {
                EST_LOG_ERR("Could not store path_seg into client context.");
                return rv;
            }
        }

        /*
         * Invoke client code to retrieve the cacerts.
         * Note: there is no need to authenticate the client (see sec 4.5)
         */
        EST_LOG_INFO(
            "Proxy: Attempting to retrieve CA certs from upstream server");

        start_timer(&send_to_server_timer, ctx,
                    "HTTPS proxy est_client_get_cacerts");
        rv = est_client_get_cacerts(client_ctx, &cacerts_len);
        stop_timer(&send_to_server_timer);
        ctx->retry_after_delay = client_ctx->retry_after_delay;

        /*
         * If the upstream request was successful, the retrieved CA certs will be
         * in the context
         */
        switch (rv) {
        case EST_ERR_NONE:
            EST_LOG_INFO("Proxy: CA certs retrieved successfully from server. "
                         "Forwarding to EST client.");
            break;
        /*
         * Something went wrong with the upstream request to the
         * server.
         */
        case EST_ERR_IP_GETADDR:
        case EST_ERR_IP_CONNECT:
        case EST_ERR_SSL_READ:
            /* This section will map to a 504 repsonse */
            EST_LOG_ERR("Proxy: Server not reachable %s (%d)",
                        EST_ERR_NUM_TO_STR(rv), rv);
            return (EST_ERR_IP_CONNECT);
        case EST_ERR_SSL_CONNECT:
        case EST_ERR_FQDN_MISMATCH:
        case EST_ERR_SSL_WRITE:
        case EST_ERR_ZERO_LENGTH_BUF:
        case EST_ERR_MULTIPART_PARSE:
        case EST_ERR_UNKNOWN:
        case EST_ERR_BUF_EXCEEDS_MAX_LEN:
        case EST_ERR_HTTP_UNSUPPORTED:
            /* This section will map to a 502 repsonse */
            EST_LOG_ERR(
                "Proxy: Error while communicating with upstream server %s (%d)",
                EST_ERR_NUM_TO_STR(rv), rv);
            return (EST_ERR_HTTP_UNSUPPORTED);
        case EST_ERR_HTTP_BAD_REQ:
        case EST_ERR_HTTP_NO_CONTENT:
        case EST_ERR_HTTP_NOT_FOUND:
        case EST_ERR_AUTH_FAIL:
        case EST_ERR_HTTP_LOCKED:
        case EST_ERR_CA_ENROLL_RETRY:
            /* 
             * This section will pass through the response code from the server
             */
            EST_LOG_ERR("Proxy: Passing through error response code from "
                        "upstream server %s (%d)",
                        EST_ERR_NUM_TO_STR(rv), rv);
            return rv;
        default:
            /* This section will map to a 500 repsonse */
            EST_LOG_ERR("Proxy: Unhandled error occured while communicating "
                        "with the upstream server %s (%d)",
                        EST_ERR_NUM_TO_STR(rv), rv);
            return (EST_ERR_UNKNOWN);
        }

        /*
         * If in coap mode then set certs in memory so the coap
         * code can send it back to the client
         */
        if (ctx->transport_mode == EST_COAP) {
            /*
             * pass the retrieved cert from the client ctx to the
             * server ctx to avoid a double free later on
             */
            ctx->ca_certs = client_ctx->retrieved_ca_certs;
            ctx->ca_certs_len = client_ctx->retrieved_ca_certs_len;
            client_ctx->retrieved_ca_certs = NULL;
            client_ctx->retrieved_ca_certs_len = 0;
            rv = EST_ERR_NONE;
        } else if (ctx->transport_mode == EST_HTTP) {
            rv = est_handle_cacerts(ctx, client_ctx->retrieved_ca_certs,
                                    client_ctx->retrieved_ca_certs_len,
                                    http_ctx, path_seg);
        } else {
            EST_LOG_ERR("EST in improper transport mode. Cannot forward "
                        "cacerts to client.");
            rv = EST_ERR_BAD_MODE;
        }
    }
    
    return (rv);
}


/*
 * This function is used by the server side of the EST proxy to respond to an
 * incoming CSR Attributes request.  This function is similar to the Client API
 * function, est_client_get_csrattrs().
 */
EST_ERROR est_proxy_handle_csr_attrs (EST_CTX *ctx, void *http_ctx,
                                      char *path_seg,
                                      unsigned char **returned_attrs,
                                      int *returned_attrs_len)
{
    int rv = EST_ERR_NONE;
    int pop_present;
    char *csr_data, *csr_data_pop;
    int csr_len, csr_pop_len;
    EST_CTX *client_ctx;

    /* Performance Timers */
    EST_TIMER send_to_server_timer;

    /*
     * get the client context for this thread
     */
    client_ctx = get_client_ctx(ctx);
    if (!client_ctx) {
        EST_LOG_ERR("Unable to obtain client context for proxy operation");
        return (EST_ERR_NO_CTX);
    }

    /*
     * path_segment.  The path seg value is coming in from the
     * downstream client on this request.  It's already been validated,
     * place it in ctx for use by client code.
     */

    /* 
     * If no path segment was given by the client, set it to
     * the path segment that may already be stored in the proxy context
     */
    if (path_seg == NULL) {
        /* TODO: this will need to be altered when coap can handle path segments */
        path_seg = ctx->uri_path_segment;
    }

    /* store the proxy path segment in the client context */
    if (path_seg != NULL) {
        rv = est_proxy_set_path_segment(client_ctx, path_seg);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Could not store path_seg into client context.");
            return rv;
        }
    }

    /*
     * Invoke client code to retrieve the CSR attributes.
     * Note: there is no need to authenticate the client (see sec 4.5)
     */
    EST_LOG_INFO("Proxy: Attempting to retrieve CSR attrs from upstream server");
    start_timer(&send_to_server_timer, ctx,
                "HTTPS proxy est_client_get_csrattrs");
    rv = est_client_get_csrattrs(client_ctx, (unsigned char **)&csr_data, &csr_len);
    stop_timer(&send_to_server_timer);
    ctx->retry_after_delay = client_ctx->retry_after_delay;
    /*
     * csr_data points to the memory allocated to hold the csr attributes,
     * which will be freed in this call stack.  To prevent a double-free
     * we null the to pointer on the client context.
     */
    client_ctx->retrieved_csrattrs = NULL;
    client_ctx->retrieved_csrattrs_len = 0;
    switch (rv) {
    case EST_ERR_NONE:
        break;
    /*
     * Something went wrong with the upstream request to the
     * server.
     */
    case EST_ERR_IP_GETADDR:
    case EST_ERR_IP_CONNECT:
    case EST_ERR_SSL_READ:
        /* This section will map to a 504 repsonse */
        EST_LOG_ERR("Proxy: Server not reachable %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        return (EST_ERR_IP_CONNECT);
    case EST_ERR_SSL_CONNECT:
    case EST_ERR_FQDN_MISMATCH:
    case EST_ERR_SSL_WRITE:
    case EST_ERR_ZERO_LENGTH_BUF:
    case EST_ERR_MULTIPART_PARSE:
    case EST_ERR_UNKNOWN:
    case EST_ERR_BUF_EXCEEDS_MAX_LEN:
    case EST_ERR_HTTP_UNSUPPORTED:
        /* This section will map to a 502 repsonse */
        EST_LOG_ERR(
            "Proxy: Error while communicating with upstream server %s (%d)",
            EST_ERR_NUM_TO_STR(rv), rv);
        return (EST_ERR_HTTP_UNSUPPORTED);
    case EST_ERR_HTTP_NO_CONTENT:
        if (ctx->server_enable_pop) {
            break;
        }
    case EST_ERR_HTTP_BAD_REQ:
    case EST_ERR_HTTP_NOT_FOUND:
    case EST_ERR_AUTH_FAIL:
    case EST_ERR_HTTP_LOCKED:
    case EST_ERR_CA_ENROLL_RETRY:
        /* This section will pass through the response code from the server */
        EST_LOG_ERR("Proxy: Passing through error response code from upstream "
                    "server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        return rv;
    default:
        /* This section will map to a 500 repsonse */
        EST_LOG_ERR("Proxy: Unhandled error occured while communicating with "
                    "the upstream server %s (%d)",
                    EST_ERR_NUM_TO_STR(rv), rv);
        return (EST_ERR_UNKNOWN);
    }
    ctx->csr_pop_present = 0;
    if (ctx->server_enable_pop) {
        rv = est_is_challengePassword_present(csr_data, csr_len, &pop_present);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Error during PoP/sanity check");
            /*
             * send the error back to the client
             */
            if (ctx->transport_mode == EST_HTTP) {
                est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
            } else if (ctx->transport_mode == EST_COAP) {
                return (EST_ERR_HTTP_NO_CONTENT);
            } else {
                EST_LOG_ERR("EST in improper transport mode. "
                            "Cannot get csr attrs.");
                return (EST_ERR_BAD_MODE);
            }
            return (EST_ERR_NONE);
        }
        ctx->csr_pop_present = pop_present;

        if (!ctx->csr_pop_present) {
            if (csr_len == 0) {
                csr_data = malloc(EST_CSRATTRS_POP_LEN + 1);
                if (!csr_data) {
                    return (EST_ERR_MALLOC);
                }
                strcpy_s(csr_data, EST_CSRATTRS_POP_LEN + 1, EST_CSRATTRS_POP);
                csr_data[EST_CSRATTRS_POP_LEN] = 0;
                csr_len = EST_CSRATTRS_POP_LEN;
                /*
                * send the attrs back to the client
                */
                if (ctx->transport_mode == EST_HTTP) {
                    return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
                } else if (ctx->transport_mode == EST_COAP) {
                    *returned_attrs = (unsigned char *)csr_data;
                    *returned_attrs_len = csr_len;
                    return (EST_ERR_NONE);
                } else {
                    EST_LOG_ERR("EST in improper transport mode. "
                                "Cannot get csr attrs.");
                    return (EST_ERR_BAD_MODE);
                }
            }
            rv = est_add_challengePassword(csr_data, csr_len, &csr_data_pop, &csr_pop_len);
            if (rv != EST_ERR_NONE) {
                if (csr_data) {
                    free(csr_data);
                }
                EST_LOG_ERR("Error during add PoP");
                /*
                 * send the error back to the client
                 */
                if (ctx->transport_mode == EST_HTTP) {
                    est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
                } else if (ctx->transport_mode == EST_COAP) {
                    return (EST_ERR_HTTP_NO_CONTENT);
                } else {
                    EST_LOG_ERR("EST in improper transport mode. "
                                "Cannot get csr attrs.");
                    return (EST_ERR_BAD_MODE);
                }
                return (EST_ERR_NONE);
            }
            if (csr_data) {
                free(csr_data);
            }
            csr_data = csr_data_pop;
            csr_len = csr_pop_len;
        }
    }
    /*
     * send the attrs back to the client
     */
    if (ctx->transport_mode == EST_HTTP) {
        return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
    } else if (ctx->transport_mode == EST_COAP) {
        *returned_attrs = (unsigned char *)csr_data;
        *returned_attrs_len = csr_len;
        return (EST_ERR_NONE);
    } else {
        EST_LOG_ERR("EST in improper transport mode. "
                    "Cannot get csr attrs.");
        return (EST_ERR_BAD_MODE);
    }
}


/*
 * This function should be called by the web server layer when
 * a HTTP request arrives on the listening port of the EST proxy.
 * It will determine the EST request type and dispatch the request
 * to the appropriate handler.
 *
 * Parameters:
 *      ctx:	    Pointer to EST_CTX
 *      http_ctx:   Context pointer from web server
 *      method:     The HTML method in the request, should be either "GET" or "POST"
 *	uri:	    pointer to HTTP URI
 *	body:	    pointer to full HTML body contents
 *	body_len:   length of HTML body
 *	ct:         HTML content type header
 */
EST_ERROR est_proxy_http_request (EST_CTX *ctx, void *http_ctx,
                                  char *method, char *uri,
                                  char *body, int body_len, const char *ct)
{
    SSL *ssl;
    EST_ERROR rc;
    int diff;
    errno_t safec_rc;
    EST_OPERATION operation;
    char *path_seg = NULL;    
    EST_ERROR rv = EST_ERR_NONE;
    X509 *peer_cert = NULL;    
    EST_ERROR event_rc;
    unsigned char *returned_cert = NULL;
    int returned_cert_len = 0;
    unsigned char *returned_key = NULL;
    int returned_key_len = 0;

    /* Performance Timers */
    pid_t proc_pid;
    char pid_str[MAX_PID_STR_LEN + 1];
    EST_TIMER http_req_timer;
    EST_TIMER event_cb_timer;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a proxy, not a client or server
     */
    if (ctx->est_mode != EST_PROXY) {
        return (EST_ERR_BAD_MODE);
    }

    /*
     * Get the SSL context, which is required for authenticating
     * the client.
     */
    ssl = (SSL*)mg_get_conn_ssl(http_ctx);
    if (!ssl) {
        est_send_http_error(ctx, http_ctx, EST_ERR_NO_SSL_CTX);
        free(path_seg);
        path_seg = NULL;
        return (EST_ERR_NO_SSL_CTX);
    }
    
    /*
     * Get the peer certificate now.  It's needed for some commands.
     * There may or may not be one, so no need to check to ensure that
     * we got one.
     */
    peer_cert = SSL_get_peer_certificate(ssl);    
    
    /*
     * Announce the 'EST request received from an end point' event.
     */
    start_timer(&event_cb_timer, ctx,
                "HTTP Proxy est_invoke_endpoint_req_event_cb REQ_START");
    est_invoke_endpoint_req_event_cb(ctx, peer_cert, ssl, NULL,
                                     (const char *)uri, EST_ENDPOINT_REQ_START);
    if (ctx->perf_timers_enabled) {
        proc_pid = GETPID();
        snprintf(pid_str, MAX_PID_STR_LEN + 1, "%ld", (unsigned long)proc_pid);
    }
    stop_timer_with_id(&event_cb_timer, pid_str);
    rv = est_parse_uri(uri, &operation, &path_seg);
    if (rv != EST_ERR_NONE) {
        est_send_http_error(ctx, http_ctx, rv);
        return (rv);
    }
    
    start_http_req_timer(&http_req_timer, ctx, operation);
    /*
     * See if this is a cacerts request
     */
    if (operation == EST_OP_CACERTS) {
        /* Only GET is allowed */
        safec_rc = strcmp_s(method, MAX_HTTP_METHOD_LEN, "GET", &diff);
        if (safec_rc != EOK) {
            EST_LOG_INFO("strcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        
        rc = est_proxy_handle_cacerts(ctx, http_ctx, path_seg);
        if (rc != EST_ERR_NONE) {
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (rc);
        } 
        stop_timer_with_id(&http_req_timer, pid_str);           
    }

    /*
     * See if this is a simple enrollment request
     */
    else if (operation == EST_OP_SIMPLE_ENROLL) {
        /* Only POST is allowed */
        safec_rc = strcmp_s(method, MAX_HTTP_METHOD_LEN, "POST", &diff);
        if (safec_rc != EOK) {
            EST_LOG_INFO("strcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_TYPE); 
        }
        /*
         * In this case body is indicating that no content was passed in, and
         * this is a enroll request.  This cannot be correct because a CSR is
         * required.  If this continues, and we're in proxy mode, we'll try to
         * forward this non-existent CSR
         */
        if (body == NULL) {
            EST_LOG_WARN("Incoming HTTP header has no CSR content.\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_LEN);
        }

        /*
         * Announce an EST Enroll or Re-Enroll CSR request is taking
         * place now.
         */
        if (ctx->enroll_req_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_req_event_cb SIMPLE_ENROLL");
            event_rc = est_invoke_enroll_req_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, SIMPLE_ENROLL_REQ);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }
        
        rc = est_proxy_handle_simple_enroll(ctx, http_ctx, ssl, ct,
                                            body, body_len, path_seg, 0,
                                            &returned_cert, &returned_cert_len);

        /*
         * Announce the response event for this request.
         */
        if (ctx->enroll_rsp_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_rsp_event_cb SIMPLE_ENROLL");
            event_rc = est_invoke_enroll_rsp_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, SIMPLE_ENROLL_REQ,
                                                      returned_cert, returned_cert_len, rc);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }
        /*
         * We're done with the returned cert now. 
         */
        free(returned_cert);

        if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING) {
            EST_LOG_WARN("Enrollment failed with rc=%d (%s)\n", 
		         rc, EST_ERR_NUM_TO_STR(rc));
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return rc;
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * See if this is a re-enrollment request
     */
    else if (operation == EST_OP_SIMPLE_REENROLL) {
        /* Only POST is allowed */
        safec_rc = strcmp_s(method, MAX_HTTP_METHOD_LEN, "POST", &diff);
        if (safec_rc != EOK) {
            EST_LOG_INFO("strcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
	        return (EST_ERR_BAD_CONTENT_TYPE); 
	    }
        /*
         * In this case body is indicating that no content was passed in, and
         * this is a enroll request.  This cannot be correct because a CSR is
         * required.  If this continues, and we're in proxy mode, we'll try to
         * forward this non-existent CSR
         */
        if (body == NULL) {
            EST_LOG_WARN("Incoming HTTP header has no CSR content.\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_LEN);
        }

        /*
         * Announce an EST Enroll or Re-Enroll CSR request is taking
         * place now.
         */
        if (ctx->enroll_req_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_req_event_cb REENROLL_REQ");
            event_rc = est_invoke_enroll_req_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, REENROLL_REQ);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }
        
        rc = est_proxy_handle_simple_enroll(ctx, http_ctx, ssl, ct,
                                            body, body_len, path_seg, 1,
                                            &returned_cert, &returned_cert_len);

        /*
         * Announce the response event for this request.
         */
        if (ctx->enroll_rsp_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_rsp_event_cb REENROLL_REQ");
            event_rc = est_invoke_enroll_rsp_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, REENROLL_REQ,
                                                      returned_cert, returned_cert_len, rc);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }
        /*
         * We're done with the returned cert now. 
         */
        free(returned_cert);

        if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING) {
            EST_LOG_WARN("Reenroll failed with rc=%d (%s)\n", 
		         rc, EST_ERR_NUM_TO_STR(rc));
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (rc);
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * See if this is a server-side keygen request
     */
    else if (operation == EST_OP_SERVER_KEYGEN) {
        /* Only POST is allowed */
        safec_rc = strcmp_s(method, MAX_HTTP_METHOD_LEN, "POST", &diff);
        if (safec_rc != EOK) {
            EST_LOG_INFO("strcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_TYPE);
        }
        /*
         * In this case body is indicating that no content was passed in, and
         * this is a enroll request.  This cannot be correct because a CSR is
         * required.  If this continues, and we're in proxy mode, we'll try to
         * forward this non-existent CSR
         */
        if (body == NULL) {
            EST_LOG_WARN("Incoming HTTP header has no CSR content.\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_LEN);
        }
        /*
         * Announce an EST Server Keygen request is taking place now.
         */
        if (ctx->enroll_req_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_req_event_cb SERVERKEYGEN_REQ");
            event_rc = est_invoke_enroll_req_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, SERVERKEYGEN_REQ);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }

        rc = est_proxy_handle_server_keygen(ctx, http_ctx, ssl, ct, body, body_len, path_seg,
                                            &returned_cert, &returned_cert_len, &returned_key, &returned_key_len);
        
        if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING) {
            EST_LOG_WARN("Server-side key generation enrollment failed with rc=%d (%s)\n",
                         rc, EST_ERR_NUM_TO_STR(rc));
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return rc;
        }

        /*
         * Announce the response event for this request.
         */
        if (ctx->enroll_rsp_event_cb != NULL) {
            start_timer(
                &event_cb_timer, ctx,
                "HTTP Proxy est_invoke_enroll_rsp_event_cb SERVERKEYGEN_REQ");
            event_rc = est_invoke_enroll_rsp_event_cb(ctx, ssl, peer_cert,
                                                      (unsigned char *)body, body_len,
                                                      NULL, path_seg, SERVERKEYGEN_REQ,
                                                      returned_cert, returned_cert_len, rc);
            stop_timer_with_id(&event_cb_timer, pid_str);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }
        /* 
         * returned_cert and returned_key will only hold data if
         * handle_server_keygen was successful
         */
        if(rc == EST_ERR_NONE) {
            free(returned_cert);
            memzero_s(returned_key, returned_key_len);
            free(returned_key);
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * See if this is a CSR attributes request
     */
    else if (operation == EST_OP_CSRATTRS) {
        /* Only GET is allowed */
        safec_rc = strcmp_s(method, MAX_HTTP_METHOD_LEN, "GET", &diff);
        if (safec_rc != EOK) {
            EST_LOG_INFO("strcmp_s error 0x%xO\n", safec_rc);
        }

        if (diff) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        rc = est_proxy_handle_csr_attrs(ctx, http_ctx, path_seg, NULL, 0);
        if (rc != EST_ERR_NONE) {
            est_send_http_error(ctx, http_ctx, rc); 
            free(path_seg);
            path_seg = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (rc);
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * Send a 404 error if the URI didn't match 
     */
    else {
        est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NOT_FOUND);
    }

    /*
     * Announce the end of the EST endpoint request event.
     */
    start_timer(&event_cb_timer, ctx,
                "HTTP Proxy est_invoke_endpoint_req_event_cb REQ_END");
    est_invoke_endpoint_req_event_cb(ctx, peer_cert, ssl, NULL,
                                     (const char *)uri, EST_ENDPOINT_REQ_END);
    stop_timer_with_id(&event_cb_timer, pid_str);    

    free(path_seg);
    path_seg = NULL;
    return (EST_ERR_NONE);
}

/*
 * This function is called by the application to start
 * the EST proxy server HTTP services layer.
 */
/*! @brief est_proxy_start() is used by an application to start the EST proxy
    after est_proxy_init() and est_proxy_set_server() have been called and all
    the required callback functions have been provided by the application.

    @param ctx Pointer to the EST context

    libEST uses HTTP code from the Mongoose HTTP server.
    This function allows the application to start the HTTP
    services layer, which is required by EST.
 
    @return EST_ERROR.    
 */
EST_ERROR est_proxy_start (EST_CTX *ctx)
{
    EST_MG_CONTEXT *mgctx;

    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    mgctx = mg_start(ctx);
    if (mgctx) {
        ctx->mg_ctx = mgctx;
        return (EST_ERR_NONE);
    } else {
        return (EST_ERR_NO_SSL_CTX);
    }
}

/*! @brief est_proxy_stop() is used by an application to stop
    the EST proxy.  This should be called prior to est_destroy().
 
    @param ctx Pointer to the EST context

    libEST uses HTTP code from the Mongoose HTTP server.
    This function allows the application to stop the HTTP
    services layer.
 
    @return EST_ERROR.
 */
EST_ERROR est_proxy_stop (EST_CTX *ctx)
{
    EST_MG_CONTEXT *mgctx;

    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    mgctx = (EST_MG_CONTEXT*)ctx->mg_ctx;
    if (mgctx) {
        mg_stop(mgctx);
    }
    return (EST_ERR_NONE);
}

/*! @brief est_proxy_init() is used by an application to create
    a context in the EST library.  This context is used when invoking
    other functions in the API while in Proxy mode.
 
    @param ca_chain     Char array containing PEM encoded CA certs & CRL entries.
                        This chain of certificates is used as the trust anchor when
                        establishing a TLS connection.
    @param ca_chain_len Length of ca_chain char array. 
    @param cacerts_resp_chain Char array containing PEM encoded CA certs to
                              include in the /cacerts response.  This is
                              an optional parameter.  If it set, it contains
                              the chain of certificates used by the proxy to
                              respond to GET CA Certs requests from EST Clients.
                              If this parameter is not included, then the proxy
                              will obtain the CA certificate chain from the
                              configured upstream EST server.  If this parameter
                              is not NULL, then the correct length of this
                              buffer must be specified in cacerts_resp_chain_len.
    @param cacerts_resp_chain_len Length of cacerts_resp_chain char array
    @param cert_format Specifies the encoding of the local and external
                       certificate chains (PEM/DER).  
    @param http_realm Char array containing HTTP realm name for HTTP auth
    @param tls_id_cert Pointer to X509 that contains the proxy's certificate
                    for the TLS layer.
    @param tls_id_key Pointer to EVP_PKEY that contains the private key
                   associated with the proxy's certificate.
    @param uid  User ID to use for authenticating with server
    @param pwd  Password to use for authenticating with server

    This function allows an application to initialize an EST server context
    for proxy mode operation, which is used when operating as an RA.  The
    application must provide the trusted CA certificates to use for server
    operation using the ca_chain parameter.  This certificate set should
    include the explicit trust anchor certificate, any number of implicit
    trust anchor certificates, and any intermediate sub-CA certificates
    required to complete the chain of trust between the identity certificate
    passed into the tls_id_cert parameter and the root certificate for that
    identity certificate.  The CA certificates should be encoded using the
    format specified in the cert_format parameter (e.g. PEM) and may contain
    CRL entries that will be used when authenticating EST clients connecting
    to the server.  The applications must also provide the HTTP realm to use
    for HTTP authentication and the server certificate/private key to use for
    TLS.
    
    Warning: Including additional intermediate sub-CA certificates that are
             not needed to complete the chain of trust may result in a
	     potential MITM attack.  
 
    @return EST_CTX.
 */
EST_CTX * est_proxy_init (unsigned char *ca_chain, int ca_chain_len,
                          unsigned char *cacerts_resp_chain, int cacerts_resp_chain_len,
			  EST_CERT_FORMAT cert_format,
                          char *http_realm, 
			  X509 *tls_id_cert, EVP_PKEY *tls_id_key,
                          char *uid, char *pwd)
{
    EST_CTX *ctx;
    int len;
#if HAVE_LIBCOAP
    EST_ERROR rc;
#endif
    
    est_log_version();

    /*
     * Sanity check the input
     */
    if (ca_chain == NULL) {
        EST_LOG_ERR("Trusted CA certificate set is empty");
        return NULL;
    }
    if (tls_id_cert == NULL) {
        EST_LOG_ERR("TLS cert is empty");
        return NULL;
    }
    if (tls_id_key == NULL) {
        EST_LOG_ERR("TLS private key is empty");
        return NULL;
    }
    if (http_realm == NULL) {
        EST_LOG_ERR("EST HTTP realm is NULL");
        return NULL;
    }
    if (cert_format != EST_CERT_FORMAT_PEM) {
        EST_LOG_ERR("Only PEM encoding of certificates is supported.");
        return NULL;
    }    

    /*
     * Verify the lengths of the cert chains 
     */
    len = (int) strnlen_s((char *)ca_chain, EST_CA_MAX);
    if (len != ca_chain_len) {
	EST_LOG_ERR("Length of ca_chain doesn't match ca_chain_len");
        return NULL;
    }
    if (cacerts_resp_chain) {    
        len = (int) strnlen_s((char *)cacerts_resp_chain, EST_CA_MAX);
        if (len != cacerts_resp_chain_len) {
            EST_LOG_ERR("Length of cacerts_resp_chain doesn't match cacerts_resp_chain_len");
            return NULL;
        }
    }
    
    /*
     * Allocate and set up the Proxy based EST Context.  This context will be
     * use when operating as the Server to the downstream clients.  EST Proxy mode
     * is basically a server function that requires client capabilities to
     * communicate to the upstream server when needed. 
     */
    ctx = malloc(sizeof(EST_CTX));
    if (!ctx) {
        EST_LOG_ERR("malloc failed");
        return NULL;
    }
    memzero_s(ctx, sizeof(EST_CTX));
    ctx->est_mode = EST_PROXY;
    ctx->retry_period = EST_RETRY_PERIOD_DEF;
    ctx->server_enable_pop = 1;
    ctx->require_http_auth = HTTP_AUTH_REQUIRED;
    ctx->enhanced_cert_auth_enabled = ENHANCED_CERT_AUTH_DISABLED;
    ctx->server_read_timeout = EST_SSL_READ_TIMEOUT_DEF;

    if (est_client_set_uid_pw(ctx, uid, pwd) != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to store the userid and password during proxy initialization");
        free(ctx);
        return NULL;
    }        
    
    /*
     * Load the CA certificates into local memory and retain
     * for future use.  This will be used for /cacerts requests.
     */
    if (cacerts_resp_chain) {    
        if (est_load_ca_certs(ctx, cacerts_resp_chain, cacerts_resp_chain_len)) {
            EST_LOG_ERR("Failed to load CA certificates response buffer");
            free(ctx);
            return NULL;
        }
    }
    
    /*
     * Load the CA certificate chain into an X509 store structure
     * This will be used in verifying incoming certs during TLS
     * establishment.
     * Also save a way a raw copy of the ca_chain buffer so that
     * it can be used when creating client contexts used to communicate
     * to the upstream server.
     */
    if (est_load_trusted_certs(ctx, ca_chain, ca_chain_len)) {
        EST_LOG_ERR("Failed to load trusted certificate store");
	est_destroy(ctx);
        return NULL;
    }
    ctx->ca_chain_raw =  malloc(ca_chain_len+1);
    if (!ctx->ca_chain_raw) {
        EST_LOG_ERR("malloc failed");
	est_destroy(ctx);
        return NULL;
    }
    memcpy_s((char *)ctx->ca_chain_raw, ca_chain_len+1, (char *)ca_chain, ca_chain_len);
    ctx->ca_chain_raw[ca_chain_len] = '\0';
    ctx->ca_chain_raw_len = ca_chain_len;
    
    strcpy_s(ctx->realm, MAX_REALM, http_realm);
    ctx->server_cert = tls_id_cert;
    ctx->server_priv_key = tls_id_key;
    ctx->auth_mode = AUTH_BASIC;
    ctx->read_timeout = EST_SSL_READ_TIMEOUT_DEF;
    ctx->retry_after_delay = 0;
    ctx->retry_after_date = 0;

    ctx->client_ctx_array = (CLIENT_CTX_LU_NODE_T *) malloc( sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);
    memzero_s(ctx->client_ctx_array, sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);

#ifdef HAVE_LIBCOAP
    /*
     * Initialize the DTLS handshake configuration values.
     * timeout value set to DEF(0), this will cause the initial timeout value to be
     * CiscoSSL's value of 1.
     * mtu value set to DEF(0), this will cause libcoap to specify its default
     * MTU value of 1152.
     */
    ctx->dtls_handshake_timer = EST_DTLS_HANDSHAKE_TIMEOUT_DEF;
    ctx->dtls_handshake_mtu = EST_DTLS_HANDSHAKE_MTU_DEF;
    ctx->dtls_session_max = EST_DTLS_SESSION_MAX_DEF;
    
    /*
     * Initialize the CoAP request array
     */
    rc = est_coap_init_req_array(ctx, ctx->dtls_session_max);
    if (rc != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to initialize the CoAP request array");
        free(ctx);
        return NULL;
    }

    ctx->down_time_timer_initialized = 0;
#endif    
    ctx->perf_timers_enabled = 0;
    
    return (ctx);
}

/*! @brief est_proxy_coap_init_start() is called by the application layer to
     specify the address/port of the EST server. It must be called after
     est_proxy_init() and prior to starting the EST proxy functionality.
 
    @param ctx Pointer to EST context for a client session
    @param port UDP port that this EST proxy will listen on
 
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_BAD_MODE - This can only be called when in server or proxy mode
    EST_ERR_INVALID_PORT_NUM - Invalid port number input, less than zero or
    greater than 65535
    EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED - Returned if libest has not been
    built with CoAP support.
    EST_ERR_COAP_PROCESSING_ERROR - Procesing error occurred with the CoAP
    library.
    
    est_proxy_coap_init_start error checks its input parameters and then stores
    the port number into the EST context.  It then initializes
    the CoAP library and setting up the resources with which to respond.
 */
EST_ERROR est_proxy_coap_init_start (EST_CTX *ctx, int port)
{
    if (!ctx) {
        return EST_ERR_NO_CTX;
    } else {
        if (ctx->est_mode == EST_PROXY) {
            /* 
            * Calls function in est_server.c in
            * order to reduce redundant code.
            */
            return(est_server_coap_init_start(ctx, port));
        } else {
            EST_LOG_ERR("Cannot start EST proxy with coap when context is not in EST proxy mode.");
            return EST_ERR_BAD_MODE;
        }
    }
}


/*! @brief est_proxy_set_auth_mode() is used by an application layer to
    configure the HTTP authentication method to use for validating the
    identity of an EST client.
 
    @param ctx Pointer to the EST proxy context.  This was returned from
    est_proxy_init().
    @param amode Should be either AUTH_BASIC or AUTH_DIGEST

    This function can optionally be invoked by the application layer to change
    the default HTTP authentication mode.  The default mode is HTTP Basic
    authentication.  An application may desire to use Digest authentication
    instead, in which case this function can be used to set that mode.  This
    function should be invoked prior to starting the EST proxy.

    @return EST_ERROR.
 */
EST_ERROR est_proxy_set_auth_mode (EST_CTX *ctx, EST_HTTP_AUTH_MODE amode)
{
    return(est_server_set_auth_mode(ctx, amode));
}


/*! @brief est_proxy_set_auth_cred_cb() is used by an application to register
  its callback function. 
    
  @param ctx EST context obtained from the est_proxy_init() call.
  @param auth_credentials_cb  Function pointer to the application layer callback

  The registered callback function is used by the EST client library to obtain
  authentication credentials.  The application can provide authentication
  credentials during initialization if they are available, such as the userid
  and password used with HTTP basic authentication.  During the processing of
  a request, the EST client library will call this application callback in the
  event that it does not have the authentication credentials that are being
  requested by the EST server.

  The callback function definition must match the following function
  prototype,

  int (*auth_credentials_cb)(EST_HTTP_AUTH_HDR *auth_credentials);

  auth_credentials - A pointer to a EST_HTTP_AUTH_HDR structure.  The
                     structure is provided by the EST library and the callback
                     function fills in the specific credentials being
                     requested.  These credential values must be passed in the
                     format in which they will be sent to the server, that is,
                     the EST client library will perform no reformatting of
                     these credentials.  Ownership of the memory holding these
                     credential values is transferred from the application
                     layer to the EST library when the application layer
                     returns these values to the EST library.  This allows the
                     EST library to free up this memory as soon as it is done
                     using these values.
                         
  The return value from the callback must be one of the following values:

  EST_HTTP_AUTH_CRED_SUCCESS - If the callback was able to provide the
                               requested credentials.
  EST_HTTP_AUTH_CRED_NOT_AVAILABLE - If the callback could not provide the
                                     requested credentials.

  The auth_credentials_cb parameter can be set to NULL to reset the callback
  function.
  
  All string parameters are NULL terminated strings.
    
  @return EST_ERROR.
  EST_ERR_NONE - Success.
  EST_ERR_NO_CTX
*/
EST_ERROR est_proxy_set_auth_cred_cb (EST_CTX *ctx, auth_credentials_cb callback)
{
    return(est_client_set_auth_cred_cb(ctx, callback));
}


/*! @brief est_proxy_set_read_timeout() is used by an application to set
    timeout value of read operations.  After the EST proxy sends a request to
    the EST server it will attempt to read the response from the server.  This
    timeout value limits the amount of time the proxy will wait for the
    response.

    @param ctx Pointer to the EST context
    @param timeout Integer value representing the read timeout in seconds.
    The minimum value is EST_SSL_READ_TIMEOUT_MIN and the maximum value is
    EST_SSL_READ_TIMEOUT_MAX.
 
    @return EST_ERROR.
 */
EST_ERROR est_proxy_set_read_timeout (EST_CTX *ctx, int timeout)
{
    return(est_client_set_read_timeout(ctx, timeout));
}


/*! @brief est_proxy_set_server() is called by the application layer to
     specify the address/port of the EST server. It must be called after
     est_proxy_init() and prior to issuing any EST commands.
 
    @param ctx Pointer to EST context for a client session
    @param server Name of the EST server to connect to.  The ASCII string
    representing the name of the server is limited to 254 characters
    @param port TCP port on the EST server to connect
 
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_INVALID_SERVER_NAME - NULL value passed for EST server name, or
    server name string too long
    EST_ERR_INVALID_PORT_NUM - Invalid port number input, less than zero or
    greater than 65535

    est_proxy_set_server error checks its input parameters and then stores
    both the hostname and port number into the EST context.
 */
EST_ERROR est_proxy_set_server (EST_CTX *ctx, const char *server, int port)
{
    
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }

    if (server == NULL) {
        return EST_ERR_INVALID_SERVER_NAME;
    }
    if (EST_MAX_SERVERNAME_LEN-1 < strnlen_s(server, EST_MAX_SERVERNAME_LEN)) {
        return EST_ERR_INVALID_SERVER_NAME;
    }   
    
    if (port <= 0 || port > 65535) {
        return EST_ERR_INVALID_PORT_NUM;
    }
    
    strcpy_s(ctx->est_server, EST_MAX_SERVERNAME_LEN, server);
    ctx->est_port_num = port;
    
    return EST_ERR_NONE;
}
