/*------------------------------------------------------------------
 * est/est_proxy.c - EST Proxy specific code
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       module.
 *
 * May, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2014 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2014-12-17 improved error handling of est_proxy_http_request() and diagnostic messages

#include "est.h"
#include <string.h>
#include <stdlib.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#endif
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
 * context pointers when calling into the EST client code to communincate with
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
    
    if (a->threadid > b->threadid) result = 1;
    if (a->threadid < b->threadid) result = -1;
    if (a->threadid == b->threadid) result = 0;

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
    CLIENT_CTX_LU_NODE_T *found_node;
    unsigned long zero_threadid = 0x0;
    CLIENT_CTX_LU_NODE_T *empty_node;
    int empty_index;

    /*
     * TODO: This is really returning a pointer to an opaque value, so
     * what's being used here is typically a pointer in pthread based
     * environments and not the actual pthread id.  The only helper API to
     * access the actual id is pthread_equal().  If this must be used, then
     * the array search would best be changed to a linear search.
     * We mix in the PID of the current process with the thread ID in
     * case the application is forking new processes (e.g. NGINX).  
     */
#ifdef _WIN32
    cur_threadid = (unsigned long) GetCurrentThreadId();
#else
#ifndef DISABLE_PTHREADS
    cur_threadid = (unsigned long) pthread_self();
#endif
#endif
    cur_threadid += getpid();

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
            EST_LOG_ERR("Unable to allocate and initialize EST client context for proxy use");
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
            EST_LOG_ERR("Unable to set authentication configuration in the client context for proxy use");
	    est_destroy(c_ctx);
            return (NULL);
	}        

        rv = est_client_set_auth_cred_cb(c_ctx, p_ctx->auth_credentials_cb);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to register authentication credential callback.");
            return (NULL);
        }

	rv = est_client_set_server(c_ctx, p_ctx->est_server, p_ctx->est_port_num);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to set the upstream server configuration in the client context for proxy use");
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
            memset(temp_array, 0, sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);                
            memcpy(temp_array, p_ctx->client_ctx_array,
		   sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array/2);
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
         * the entry was found in the tree, return the client context for this pid
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
 * This routine will check the result code from an enroll
 * attempt and propagate the retry-after message to the 
 * client if needed.
 */
static EST_ERROR est_proxy_propagate_retry (EST_CTX *ctx, void *http_ctx)
{
    /*
     * The CA did not sign the request and has asked the
     * client to retry in the future.  This may occur if
     * the CA is not configured for automatic enrollment.
     * Send the HTTP retry response to the client.
     * We need to propagate the retry-after response to
     * the client.
     */
    EST_LOG_INFO("CA server requests retry, propagate this to the client (%d)", 
        ctx->retry_after_delay);
    if (EST_ERR_NONE != est_server_send_http_retry_after(ctx, http_ctx, ctx->retry_after_delay)) {
        EST_LOG_ERR("HTTP write error while propagating retry-after");
        return (EST_ERR_HTTP_WRITE);
    }
    return (EST_ERR_NONE);
}


/*
 * This routine will send a PKCS7 encoded certificate to
 * the EST client via HTTP. 
 */
static EST_ERROR est_proxy_propagate_pkcs7 (void *http_ctx, unsigned char *pkcs7, int pkcs7_len)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;
    struct mg_connection *conn = (struct mg_connection*)http_ctx;

    /*
     * Send HTTP header
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200, EST_HTTP_HDR_EOL,
             EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
    hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_PKCS7_CO, EST_HTTP_HDR_EOL);
    hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CE,
             EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
    hdrlen = strnlen(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
             pkcs7_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
    if (!mg_write(conn, http_hdr, strnlen(http_hdr, EST_HTTP_HDR_MAX))) {
            return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send the signed PKCS7 certificate in the body
     */
    if (!mg_write(conn, pkcs7, pkcs7_len)) {
        EST_LOG_ERR("HTTP write error while propagating pkcs7");
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
    rcvd_cacerts = (unsigned char *)malloc(rcvd_cacerts_len);
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
 * it will return the X509 cert in the *pkcs7 buffer.
 * The length of the returned cert will be in *pkcs7_len.
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
 * This function is used by the server side of the EST proxy to respond to an
 * incoming Simple Enroll request.  This function is similar to the Client API
 * function, est_client_enroll_req(), except it bypasses some things that are
 * not done when functioning as a proxy, such as signing the CSR, not
 * inserting the TLS unique id and instead including the id-kp-cmcRA usage
 * extension.
 */
static EST_ERROR est_proxy_handle_simple_enroll (EST_CTX *ctx, void *http_ctx,
                                                 SSL *ssl, const char *ct,
                                                 char *body, int body_len,
					         int reenroll)
{
    EST_ERROR rv;
    BUF_MEM *pkcs10;
    unsigned char *pkcs7;
    int pkcs7_len = 0;
    X509_REQ *csr = NULL;
    EST_CTX *client_ctx;
     
    /*
     * Make sure the client has sent us a PKCS10 CSR request
     */
    if (strcmp(ct, "application/pkcs10")) {
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_enroll_auth(ctx, http_ctx, ssl, reenroll)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
        break;
    case EST_HTTP_AUTH_PENDING:
        return (EST_ERR_AUTH_PENDING);
        break;
    case EST_UNAUTHORIZED:
    default:
        return (EST_ERR_AUTH_FAIL);
        break;
    }

    /*
     * Parse the PKCS10 CSR from the client
     */
    csr = est_server_parse_csr((unsigned char*)body, body_len);
    if (!csr) {
	EST_LOG_ERR("Unable to parse the PKCS10 CSR sent by the client");
	return (EST_ERR_BAD_PKCS10);
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
     * Allocate some space to hold the cert that we
     * expect to receive from the EST server.
     */
    pkcs7 = (unsigned char*)malloc(EST_CA_MAX); 

    /*
     * Attempt to enroll the CSR from the client
     */
    rv = est_proxy_send_enroll_request(client_ctx, pkcs10, pkcs7, &pkcs7_len, reenroll);

    /*
     * Handle any errors that likely occurred
     */
    switch (rv) {
    case EST_ERR_AUTH_FAIL:
        /* Try one more time if we're doing Digest auth */
        if ((ctx->auth_mode == AUTH_DIGEST ||
             ctx->auth_mode == AUTH_BASIC  ||
             ctx->auth_mode == AUTH_TOKEN)) {
            
            EST_LOG_INFO("HTTP Auth failed, trying again with digest/basic parameters");

            rv = est_proxy_send_enroll_request(client_ctx, pkcs10, pkcs7, &pkcs7_len, reenroll);
	    if (rv == EST_ERR_CA_ENROLL_RETRY) {
	        rv = est_proxy_propagate_retry(client_ctx, http_ctx);
	    } else if (rv != EST_ERR_NONE) {
                EST_LOG_WARN("EST enrollment failed, error code is %d", rv);
            }
        }
        break;
    case EST_ERR_CA_ENROLL_RETRY:
	rv = est_proxy_propagate_retry(client_ctx, http_ctx);
	break;
    default:
        EST_LOG_WARN("Initial EST enrollment request error code is %d", rv);
	break;
    }

    client_ctx->auth_mode = AUTH_NONE;
    
    /*
     * Prevent OpenSSL from freeing our data
     */
    est_proxy_free_ossl_bufmem(pkcs10);

    /*
     * If we have a cert response from the EST server, let's forward
     * it back to the EST client
     */
    if (pkcs7_len > 0) {
        rv = est_proxy_propagate_pkcs7(http_ctx, pkcs7, pkcs7_len);
    }
    free(pkcs7);

    return (rv);
}

#if 0
static int est_proxy_handle_keygen (EST_CTX *ctx)
{
    //TODO
    return (EST_ERR_NONE);
}
#endif

/*
 * This function is used by the server side of the EST proxy to respond to an
 * incoming CSR Attributes request.  This function is similar to the Client API
 * function, est_client_get_csrattrs().
  */
static EST_ERROR est_proxy_handle_csr_attrs (EST_CTX *ctx, void *http_ctx)
{
    EST_ERROR rv = EST_ERR_NONE;
    int pop_present;
    char *csr_data, *csr_data_pop;
    int csr_len, csr_pop_len;
    EST_CTX *client_ctx;

    /*
     * get the client context for this thread
     */
    client_ctx = get_client_ctx(ctx);
    if (!client_ctx) {
        EST_LOG_ERR("Unable to obtain client context for proxy operation");
	return (EST_ERR_NO_CTX);
    }

    /*
     * Invoke client code to retrieve the CSR attributes.
     * Note: there is no need to authenticate the client (see sec 4.5)
     */
    EST_LOG_INFO("Proxy get csr attributes");
    rv = est_client_get_csrattrs(client_ctx, (unsigned char **)&csr_data, &csr_len);
    /*
     * csr_data points to the memory allocated to hold the csr attributes,
     * which will be freed in this call stack.  To prevent a double-free
     * we null the to pointer on the client context.
     */
    client_ctx->retrieved_csrattrs = NULL;
    client_ctx->retrieved_csrattrs_len = 0;
    if (rv == EST_ERR_NONE) {
	ctx->csr_pop_present = 0;
	if (ctx->server_enable_pop) {
	    rv = est_is_challengePassword_present(csr_data, csr_len, &pop_present);
	    if (rv != EST_ERR_NONE) {
		EST_LOG_ERR("Error during PoP/sanity check");
		est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
		return (EST_ERR_NONE);
	    }
	    ctx->csr_pop_present = pop_present;

	    if (!ctx->csr_pop_present) {
		if (csr_len == 0) {
                    csr_data = (char *)malloc(EST_CSRATTRS_POP_LEN + 1);
		    if (!csr_data) {
			return (EST_ERR_MALLOC);
		    }
		    strncpy(csr_data, EST_CSRATTRS_POP, EST_CSRATTRS_POP_LEN);
		    csr_data[EST_CSRATTRS_POP_LEN] = 0;
		    csr_len = EST_CSRATTRS_POP_LEN;
		    return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
		}
		rv = est_add_challengePassword(csr_data, csr_len, &csr_data_pop, &csr_pop_len);
		if (rv != EST_ERR_NONE) {
		    if (csr_data) {
		        free(csr_data);
		    }
		    EST_LOG_ERR("Error during add PoP");
		    est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
		    return (EST_ERR_NONE);
		}
		if (csr_data) {
		    free(csr_data);
		}
		csr_data = csr_data_pop;
		csr_len = csr_pop_len;
	    }
	}
    } else {
	EST_LOG_ERR("Server not reachable or sent corrupt attributes");
	est_send_http_error(ctx, http_ctx, EST_ERR_HTTP_NO_CONTENT);
	return (EST_ERR_NONE);
    }
    return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
}


/*
 * This function should be called by the web server layer when
 * a HTTP request arrives on the listening port of the EST proxy.
 * It will determine the EST request type and dispatch the request
 * to the appropriate handler.
 *
 * Paramters:
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

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a proxy, not a client or server
     */
    if (ctx->est_mode != EST_PROXY) {
        return (EST_ERR_BAD_MODE);
    }

    // EST_LOG_INFO("Proxy started handling %s %s", method, uri);

    /*
     * See if this is a cacerts request
     */
    if (strncmp(uri, EST_CACERTS_URI, EST_URI_MAX_LEN) == 0) {
        /* Only GET is allowed */
        if (strcmp(method, "GET")) {
	    rc = EST_ERR_WRONG_METHOD;
        } else {
	    rc = est_handle_cacerts(ctx, http_ctx);
	}
    }

    /*
     * See if this is a simple (re-)enrollment request
     */
    else if (strncmp(uri, EST_SIMPLE_ENROLL_URI, EST_URI_MAX_LEN) == 0
          || strncmp(uri, EST_RE_ENROLL_URI, EST_URI_MAX_LEN) == 0) {
        /* Only POST is allowed */
        if (strcmp(method, "POST")) {
            rc = EST_ERR_WRONG_METHOD;
        }
	else if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header");
	    rc = EST_ERR_BAD_CONTENT_TYPE;
	} else {
	    /*
	     * Get the SSL context, which is required for authenticating the client.
	     */
	    ssl = (SSL *)mg_get_conn_ssl((struct mg_connection *)http_ctx);
	    if (!ssl) {
		rc = EST_ERR_NO_SSL_CTX;
	    } else {
		rc = est_proxy_handle_simple_enroll(ctx, http_ctx, ssl, ct, body, body_len, 
						    strncmp(uri, EST_RE_ENROLL_URI, EST_URI_MAX_LEN) == 0);
#if 0 // I see no reason for hiding the actual cause of errors from clients
		if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING && rc != EST_ERR_AUTH_FAIL) {
		    rc = EST_ERR_BAD_PKCS10;
		}
#endif
	    }
	}
    }

#if 0
    /*
     * See if this is a keygen request
     * FIXME: this is currently not implemented
     */
    else if (strncmp(uri, EST_KEYGEN_URI, EST_URI_MAX_LEN) == 0) {

        /* Only POST is allowed */
        if (strcmp(method, "POST")) {
            rc = EST_ERR_WRONG_METHOD;
        }
	else if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header");
	    rc = EST_ERR_BAD_CONTENT_TYPE;
	}
        else if (est_proxy_handle_keygen(ctx)) {
            rc = EST_ERR_HTTP_WRITE;             //FIXME: need the appropriate return code
        }
    }
#endif

    /*
     * See if this is a CSR attributes request
     */
    else if (strncmp(uri, EST_CSR_ATTRS_URI, EST_URI_MAX_LEN) == 0) {
        /* Only GET is allowed */
        if (strcmp(method, "GET")) {
            rc = EST_ERR_WRONG_METHOD;
        } else {
           rc = est_proxy_handle_csr_attrs(ctx, http_ctx);
        }
    }

    /*
     * Send a 404 error if the URI didn't match 
     */
    else {
        rc = EST_ERR_HTTP_NOT_FOUND;
    }

    // EST_LOG_INFO("Proxy finished handling %s %s with rv = %d (%s)", method, uri, rc, EST_ERR_NUM_TO_STR(rc));

    if (rc != EST_ERR_NONE) {
	est_send_http_error(ctx, http_ctx, rc);
    }
    return (rc);
}

/*
 * This function is called by the application to start
 * the EST proxy server HTTP services layer.
 */
/*! @brief est_proxy_start() is used by an application to start the EST proxy
    after est_proxy_init() and est_proxy_set_server() have been called and all
    the required callback functions have been provided by the application.

    @param ctx Pointer to the EST context

    libest uses HTTP code from the Mongoose HTTP server.
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

    libest uses HTTP code from the Mongoose HTTP server.
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
    for HTTP authentication and the server cerificate/private key to use for
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
    len = (int) strnlen((char *)ca_chain, EST_CA_MAX);
    if (len != ca_chain_len) {
	EST_LOG_ERR("Length of ca_chain doesn't match ca_chain_len");
        return NULL;
    }
    if (cacerts_resp_chain) {    
        len = (int) strnlen((char *)cacerts_resp_chain, EST_CA_MAX);
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
    ctx = (EST_CTX *)malloc(sizeof(EST_CTX));
    if (!ctx) {
        EST_LOG_ERR("malloc failed");
        return NULL;
    }
    memset(ctx, 0, sizeof(EST_CTX));
    ctx->est_mode = EST_PROXY;
    ctx->retry_period = EST_RETRY_PERIOD_DEF;
    ctx->server_enable_pop = 1;
    ctx->require_http_auth = HTTP_AUTH_REQUIRED;

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
     * establishement.
     * Also save a way a raw copy of the ca_chain buffer so that
     * it can be used when creating client contexts used to communincate
     * to the upstream server.
     */
    if (est_load_trusted_certs(ctx, ca_chain, ca_chain_len)) {
        EST_LOG_ERR("Failed to load trusted certificate store");
	est_destroy(ctx);
        return NULL;
    }
    ctx->ca_chain_raw =  (unsigned char *)malloc(ca_chain_len+1);
    if (!ctx->ca_chain_raw) {
        EST_LOG_ERR("malloc failed");
	est_destroy(ctx);
        return NULL;
    }
    memcpy((char *)ctx->ca_chain_raw, (char *)ca_chain, ca_chain_len);
    ctx->ca_chain_raw[ca_chain_len] = '\0';
    ctx->ca_chain_raw_len = ca_chain_len;
    
    strncpy(ctx->realm, http_realm, MAX_REALM);
    ctx->server_cert = tls_id_cert;
    ctx->server_priv_key = tls_id_key;
    ctx->auth_mode = AUTH_BASIC;
    ctx->read_timeout = EST_SSL_READ_TIMEOUT_DEF;
    ctx->retry_after_delay = 0;
    ctx->retry_after_date = 0;

    ctx->client_ctx_array = (CLIENT_CTX_LU_NODE_T *) malloc( sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);
    memset(ctx->client_ctx_array, 0, sizeof(CLIENT_CTX_LU_NODE_T)*cur_max_ctx_array);
    
    return (ctx);
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
    int rcvd_cacerts_len = 0;
    unsigned char *rcvd_cacerts = NULL;
    EST_ERROR rv;
    
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }

    if (server == NULL) {
        return EST_ERR_INVALID_SERVER_NAME;
    }
    if (EST_MAX_SERVERNAME_LEN-1 < strnlen(server, EST_MAX_SERVERNAME_LEN)) {
        return EST_ERR_INVALID_SERVER_NAME;
    }   
    
    if (port <= 0 || port > 65535) {
        return EST_ERR_INVALID_PORT_NUM;
    }
    
    strncpy(ctx->est_server, server, EST_MAX_SERVERNAME_LEN);
    ctx->est_port_num = port;

    /*
     * It's possible that the application did not provide the CA Certs chain
     * used to respond to Get CACerts requests.  If this is the case, then get
     * them now and save them away in the context.
     */
    if (ctx->ca_certs == NULL) {

        rv = est_proxy_retrieve_cacerts(ctx, &rcvd_cacerts, &rcvd_cacerts_len);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Unable to retrieve CA Cert chain from server");
            return (rv);
        }
        /*
         * This buffer will be freed normally with est_destroy()
         */
        ctx->ca_certs = rcvd_cacerts;
        ctx->ca_certs_len = rcvd_cacerts_len;    
    }
    
    return EST_ERR_NONE;
}
