/** @file */
/*------------------------------------------------------------------
 * est/est_server_coap.c - EST Server code that is CoAP specific.
 *
 * October, 2019
 *
 * Copyright (c) 2018-2019 by cisco Systems, Inc.
 * All rights reserved.
 **-----------------------------------------------------------------
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef WIN32
#include <WS2tcpip.h>
#endif
#include "est.h"
#include "est_server.h"
#include "est_server_http.h"
#include "est_locl.h"
#include "est_ossl_util.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/bio.h>

#if HAVE_LIBCOAP
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define COAP_MEDIA_TYPE_MULTI             62
#define COAP_MEDIA_TYPE_PKCS7_SKG         280
#define COAP_MEDIA_TYPE_PKCS7_CERTS       281
#define COAP_MEDIA_TYPE_PKCS7_CMCREQ      282
#define COAP_MEDIA_TYPE_PKCS7_CMCRES      283
#define COAP_MEDIA_TYPE_PKCS8             284
#define COAP_MEDIA_TYPE_CSR_ATTRS         285
#define COAP_MEDIA_TYPE_PKCS10            286
/* the maximum acceptable coap method code */
#define COAP_CONTENT_TYPE_MAX           65535
#define MAX_CONTENT_TYPE_BUF_SIZE         40

static int reinit_coap_req(EST_CTX *ctx, coap_req_node_t *node, EST_COAP_REQ new_req);

typedef struct coap_dtls_context_t {
    SSL_CTX *ctx;
    SSL *ssl;    /* OpenSSL object for listening to connection requests */
    HMAC_CTX *cookie_hmac;
    BIO_METHOD *meth;
    BIO_ADDR *bio_addr;
} coap_dtls_context_t;

typedef struct coap_tls_context_t {
  SSL_CTX *ctx;
  BIO_METHOD *meth;
} coap_tls_context_t;

typedef struct coap_openssl_context_t {
  coap_dtls_context_t dtls;
  coap_tls_context_t tls;
  int psk_pki_enabled;
} coap_openssl_context_t;

static void start_down_time_timer (EST_CTX *ctx)
{
    if (ctx->perf_timers_enabled && !ctx->down_time_timer_initialized) {
        ctx->down_time_timer_initialized = 1;
    }
    start_timer(&ctx->down_time_timer, ctx, "CoAP Down Time Timer");
}

static void stop_down_time_timer (EST_CTX *ctx)
{
    if (ctx->down_time_timer_initialized) {
        stop_timer(&ctx->down_time_timer);
    }
}

/*
 * Checks the CoAP message options, such as the Accept Option 
 * and the Content Format Option, to see if they are the expected values.
 * Returns an error if an unexpected option is found.
 * 
 * @param option_type      The type of Option to check
 *                         (e.g., Content Format, Accept, etc)
 * @param coap_media_type  The expected media type for the given option type
 *                         (e.g., COAP_MEDIA_TYPE_PKCS10, etc)
 */
static EST_ERROR est_coap_check_option (coap_pdu_t *request,
                                        const char *function,
                                        uint16_t option_type,
                                        const int coap_media_type)
{
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    unsigned int option_val = 0;

    /*
     * Check for the correct option type
     */
    option = coap_check_option(request, option_type, &opt_iter);
    if (option) {
        option_val = coap_decode_var_bytes(coap_opt_value(option),
                                           coap_opt_length(option));
        /*
         * error out if the expected type (coap_media_type) is
         * not what is received (option_val)
         */
        if (option_val != coap_media_type) {
            /*
             * 65536+ is considered a BAD_OPTION
             */
            if (option_val > COAP_CONTENT_TYPE_MAX) {
                EST_LOG_ERR("CoAP: Bad option found in %s. "
                            "Expected %d, received %d.", function,
                            coap_media_type, option_val);
                /* return a BAD_OPTION error code (CoAP 402) */
                return EST_ERR_BAD_CONTENT_TYPE;
                /*
                 * 0-65535 is considered a BAD_REQUEST for content-format options
                 * and considered NOT_ACCEPTABLE for accept options
                 */
            } else {
                EST_LOG_ERR("CoAP: Incorrect media type found in %s. "
                            "Expected %d, received %d.", function,
                            coap_media_type, option_val);
                switch (option_type) {
                case COAP_OPTION_CONTENT_TYPE:
                    /* return a BAD_REQUEST error code (CoAP 400) */
                    return EST_ERR_HTTP_BAD_REQ;
                case COAP_OPTION_ACCEPT:
                    /* return a NOT_ACCEPTABLE error code (CoAP 406) */
                    return EST_ERR_HTTP_UNSUPPORTED;
                }
            }
        }
        /* 
         * it is considered a BAD_OPTION if there
         * are multiple options of the same type
         * for an Accept option or a Content-Format option
         */
        if (coap_option_next(&opt_iter)) {
            EST_LOG_ERR("CoAP: Multiple options of the same type found in %s.",
                        function);
            /* return a BAD_OPTION error code (CoAP 402) */
            return EST_ERR_BAD_CONTENT_TYPE;
        }
    } else {
        /* it is acceptable to not have an Accept Option */
        if (option_type != COAP_OPTION_ACCEPT) {
            EST_LOG_ERR("CoAP: Option not found in %s.", function);
            /* return a BAD_OPTION error code (CoAP 402) */
            return EST_ERR_BAD_CONTENT_TYPE;
        }
    }
    return EST_ERR_NONE;
}


/*
 * coap_bsearch_compare is used by the bsearch function to perform the
 * comparison of the nodes within the coap req array.
 */
static int coap_bsearch_compare (const void *pa, const void *pb)
{
    int result;
    coap_req_node_t *a = (coap_req_node_t *)pa;
    coap_req_node_t *b = (coap_req_node_t *)pb;
    int diff;
    errno_t safec_rc;

    safec_rc = strcmp_s(a->key, MAX_SEARCH_STRING_LEN, b->key, &diff);
    if (safec_rc != EOK) {
        EST_LOG_ERR("strcmp_s error 0x%xO", safec_rc);
    }
    
    if (diff > 0) {
        result = 1;
    } else if (diff < 0) {
        result = -1;
    } else {
        result = 0;
    }
    return (result);
}

/*
 * get_coap_req() performs a search through an ordered array.  The key for the
 * search is the concatenated string, "remote_port_num"|"remote_ip_addr". If
 * found, the coap req structure for this key is returned.  If not found, a
 * new coap structure is created, added to the list, and this structure is
 * returned.  NULL is returned on an error in processing.
 */
static coap_req_node_t *get_coap_req (EST_CTX *ctx, void *addr_info,
                                      EST_COAP_REQ incoming_req)
{
    EST_ERROR est_rc;
    coap_req_node_t *found_node = NULL;
    char * zero_coap_req = "";
    coap_req_node_t *empty_node = NULL;
    char src_ipstr[INET6_ADDRSTRLEN];
    int src_port = 0;
    char search_key[MAX_SEARCH_STRING_LEN+1];
    errno_t safec_rc;
    
    /*
     * Build up the key to be used.  This is a concatenation of
     * "src_port_str"|"src_ipaddr_str".  Port number first because it's more
     * likely to be random.
     * - zeroize the buffers
     * - obtain the src address and src port
     * - get them into strings and concatenate them
     */
    memzero_s(src_ipstr, INET6_ADDRSTRLEN+1);
    memzero_s(search_key, MAX_SEARCH_STRING_LEN+1);
    est_rc = est_invoke_enroll_get_ip_port(ctx, NULL, addr_info,
                                           &src_ipstr[0], INET6_ADDRSTRLEN,
                                           &src_port);
    if (est_rc != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to obtain source IP address and port.");
        return (NULL);
    }
        
    sprintf(search_key, "%d", src_port);
    safec_rc = strcat_s(search_key, MAX_SEARCH_STRING_LEN, src_ipstr);
    if (safec_rc != EOK) {
        EST_LOG_ERR("strcat_s error 0x%xO. Failed to create search string for coap request."
                    " Source IP = %s, Source port = %s",
                    safec_rc, src_ipstr, search_key);
        return (NULL);
    }

    /*
     * Look for this string based key.
     */
    found_node = (coap_req_node_t *) bsearch(&search_key[0],
                                             ctx->coap_req_array,
                                             ctx->cur_max_coap_req_array,
                                             sizeof(coap_req_node_t),
                                             coap_bsearch_compare);
    if (found_node == NULL) {
        
        /*
         * Make sure there's room for another entry
         */
        empty_node = (coap_req_node_t *) bsearch(zero_coap_req,
                                                 ctx->coap_req_array,
                                                 ctx->cur_max_coap_req_array,
                                                 sizeof(coap_req_node_t),
                                                 coap_bsearch_compare);        
        if (empty_node == NULL) {
            EST_LOG_ERR("coap_req: Failed to obtain a free node in the CoAP request array");
            return (NULL);
        }

        /*
         * Assign the new entry and sort it into the array
         */
        safec_rc = memcpy_s(empty_node->key, MAX_SEARCH_STRING_LEN, search_key,
                            MAX_SEARCH_STRING_LEN);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s error 0x%xO."
                        " Failed to copy in new entry key to empty_node in array.");
            return (NULL);
        }
        /*
         * set the EST request
         */
        empty_node->cur_req = incoming_req;
        
        qsort(ctx->coap_req_array, ctx->cur_max_coap_req_array,
              sizeof(coap_req_node_t), 
              coap_bsearch_compare);

        /*
         * Look for this key one more time now that it's in its
         * proper location in the array to obtain its index
         */
        found_node = (coap_req_node_t *) bsearch(&search_key[0],
                                                 ctx->coap_req_array,
                                                 ctx->cur_max_coap_req_array,
                                                 sizeof(coap_req_node_t),
                                                 coap_bsearch_compare);
        if (found_node == NULL) {
            EST_LOG_ERR("coap_req: Error in entering new coap_req entry into array");
            return (NULL);
        }
        /*
         * Starts timers that aren't started yet according to the coap requests
         * state
         */
        start_coap_req_timers(ctx, found_node);
        ctx->coap_req_cnt++;
    } else {
        /*
         * An entry must have been found.  Check to see if it's currently
         * in use and if it is, does the request match with the request
         * that's coming in now.
         * BUT don't reinit when the incoming request is a EST_COAP_REQ_RESET as
         * we are likely just trying to shut down.
         */
        if (found_node->cur_req != incoming_req &&
            incoming_req != EST_COAP_REQ_RESET) {
            /*
             * Doesn't match so reinitialize the entry
             */
            EST_LOG_INFO("coap_req: Found mismatch in EST requests. "
                         "Reinitializing coap_req. cur_req: %d  incoming req: %d",
                         found_node->cur_req, incoming_req);
            
            if (!reinit_coap_req(ctx, found_node, incoming_req)) {
                /*
                 * reinit has somehow failed, so error out
                 */
                EST_LOG_ERR("coap_req: Error in entering new coap_req entry into array");
                return (NULL);
            }   

            /*
             * set the EST request
             */
            found_node->cur_req = incoming_req;
        }
    }
    
    /*
     * At this point we're leaving under three possible conditions
     * 1. There was no matching entry so we allocated one by setting the key
     * 2. We found a matching entry AND the EST request in the
     *    entry matches the new incoming request.  We leave with the found entry
     *    with its contents still set from previous incoming packets
     * 3. We found a matching entry AND the EST request in the entry does NOT
     *    match the new incoming request.  This means a new EST request is coming
     *    in on the same DTLS session.  We leave with the entry reinitialized as
     *    if we had just allocated it in case 1 above.
     */
    
    EST_LOG_INFO("coap_req: active count is: %d", ctx->coap_req_cnt);
    return (found_node);
}

/*
 * free up the coap_req entry that is passed in.  If found and reset, then return
 * 1, if failure, then return 0
 */
static int remove_coap_req (EST_CTX *ctx, coap_req_node_t *node)
{
    coap_req_node_t *found_node = NULL;

    if (node == NULL) {
        EST_LOG_ERR("NULL pointer for coap_req node");
        return 0;
    }        
    if (ctx == NULL) {
        EST_LOG_ERR("NULL pointer for EST ctx");
        return 0;
    }        
    if (ctx->coap_req_cnt == 0) {
        EST_LOG_ERR("coap_req: Attempt to return coap req entry when array is already empty");
        return 0;
    }
    
    /*
     * Look for this string based key.
     */
    found_node = (coap_req_node_t *) bsearch(&node->key[0],
                                             ctx->coap_req_array,
                                             ctx->cur_max_coap_req_array,
                                             sizeof(coap_req_node_t),
                                             coap_bsearch_compare);
    if (found_node == NULL) {
        EST_LOG_ERR("coap_req: CoAP request node not found in CoAP request array."
                    " Node key = %s", node->key);
        return 0;
    }

    stop_timer_with_id(&(found_node->session_timer), found_node->key);
    /*
     *  Catch the handling timer if it wasn't already stopped
     *  Should never happen 
     */
    if (is_running(&(found_node->handle_req_timer))) {
        EST_LOG_ERR("Handling Timer Missed");
        stop_timer_with_id(&(found_node->handle_req_timer), found_node->key);
    }
    /* 
     * Stop gap timer if it was started
     */
    if (is_started(&(found_node->req_gap_timer))) {
        stop_timer_with_id(&(found_node->req_gap_timer), found_node->key);
    }
    /*
     * Reset the node and re-sort the array
     */
    memzero_s(found_node, sizeof(coap_req_node_t));
    qsort(ctx->coap_req_array, ctx->cur_max_coap_req_array,
          sizeof(coap_req_node_t), 
          coap_bsearch_compare);
    ctx->coap_req_cnt--;
    EST_LOG_INFO("coap_req: active count is: %d", ctx->coap_req_cnt);
    
    return 1;
}

/*
 * Reinitialize the coap_req entry passed in. This is used to get a currently
 * active coap_req entry ready for reuse when multiple EST requests per
 * session is occurring.  This will reinitialize the entry and get it ready
 * for a subsequent EST request.
 * Return:
 * 1 if correct parameters and reinitialized
 * 0 if invalid parameters are passed.
 */
static int reinit_coap_req (EST_CTX *ctx, coap_req_node_t *node,
                            EST_COAP_REQ new_req)
{

    if (node == NULL) {
        EST_LOG_ERR("NULL pointer for coap_req node");
        return 0;
    }
    if (ctx == NULL) {
        EST_LOG_ERR("NULL pointer for EST ctx");
        return 0;
    }

    /*
     *  Catch the handling timer if it wasn't already stopped
     *  Should never happen
     */
    if (is_running(&(node->handle_req_timer))) {
        EST_LOG_ERR("Handling Timer Missed");
        stop_timer_with_id(&(node->handle_req_timer), node->key);
    }
    /* 
     * Stop gap timer if it was started
     */
    if (is_started(&(node->req_gap_timer))) {
        stop_timer_with_id(&(node->req_gap_timer), node->key);
    }

    /*
     * Reset all the elements of the request except for the key.
     */
    memzero_s(&(node->req_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
    node->req_buf_len = 0;
    memzero_s(&(node->resp_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
    node->resp_buf_len = 0;
    node->resp_blk_num = 0;
    node->cur_req = new_req;
    null_timer(&(node->handle_req_timer));
    null_timer(&(node->req_gap_timer));
    /*
     * Starts timers that aren't started yet according to the coap requests
     * state
     */
    start_coap_req_timers(ctx, node);

    return 1;
}


#define DEBUG_COAP_REQ_ARRAY 0
#if DEBUG_COAP_REQ_ARRAY
static int check_coap_req_array (EST_CTX *ctx, int expected_active) 
{
    int i;
    int active = 0;
    
    for (i=0; i<ctx->cur_max_coap_req_array; i++){
        if (ctx->coap_req_array[i].key[0] != '\0') {
            EST_LOG_ERR("coap_req_array entry not empty. entry key = %s.",
                        &(ctx->coap_req_array[i].key[0]));
            expected_active++;
        }
    }
    return (active == expected_active);
}
#endif


/*
 * Allocate and initialize the coap_req_array.  Called during EST init
 * as well as when application layer is explicitly setting the max sessions.
 */
EST_ERROR est_coap_init_req_array (EST_CTX *ctx, int entry_count) 
{
    /*
     * Make sure it's not already initialized.
     */
    if (ctx->coap_req_array) {
        free(ctx->coap_req_array);
    }

    ctx->coap_req_array = (coap_req_node_t *) calloc(sizeof(coap_req_node_t)*entry_count,
                                                     sizeof(char));
    if (ctx->coap_req_array == NULL) {
        return (EST_ERR_MALLOC);
    }

    ctx->cur_max_coap_req_array = entry_count;
    
    return (EST_ERR_NONE);    
}


/*
 * Handler that is registered with libcoap library for the simpleenroll
 * request (sen).  At this point we know we have a simpleenroll and we can
 * take the payload of a CSR and pass it up to the existing simpleenroll
 * processing function
 */
static void
est_coap_sen_handler (coap_context_t  *ctx, struct coap_resource_t *resource,
                      coap_session_t *session, coap_pdu_t *request,
                      coap_binary_t *token, coap_string_t *query,
                      coap_pdu_t *response)
{
    EST_CTX *est_ctx = NULL;
    SSL *ssl = NULL;
    X509 *peer_cert = NULL;
    EST_ERROR rc = EST_ERR_NONE;
    EST_ERROR event_rc = EST_ERR_NONE;
    EST_ENROLL_REQ_TYPE enroll_req;
    int ind;
    char *b64_based_csr = NULL;
    int b64_based_len = 0;
    unsigned char *returned_cert = NULL;
    int returned_cert_len = 0;
    char *cert_der = NULL;
    char *cert_b64 = NULL;
    int cert_der_len = 0;
    char *cert_der_str = NULL;
    size_t csr_len;
    unsigned char *csr_buf = NULL;
    errno_t safec_rc;
    unsigned char buf[MAX_CONTENT_TYPE_BUF_SIZE];
    size_t size;
    uint8_t *data;
    coap_block_t block1;
    coap_req_node_t *coap_req = NULL;
    unsigned int done_receiving = 0;
    coap_block_t resp_block2 = { 0, 0, 0 };
    int payload = 0;
    int block1_exists = 0;
    EST_COAP_REQ req_type;
    

    /* Performance Timers */
    EST_TIMER handler_execute_timer;
    EST_TIMER processing_timer;
    EST_TIMER event_cb_timer;
    
    EST_LOG_INFO("Entering %s", __FUNCTION__);

    null_timer(&handler_execute_timer);
    /*
     * Check for the correct media type from the content format option
     */
    rc = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_CONTENT_TYPE,
                               COAP_MEDIA_TYPE_PKCS10);
    switch (rc) {
    case EST_ERR_NONE:
        break;
    case EST_ERR_BAD_CONTENT_TYPE:
        /* return a BAD_OPTION error code */
        response->code = COAP_RESPONSE_CODE(402);
        goto error_exit;
    case EST_ERR_HTTP_BAD_REQ:
        /* return a BAD_REQUEST error code */
        response->code = COAP_RESPONSE_CODE(400);
        goto error_exit;
    default:
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    
    /*
     * Get addressability to the EST context
     */
    est_ctx = coap_get_app_data(ctx);
    if (est_ctx == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain EST context from CoAP context.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    start_timer(&handler_execute_timer, est_ctx, "CoAP est_coap_sen_handler");
    /*
     * Obtain access to the SSL structure and then obtain the peer certificate.
     * If there is none, we cannot proceed since certificates are the
     * only way to be authenticated in CoAP.  Send back an unauthorized.
     */
    ssl = (SSL *)session->tls;
    if (ssl == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain SSL session information.");
        response->code = COAP_RESPONSE_CODE(401);
        goto error_exit;
    }
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain client certificate.");
        response->code = COAP_RESPONSE_CODE(401);
        goto error_exit;
    }

    /*
     * Check to see if this is an enroll or a reenroll
     */
    /* TODO: this ought to be altered when coap can handle path segments */
    if (EOK == strcmp_s(((const char *)resource->uri_path->s),
                        resource->uri_path->length, "est/sen", &ind) &&
        ind == 0) {
        enroll_req = SIMPLE_ENROLL_REQ;
        req_type = EST_COAP_REQ_SEN;
    } else if (EOK ==
               (strcmp_s(((const char *)resource->uri_path->s),
                         resource->uri_path->length, "est/sren", &ind)) &&
               ind == 0) {
        enroll_req = REENROLL_REQ;
        req_type = EST_COAP_REQ_SREN;
    } else {
        EST_LOG_ERR("Incorrect URI in enroll request");
        free(b64_based_csr);
        b64_based_csr = NULL;
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }

    /*
     * Obtain the coap request structure to hold on to the response
     * and the request (if needed)
     */
    coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                            req_type);
    if (coap_req == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain the CoAP request structure.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }

    /*
     * If we're already in the middle of processing a request and now we're
     * starting over on a new /sen or /sren, then we need to reset the
     * coap_req entry.
     *
     * If there's payload AND
     * no block1 = new request in its entirety
     * block1(0) = new request, first block
     * block1(>0) = continuing request
     */
    payload = (coap_get_data(request, &size, &data) && (size > 0));
    block1_exists = coap_get_block(request, COAP_OPTION_BLOCK1, &block1);
    if (coap_req->req_buf[0] != '\0' &&
        payload && (!block1_exists || (block1_exists && block1.num == 0))) {
        
        if (!reinit_coap_req(est_ctx, coap_req, req_type)) {
            /*
             * reinit has somehow failed, so error out
             */
            response->code = COAP_RESPONSE_CODE(500);
            EST_LOG_ERR(
                "coap_req: Error in entering new coap_req entry into array");
            goto error_exit;
        }
    }

    /*
     * If the response buffer is empty this means we're still in the process
     * of taking in the request.  If it's not empty, then we're in the middle
     * of response processing and can just call coap_add_data_blocked_response()
     * and leave.
     */
    if (coap_req->resp_buf[0] == '\0') {

        if (coap_req->req_buf[0] == '\0') {
            /*
             * This is the start of processing of the enroll request, so
             * indicate that this endpoint request is now being processed
             */
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_START");
            est_invoke_endpoint_req_event_cb(est_ctx, peer_cert, ssl,
                                             (void *)&(session->remote_addr),
                                             (char *) resource->uri_path->s,
                                             EST_ENDPOINT_REQ_START);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
        }
        
        /*
         * Check that the client accepts the type of
         * response the server plans to return
         */
        rc = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_ACCEPT,
                                   COAP_MEDIA_TYPE_PKCS7_CERTS);
        switch (rc) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_CONTENT_TYPE:
            /* return a BAD_OPTION error code */
            response->code = COAP_RESPONSE_CODE(402);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            /* return a NOT_ACCEPTABLE error code */
            response->code = COAP_RESPONSE_CODE(406);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * We're still in the middle of request processing and have not yet
         * transitioned to response processing.
         *
         * See if there is a block1 option on this inbound request
         */
        if (block1_exists) {
            /*
             * See if there's data in this PDU and if so, how much
             */
            if (payload) {
                /*
                 * there is data, so calculate the starting offset
                 */
                size_t offset = block1.num << (block1.szx + 4);
                /*
                 * If this is the first block for this payload, then reset the
                 * req_buf that holds what's been brought in so far
                 */
                if (offset == 0) {
                    if (coap_req->req_buf[0] != '\0') {
                        memzero_s(&(coap_req->req_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
                    }
                    coap_req->req_buf_len = 0;
                } else if (offset > coap_req->req_buf_len) {
                    /*
                     * Upload is not sequential - block missing
                     */
                    response->code = COAP_RESPONSE_CODE(408);
                    goto error_exit;
                }
                else if (offset < coap_req->req_buf_len) {
                    /*
                     * Upload is not sequential - block duplicated. ie, we've already
                     * seen this one
                     */
                    goto just_respond;
                }
            
                /*
                 * Add in new block to end of current data
                 */
                safec_rc = memcpy_s(&(coap_req->req_buf[offset]), size, data, size);
                if (safec_rc != EOK) {
                    EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
                    response->code = COAP_RESPONSE_CODE(500);
                    goto error_exit;
                }            
                coap_req->req_buf_len = offset + size;
            }

        
          just_respond:
            if (block1.m) {
                response->code = COAP_RESPONSE_CODE(231);
                done_receiving = 0;
            }
            else {
                response->code = COAP_RESPONSE_CODE(204);
                done_receiving = 1;
            }

            if (!done_receiving) {
                /* Make sure there is no Block1 in the response when
                 * we're about to use the response for actually
                 * responding with our response.  This should only
                 * added when responding to incoming block1s
                 */
                coap_add_option(response, COAP_OPTION_BLOCK1,
                                coap_encode_var_safe(buf, sizeof(buf),
                                                     ((block1.num << 4) |
                                                      (block1.m << 3) |
                                                      block1.szx)),
                                buf);
            }
            
        } /* Block1 processing */
        else if (coap_get_data(request, &size, &data) && (size > 0)) {
            /*
             * Not a BLOCK1 with data
             *
             * Just copy in the payload into the coap_req array
             */
            safec_rc = memcpy_s(&(coap_req->req_buf[0]), size, data, size);
            if (safec_rc != EOK) {
                EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
                response->code = COAP_RESPONSE_CODE(500);
                goto error_exit;
            }            
            coap_req->req_buf_len = size;
            done_receiving = 1;
        } else {
            /*
             * Not a BLOCK1 and no data
             *
             * Check to see if we've already received some of a block1 based
             * request
             */
            if (coap_req->req_buf_len != 0) {
                response->code = COAP_RESPONSE_CODE(400);
                goto error_exit;
            }
            /*
             * Just make sure the req buf is zeroed out
             */
            if (coap_req->req_buf[0] != '\0') {
                memzero_s(&(coap_req->req_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
            }
            coap_req->req_buf_len = 0;
            done_receiving = 1;
        }

        /*
         * If we're not done receiving the request payload then just return now
         */
        if (!done_receiving) {
            X509_free(peer_cert);
            stop_timer(&handler_execute_timer);
            return;
        }

        /* 
         * Check to make sure req length is greater than 0
         */
        if(coap_req->req_buf_len <= 0) {
            EST_LOG_ERR("COAP: Zero length payload");
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        }
    
        /*
         * The CSR resides in the req_buf.  Copy it over into a separate buffer for
         * actual processing.
         */
        csr_buf = calloc(coap_req->req_buf_len*2, sizeof(char));
        if (csr_buf == NULL) {
            EST_LOG_ERR("calloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        safec_rc = memcpy_s(csr_buf, coap_req->req_buf_len, &(coap_req->req_buf[0]), coap_req->req_buf_len);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        csr_len = coap_req->req_buf_len;

        /*
         * The enrollment code assumes that the CSR is base64 encoded.
         * There are numerous places where this assumption is made and
         * a base64 decode is performed.  Because of this, it's easier
         * to encode it here instead of changing all the places to condition
         * on a flag to decode or not decode
         */
        b64_based_csr = calloc(csr_len*2, sizeof(char));
        if (!b64_based_csr) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        b64_based_len = est_base64_encode((const char *)csr_buf, csr_len,
                                          (char *)b64_based_csr, csr_len*2, 1);
        if (b64_based_len <= 0) {
            EST_LOG_ERR("Invalid base64 encoded data");
            free(b64_based_csr);
            b64_based_csr = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        
        /*
         * Announce an EST Enroll or Re-Enroll CSR request is taking
         * place now.
         */
        if (est_ctx->enroll_req_event_cb != NULL) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_enroll_req_event_cb");
            event_rc = est_invoke_enroll_req_event_cb(est_ctx, ssl, peer_cert, csr_buf, csr_len,
                                                      (void *)&(session->remote_addr),
                                                      NULL /*path_seg */, enroll_req);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }


        /*
         * handle the enroll as proxy or server
         */
        if (est_ctx->est_mode == EST_SERVER) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_handle_simple_enroll");

            rc = est_handle_simple_enroll(
                est_ctx, NULL /*http_ctx */, ssl, peer_cert, NULL,
                (char *)b64_based_csr, b64_based_len, NULL /* path_seg */,
                enroll_req, &returned_cert, &returned_cert_len);

            stop_timer(&processing_timer);
        } else if (est_ctx->est_mode == EST_PROXY) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_proxy_handle_simple_enroll");

            rc = est_proxy_handle_simple_enroll(
                est_ctx, NULL /*http_ctx */, ssl, NULL, (char *)b64_based_csr,
                b64_based_len, NULL /* path_seg */, enroll_req, &returned_cert,
                &returned_cert_len);

            stop_timer(&processing_timer);
        } else {
            EST_LOG_ERR("Invalid EST mode. Cannot handle simple enroll.");
            free(b64_based_csr);
            b64_based_csr = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * Announce the response event for this request.
         */
        if (est_ctx->enroll_rsp_event_cb != NULL) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_enroll_rsp_event_cb");
            event_rc = est_invoke_enroll_rsp_event_cb(est_ctx, ssl, peer_cert, csr_buf, csr_len,
                                                      (void *)&(session->remote_addr),
                                                      NULL /*path_seg */, enroll_req,
                                                      returned_cert, returned_cert_len, rc);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }        
        }
        
        free(b64_based_csr);
        b64_based_csr = NULL;
        free(csr_buf);
        csr_buf = NULL;
        
        if(rc != EST_ERR_NONE) {
            EST_LOG_WARN("Enrollment failed with rc=%d (%s)\n", 
                         rc, EST_ERR_NUM_TO_STR(rc));
        }
        switch (rc) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_PKCS10:
        case EST_ERR_CSR_ATTR_MISSING:
        case EST_ERR_HTTP_BAD_REQ:
        case EST_ERR_NO_SSL_CTX:
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        case EST_ERR_HTTP_NO_CONTENT:
            response->code = COAP_RESPONSE_CODE(204);
            goto error_exit;
        case EST_ERR_HTTP_NOT_FOUND:
            response->code = COAP_RESPONSE_CODE(404);
            goto error_exit;
        case EST_ERR_AUTH_FAIL_TLSUID:
        case EST_ERR_AUTH_FAIL:
            response->code = COAP_RESPONSE_CODE(401);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            response->code = COAP_RESPONSE_CODE(502);
            goto error_exit;
        case EST_ERR_CA_ENROLL_RETRY:
        case EST_ERR_HTTP_LOCKED:
            response->code = COAP_RESPONSE_CODE(503);
            goto error_exit;
        case EST_ERR_IP_CONNECT:
            response->code = COAP_RESPONSE_CODE(504);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * b64 decode the cert to be sent back
         */
        cert_b64 = malloc(returned_cert_len + 1);
        if (!cert_b64) {
            EST_LOG_ERR("malloc error");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * est_base64_decode expects the input to be a string
         * so we need to copy it over to a new string buffer
         */
        safec_rc = memcpy_s(cert_b64, returned_cert_len + 1, returned_cert,
                            returned_cert_len);
        if (safec_rc != EOK) {
            EST_LOG_INFO("memcpy_s error 0x%xO\n", safec_rc);
            free(cert_b64);
            cert_b64 = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * Null terminate the newly copied buffer
         */
        cert_b64[returned_cert_len] = '\0';
        free(returned_cert);
        returned_cert = NULL;

        /*
         * Clamp the max size of the buffer to be the max which can be sent
         */
        cert_der_len = returned_cert_len > COAP_REQ_NODE_BUF_LEN_MAX
            ? COAP_REQ_NODE_BUF_LEN_MAX
            : returned_cert_len;
        /*
         * Allocate a buffer to put the b64 decoded data into
         */
        cert_der = malloc(cert_der_len);
        if (!cert_der) {
            EST_LOG_ERR("malloc error");
            free(cert_b64);
            cert_b64 = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* 
         * This function is taking the responsibility of ensuring the data is 
         * not too long to send 
         */
        cert_der_len = est_base64_decode((const char *)cert_b64,
                                         (char *)cert_der, cert_der_len);
        free(cert_b64);
        cert_b64 = NULL;
        if (cert_der_len <= 0) {
            EST_LOG_ERR("Invalid or too long base64 encoded data");
            free(cert_der);
            cert_der = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        cert_der_str = calloc(cert_der_len * 2 + 2, sizeof(char));
        est_hex_to_str(cert_der_str, (unsigned char *)cert_der, cert_der_len);
        EST_LOG_INFO("Cert in DER format is: %s\n", cert_der_str);
        free(cert_der_str);

        /*
         * This is the first response to be given on this request so load the
         * cacerts buffer into the coap_req node so that it can be used with
         * the subsequent responses
         */
        safec_rc = memcpy_s(coap_req->resp_buf, COAP_REQ_NODE_BUF_LEN_MAX,
                            cert_der, cert_der_len);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
            free(cert_der);
            cert_der = NULL;
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        coap_req->resp_buf_len = cert_der_len;

        free(cert_der);
        cert_der = NULL;

    }  /* request processing because resp_buf is currently empty */    
    
    /*
     * Send the response back to the client
     */
    response->code = COAP_RESPONSE_CODE(204);
    
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIA_TYPE_PKCS7_CERTS, -1,
                                   coap_req->resp_buf_len,
                                   (const unsigned char *)coap_req->resp_buf);

    /*
     * Retrieve the block2 that libcoap is going to send back
     * and check to see if the more bit is off.  If it's off then
     * we're sending the last block of data making up the response.
     * Return the coap_req and then we're done.
     */
    coap_get_block(response, COAP_OPTION_BLOCK2, &resp_block2);
    if (!resp_block2.m) {

    error_exit:
        if (est_ctx) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_END");
        }
        est_invoke_endpoint_req_event_cb(
            est_ctx, peer_cert, ssl, (void *)&(session->remote_addr),
            (char *)resource->uri_path->s, EST_ENDPOINT_REQ_END);
        /*
         * Stop and mark the handle request timer as complete.
         * Then start the request gap timer.
         */
        if (est_ctx) {
            if (coap_req) {
                stop_timer_with_id(&event_cb_timer, coap_req->key);
                enter_wait_coap_req_timers(est_ctx, coap_req);
            } else {
                stop_timer(&event_cb_timer);
            }
        }

#if DEBUG_COAP_REQ_ARRAY
        if (check_coap_req_array(est_ctx, 0) != 1) {
            EST_LOG_ERR("COAP_DEBUG: coap_req_array does not contain the expected number of entries");
        }
#endif
    } /* ! more bit */

    /*
     * Hold onto the peer_cert until the very end so that it can be passed
     * up on event notifications.
     * There are paths that lead here with the csr_buf still allocated. free it now.
     */
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    if (csr_buf) {
        free(csr_buf);
        csr_buf = NULL;
    }
    if (est_ctx) {
        stop_timer(&handler_execute_timer);
    }
}

/*
 * Creates and returns a CBOR bytestring by assigning an initial byte and
 * n length based on the size of the given buffer using proper CBOR notation.
 */ 
cbor_bytestring makeCborBytestring (uint64_t len, unsigned char *data)
{
    cbor_bytestring cbor;
    
    if (len <= INITIAL_BYTE_LENGTH_MAX) {
        cbor.initial_byte = INITIAL_BYTE_BYTESTRING_SMALL_BASE + len;
        /*0 bytes long*/
        cbor.n_length = 0;
    } else if (len <= UINT8_MAX) {
        cbor.initial_byte = INITIAL_BYTE_BYTESTRING_UINT8;
        cbor.n_length = 1;
    } else if (len <= UINT16_MAX) {
        cbor.initial_byte = INITIAL_BYTE_BYTESTRING_UINT16;
        cbor.n_length = 2;
    } else if (len <= UINT32_MAX) {
        cbor.initial_byte = INITIAL_BYTE_BYTESTRING_UINT32;
        cbor.n_length = 4;
    } else {
        cbor.initial_byte = INITIAL_BYTE_BYTESTRING_UINT64;
        cbor.n_length = 8;
    }
    cbor.data = data;
    cbor.len = len;
    return (cbor);
}

/*
* Adds the intial byte, length of data, and actual data to the buffer
*/
EST_ERROR writeCborBytestring (unsigned char **buffer,
                               cbor_bytestring *bytestring)
{
    int n;
    errno_t safec_rc;

    /* Copy in initial byte based on the cert length */
    **buffer = bytestring->initial_byte;
    (*buffer)++;

    /* Copy in actual length of key */
    for (n = bytestring->n_length - 1; n >= 0; n--) {
        **buffer = (bytestring->len >> (8 * n)) & 0xFF;
        (*buffer)++;
    }

    /* Copy in actual data */
    safec_rc = memcpy_s(*buffer, bytestring->len, bytestring->data, bytestring->len);
    if (safec_rc != EOK) {
        EST_LOG_ERR("memcpy_s error, failed to copy over data buffer");
        return (EST_ERR_INVALID_PARAMETERS);
    }
    *buffer += bytestring->len;
    return (EST_ERR_NONE);
}

/*
 * Handler that is registered with libcoap library for a server-side keygen request.
 * At this point we know we have a server-side keygen request and we can
 * take the payload which is a CSR and pass it up to the existing server-side keygen
 * processing function
 */
static void
est_coap_skg_handler (coap_context_t  *ctx, struct coap_resource_t *resource,
                      coap_session_t *session, coap_pdu_t *request,
                      coap_binary_t *token, coap_string_t *query,
                      coap_pdu_t *response)
{    
    EST_CTX *est_ctx = NULL;
    SSL *ssl = NULL;
    X509 *peer_cert = NULL;
    EST_ERROR rc = EST_ERR_NONE;
    EST_ERROR event_rc = EST_ERR_NONE;
    EST_ENROLL_REQ_TYPE enroll_req = SERVERKEYGEN_REQ;
    int ind;
    char *b64_based_csr = NULL;
    int b64_based_len = 0;
    unsigned char *returned_cert = NULL, *returned_key = NULL;
    int returned_cert_len = 0, returned_key_len = 0;
    size_t csr_len;
    unsigned char *csr_buf = NULL;
    errno_t safec_rc;
    unsigned char buf[MAX_CONTENT_TYPE_BUF_SIZE];
    size_t size;
    uint8_t *data;
    coap_block_t block1;
    coap_req_node_t *coap_req = NULL;
    unsigned int done_receiving = 0;
    coap_block_t resp_block2 = { 0, 0, 0 };
    char *cert_b64 = NULL, *key_b64 = NULL;
    unsigned char *cert_der = NULL, *key_der = NULL, *currentPos;
    int cert_der_len = 0, key_der_len = 0;
    cbor_bytestring keyCbor, certCbor;
    int cbor_len, rv;
    unsigned char *cbor = NULL;
    int payload = 0;
    int block1_exists = 0;

    /* Performance Timers */
    EST_TIMER handler_execute_timer;
    EST_TIMER processing_timer;
    EST_TIMER event_cb_timer;

    EST_LOG_INFO("Entering %s", __FUNCTION__);

    null_timer(&handler_execute_timer);
    /*
     * Check for the correct media type from the content format option
     */
    rc = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_CONTENT_TYPE,
                               COAP_MEDIA_TYPE_PKCS10);
    switch (rc) {
    case EST_ERR_NONE:
        break;
    case EST_ERR_BAD_CONTENT_TYPE:
        /* return a BAD_OPTION error code */
        response->code = COAP_RESPONSE_CODE(402);
        goto error_exit;
    case EST_ERR_HTTP_BAD_REQ:
        /* return a BAD_REQUEST error code */
        response->code = COAP_RESPONSE_CODE(400);
        goto error_exit;
    default:
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    
    /*
     * Get addressability to the EST context
     */
    est_ctx = coap_get_app_data(ctx);
    if (est_ctx == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain EST context from CoAP context.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    start_timer(&handler_execute_timer, est_ctx, "CoAP est_coap_skg_handler");
    /*
     * Obtain access to the SSL structure and then obtain the peer certificate.
     * If there is none, we cannot proceed since certificates are the
     * only way to be authenticated in CoAP.  Send back an unauthorized.
     */
    ssl = (SSL *)session->tls;
    if (ssl == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain SSL session information.");
        response->code = COAP_RESPONSE_CODE(401);
        goto error_exit;
    }
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain client certificate.");
        response->code = COAP_RESPONSE_CODE(401);
        goto error_exit;
    }

    /*
     * Obtain the coap request structure to hold on to the response
     * and the request (if needed)
     */
    coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                            EST_COAP_REQ_SKG);
    if (coap_req == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain the CoAP request structure.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }

    /*
     * If we're already in the middle of processing a request and now we're
     * starting over on a new /skg, then we need to reset the coap_req entry.
     *
     * If there's payload AND
     * no block1 = new request in its entirety
     * block1(0) = new request, first block
     * block1(>0) = continuing request
     */
    payload = (coap_get_data(request, &size, &data) && (size > 0));
    block1_exists = coap_get_block(request, COAP_OPTION_BLOCK1, &block1);
    if (coap_req->req_buf[0] != '\0' &&
        payload && (!block1_exists || (block1_exists && block1.num == 0))) {
        
        if (!reinit_coap_req(est_ctx, coap_req, EST_COAP_REQ_SKG)) {
            /*
             * reinit has somehow failed, so error out
             */
            EST_LOG_ERR(
                "coap_req: Error in entering new coap_req entry into array");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
    }
    
    /*
     * If the response buffer is empty this means we're still in the process
     * of taking in the request.  If it's not empty, then we're in the middle
     * of response processing and can just call coap_add_data_blocked_response()
     * and leave.
     */
    if (coap_req->resp_buf[0] == '\0') {

        if (coap_req->req_buf[0] == '\0') {
            /*
             * This is the start of processing of the enroll request, so
             * indicate that this endpoint request is now being processed
             */
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_START");
            est_invoke_endpoint_req_event_cb(est_ctx, peer_cert, ssl,
                                             (void *)&(session->remote_addr),
                                             (char *) resource->uri_path->s,
                                             EST_ENDPOINT_REQ_START);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
        }
        
        /*
         * Check that the client accepts the type of
         * response the server plans to return
         */
        rc = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_ACCEPT,
                                   COAP_MEDIA_TYPE_MULTI);
        switch (rc) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_CONTENT_TYPE:
            /* return a BAD_OPTION error code */
            response->code = COAP_RESPONSE_CODE(402);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            /* return a NOT_ACCEPTABLE error code */
            response->code = COAP_RESPONSE_CODE(406);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * We're still in the middle of request processing and have not yet
         * transitioned to response processing.
         *
         * See if there is a block1 option on this inbound request
         */
        if (block1_exists) {
            /*
             * See if there's data in this PDU and if so, how much
             */
            if (payload) {
                /*
                 * there is data, so calculate the starting offset
                 */
                size_t offset = block1.num << (block1.szx + 4);
                /*
                 * If this is the first block for this payload, then reset the
                 * req_buf that holds what's been brought in so far
                 */
                if (offset == 0) {
                    if (coap_req->req_buf[0] != '\0') {
                        memzero_s(&(coap_req->req_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
                    }
                    coap_req->req_buf_len = 0;
                } else if (offset > coap_req->req_buf_len) {
                    /*
                     * Upload is not sequential - block missing
                     */
                    response->code = COAP_RESPONSE_CODE(408);
                    goto error_exit;
                }
                else if (offset < coap_req->req_buf_len) {
                    /*
                     * Upload is not sequential - block duplicated. ie, we've already
                     * seen this one
                     */
                    goto just_respond;
                }
            
                /*
                 * Add in new block to end of current data
                 */
                safec_rc = memcpy_s(&(coap_req->req_buf[offset]), size, data, size);
                if (safec_rc != EOK) {
                    EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
                    response->code = COAP_RESPONSE_CODE(500);
                    goto error_exit;
                }            
                coap_req->req_buf_len = offset + size;
            }

        
          just_respond:
            if (block1.m) {
                response->code = COAP_RESPONSE_CODE(231);
                done_receiving = 0;
            }
            else {
                response->code = COAP_RESPONSE_CODE(204);
                done_receiving = 1;
            }

            if (!done_receiving) {
                /* Make sure there is no Block1 in the response when
                 * we're about to use the response for actually
                 * responding with our response.  This should only
                 * added when responding to incoming block1s
                 */
                coap_add_option(response, COAP_OPTION_BLOCK1,
                                coap_encode_var_safe(buf, sizeof(buf),
                                                     ((block1.num << 4) |
                                                      (block1.m << 3) |
                                                      block1.szx)),
                                buf);
            }
            
        } /* Block1 processing */
        else if (coap_get_data(request, &size, &data) && (size > 0)) {
            /*
             * Not a BLOCK1 with data
             *
             * Just copy in the payload into the coap_req array
             */
            safec_rc = memcpy_s(&(coap_req->req_buf[0]), size, data, size);
            if (safec_rc != EOK) {
                EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
                response->code = COAP_RESPONSE_CODE(500);
                goto error_exit;
            }            
            coap_req->req_buf_len = size;
            done_receiving = 1;
        } else {
            /*
             * Not a BLOCK1 and no data
             *
             * Check to see if we've already received some of a block1 based
             * request
             */
            if (coap_req->req_buf_len != 0) {
                response->code = COAP_RESPONSE_CODE(400);
                goto error_exit;
            }
            /*
             * Just make sure the req buf is zeroed out
             */
            if (coap_req->req_buf[0] != '\0') {
                memzero_s(&(coap_req->req_buf[0]), COAP_REQ_NODE_BUF_LEN_MAX);
            }
            coap_req->req_buf_len = 0;
            done_receiving = 1;
        }

        /*
         * If we're not done receiving the request payload then just return now
         */
        if (!done_receiving) {
            X509_free(peer_cert);
            stop_timer(&handler_execute_timer);
            return;
        }

        /* 
         * Check to make sure req length is greater than 0
         */
        if(coap_req->req_buf_len <= 0) {
            EST_LOG_ERR("COAP: Zero length payload");
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        }

        /*
         * The CSR resides in the req_buf.  Copy it over into a separate buffer for
         * actual processing.
         */
        csr_buf = calloc(coap_req->req_buf_len*2, sizeof(char));
        if (csr_buf == NULL) {
            EST_LOG_ERR("calloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        safec_rc = memcpy_s(csr_buf, coap_req->req_buf_len, &(coap_req->req_buf[0]),
                            coap_req->req_buf_len);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }            
        csr_len = coap_req->req_buf_len;

        /*
         * The enrollment code assumes that the CSR is base64 encoded.
         * There are numerous places where this assumption is made and
         * a base64 decode is performed.  Because of this, it's easier
         * to encode it here instead of changing all the places to condition
         * on a flag to decode or not decode
         */
        b64_based_csr = calloc(csr_len*2, sizeof(char));
        if (!b64_based_csr) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        b64_based_len = est_base64_encode((const char *)csr_buf, csr_len,
                                          (char *)b64_based_csr, csr_len*2, 1);
        if (b64_based_len <= 0) {
            EST_LOG_ERR("Invalid base64 encoded data");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * Check to see if this is a server-side keygen request
         */
        /* TODO: this ought to be altered when coap can handle path segments */
        if (EOK != strcmp_s(((const char *) resource->uri_path->s),
                            resource->uri_path->length, "est/skg", &ind) || ind != 0) {
            EST_LOG_ERR("Incorrect URI in enroll request");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        } 

        /*
         * Announce a Server Keygen CSR request is taking
         * place now.
         */
        if (est_ctx->enroll_req_event_cb != NULL) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_enroll_req_event_cb");
            event_rc = est_invoke_enroll_req_event_cb(est_ctx, ssl, peer_cert, csr_buf, csr_len,
                                                      (void *)&(session->remote_addr),
                                                      NULL /*path_seg */, enroll_req);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }
        }

    
        /*
         * handle the enroll as proxy or server
         */
        if (est_ctx->est_mode == EST_SERVER) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_handle_server_keygen");

            rc = est_handle_server_keygen(
                est_ctx, NULL /*http_ctx */, ssl, peer_cert, NULL,
                (char *)b64_based_csr, b64_based_len, NULL /* path_seg */,
                &returned_cert, &returned_cert_len, &returned_key,
                &returned_key_len);
            
            stop_timer(&processing_timer);
        } else if (est_ctx->est_mode == EST_PROXY) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_proxy_handle_server_keygen");

            rc = est_proxy_handle_server_keygen(
                est_ctx, NULL /*http_ctx */, ssl, NULL, (char *)b64_based_csr,
                b64_based_len, NULL /* path_seg */, &returned_cert,
                &returned_cert_len, &returned_key, &returned_key_len);

            stop_timer(&processing_timer);
        } else {
            EST_LOG_ERR("Invalid EST mode. Cannot handle simple enroll.");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * Announce the response event for this request.
         */
        if (est_ctx->enroll_rsp_event_cb != NULL) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_enroll_rsp_event_cb");
            event_rc = est_invoke_enroll_rsp_event_cb(est_ctx, ssl, peer_cert, csr_buf, csr_len,
                                                      (void *)&(session->remote_addr),
                                                      NULL /*path_seg */, enroll_req,
                                                      returned_cert, returned_cert_len, rc);
            stop_timer_with_id(&event_cb_timer, coap_req->key);
            if (event_rc != EST_ERR_NONE) {
                EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
            }        
        }

        free(b64_based_csr);
        b64_based_csr = NULL;
        free(csr_buf);
        csr_buf = NULL;
        
        if(rc != EST_ERR_NONE) {
            EST_LOG_WARN("Server Keygen failed with rc=%d (%s)\n", 
                         rc, EST_ERR_NUM_TO_STR(rc));
        }
        switch (rc) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_PKCS10:
        case EST_ERR_CSR_ATTR_MISSING:
        case EST_ERR_HTTP_BAD_REQ:
        case EST_ERR_NO_SSL_CTX:
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        case EST_ERR_HTTP_NO_CONTENT:
            response->code = COAP_RESPONSE_CODE(204);
            goto error_exit;
        case EST_ERR_HTTP_NOT_FOUND:
            response->code = COAP_RESPONSE_CODE(404);
            goto error_exit;
        case EST_ERR_AUTH_FAIL_TLSUID:
        case EST_ERR_AUTH_FAIL:
            response->code = COAP_RESPONSE_CODE(401);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            response->code = COAP_RESPONSE_CODE(502);
            goto error_exit;
        case EST_ERR_HTTP_LOCKED:
        case EST_ERR_CA_ENROLL_RETRY:
            response->code = COAP_RESPONSE_CODE(503);
            goto error_exit;
        case EST_ERR_IP_CONNECT:
            response->code = COAP_RESPONSE_CODE(504);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* b64 decode the cert */
        cert_b64 = malloc(returned_cert_len + 1);
        if (!cert_b64) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * est_base64_decode expects the input to be a string 
         * so we need to copy it over to a new string buffer
         */
        safec_rc = memcpy_s(cert_b64, returned_cert_len + 1, returned_cert,
                            returned_cert_len);
        if (safec_rc != EOK) {
            EST_LOG_INFO("memcpy_s error 0x%xO\n", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Null terminate the newly copied buffer */
        cert_b64[returned_cert_len] = '\0';
        free(returned_cert);
        returned_cert = NULL;
        /*
         * Caluculate the length of the beginning of the the CBOR data and add
         * it to the total length
         */
        cbor_len = INITIAL_BYTE_SIZE + INITIAL_BYTE_SIZE + UINT16_SIZE +
            INITIAL_BYTE_SIZE;
        /* b64 decode the key */
        key_b64 = malloc(returned_key_len + 1);
        if (!key_b64) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * est_base64_decode expects the input to be a string 
         * so we need to copy it over to a new string buffer
         */
        safec_rc = memcpy_s(key_b64, returned_key_len + 1, returned_key,
                            returned_key_len);
        if (safec_rc != EOK) {
            EST_LOG_INFO("memcpy_s error 0x%xO\n", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Null terminate the newly copied buffer */
        key_b64[returned_key_len] = '\0';
        memzero_s(returned_key, returned_key_len);
        free(returned_key);
        returned_key = NULL;

        /* Allocate a buffer to put the b64 decoded data into */
        key_der = malloc(returned_key_len);
        if (!key_der) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Clamp the max size of the buffer to be the max which can be sent */
        key_der_len = returned_key_len > COAP_REQ_NODE_BUF_LEN_MAX - cbor_len
            ? COAP_REQ_NODE_BUF_LEN_MAX - cbor_len
            : returned_key_len;
        /* 
         * This function is taking the responsibility of ensuring the data is 
         * not too long to send 
         */
        key_der_len = est_base64_decode((const char *)key_b64, (char *)key_der,
                                        key_der_len);
        memzero_s(key_b64, returned_key_len);
        free(key_b64);
        key_b64 = NULL;
        if (key_der_len <= 0) {
            EST_LOG_ERR("Invalid or too long base64 encoded data");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Initialize values in the CBOR bytestring for key */
        keyCbor = makeCborBytestring((uint64_t) key_der_len, key_der);
        
        /* Add in the length of the key data */
        cbor_len += keyCbor.n_length + keyCbor.len;
        
        /* Add in the length of the cert data header info */
        cbor_len += INITIAL_BYTE_SIZE + UINT16_SIZE + INITIAL_BYTE_SIZE;

        /* Clamp the max size of the buffer to be the max space left over */
        cert_der_len = returned_cert_len > COAP_REQ_NODE_BUF_LEN_MAX - cbor_len
            ? COAP_REQ_NODE_BUF_LEN_MAX - cbor_len
            : returned_cert_len;

        /* Allocate a buffer to put the b64 decoded data into */
        cert_der = malloc(cert_der_len);
        if (!cert_der) {
            EST_LOG_ERR("Malloc failed");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        /* 
         * This function is taking the responsibility of ensuring the data is 
         * not too long to send 
         */
        cert_der_len = est_base64_decode((const char *)cert_b64,
                                         (char *)cert_der, cert_der_len);
        free(cert_b64);
        cert_b64 = NULL;
        if (cert_der_len <= 0) {
            EST_LOG_ERR("Invalid or too long base64 encoded data");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Initialize values in the CBOR bytestring for cert */
        certCbor = makeCborBytestring((uint64_t) cert_der_len, cert_der);
        /* Add in the length of the cert data */
        cbor_len += certCbor.n_length + certCbor.len;
        
        /* Check the the final data length to ensure it can be sent */
        if (cbor_len > COAP_REQ_NODE_BUF_LEN_MAX) {
            EST_LOG_ERR("CBOR final length check failed. Data too big.");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        cbor = malloc(cbor_len);
        /* Pointer used to go through cbor so we can return cbor later */
        currentPos = cbor;

        /* Corresponds to an array of 4 bytes in CBOR notation */
        *currentPos = INITIAL_BYTE_ARRAY_SMALL_BASE + 4;
        currentPos++;

        /* Copy in key portion */
        /* Corresponds to a 16 byte unsigned int to follow */
        *currentPos = INITIAL_BYTE_UINT16;
        currentPos++;

        /*
         * Masks and shifts bits in order to properly copy format identifier
         * into the cbor in correct order
         */
        unsigned char keyFormatIdentifier[2] =
            {KEY_CONTENT_FORMAT_IDENTIFIER >> 8,
             KEY_CONTENT_FORMAT_IDENTIFIER & 0xff};

        /* Copy in key content-format identifier */
        safec_rc = memcpy_s(currentPos, 2, keyFormatIdentifier, 2);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s error, failed to copy format identifier");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        currentPos += 2;

        /* Copy in initial byte, length of key, and actual key data */
        rv = writeCborBytestring(&currentPos, &keyCbor);
        if (rv != EST_ERR_NONE) {
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* Copy in cert portion */

        /* Corresponds to a 16 byte unsigned int to follow */
        *currentPos = INITIAL_BYTE_UINT16;
        currentPos++;

        /*
         * Masks and shifts bits in order to properly copy format identifier
         * into the cbor in correct order
         */
        unsigned char certFormatIdentifier[2] =
            {CERT_CONTENT_FORMAT_IDENTIFIER >> 8,
             CERT_CONTENT_FORMAT_IDENTIFIER & 0xff};

        /* Copy in cert content-format identifier */
        safec_rc = memcpy_s(currentPos, 2, certFormatIdentifier, 2);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s error, failed to copy format identifier");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        currentPos += 2;
        
        /* Copy in initial byte, length of cert, and actual cert data */
        rv = writeCborBytestring(&currentPos, &certCbor);
        if (rv != EST_ERR_NONE) {
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * This is the first response to be given on this request so load the
         * cbor buffer into the coap_req node so that it can be used with
         * the subsequent responses
         */        
        safec_rc = memcpy_s(coap_req->resp_buf, COAP_REQ_NODE_BUF_LEN_MAX,
                            cbor, cbor_len);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        coap_req->resp_buf_len = cbor_len;

    }  /* request processing because resp_buf is currently empty */    
    
    /*
     * Send the response back to the client
     */
    response->code = COAP_RESPONSE_CODE(204);
    
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIA_TYPE_MULTI, -1,
                                   coap_req->resp_buf_len,
                                   (const unsigned char *)coap_req->resp_buf);

    /*
     * Retrieve the block2 that libcoap is going to send back
     * and check to see if the more bit is off.  If it's off then
     * we're sending the last block of data making up the response.
     * Return the coap_req and then we're done.
     */
    coap_get_block(response, COAP_OPTION_BLOCK2, &resp_block2);
    if (!resp_block2.m) {

    error_exit:
        if (est_ctx) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_END");
        }
        est_invoke_endpoint_req_event_cb(
            est_ctx, peer_cert, ssl, (void *)&(session->remote_addr),
            (char *)resource->uri_path->s, EST_ENDPOINT_REQ_END);
        /*
         * Stop and mark the handle request timer as complete.
         * Then start the request gap timer.
         */
        if (est_ctx) {
            if (coap_req) {
                stop_timer_with_id(&event_cb_timer, coap_req->key);
                enter_wait_coap_req_timers(est_ctx, coap_req);
            } else {
                stop_timer(&event_cb_timer);
            }
        }
#if DEBUG_COAP_REQ_ARRAY
        if (check_coap_req_array(est_ctx, 0) != 1) {
            EST_LOG_ERR("COAP_DEBUG: coap_req_array does not contain the expected number of entries");
        }
#endif
    } /* ! more bit */

    if (csr_buf) {
        free(csr_buf);
        csr_buf = NULL;
    }
    if (b64_based_csr) free(b64_based_csr);
    if (cert_b64) free(cert_b64);
    if (cert_der) free(cert_der);
    if (key_b64) {
        memzero_s(key_b64, returned_key_len);
        free(key_b64);
    }
    if (key_der) {
        memzero_s(key_der, key_der_len);
        free(key_der);
    }
    if (cbor) {
        memzero_s(cbor, cbor_len);
        free(cbor);
    }

    /*
     * Hold onto the peer_cert until the very end so that it can be passed
     * up on event notifications
     */
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    if (est_ctx) {
        stop_timer(&handler_execute_timer);
    }
}

/*
 * TODO: est_coap_skc_handler - PKIX-cert server-side keygen
 */ 

/*
 * Handler that is registered with libcoap library for the cacerts request (crts).
 * At this point we know we have a /cacerts request so we can pass it along to
 * the /cacerts handler for it to respond with the cacerts
 */
static void
est_coap_crts_handler (coap_context_t  *ctx, struct coap_resource_t *resource,
                       coap_session_t *session, coap_pdu_t *request,
                       coap_binary_t *token, coap_string_t *query,
                       coap_pdu_t *response)
{    
    EST_CTX *est_ctx = NULL;
    unsigned char *cacert_der = NULL;
    int cacert_der_len = 0;
    EST_ERROR rv;
    SSL *ssl = NULL;
    X509 *peer_cert = NULL;
    coap_req_node_t *coap_req = NULL;
    errno_t safec_rc;
    coap_block_t block2 = { 0, 0, 0 };

    /* Performance Timers */
    EST_TIMER handler_execute_timer;
    EST_TIMER processing_timer;
    EST_TIMER event_cb_timer;
    
    null_timer(&handler_execute_timer);
    /*
     * Get addressability to the EST context
     */
    est_ctx = coap_get_app_data(ctx);
    if (est_ctx == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain EST context from CoAP context.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    start_timer(&handler_execute_timer, est_ctx, "CoAP est_coap_crts_handler");

    /*
     * Obtain access to the SSL structure and then obtain the peer certificate.
     * If there is none, we cannot proceed since certificates are the
     * only way to be authenticated in CoAP.  Send back an unauthorized.
     */
    ssl = (SSL *)session->tls;
    if (ssl == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain SSL session information.");
        response->code = COAP_RESPONSE_CODE(401);
        goto error_exit;
    }
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_WARN("COAP: No client certificate received.");
    }

    /*
     * perform CoAP block processing.  Since this is a /crts, there
     * are no block1's (request based) and only Block2's (response based)
     *
     * obtain the coap request structure to hold on to the response
     * and the request (if needed)
     */
    coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                            EST_COAP_REQ_CRTS);
    if (coap_req == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain the CoAP request structure.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }

    /*
     * If the response buffer is empty this means we just obtained the
     * coap_req buffer for the first time, so we need to proceed with
     * processing the request.  If it's not empty, then we're being invoked
     * for subsequent incoming ACKs from the client.
     */
    if (coap_req->resp_buf[0] == '\0') {

        /*
         * Check that the client accepts the type of response the server plans
         * to return
         */
        rv = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_ACCEPT,
                                   COAP_MEDIA_TYPE_PKCS7_CERTS);
        switch (rv) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_CONTENT_TYPE:
            /* return a BAD_OPTION error code */
            response->code = COAP_RESPONSE_CODE(402);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            /* return a NOT_ACCEPTABLE error code */
            response->code = COAP_RESPONSE_CODE(406);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        
        /*
         * Announce the 'EST request received from an end point' event.
         */
        start_timer(&event_cb_timer, est_ctx,
                    "CoAP est_invoke_endpoint_req_event_cb REQ_START");
        est_invoke_endpoint_req_event_cb(est_ctx, peer_cert, ssl,
                                         (void *)&(session->remote_addr),
                                         (char *) resource->uri_path->s,
                                         EST_ENDPOINT_REQ_START);
        stop_timer_with_id(&event_cb_timer, coap_req->key);
        
        /*
         * Get the cacerts into the EST context
         */
        if (est_ctx->est_mode == EST_SERVER) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_server_handle_cacerts");
            rv = est_server_handle_cacerts(est_ctx, NULL /* http_ctx */,
                                           NULL /* path_seg */);
            stop_timer_with_id(&processing_timer, coap_req->key);
        } else if (est_ctx->est_mode == EST_PROXY) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_proxy_handle_cacerts");
            rv = est_proxy_handle_cacerts(est_ctx, NULL /*http_ctx*/,
                                          NULL /*path_seg*/);
            stop_timer_with_id(&processing_timer, coap_req->key);
        } else {
            EST_LOG_ERR("Invalid EST mode. Cannot get CACerts when not in proxy"
                        " or server mode.");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        
        switch (rv) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_HTTP_BAD_REQ:
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        case EST_ERR_HTTP_NO_CONTENT:
            response->code = COAP_RESPONSE_CODE(205);
            goto error_exit;
        case EST_ERR_HTTP_NOT_FOUND:
            response->code = COAP_RESPONSE_CODE(404);
            goto error_exit;
        case EST_ERR_AUTH_FAIL:
            response->code = COAP_RESPONSE_CODE(401);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            response->code = COAP_RESPONSE_CODE(502);
            goto error_exit;
        case EST_ERR_CA_ENROLL_RETRY:
        case EST_ERR_HTTP_LOCKED:
            response->code = COAP_RESPONSE_CODE(503);
            goto error_exit;
        case EST_ERR_IP_CONNECT:
            response->code = COAP_RESPONSE_CODE(504);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        
        /*
         * If cacerts are stored in the context then send them back to the
         * client
         */
        if (est_ctx->ca_certs != NULL) {
            /*
             * Clamp the max size of the buffer to be the max which can be sent
             */
            cacert_der_len = est_ctx->ca_certs_len > COAP_REQ_NODE_BUF_LEN_MAX
                ? COAP_REQ_NODE_BUF_LEN_MAX
                : est_ctx->ca_certs_len;
            cacert_der = calloc(cacert_der_len, sizeof(char));
            if (!cacert_der) {
                EST_LOG_ERR("malloc error");
                response->code = COAP_RESPONSE_CODE(500);
                goto error_exit;
            }

            /*
             * b64 decode the cert to be sent back.
             * This function is taking the responsibility of ensuring the data
             * is not too long to send
             */
            cacert_der_len =
                est_base64_decode((const char *)est_ctx->ca_certs,
                                  (char *)cacert_der, cacert_der_len);
            if (cacert_der_len <= 0) {
                EST_LOG_ERR("Invalid or too long base64 encoded data");
                response->code = COAP_RESPONSE_CODE(500);
                goto error_exit;
            }        
            
            /*
             * This is the first response to be given on this request so
             * load the cacerts buffer into the coap_req node so that it
             * can be used with the subsequent responses.
             */        
            safec_rc = memcpy_s(coap_req->resp_buf, COAP_REQ_NODE_BUF_LEN_MAX,
                                cacert_der, cacert_der_len);
            if (safec_rc != EOK) {
                EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
                response->code = COAP_RESPONSE_CODE(500);
                goto error_exit;
            }
            coap_req->resp_buf_len = cacert_der_len;

            free(cacert_der);
            cacert_der = NULL;
        } else {
            /*
             * No cacerts were found, send back a 404
             */
            response->code = COAP_RESPONSE_CODE(404);
            goto error_exit;
        }
    } /* response buf == '\0' */
        
    response->code = COAP_RESPONSE_CODE(205);
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIA_TYPE_PKCS7_CERTS, -1,
                                   coap_req->resp_buf_len,
                                   (const unsigned char *)coap_req->resp_buf);
    
    /*
     * retrieve the block2 that libcoap is going to send back
     * and check to see if the more bit is off.  If it's off then
     * it's time to return the coap_req structure
     */
    coap_get_block(response, COAP_OPTION_BLOCK2, &block2);
    if (!block2.m) {

    error_exit:
        if (est_ctx) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_END");
        }
        est_invoke_endpoint_req_event_cb(
            est_ctx, peer_cert, ssl, (void *)&(session->remote_addr),
            (char *)resource->uri_path->s, EST_ENDPOINT_REQ_END);

        if (cacert_der) {
            free(cacert_der);
            cacert_der = NULL;
        }
        /* 
         * Stop and mark the handle request timer as complete.
         * Then start the request gap timer.
         */

        if (est_ctx) {
            if (coap_req) {
                stop_timer_with_id(&event_cb_timer, coap_req->key);
                enter_wait_coap_req_timers(est_ctx, coap_req);
            } else {
                stop_timer(&event_cb_timer);
            }
        }
#if DEBUG_COAP_REQ_ARRAY
        if (check_coap_req_array(est_ctx, 0) != 1) {
            EST_LOG_ERR("COAP_DEBUG: coap_req_array does not contain the expected number of entries");
        }
#endif        
    } /* ! more bit */

    /*
     * Hold onto the peer_cert until the very end so that it can be passed
     * up on event notifications
     */
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    /* 
     * This will error saying the timer was invalid if the est_ctx was NULL at
     * the start of this function
     */
    if (est_ctx) {
        stop_timer(&handler_execute_timer);
    }
}

/*
 * Handler that is registered with libcoap library for the csr attrs request (att).
 * At this point we know we have a /att request so we can pass it along to
 * the /att handler for it to respond with the csrattrs
 */
static void
est_coap_att_handler (coap_context_t  *ctx, struct coap_resource_t *resource,
                      coap_session_t *session, coap_pdu_t *request,
                      coap_binary_t *token, coap_string_t *query,
                      coap_pdu_t *response)
{    
    EST_CTX *est_ctx = NULL;
    SSL *ssl = NULL;
    unsigned char *returned_attrs = NULL;
    int returned_attrs_len = 0;
    unsigned char *csr_attrs_der = NULL;
    int csr_attrs_der_len = 0;
    X509 *peer_cert = NULL;
    EST_ERROR rv;
    coap_req_node_t *coap_req = NULL;
    errno_t safec_rc;
    coap_block_t block2 = { 0, 0, 0 };

    /* Performance Timers */
    EST_TIMER handler_execute_timer;
    EST_TIMER processing_timer;
    EST_TIMER event_cb_timer;

    null_timer(&handler_execute_timer);
    /*
     * Get addressability to the EST context
     */
    est_ctx = coap_get_app_data(ctx);
    if (est_ctx == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain EST context from CoAP context.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    start_timer(&handler_execute_timer, est_ctx, "CoAP est_coap_att_handler");

    /*
     * Obtain access to the SSL structure and then obtain the peer certificate.
     * If there is none, we cannot proceed since certificates are the
     * only way to be authenticated in CoAP.  Send back an unauthorized.
     */
    ssl = (SSL *)session->tls;
    if (ssl == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain SSL context from CoAP session context.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_WARN("COAP: No client certificate received.");
    }

    /*
     * perform CoAP block processing.  Since this is a /crts, there
     * are no block1's (request based) and only Block2's (response based)
     *
     * obtain the coap request structure to hold on to the response
     * and the request (if needed)
     */
    coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                            EST_COAP_REQ_ATT);
    if (coap_req == NULL) {
        EST_LOG_ERR("COAP: Failed to obtain the CoAP request structure.");
        response->code = COAP_RESPONSE_CODE(500);
        goto error_exit;
    }
    
    /*
     * If the response buffer is empty this means we just obtained the
     * coap_req buffer for the first time, so we need to proceed with
     * processing the request.  If it's not empty, then we're being invoked
     * for subsequent incoming ACKs from the client.
     */
    if (coap_req->resp_buf[0] == '\0') {
    
        /*
         * Announce the 'EST request received from an end point' event.
         */
        start_timer(&event_cb_timer, est_ctx,
                    "CoAP est_invoke_endpoint_req_event_cb REQ_START");
        est_invoke_endpoint_req_event_cb(est_ctx, peer_cert, ssl,
                                         (void *)&(session->remote_addr),
                                         (char *) resource->uri_path->s,
                                         EST_ENDPOINT_REQ_START);
        stop_timer_with_id(&event_cb_timer, coap_req->key);
        /*
         * Check that the client accepts the type of
         * response the server plans to return
         */
        rv = est_coap_check_option(request, __FUNCTION__, COAP_OPTION_ACCEPT,
                                   COAP_MEDIA_TYPE_CSR_ATTRS);
        switch (rv) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_BAD_CONTENT_TYPE:
            /* return a BAD_OPTION error code */
            response->code = COAP_RESPONSE_CODE(402);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            /* return a NOT_ACCEPTABLE error code */
            response->code = COAP_RESPONSE_CODE(406);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        
        if (est_ctx->est_mode == EST_SERVER) {
            start_timer(&processing_timer, est_ctx,
                        "CoAP est_handle_csr_attrs");
            rv = est_handle_csr_attrs(est_ctx, NULL /* http_ctx */, ssl,
                                      peer_cert, NULL /* path_seg */,
                                      &returned_attrs, &returned_attrs_len);
            stop_timer_with_id(&processing_timer, coap_req->key);
        } else if (est_ctx->est_mode == EST_PROXY) {
            start_timer(&processing_timer, est_ctx, "CoAP est_proxy_handle_csr_attrs");
            rv = est_proxy_handle_csr_attrs(est_ctx, NULL /*http_ctx*/,
                                            NULL /*path_seg*/, &returned_attrs,
                                            &returned_attrs_len);
            stop_timer_with_id(&processing_timer, coap_req->key);
        } else {
            EST_LOG_ERR("Invalid EST mode. Cannot get CSR Attrs when not in proxy"
                        " or server mode.");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        switch (rv) {
        case EST_ERR_NONE:
            break;
        case EST_ERR_HTTP_BAD_REQ:
            response->code = COAP_RESPONSE_CODE(400);
            goto error_exit;
        case EST_ERR_HTTP_NO_CONTENT:
            response->code = COAP_RESPONSE_CODE(205);
            goto error_exit;
        case EST_ERR_HTTP_NOT_FOUND:
            response->code = COAP_RESPONSE_CODE(404);
            goto error_exit;
        case EST_ERR_AUTH_FAIL:
            response->code = COAP_RESPONSE_CODE(401);
            goto error_exit;
        case EST_ERR_HTTP_UNSUPPORTED:
            response->code = COAP_RESPONSE_CODE(502);
            goto error_exit;
        case EST_ERR_CA_ENROLL_RETRY:
        case EST_ERR_HTTP_LOCKED:
            response->code = COAP_RESPONSE_CODE(503);
            goto error_exit;
        case EST_ERR_IP_CONNECT:
            response->code = COAP_RESPONSE_CODE(504);
            goto error_exit;
        default:
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * no csr attribute payload was returned. Send an empty Content
         */
        if (returned_attrs == NULL) {
            EST_LOG_ERR("Empty CSR Attrs response.");
            response->code = COAP_RESPONSE_CODE(205);
            goto error_exit;
        }

        /*
         * Clamp the max size of the buffer to be the max which can be sent
         */
        csr_attrs_der_len = returned_attrs_len > COAP_REQ_NODE_BUF_LEN_MAX
            ? COAP_REQ_NODE_BUF_LEN_MAX
            : returned_attrs_len;
        /*
         * b64 decode the attrs to be sent back
         */
        csr_attrs_der = malloc(csr_attrs_der_len);
        if (!csr_attrs_der) {
            EST_LOG_ERR("malloc error");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /* 
         * This function is taking the responsibility of ensuring the data is 
         * not too long to send 
         */
        csr_attrs_der_len = est_base64_decode((const char *)returned_attrs,
                                              (char *)csr_attrs_der,
                                              csr_attrs_der_len);
        if (csr_attrs_der_len <= 0) {
            EST_LOG_ERR("Invalid or too long base64 encoded data");
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }

        /*
         * This is the first response to be given on this request so
         * load the cacerts buffer into the coap_req node so that it
         * can be used with the subsequent responses.
         */        
        safec_rc = memcpy_s(coap_req->resp_buf, COAP_REQ_NODE_BUF_LEN_MAX,
                            csr_attrs_der, csr_attrs_der_len);
        if (safec_rc != EOK) {
            EST_LOG_ERR("memcpy_s failed with 0x%xO", safec_rc);
            response->code = COAP_RESPONSE_CODE(500);
            goto error_exit;
        }
        coap_req->resp_buf_len = csr_attrs_der_len;

    } /* response buf == '\0' */

    /*
     * Send the response to the client
     */
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIA_TYPE_CSR_ATTRS, -1,
                                   coap_req->resp_buf_len,
                                   (const unsigned char *)coap_req->resp_buf);

    response->code = COAP_RESPONSE_CODE(205);
    
    free(csr_attrs_der);
    csr_attrs_der = NULL;
    free(returned_attrs);
    returned_attrs = NULL;
    
    /*
     * retrieve the block2 that libcoap is going to send back
     * and check to see if the more bit is off.  If it's off then
     * it's time to return the coap_req structure
     */
    coap_get_block(response, COAP_OPTION_BLOCK2, &block2);
    if (!block2.m) {

    error_exit:
        if (est_ctx) {
            start_timer(&event_cb_timer, est_ctx,
                        "CoAP est_invoke_endpoint_req_event_cb REQ_END");
        }
        est_invoke_endpoint_req_event_cb(
            est_ctx, peer_cert, ssl, (void *)&(session->remote_addr),
            (char *)resource->uri_path->s, EST_ENDPOINT_REQ_END);

        if (csr_attrs_der) {
            free(csr_attrs_der);
            csr_attrs_der = NULL;
        }
        if (returned_attrs) {
            free(returned_attrs);
            returned_attrs = NULL;
        }
        /*
         * Stop and mark the handle request timer as complete.
         * Then start the request gap timer.
         */
        if (est_ctx) {
            if (coap_req) {
                stop_timer_with_id(&event_cb_timer, coap_req->key);
                enter_wait_coap_req_timers(est_ctx, coap_req);
            } else {
                stop_timer(&event_cb_timer);
            }
        }
#if DEBUG_COAP_REQ_ARRAY
        if (check_coap_req_array(est_ctx, 0) != 1) {
            EST_LOG_ERR("COAP_DEBUG: coap_req_array does not contain the expected number of entries");
        }
#endif        
    } /* ! more bit */
    
    /*
     * Hold onto the peer_cert until the very end so that it can be passed
     * up on event notifications
     */
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    if (est_ctx) {
        stop_timer(&handler_execute_timer);
    }
}

/*
 * Define the resources for EST and register them with the CoAP library
 */
static void est_server_coap_init_resources (coap_context_t *ctx)
{
    coap_resource_t *r;
  
    /*
     * EST resources
     */
/*   #define EST_COAP_SIMPLEENROLL_URI ".well-known/est/sen" */
#define EST_COAP_SIMPLEENROLL_URI "est/sen"
    r = coap_resource_init(coap_make_str_const(EST_COAP_SIMPLEENROLL_URI),
                           COAP_RESOURCE_FLAGS_NOTIFY_CON);
  
    coap_register_handler(r, COAP_REQUEST_POST, est_coap_sen_handler);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"),    coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"SimpleEnroll\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"),    coap_make_str_const("\"certificate\""), 0);
    coap_add_attr(r, coap_make_str_const("if"),    coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);
  
#define EST_COAP_SIMPLEREENROLL_URI "est/sren"
    r = coap_resource_init(coap_make_str_const(EST_COAP_SIMPLEREENROLL_URI),
                           COAP_RESOURCE_FLAGS_NOTIFY_CON);
  
    coap_register_handler(r, COAP_REQUEST_POST, est_coap_sen_handler);
    coap_resource_set_get_observable(r, 1);
    
    coap_add_attr(r, coap_make_str_const("ct"),    coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"SimpleReenroll\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"),    coap_make_str_const("\"certificate\""), 0);
    coap_add_attr(r, coap_make_str_const("if"),    coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);
/*TODO BD: Make sure legit */
#define EST_COAP_SERVERKEYGEN_URI "est/skg"
    r = coap_resource_init(coap_make_str_const(EST_COAP_SERVERKEYGEN_URI),
                           COAP_RESOURCE_FLAGS_NOTIFY_CON);
  
    coap_register_handler(r, COAP_REQUEST_POST, est_coap_skg_handler);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"),    coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"ServerKeygen\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"),    coap_make_str_const("\"certificate\""), 0);
    coap_add_attr(r, coap_make_str_const("if"),    coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);

#define EST_COAP_CACERTS_URI "est/crts"
    r = coap_resource_init(coap_make_str_const(EST_COAP_CACERTS_URI),
                           COAP_RESOURCE_FLAGS_NOTIFY_CON);
  
    coap_register_handler(r, COAP_REQUEST_GET, est_coap_crts_handler);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"),    coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"CACerts\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"),    coap_make_str_const("\"certificate\""), 0);
    coap_add_attr(r, coap_make_str_const("if"),    coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);

#define EST_COAP_CSR_ATTRS_URI "est/att"
    r = coap_resource_init(coap_make_str_const(EST_COAP_CSR_ATTRS_URI),
                           COAP_RESOURCE_FLAGS_NOTIFY_CON);
  
    coap_register_handler(r, COAP_REQUEST_GET, est_coap_att_handler);
    coap_resource_set_get_observable(r, 1);

    coap_add_attr(r, coap_make_str_const("ct"),    coap_make_str_const("0"), 0);
    coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"CSRAttrs\""), 0);
    coap_add_attr(r, coap_make_str_const("rt"),    coap_make_str_const("\"certificate\""), 0);
    coap_add_attr(r, coap_make_str_const("if"),    coap_make_str_const("\"clock\""), 0);

    coap_add_resource(ctx, r);
}

/*
 * Stub function to register with CoAP library
 */
static
int est_coap_verify_cn_callback (const char *cn,
                                 const unsigned char *asn1_public_cert,
                                 size_t asn1_length,
                                 coap_session_t *session,
                                 unsigned depth,
                                 int validated,
                                 void *arg) 
{
    EST_LOG_INFO("CN '%s' presented by client (%s)",
                 cn, depth ? "CA" : "Certificate");
    return 1;
}

/*
 * Handle a request from the CoAP library for the needed credentials
 * for this incoming connection request.  We currently do not support
 * SNI so we always provide the same credentials.
 */
static coap_dtls_key_t *est_coap_verify_sni_callback (const char *sni, void *arg)
{
    static coap_dtls_key_t dtls_key;
    EST_CTX *ectx = (EST_CTX *)arg;
    
    EST_LOG_INFO("Providing ID cert and key, and trust store to CoAP library");  
    
    /*
     * Pass down the configured cert, key, and trust store
     */
    memzero_s(&dtls_key, sizeof(dtls_key));
    dtls_key.key_type = COAP_PKI_KEY_OSSL;
    dtls_key.key.ossl.public_cert = ectx->server_cert;
    dtls_key.key.ossl.private_key = ectx->server_priv_key;
    dtls_key.key.ossl.ca_certs = ectx->trusted_certs_store;
        
    if (sni[0]) {
        EST_LOG_INFO("SNI '%s' requested from client", sni);  
    } else {
        EST_LOG_INFO("SNI not requested from client");  
    }
    
    return &dtls_key;
}

/*
 * This function sets the initial DTLS handshake timeout value.  This function
 * is passed down to libcoap which in turn registers it with OpenSSL.  OpenSSL
 * calls this function at the appropriate times during DTLS handshake
 * processing to obtain the correct timeout value.  Both the incoming and the
 * returned timer value are in microseconds.  This logic is largely taken from
 * OpenSSL's timer_cb() in dtlstest.c and dtls_double_timeout() in d1_lib.c
 */
static unsigned int est_coap_dtls_timer_callback (SSL *ssl,
                                                  unsigned int incoming_timer_val)
{
    int ret_timer_val = 0;
    coap_session_t *coap_session = SSL_get_app_data(ssl);
    EST_CTX *est_ctx = (EST_CTX *) coap_session_get_app_data(coap_session);

    if (incoming_timer_val == 0) {
        ret_timer_val = est_ctx->dtls_handshake_timer*1000*1000;
    } else {
        ret_timer_val = 2 * incoming_timer_val;
    }

    /*
     * RFC recommends capping at 60 secs.
     */
    if (ret_timer_val > 60000000) {
        ret_timer_val = 60000000;
    }

    return (ret_timer_val);
}

/*
 * Call CoAP to configure the PKI capabilities of the library.
 * In this case, all we're setting is the callback function and the
 * EST context.
 * 
 * The CoAP library currently expects strings passed in that contain the names
 * of files that hold the private key, certificate and CA certs for this node.
 * The EST library never has access to files like this and only possesses PKEY
 * and X509 structures containing these values, so the callback function is
 * used to load these values directly into the SSL context instead of having
 * the CoAP library attempt to do it from the files.  In addition, the
 * callback function needs addressability into the EST context in order to
 * perform this processing so the CoAP library has been enhanced to take in
 * this "app data" and pass this app data back to the call back function.
 */
static int est_server_coap_set_pki_identity (coap_context_t *coap_ctx,
                                             EST_CTX *ectx)
{
    int coap_rc = 0;
    coap_dtls_pki_t setup_data;

    memzero_s(&setup_data, sizeof(coap_dtls_pki_t));

    /*
     * The latest libcoap supports a form of PKI mode.
     */
    setup_data.verify_peer_cert        = 1;
    setup_data.require_peer_cert       = 1;
    setup_data.allow_self_signed       = 0;
    setup_data.allow_expired_certs     = 0;
    setup_data.cert_chain_validation   = 1;
    setup_data.cert_chain_verify_depth = 7;
    setup_data.check_cert_revocation   = 1;
    setup_data.allow_no_crl            = 1;
    setup_data.allow_expired_crl       = 1;
    setup_data.validate_cn_call_back   = est_coap_verify_cn_callback;
    setup_data.cn_call_back_arg        = ectx;
    setup_data.validate_sni_call_back  = est_coap_verify_sni_callback;
    setup_data.sni_call_back_arg       = ectx;
    /*
     * If the initial DTLS handshake timeout value has been set this indicates
     * the timeout handler should be registered
     */
    if (ectx->dtls_handshake_timer) {
        setup_data.dtls_timer_call_back = est_coap_dtls_timer_callback;
        setup_data.dtls_timer_call_back_arg = ectx;
    }

    /*
     * If the DTLS handshake MTU value has been set then pass this down
     * to libcoap so it can set this with OpenSSL.
     */
    if (ectx->dtls_handshake_mtu) {
        setup_data.dtls_handshake_mtu = ectx->dtls_handshake_mtu;
    }    

    /*
     * The coap library defines a version on this structure.  Given
     * that this structure is defined as part of the API to the library
     * this structure's definition should be defined by the API version,
     * but this library doesn't appear to follow such design, so
     * set this version value to what they want it to be.
     */
    setup_data.version = COAP_DTLS_PKI_SETUP_VERSION;
    
    coap_rc = coap_context_set_pki(coap_ctx, &setup_data);
    if (coap_rc == 0) {
        EST_LOG_ERR("COAP: Failed to initialize CoAP PKI mode.");
        return (coap_rc);
    }
    return coap_rc;
}

/*
 * Callback function that is invoked when a state change occurs
 * on a DTLS session.  The CoAP context, a pointer to the
 * session structure, and the specific event are passed.
 *
 * This function is used to determine when a new session has been established
 * and when it has been freed by libcoap.
 * The following are the possible events:
 * COAP_EVENT_DTLS_CLOSED        0x0000
 * COAP_EVENT_DTLS_CONNECTED     0x01DE
 * COAP_EVENT_DTLS_RENEGOTIATE   0x01DF
 * COAP_EVENT_DTLS_ERROR         0x0200
 *
 * The only two we care about are CLOSED and CONNECTED.
 *
 * The comments for the registration function for this callback is
 * silent on the required return values.  Looking at the current code (4.2.0)
 * it's never checked anywhere throughout libcoap, so always returning 0 here.
 */
static int est_coap_event_handler (coap_context_t *coap_ctx,
                                   coap_event_t event,
                                   struct coap_session_t *session) 
{
    coap_req_node_t *coap_req = NULL;
    EST_CTX *est_ctx = NULL;

    EST_LOG_INFO(" COAP: session = %p, EVENT = %x", session, event);

    if (session == NULL || coap_ctx == NULL) {
        
        EST_LOG_ERR("COAP: Invalid parameters passed to est_coap_event_handler()");
        return (0);
        
    } else {

        est_ctx = coap_get_app_data(coap_ctx);
        
        if (event == COAP_EVENT_DTLS_CONNECTED) {

            /*
             * Allocate a coap_req entry.  We don't need it right now, we're
             * just getting it allocated.
             */
            coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                                    EST_COAP_REQ_RESET);
            if (coap_req == NULL) {
                EST_LOG_ERR("COAP: Failed to obtain the CoAP request structure.");
            }
        
        } else if (event == COAP_EVENT_DTLS_CLOSED) {

            /*
             * free up the coap_req entry
             */
            coap_req = get_coap_req(est_ctx, (void *) &session->remote_addr,
                                    EST_COAP_REQ_RESET);
            if (!remove_coap_req(est_ctx, coap_req)) {
                EST_LOG_ERR("Failed to remove coap_req from coap_req_array");
            }
        
        } else {

            EST_LOG_INFO("Unknown event from libcoap. EVENT = %x", event);
        }
    }
    
    return (0);
}

/*
 * Obtain a libcoap context, initialize the PKI mode of operation of
 * libcoap and initialize a DTLS endpoint with libcoap.
 * Return a pointer to the newly created coap context structure or
 * NULL on error.
 */
static coap_context_t *est_server_coap_get_context (EST_CTX *ectx,
                                                    const char *port)
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int coap_rc = 0;
    errno_t safec_rc; 

    /*
     * Call CoAP to get the new context
     */
    ctx = coap_new_context(NULL);
    if (!ctx) {
        return NULL;
    }
    
    /*
     * Initialize PKI mode in the CoAP library
     */
    coap_rc = est_server_coap_set_pki_identity(ctx, ectx);
    if (coap_rc == 0) {
        coap_free_context(ctx);
        return NULL;
    }

    /*
     * The following code comes from the libcoap example server code.
     */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    s = getaddrinfo(NULL, port, &hints, &result);
    if ( s != 0 ) {
        coap_free_context(ctx);
        return NULL;
    }

    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr, addrs;
        coap_endpoint_t  *ep_dtls = NULL; 

        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            safec_rc = memcpy_s(&addr.addr, rp->ai_addrlen,
                                rp->ai_addr, rp->ai_addrlen);
            if (safec_rc != EOK) {
                EST_LOG_INFO("memcpy_s error 0x%xO\n", safec_rc);
                coap_free_context(ctx);
                freeaddrinfo(result);
                return NULL;
            }
            addrs = addr;
            if (addr.addr.sa.sa_family == AF_INET) {
                addrs.addr.sin.sin_port = htons(ntohs(addr.addr.sin.sin_port));
            } else if (addr.addr.sa.sa_family == AF_INET6) {
                addrs.addr.sin6.sin6_port = htons(ntohs(addr.addr.sin6.sin6_port));
            } else {
                goto finish;
            }

            /*
             * Call the CoAP library to have it create the DTLS based endpoint
             */
            if (coap_dtls_is_supported()) {
                ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
                if (!ep_dtls) {
                    EST_LOG_ERR("Cannot create CoAP DTLS endpoint.");
                    coap_free_context(ctx);
                    freeaddrinfo(result);
                    return NULL;
                }

                coap_endpoint_set_session_max(ep_dtls, ectx->dtls_session_max);
            }
        }
    }

  finish:
    freeaddrinfo(result);
    return ctx;
}


/*
 * This code comes from the libcoap example server code.  The purpose of this
 * code is to call into libcoap and let it perform processing on the socket.
 */
#define COAP_RESOURCE_CHECK_TIME 2
int est_server_coap_run_once (EST_CTX *ctx)
{
    unsigned int wait_ms;
    int result = 0;
    
    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    stop_down_time_timer(ctx);
    result = coap_run_once(ctx->coap_ctx, wait_ms);
    start_down_time_timer(ctx);
    
    if ( result < 0 ) {
        EST_LOG_ERR("Error return code from coap library, result = %d", result);        
        return EST_ERR_COAP_PROCESSING_ERROR;
    } else if ((unsigned)result < wait_ms) {
        wait_ms -= result;
    } else {
        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }
    
#ifndef WITHOUT_OBSERVE
    /* check if we have to send observe notifications */
    coap_check_notify(ctx->coap_ctx);
#endif /* WITHOUT_OBSERVE */

    return EST_ERR_NONE;
}

/*
 * Collect log entries from libcoap and integrate them into the EST
 * logs.  Align logging levels from libcoap into EST's logging levels.
 */
static
void est_server_coap_log (coap_log_t level, const char *message) 
{
    switch (level) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
        EST_LOG_ERR("%s", message);
        break;
    case LOG_WARNING:
        EST_LOG_WARN("%s", message);
        break;
    case LOG_NOTICE:
    case LOG_INFO:
    case LOG_DEBUG:
        EST_LOG_INFO("%s", message);
        break;
    default:
        EST_LOG_ERR("Error while attempting to log message from CoAP library."
                    "  Log level not accounted for.");
        break;
    }
}
#endif /* HAVE_LIBCOAP */


/*! @brief est_server_set_dtls_handshake_timeout() is called by the
    application layer to specify the initial timeout value for the DTLS
    handshake timer.  This timer is only run during DTLS handshaking.  This
    is an optional value that, if set, is used to cause the callback function
    to be registered with OpenSSL.  The callback function will provide the
    timer value to be used by the DTLS handshake code in OpenSSL for each
    starting of the handshake timer.  This value is the initial value.
    
    @param ctx Pointer to EST context for a client session
    @param timeout Integer value representing the initial DTLS handshake timeout
    value
    
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED - Returned if libest has not been
    built with CoAP support.
    
    est_server_set_dtls_handshake_timeout() error checks its input parameters
    and then stores the timeout value in the EST context and will be used by
    the DTLS timeout callback function to set the initial timeout value.
 */
EST_ERROR est_server_set_dtls_handshake_timeout (EST_CTX *ctx, int timeout)
{
#if HAVE_LIBCOAP
    if (ctx == NULL) {
        EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }

    /*
     * either resetting to 0 or needs to be in range, otherwise error
     */
    if (timeout != EST_DTLS_HANDSHAKE_TIMEOUT_DEF && 
        (timeout < EST_DTLS_HANDSHAKE_TIMEOUT_MIN ||
         timeout > EST_DTLS_HANDSHAKE_TIMEOUT_MAX)) {
        EST_LOG_ERR("Invalid DTLS handshake timeout value passed: %d ", timeout);
        return (EST_ERR_INVALID_PARAMETERS);
    }
        
    ctx->dtls_handshake_timer = timeout;
    return EST_ERR_NONE;
#else
    /*
     * In this case COAP support has not been enabled in this build of EST,
     * so log it and return an error.
     */
    EST_LOG_ERR("EST over CoAP has not been enabled in this build of libEST.");
    return EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED;
#endif
}

/*! @brief est_server_set_dtls_handshake_mtu() is called by the application
    layer to specify the MTU to be used during the DTLS handshake phase of the
    connection with clients.  This is an optional value that, if set, is
    passed to libcoap so that it can set this value with OpenSSL and be used
    DTLS handshake.  This value only controls the size of the DTLS payload, and
    not the MTU of the entire packets sent on the network.
    
    @param ctx Pointer to EST context for a client session
    @param mtu Integer value representing the Maximum Transmission Unit (MTU)
    for the DTLS payload.
    
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED - Returned if libest has not been
    built with CoAP support.
    
    est_server_set_dtls_handshake_mtu() error checks its input parameters and
    then stores the timeout value in the EST context so that it can be passed
    to libcoap during initialization and configuration.
 */
EST_ERROR est_server_set_dtls_handshake_mtu (EST_CTX *ctx, int mtu)
{
#if HAVE_LIBCOAP
    if (ctx == NULL) {
        EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }

    /*
     * Either resetting to 0 or needs to be in range, otherwise error
     */
    if (mtu != EST_DTLS_HANDSHAKE_MTU_DEF && 
        (mtu < EST_DTLS_HANDSHAKE_MTU_MIN ||
         mtu > EST_DTLS_HANDSHAKE_MTU_MAX)) {
        EST_LOG_ERR("Invalid DTLS handshake MTU value passed: %d ", mtu);
        return (EST_ERR_INVALID_PARAMETERS);
    }
        
    ctx->dtls_handshake_mtu = mtu;
    return EST_ERR_NONE;
#else
    /*
     * In this case COAP support has not been enabled in this build of EST,
     * so log it and return an error.
     */
    EST_LOG_ERR("EST over CoAP has not been enabled in this build of libEST.");
    return EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED;
#endif
}


/*! @brief est_server_set_dtls_sessions_max() is called by the application
    layer to specify the maximum number of DTLS sessions that can be active at
    any one moment.  If this function is not called then a default value
    is passed to libcoap.
    
    @param ctx Pointer to EST context for a client session
    @param session_max Integer value representing the maximum number of sessions
    valid at any moment.
    
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_INVALID_PARAMETERS - An invalid value for session_max was
    passed in.
    EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED - Returned if libest has not been
    built with CoAP support.
    EST_ERR_SERVER_ALREADY_OPERATIONAL - This function was called after a
    call to est_server_start()
    
    est_server_set_dtls_session_max() error checks its input parameters and
    then stores the max sessions parameter into the EST context so that it can
    be passed to libcoap during initialization and configuration.  This function
    also uses this session_max value to initialize internal control blocks used
    to manage each active EST request.
 */
EST_ERROR est_server_set_dtls_session_max (EST_CTX *ctx, int session_max)
{
#if HAVE_LIBCOAP
    EST_ERROR rc = EST_ERR_NONE;
    
    if (ctx == NULL) {
        EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }

    /*
     * The CoAP server port number is set in est_server_coap_init_start().
     * If this port number is set then the server function is operational.
     * The coap_req array cannot be altered once the server is operational.
     */
    if (ctx->coap_server_port_num != 0) {
        EST_LOG_ERR("Max DTLS sessions cannot be altered when EST server is operational");
        return (EST_ERR_SERVER_ALREADY_OPERATIONAL);
    }        

    /*
     * Needs to be in range
     */
    if ((session_max < EST_DTLS_SESSION_MAX_MIN ||
         session_max > EST_DTLS_SESSION_MAX_MAX)) {
        EST_LOG_ERR("Invalid DTLS maximum number of sessions value passed: %d ", session_max);
        return (EST_ERR_INVALID_PARAMETERS);
    }
        
    ctx->dtls_session_max = session_max;

    /*
     * Adjust the coap_req array
     */
    rc = est_coap_init_req_array(ctx, ctx->dtls_session_max);
    
    return rc;
#else
    /*
     * In this case COAP support has not been enabled in this build of EST,
     * so log it and return an error.
     */
    EST_LOG_ERR("EST over CoAP has not been enabled in this build of libEST.");
    return EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED;
#endif
}


/*! @brief est_server_coap_init_start() is called by the application layer to
     specify the address/port of the EST server. It must be called after
     est_server_init() and prior to starting the EST server functionality.
 
    @param ctx Pointer to EST context for a client session
    @param server Name of this EST server to which clients will connect.
    The ASCII string representing the name of the server is limited to 254
    characters
    @param port UDP port that this EST server will listen
 
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
    
    est_server_coap_init_start error checks its input parameters and then stores
    the port number into the EST context.  It then initializes
    the CoAP library and setting up the resources with which to respond.
 */
EST_ERROR est_server_coap_init_start (EST_CTX *ctx, int port)
{
#if HAVE_LIBCOAP
    int n;

    coap_log_t log_level = LOG_DEBUG;
    
    /*
     * validate parameters
     */
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }
    /*
     * est_proxy.c utilizes this function in order
     * to reduce redundant code, so we need 
     * to allow for both EST modes
     */
    if (ctx->est_mode != EST_SERVER && ctx->est_mode != EST_PROXY) {
        return (EST_ERR_BAD_MODE);
    }

    /*
     * Validate the interface to be listening on and store it away
     *
     * Store it in both int and string form
     */
    if (port < 0 || port > 65535) {
        return EST_ERR_INVALID_PORT_NUM;
    }

    n = snprintf(ctx->coap_server_port_str, sizeof(ctx->coap_server_port_str), "%hu", port);
    if (n < 0 || n >= (int)sizeof(ctx->coap_server_port_str)) {
        EST_LOG_ERR("Invalid server name provided, cannot determine IP address for server.");
        return EST_ERR_INVALID_PORT_NUM;
    }
    ctx->coap_server_port_num = port;
    
    /* 
     * Start and Initialize libcoap library
     */
    EST_LOG_INFO("Libcoap library version: %s", coap_package_version());

    coap_startup();
    coap_dtls_set_log_level(log_level);
    coap_set_log_level(log_level);
    
    coap_set_log_handler(est_server_coap_log);
    coap_set_show_pdu_output(0);

    ctx->coap_ctx = est_server_coap_get_context(ctx, (const char *) &(ctx->coap_server_port_str)[0]);
    if (!ctx->coap_ctx) {
        return EST_ERR_COAP_PROCESSING_ERROR;
    }

    ctx->transport_mode = EST_COAP;

    /*
     * We never receive HTTP based authentication credentials when
     * we're not in HTTP mode
     */
    ctx->require_http_auth = HTTP_AUTH_NOT_REQUIRED;
    
    /*
     * Link the EST context into the coap context in order to get
     * addressability in the reverse direction, i.e when being called
     * into callback functions from the coap library.
     */
    coap_set_app_data(ctx->coap_ctx, (void *)ctx);

    coap_register_event_handler(ctx->coap_ctx, est_coap_event_handler);

    /*
     * Set up our resources in the CoAP library
     */
    est_server_coap_init_resources(ctx->coap_ctx);

    return EST_ERR_NONE;
#else /* HAVE_LIBCOAP */
    /*
     * In this case COAP support has not been enabled in this build of EST,
     * so log it and return an error.
     */
    EST_LOG_ERR("EST over CoAP has not been enabled in this build of libEST.");
    return EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED;
#endif /* HAVE_LIBCOAP */    
}
