/** @file */
/*------------------------------------------------------------------
 * est/est_server.c - EST Server specific code
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       module.
 *
 * April, 2013
 *
 * Copyright (c) 2013-2014, 2016, 2017, 2018, 2019 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
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


static ASN1_OBJECT *o_cmcRA = NULL;
#define EST_SERVER_RSA_KEYSIZE_4096       4096
#define EST_SERVER_DEFAULT_ENHCD_CERT_PWD "cisco"

/*
 * Required forward definitions for the internal event notification invoke functions
 */
static
void est_invoke_enroll_auth_result_event_cb(EST_CTX *ctx, X509 *peer_cert,
                                            char *path_seg,
                                            EST_ENROLL_REQ_TYPE enroll_req,
                                            EST_HTTP_AUTH_HDR_RESULT enh_auth_result,
                                            EST_AUTH_STATE rv);

/*
 * Event notification callbacks.  These are global because EST_CTX is not
 * guaranteed to be available when these events occur.
 */
static est_est_err_event_cb_t est_err_event_cb = NULL;
static est_ssl_proto_err_event_cb_t ssl_proto_err_event_cb = NULL;

/*
 * This function sends EST specific HTTP error responses.
 */
void est_send_http_error(EST_CTX *ctx, void *http_ctx, int fail_code)
{
    struct mg_connection *conn = (struct mg_connection *)http_ctx;
    EST_ERROR rv;
    int retry_delay;
error:
    switch (fail_code) {
    case EST_ERR_CA_ENROLL_RETRY:
        if (ctx->est_mode == EST_SERVER) {
            retry_delay = ctx->retry_period;
        } else if (ctx->est_mode == EST_PROXY) {
            retry_delay = ctx->retry_after_delay;
        } else {
            fail_code = EST_ERR_UNKNOWN;
            EST_LOG_ERR("Unexpected EST mode while sending retry message (%d)",
                        ctx->est_mode);
            goto error;
        }
        rv = est_server_send_http_retry_after(ctx, http_ctx, retry_delay);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Error while sending retry message %s (%d)",
                        EST_ERR_NUM_TO_STR(rv), rv);
            fail_code = EST_ERR_UNKNOWN;
            goto error;
        }
        break;
    case EST_ERR_HTTP_NO_CONTENT:
        mg_send_http_error(conn, EST_HTTP_STAT_204, EST_HTTP_STAT_204_TXT, "");
        break;
    case EST_ERR_HTTP_BAD_REQ:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT, "");
        break;
    case EST_ERR_CSR_ATTR_MISSING:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_MISSING_CSR_ATTR);
        break;
    case EST_ERR_BAD_ASN1_HEX:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_BAD_ASN1);
        break;
    case EST_ERR_BAD_PKCS10:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_BAD_PKCS10);
        break;
    case EST_ERR_BAD_CONTENT_TYPE:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_BAD_CONTENT_TYPE);
        break;
    case EST_ERR_WRONG_METHOD:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_BAD_METH);
        break;
    case EST_ERR_NO_SSL_CTX:
        mg_send_http_error(conn, EST_HTTP_STAT_400, EST_HTTP_STAT_400_TXT,
                           EST_BODY_BAD_SSL);
        break;
    case EST_ERR_AUTH_FAIL:
        mg_send_http_error(conn, EST_HTTP_STAT_401, EST_HTTP_STAT_401_TXT,
                           EST_BODY_UNAUTHORIZED);
        break;
    case EST_ERR_AUTH_FAIL_TLSUID:
        mg_send_http_error(conn, EST_HTTP_STAT_401, EST_HTTP_STAT_401_TXT,
                           EST_BODY_POP_MISMATCH);
        break;
    case EST_ERR_HTTP_NOT_FOUND:
        mg_send_http_error(conn, EST_HTTP_STAT_404, EST_HTTP_STAT_404_TXT,
                           EST_BODY_NOT_FOUND);
        break;
    case EST_ERR_HTTP_INVALID_PATH_SEGMENT:
        mg_send_http_error(conn, EST_HTTP_STAT_404, EST_HTTP_STAT_404_TXT,
                           EST_BODY_INVALID_PATH_SEGMENT);
        break;
    case EST_ERR_HTTP_LOCKED:
        mg_send_http_error(conn, EST_HTTP_STAT_423, EST_HTTP_STAT_423_TXT,
                           EST_BODY_LOCKED);
        break;
    case EST_ERR_HTTP_UNSUPPORTED:
        mg_send_http_error(conn, EST_HTTP_STAT_502, EST_HTTP_STAT_502_TXT,
                           EST_BODY_BAD_GATEWAY);
        break;
    case EST_ERR_IP_CONNECT:
        mg_send_http_error(conn, EST_HTTP_STAT_504, EST_HTTP_STAT_504_TXT,
                           EST_BODY_GATEWAY_TIMEOUT);
        break;
    case EST_ERR_CA_ENROLL_FAIL:
        mg_send_http_error(conn, EST_HTTP_STAT_500, EST_HTTP_STAT_500_TXT,
                           EST_BODY_ENROLL_FAIL);
        break;
    default:
        mg_send_http_error(conn, EST_HTTP_STAT_500, EST_HTTP_STAT_500_TXT,
                           EST_BODY_UNKNOWN_ERR);
        break;
    }
}

/*
 * This function sends a HTTP 202 Accepted response to the 
 * client with the retry-after value from the CA. This
 * notifies the client that it should check back later to
 * see if the CSR was approved.
 */
EST_ERROR est_server_send_http_retry_after (EST_CTX *ctx, void *http_ctx, int delay)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    struct mg_connection *conn = (struct mg_connection*)http_ctx;

    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s%s: %d%s%s", 
	EST_HTTP_HDR_202_RESP,
        EST_HTTP_HDR_EOL, 
	EST_HTTP_HDR_STAT_202, 
	EST_HTTP_HDR_EOL,
	EST_HTTP_HDR_RETRY_AFTER, 
	delay, 
	EST_HTTP_HDR_EOL, 
	EST_HTTP_HDR_EOL);

    conn->status_code = EST_HTTP_STAT_202;
    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        EST_LOG_ERR("HTTP write error while propagating retry-after");
        return (EST_ERR_HTTP_WRITE);
    }
    return (EST_ERR_NONE);
}

/*
 * This function handles an incoming cacerts request from
 * the client.
 */
int est_handle_cacerts (EST_CTX *ctx, unsigned char *ca_certs, int ca_certs_len,
                        void *http_ctx, char *path_seg)
{
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;    
    
    if (ca_certs  == NULL) {
        return (EST_ERR_HTTP_NOT_FOUND);
    }
        
    /*
     * Send HTTP header
     */
    snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
             EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %s%s", EST_HTTP_HDR_CT,
             EST_HTTP_CT_PKCS7, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %s%s", EST_HTTP_HDR_CE,
             EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
    hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
    snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %d%s%s", EST_HTTP_HDR_CL,
             ca_certs_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
    if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
        return (EST_ERR_HTTP_WRITE);
    }

    /*
     * Send the CA certs in the body
     */
    if (!mg_write(http_ctx, ca_certs, ca_certs_len)) {
        return (EST_ERR_HTTP_WRITE);
    }

    EST_LOG_INFO("CA certs successfully sent to EST client");
    return (EST_ERR_NONE);
}


/*
 * Handle a CA certs request.  If the application layer has
 * registered a callback then call it.  Else, if the application
 * layer has provided a locally configured buffer then send it.
 * Else, return an error indicating that there are no CA Certs
 * available.
 */
int est_server_handle_cacerts (EST_CTX *ctx, void *http_ctx,
                               char *path_seg)
{
    EST_ERROR rv;
    int ca_certs_len;
    unsigned char *ca_certs;

    /*
     * If there is a call back set then call it.
     * otherwise, if there is a locally configured cacerts buffer,
     * then return that.
     * otherwise, return an error indicating that we don't have any cacerts
     */
    if (ctx->est_get_cacerts_cb) {

        EST_LOG_INFO("Server: Retrieving CA certs from application layer");
        ca_certs = ctx->est_get_cacerts_cb(&ca_certs_len, path_seg,ctx->ex_data);

        if (ca_certs) {

            EST_LOG_INFO("Server: Successfully retrieved CA certs from "
                         "application layer");
            /*
             * send the certs back to the client
             */
            if (ctx->transport_mode == EST_HTTP) {
                rv = est_handle_cacerts(ctx, ca_certs, ca_certs_len, http_ctx,
                                        path_seg);
            } else if (ctx->transport_mode == EST_COAP) {
                /*
                 * allow the context to hold these values so
                 * that the coap crts handler can access them
                 * and send them back to the client
                 */
                ctx->ca_certs = ca_certs;
                ctx->ca_certs_len = ca_certs_len;
                rv = EST_ERR_NONE;
            } else {
                EST_LOG_ERR("EST in improper transport mode. "
                            "Cannot retrieve cacerts.");
                rv = EST_ERR_BAD_MODE;
            }
            
        } else {
            /*
             * send the error back to the client
             */
            rv = EST_ERR_HTTP_NO_CONTENT;
        }
    } else if (ctx->ca_certs) {
        
        EST_LOG_INFO("Server: CA certs set locally, responding with "
                     "locally set CA certs response");

        /*
         * send the certs back to the client
         */
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
            EST_LOG_ERR("EST in improper transport mode. "
                        "Cannot retrieve cacerts.");
            rv = EST_ERR_BAD_MODE;
        }

    } else {
        /*
         * send the error back to the client
         */
        rv = EST_ERR_HTTP_NO_CONTENT;
    }
    return (rv);
}

/*! @brief est_server_set_key_generation_cb() is used by an application
    to set a callback to handle the generation of the private key.

    @param ctx EST_CTX
    @param cb The callback that will be used to generate the key. It
              should match
              unsigned char * (EVP_PKEY **, int *)

	  This function is used by an application
    to set a callback to handle the generation of the private key.

    @return EST_ERROR
 */
EST_ERROR est_server_set_key_generation_cb (EST_CTX *ctx,
                                            int (*cb)(EVP_PKEY **priv_key)) {
    if (ctx == NULL) {
        EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }

    ctx->keygen_cb = cb;
    return EST_ERR_NONE;
}

/*! @brief est_server_generate_auth_digest() is used by an application 
    to calculate the HTTP Digest value based on the header values
    provided by an EST client.  
 
    @param ah Authentication header values from client, provided by libEST
    @param HA1 The precalculated HA1 value for the user.  HA1 is defined in
           RFC 2617.  It's the MD5 calculation of the user's ID, HTTP realm,
	   and the user's password.

    This is a helper function that an application can use to calculate
    the HTTP Digest value when performing HTTP Digest Authentication
    of an EST client.  libEST does not maintain a user database. 
    This is left up to the application, with the intent of integrating  
    an external user database (e.g. Radius/AAA).
    
    The HA1 value should be calculated by the application as
    defined in RFC 2617.  HA1 is the MD5 hash of the user ID, HTTP realm,
    and user password.  This MD5 value is then converted to a hex string.
    HA1 is expected to be 32 bytes long.
 
    @return char* containing the digest, or NULL if an error occurred.
 */
char *est_server_generate_auth_digest (EST_HTTP_AUTH_HDR *ah, char *HA1)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_md5();
    uint8_t ha2[EVP_MAX_MD_SIZE];
    unsigned int ha2_len;
    char ha2_str[33];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int d_len;
    char *rv;

    if (!ah) {
	EST_LOG_ERR("Null auth header");
        return (NULL);
    }

    if (!HA1) {
	EST_LOG_ERR("Null HA1");
        return (NULL);
    }

    /*
     * Calculate HA2 using method, URI,
     */
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, "POST", 4); 
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ah->uri, strnlen_s(ah->uri, MAX_REALM));
    EVP_DigestFinal(mdctx, ha2, &ha2_len);
    EVP_MD_CTX_destroy(mdctx);
    est_hex_to_str(ha2_str, ha2, ha2_len);

    /*
     * Calculate auth digest using HA1, nonce, nonce count, client nonce, qop, HA2
     */
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, HA1, 32); 
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ah->nonce, strnlen_s(ah->nonce, MAX_NONCE));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ah->nc, strnlen_s(ah->nc, MAX_NC));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ah->cnonce, strnlen_s(ah->cnonce, MAX_NONCE));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, "auth", 4);
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ha2_str, ha2_len * 2);
    EVP_DigestFinal(mdctx, digest, &d_len);
    EVP_MD_CTX_destroy(mdctx);

    rv = malloc(33);
    est_hex_to_str(rv, digest, d_len);
    return (rv);
}

/*
 * This function allocates an HTTP authentication header
 * structure, which is used to pass the auth credentials
 * to the application layer to allow the app to authenticate
 * an EST client.
 */
static EST_HTTP_AUTH_HDR * est_create_ah()
{
    EST_HTTP_AUTH_HDR *ah;

    ah = malloc(sizeof(EST_HTTP_AUTH_HDR));
    memzero_s(ah, sizeof(EST_HTTP_AUTH_HDR));
    return (ah);
}

/*
 * This function frees all the elements on an HTTP
 * authentication header structure.
 */
static void est_destroy_ah(EST_HTTP_AUTH_HDR *ah)
{
    int len;

    if (!ah) return;
    if (ah->user) free(ah->user);
    if (ah->pwd) {
	/*
	 * Get the length of the password so it can be zeroized 
	 */
	len = strnlen_s(ah->pwd, MAX_UIDPWD);
	if (len) {
	    memzero_s(ah->pwd, len);
	}
	free(ah->pwd);
    }
    if (ah->uri) free(ah->uri);
    if (ah->cnonce) free(ah->cnonce);
    if (ah->qop) free(ah->qop);
    if (ah->nc) free(ah->nc);
    if (ah->nonce) free(ah->nonce);
    if (ah->response) free(ah->response);
    if (ah->auth_token) {
	len = strnlen_s(ah->auth_token, MAX_AUTH_TOKEN_LEN);
	if (len) {
	    memzero_s(ah->auth_token, len);
	}
	free(ah->auth_token);
    }
    free(ah);
}

/*
 * This function will handle all the checks that need to be performed by
 * Enhanced Cert Auth. If the csr check flag given is on then it will be
 * performed along with generating an auth header. If the csr check is
 * performed then the parsed csr will be cached in the given output parameter
 * (X509_REQ **csr_p).
 */
static EST_HTTP_AUTH_HDR_RESULT
handle_enhanced_cert_auth (EST_CTX *ctx, SSL *ssl, X509 *peer, char *csr_buf,
                           int csr_buf_len, X509_REQ **csr_p,
                           EST_HTTP_AUTH_HDR *ah,
                           EST_ECA_CSR_CHECK_FLAG csr_check_flag)
{
    STACK_OF(X509) *peer_chain = NULL;
    int mfg_index;
    ENCHD_CERT_MFG_INFO *mfg_info;
    EST_HTTP_AUTH_HDR_RESULT auth_hdr_res = EST_AUTH_HDR_BAD;
    EST_ERROR err_code;

    if ((peer_chain = SSL_get_peer_cert_chain(ssl)) == NULL) {
        EST_LOG_ERR("Couldn't get peer chain");
        return EST_AUTH_ECA_ERR;
    }
    err_code = est_enhcd_cert_auth_get_mfg(ctx, peer, peer_chain, &mfg_index);
    if (err_code == EST_ERR_NONE || err_code == EST_ERR_VALIDATION) {
        /* Perform CSR check if necessary */
        if (csr_check_flag == ECA_CSR_CHECK_ON) {

            /*
             * Parse the PKCS10 CSR from the client
             */
            *csr_p = est_server_parse_csr((unsigned char *)csr_buf, csr_buf_len,
                                          EST_CSR_DECODE);
            if (!(*csr_p)) {
                EST_LOG_ERR(
                    "Unable to parse the PKCS10 CSR sent by the client");
                return EST_AUTH_ECA_CSR_PARSE_FAIL;
            }
            /* Error logging happens inside check */
            auth_hdr_res = perform_enhanced_cert_auth_csr_check(
                ctx, peer, *csr_p, mfg_index);
        } else {
            /* Skip CSR check */
            auth_hdr_res = EST_AUTH_HDR_GOOD;
        }
        if (auth_hdr_res == EST_AUTH_HDR_GOOD) {
            if (mfg_index >= 0) {
                mfg_info = &(ctx->enchd_cert_mfgs_info_list[mfg_index]);
                EST_LOG_INFO("Using Enhanced Certificate Auth Mode "
                             "Auth Header from manufacturer %s\n",
                             mfg_info->name);
                auth_hdr_res = build_enhanced_cert_auth_header(ctx, ah, peer,
                                                               mfg_info->nid);
            } else {
                EST_LOG_INFO("Using Enhanced Certificate Auth Mode "
                             "Auth Header for local PKI domain\n");
                auth_hdr_res = build_enhanced_cert_auth_header(
                    ctx, ah, peer, ctx->enhcd_cert_local_pki_nid);
            }
        }
    } else {
        EST_LOG_ERR("Error during Enhanced Cert Auth manufacturer info search\n"
                    "Error Code: %s",
                    EST_ERR_NUM_TO_STR(err_code));
    }
    return auth_hdr_res;
}
/*
 * This function checks to see if TLS Auth applies to the request due to a
 * successful mutual auth TLS connection. A boolean will be returned to signify
 * whether the authentication should stop due to an invalid client cert. The
 * auth status will be updated via the auth_result reference pointer.
 */
static unsigned char check_for_TLS_cert_auth (SSL *ssl, X509 **peer,
                                              EST_AUTH_STATE *auth_result)
{
    int v_result;
    /*
     * Get client certificate from TLS stack.
     */
    if ((*peer = SSL_get_peer_certificate(ssl)) != NULL) {
        /* check TLS based client authorization (is client cert authorized) */
        v_result = (int)SSL_get_verify_result(ssl);
        if (X509_V_OK == v_result) {
            EST_LOG_INFO("TLS: client certificate is valid");
            *auth_result = EST_CERT_AUTH;
        } else if (X509_V_ERR_UNABLE_TO_GET_CRL == v_result) {
            EST_LOG_WARN("Peer cert is valid, but no CRL was loaded. Unable to "
                         "determine if peer cert is revoked.");
            *auth_result = EST_CERT_AUTH;
        } else {
            EST_LOG_INFO("TLS: client certificate not verified (v_result=%d)",
                         v_result);
            /* We need to bail since the client is using a bogus cert,
             * no need to continue with HTTP authentication below */
            X509_free(*peer);
            *peer = NULL;
            *auth_result = EST_UNAUTHORIZED;
            /* Auth should not continue */
            return 0;
        }
    } else {
        EST_LOG_INFO("TLS: no peer certificate");
        *auth_result = EST_UNAUTHORIZED;
    }
    /* Continue auth */
    return 1;
}
/*
 * This function verifies that the peer either provided a certificate
 * that was verified by the TLS stack, or HTTP authentication
 * credentials were provided. 
 *
 * Returns a EST_AUTH_STATE authorization result 
 */
EST_AUTH_STATE est_enroll_auth (EST_CTX *ctx, void *http_ctx, SSL *ssl,
                                char *path_seg, EST_ENROLL_REQ_TYPE enroll_req,
                                char *csr_buf, int csr_buf_len,
                                X509_REQ **csr_p)
{
    EST_AUTH_STATE rv = EST_UNAUTHORIZED;
    X509 *peer = NULL;
    struct mg_connection *conn = (struct mg_connection *)http_ctx;
    EST_HTTP_AUTH_HDR *ah;
    EST_HTTP_AUTH_HDR_RESULT pr = EST_AUTH_ECA_ERR;

    /* Performance Timers */
    EST_TIMER auth_timer;
    EST_TIMER event_cb_timer;

    if (!check_for_TLS_cert_auth(ssl, &peer, &rv)) {
        goto ret_label;
    }

    /*
     * See if SRP is being used.  If so, there will be no
     * certificate.
     */
    if (rv != EST_CERT_AUTH && SSL_get_srp_username(ssl) != NULL) {
        EST_LOG_INFO("TLS: no certificate from client, SRP login is %s",
                     SSL_get_srp_username(ssl));
        rv = EST_SRP_AUTH;
    }

    /*
     * If the application layer has enabled HTTP authentication we
     * will attempt HTTP authentication when TLS client auth fails
     * or when the require_http_auth flag is set by the application.
     * All this assumes the application layer has provided the HTTP auth
     * callback facility.
     */
    if (ctx->transport_mode == EST_HTTP && ctx->est_http_auth_cb &&
        (rv == EST_UNAUTHORIZED ||
         HTTP_AUTH_REQUIRED == ctx->require_http_auth)) {
        /*
         * Try HTTP authentication.
         */
        ah = est_create_ah();
        /*
         * If Enhanced Cert Auth Mode is enabled AND the request is using Cert
         * Auth AND Enhanced Cert Auth applies to the received certificate build
         * the special Enhanced Cert Auth header
         */
        if (ctx->enhanced_cert_auth_enabled == ENHANCED_CERT_AUTH_ENABLED &&
            rv == EST_CERT_AUTH) {
            pr = handle_enhanced_cert_auth(ctx, ssl, peer, csr_buf, csr_buf_len,
                                           csr_p, ah,
                                           ctx->enhanced_cert_auth_csr_check);
        } else {
            pr = mg_parse_auth_header(conn, ah);
        }
        switch (pr) {
        case EST_AUTH_HDR_GOOD:
            /*
             * Invoke the application specific auth check now
             * that we have the user's credentials
             */
            start_timer(&auth_timer, ctx, "HTTP est_http_auth_cb");
            if (ctx->est_http_auth_cb(ctx, ah, peer, path_seg, ctx->ex_data)) {
                rv = EST_HTTP_AUTH;
            } else {
                EST_LOG_WARN("HTTP authentication failed. Auth type=%d",
                             ah->mode);
                rv = EST_UNAUTHORIZED;
            }
            stop_timer(&auth_timer);
            break;
        case EST_AUTH_HDR_MISSING:
            /*  ask client to send us authorization headers */
            mg_send_authorization_request(conn);
            EST_LOG_INFO("HTTP auth headers missing, sending HTTP auth request "
                         "to client.");
            rv = EST_HTTP_AUTH_PENDING;
            break;
        case EST_AUTH_ECA_CSR_CHECK_FAIL:
            EST_LOG_WARN("Enhanced Cert Auth CSR check failed");
            rv = EST_UNAUTHORIZED;
            break;
        case EST_AUTH_ECA_CSR_PARSE_FAIL:
            rv = EST_CSR_PARSE_FAIL;
            break;
        case EST_AUTH_ECA_ERR:
            EST_LOG_WARN("An error occurred in Enhanced Cert Auth.");
            rv = EST_UNAUTHORIZED;
            break;
        case EST_AUTH_HDR_BAD:
        default:
            EST_LOG_WARN("Client sent incomplete HTTP authorization header");
            if (enroll_req && rv == EST_CERT_AUTH) {
                EST_LOG_INFO("Client cert was authenticated, HTTP auth not "
                             "required for reenroll");
            } else {
                rv = EST_UNAUTHORIZED;
            }
            break;
        }
        est_destroy_ah(ah);
    } else if (ctx->transport_mode == EST_COAP) {
        if (rv != EST_CERT_AUTH) {
            rv = EST_UNAUTHORIZED;
        } else if (ctx->enhanced_cert_auth_enabled ==
                   ENHANCED_CERT_AUTH_ENABLED) {
            if (csr_buf_len <= 0) {
                EST_LOG_WARN(
                    "Enhanced Cert Auth failed. No request body found.");
                rv = EST_CSR_PARSE_FAIL;
                goto ret_label;
            }
            ah = est_create_ah();
            pr = handle_enhanced_cert_auth(ctx, ssl, peer, csr_buf, csr_buf_len,
                                           csr_p, ah,
                                           ctx->enhanced_cert_auth_csr_check);
            switch (pr) {
            case EST_AUTH_HDR_GOOD:
                /*
                 * Invoke the application specific auth check now
                 * that we have the user's credentials
                 */
                start_timer(&auth_timer, ctx, "CoAP est_http_auth_cb");
                if (ctx->est_http_auth_cb(ctx, ah, peer, path_seg,
                                          ctx->ex_data)) {
                    rv = EST_HTTP_AUTH;
                } else {
                EST_LOG_WARN("Enhanced Cert Auth failed. Certificate "
                             "credentials failed authentication "
                             "or authorization");
                    rv = EST_UNAUTHORIZED;
                }
                stop_timer(&auth_timer);
                break;
            case EST_AUTH_ECA_CSR_CHECK_FAIL:
                EST_LOG_WARN("Enhanced Cert Auth CSR check failed");
                rv = EST_UNAUTHORIZED;
                break;
            case EST_AUTH_ECA_CSR_PARSE_FAIL:
                rv = EST_CSR_PARSE_FAIL;
                break;
            case EST_AUTH_ECA_ERR:
                EST_LOG_WARN("An error occurred in Enhanced Cert Auth.");
                rv = EST_UNAUTHORIZED;
                break;
            case EST_AUTH_HDR_MISSING:
            case EST_AUTH_HDR_BAD:
            default:
                EST_LOG_WARN("An unexpected error code was returned in "
                             "Enhanced Cert Auth");
                rv = EST_UNAUTHORIZED;
                break;
            }
            est_destroy_ah(ah);
        }
    }

ret_label:

    /*
     * Announce the EST enroll/reenroll/serverkeygen authentication
     * result event.
     */
    start_timer(&event_cb_timer, ctx, "est_invoke_enroll_auth_result_event_cb");
    est_invoke_enroll_auth_result_event_cb(ctx, peer, path_seg, enroll_req,
                                           pr, rv);
    stop_timer(&event_cb_timer);
    if (peer) {
        X509_free(peer);
    }

    return (rv);
}

/*
 * This function verifies for a brski request that the peer either provided a
 * certificate that was verified by the TLS stack, or HTTP authentication
 * credentials were provided.
 *
 * Returns a EST_AUTH_STATE authorization result
 */
EST_AUTH_STATE est_brski_auth (EST_CTX *ctx, void *http_ctx, SSL *ssl,
                               char *path_seg)
{
    EST_AUTH_STATE rv = EST_UNAUTHORIZED;
    X509 *peer = NULL;
    struct mg_connection *conn = (struct mg_connection *)http_ctx;
    EST_HTTP_AUTH_HDR *ah;
    EST_HTTP_AUTH_HDR_RESULT pr = EST_AUTH_ECA_ERR;

    if (!check_for_TLS_cert_auth(ssl, &peer, &rv)) {
        goto ret_label;
    }

    /*
     * See if SRP is being used.  If so, there will be no
     * certificate.
     */
    if (rv != EST_CERT_AUTH && SSL_get_srp_username(ssl) != NULL) {
        EST_LOG_INFO("TLS: no certificate from client, SRP login is %s",
                     SSL_get_srp_username(ssl));
        rv = EST_SRP_AUTH;
    }

    /*
     * If the application layer has enabled HTTP authentication we
     * will attempt HTTP authentication when TLS client auth fails
     * or when the require_http_auth flag is set by the application.
     * All this assumes the application layer has provided the HTTP auth
     * callback facility.
     */
    if (ctx->transport_mode == EST_HTTP && ctx->est_http_auth_cb &&
        (rv == EST_UNAUTHORIZED ||
         HTTP_AUTH_REQUIRED == ctx->require_http_auth)) {
        /*
         * Try HTTP authentication.
         */
        ah = est_create_ah();

        /*
         * If Enhanced Cert Auth Mode is enabled AND the request is using Cert
         * Auth AND Enhanced Cert Auth applies to the received certificate build
         * the special Enhanced Cert Auth header
         */
        if (ctx->enhanced_cert_auth_enabled == ENHANCED_CERT_AUTH_ENABLED &&
            rv == EST_CERT_AUTH) {
            /*
             * CSR Check cannot be performed in brski since no CSR is provided
             */
            pr = handle_enhanced_cert_auth(ctx, ssl, peer, NULL, 0, NULL, ah,
                                           ECA_CSR_CHECK_OFF);
        } else {
            pr = mg_parse_auth_header(conn, ah);
        }
        switch (pr) {
        case EST_AUTH_HDR_GOOD:
            /*
             * Invoke the application specific auth check now
             * that we have the user's credentials
             */
            if (ctx->est_http_auth_cb(ctx, ah, peer, path_seg, ctx->ex_data)) {
                rv = EST_HTTP_AUTH;
            } else {
                EST_LOG_WARN("HTTP authentication failed. Auth type=%d",
                             ah->mode);
                rv = EST_UNAUTHORIZED;
            }
            break;
        case EST_AUTH_HDR_MISSING:
            /*  ask client to send us authorization headers */
            mg_send_authorization_request(conn);
            EST_LOG_INFO("HTTP auth headers missing, sending HTTP auth request "
                         "to client.");
            rv = EST_HTTP_AUTH_PENDING;
            break;
        case EST_AUTH_ECA_CSR_PARSE_FAIL:
            EST_LOG_ERR("Received unexpected CSR parser error during auth "
                        "parsing");
            rv = EST_UNAUTHORIZED;
            break;
        case EST_AUTH_HDR_BAD:
        default:
            EST_LOG_WARN("Client sent incomplete HTTP authorization header");
            rv = EST_UNAUTHORIZED;
            break;
        }
        est_destroy_ah(ah);
    } else if (ctx->transport_mode == EST_COAP) {
        if (rv != EST_CERT_AUTH) {
            rv = EST_UNAUTHORIZED;
        } else if (ctx->enhanced_cert_auth_enabled ==
                   ENHANCED_CERT_AUTH_ENABLED) {
            ah = est_create_ah();
            /* 
             * CSR Check cannot be performed in brski since no CSR is provided
             */
            pr = handle_enhanced_cert_auth(ctx, ssl, peer, NULL, 0, NULL, ah,
                                           ECA_CSR_CHECK_OFF);
            switch (pr) {
            case EST_AUTH_HDR_GOOD:
                /*
                 * Invoke the application specific auth check now
                 * that we have the user's credentials
                 */
                if (!ctx->est_http_auth_cb(ctx, ah, peer, path_seg,
                                           ctx->ex_data)) {
                    EST_LOG_WARN("Enhanced Cert Auth failed. Certificate "
                                 "credentials failed authentication "
                                 "or authorization");
                    rv = EST_UNAUTHORIZED;
                }
                break;
            case EST_AUTH_ECA_ERR:
            case EST_AUTH_HDR_BAD:
                EST_LOG_ERR("Invalid parameters to build Enhanced Cert "
                            "Auth header.");
                rv = EST_UNAUTHORIZED;
                break;
            default:
                EST_LOG_ERR("Received unexpected received error during auth "
                            "parsing");
                rv = EST_UNAUTHORIZED;
                break;
            }
            est_destroy_ah(ah);
        }
    }
ret_label:

    /*
     * Announce the EST enroll/reenroll/serverkeygen authentication
     * result event.
     */
    est_invoke_enroll_auth_result_event_cb(ctx, peer, path_seg, 0,
                                           pr, rv);

    if (peer) {
        X509_free(peer);
    }

    return (rv);
}

/* This function sets the predefined password to be used within the Auth
 * header when the server enables Cisco Enhanced Cert Auth Mode  */
static EST_ERROR est_server_set_enhcd_cert_auth_pwd (EST_CTX *ctx,
                                                     const char *pwd)
{
    if (!ctx) {
        EST_LOG_ERR("No context provided");
        return EST_ERR_INVALID_PARAMETERS;
    }
    if (pwd == NULL) {
        EST_LOG_ERR("No password provided");
        return EST_ERR_INVALID_PARAMETERS;
    }
    if (strnlen_s(pwd, MAX_UIDPWD+1) > MAX_UIDPWD) {
        EST_LOG_ERR("Password too long.");
        return EST_ERR_INVALID_PARAMETERS;
    }
    if (EOK != strcpy_s(ctx->enhcd_cert_auth_pwd, MAX_UIDPWD+1, pwd)) {
        EST_LOG_ERR("Invalid Password provided");
        return EST_ERR_INVALID_PARAMETERS;
    }

    return (EST_ERR_NONE);
}

/*
 * This function sets the NID for the subject field to be used as the user
 * within the Auth header when the server enables Cisco Enhanced Cert Auth Mode
 * for the local pki domain
 */
static EST_ERROR
est_server_set_enhcd_cert_auth_local_pki_nid (EST_CTX *ctx,
                                              int lcl_pki_subj_field_nid)
{
    if (!ctx) {
        EST_LOG_ERR("No context provided");
        return EST_ERR_INVALID_PARAMETERS;
    }
    ctx->enhcd_cert_local_pki_nid = lcl_pki_subj_field_nid;
    return (EST_ERR_NONE);
}

/*
 * This function is used to determine if the EST client, which could be
 * an RA, is using a certificate that contains the id-kp-cmcRA usage
 * extension.  When this usage bit is present, the PoP check is disabled
 * to allow the RA use case. 
 *
 * This logic was taken from x509v3_cache_extensions() in v3_purp.c (OpenSSL).
 *
 * Returns 1 if the cert contains id-kp-cmcRA extended key usage extension.
 * Otherwise it returns 0.
 */
static int est_check_cmcRA (X509 *cert) 
{
    int cmcRA_found = 0;
    EXTENDED_KEY_USAGE *extusage;
    int i;
    ASN1_OBJECT *obj;

    /*
     * Get the extended key usage extension.  If found
     * loop through the values and look for the ik-kp-cmcRA
     * value in this extension.
     */
    if ((extusage = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL))) {
	/*
	 * Iterate through the extended key usage values
	 */
        for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
	    obj =  sk_ASN1_OBJECT_value(extusage,i);
	    /*
	     * Compare the current iteration with the global
	     * id-kp-cmcRA value that was created earlier
	     */
            if (!OBJ_cmp(obj, o_cmcRA)) {
                cmcRA_found = 1; 
                break;
            }
        }
        sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
    }

    return (cmcRA_found);
}

/*
 * This is a utility function to convert the base64 DER encoded
 * CSR to an OpenSSL X509_REQ pointer.  Returns NULL if there
 * was a problem.
 */
X509_REQ *est_server_parse_csr (unsigned char *pkcs10, int pkcs10_len,
                                EST_CSR_BASE64_DECODE base64_decode)
{
    BIO *in, *b64;
    X509_REQ *req;

    /*
     * Get the original pkcs10 request from the client
     */
    in = BIO_new_mem_buf(pkcs10, pkcs10_len);

    if (in == NULL) {
        EST_LOG_ERR("Unable to open PKCS10 raw buffer");
        return (NULL);
    }

    if (base64_decode == EST_CSR_DECODE) {
        b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL) {
            EST_LOG_ERR("Unable to open PKCS10 b64 buffer");
            BIO_free(in);
            return (NULL);
        }        
        in = BIO_push(b64, in);
    }
    
    /*
     * Read the PEM encoded pkcs10 cert request
     */
    req = d2i_X509_REQ_bio(in, NULL);
    if (req == NULL) {
        EST_LOG_ERR("Problem reading DER encoded certificate request");
        ossl_dump_ssl_errors();
        BIO_free_all(in);
        return (NULL);
    }
    BIO_free_all(in);

    return req;
}

/*
 * This function implements the Proof of Possession check (PoP).  The TLS UID has
 * already been saved from the TLS session earlier.  This TLS UID should match the
 * value of the challengePassword attribute in the pkcs10 client certificate.  The
 * client will have provided this value when signing the pkcs10 cert request
 * with its private key, which proves the client is in possession of the private key.
 * This check is enforced as follows:
 *     1. If CSR contains the PoP, it must be valid.
 *     2. If CSR didn't contain the PoP and the server is configured
 *        to require the PoP, then the authentication fails.
 *     3. Otherwise, if CSR didn't contain the PoP and the server is not
 *        configured to require PoP, then authentication passes.
 *
 * Parameters:
 *	ctx:	    Pointer to EST context
 *	ssl:        Pointer to SSL context
 *	pkcs10:	    Pointer to raw PKCS10 data
 *	pkcs10_len: Length of raw PKCS10 data
 *
 * Return value:
 *	EST_ERR_NONE when PoP check passes
 */
int est_tls_uid_auth (EST_CTX *ctx, SSL *ssl, X509_REQ *req) 
{
    X509_ATTRIBUTE *attr;
#ifdef HAVE_OLD_CISCOSSL    
    int i, j;
#else        
    int i;
#endif    

    ASN1_TYPE *at;
    ASN1_BIT_STRING *bs = NULL;
#ifdef HAVE_OLD_CISCOSSL    
    ASN1_TYPE *t;
#endif
    int rv = EST_ERR_NONE;
    char *tls_uid;
    int   uid_len = 0;
    int diff;

    /*
     * Get the index of the challengePassword attribute in the request
     */
    i = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
    if (i < 0) {
        EST_LOG_INFO("Cert request does not contain PoP challengePassword attribute");
        /*
         * If PoP is enabled, we must fail at this point
         * since the client didn't send the channel binding
         * info in the CSR.
         */
        if (ctx->server_enable_pop) {
            EST_LOG_WARN("PoP enabled, CSR was not authenticated");
                return (EST_ERR_AUTH_FAIL_TLSUID);
        } else {
            return (EST_ERR_NONE);
        }
    } else {
        /*
         * Get a reference to the attribute now that we know where it's located
	 * RFC 7030 requires that we check the PoP when it's present
         */
        attr = X509_REQ_get_attr(req, i);

        /*
         * If we found the attribute, get the actual value of the challengePassword
         */
        if (attr) {
#ifdef HAVE_OLD_CISCOSSL    
            if (attr->single) {
                t = attr->value.single;
                bs = t->value.bit_string;
            } else {
                j = 0;
                at = sk_ASN1_TYPE_value(attr->value.set, j);
                bs = at->value.asn1_string;
            }
#else
            at = X509_ATTRIBUTE_get0_type(attr, 0);
            bs = at->value.asn1_string;
#endif            
        } else {
            EST_LOG_WARN("PoP challengePassword attribute not found in client cert request");
            return (EST_ERR_AUTH_FAIL_TLSUID);
        }

        /*
         * Now that we have the challengePassword from the client cert request,
         * compare it to the TLS UID we calculated on the server side.
         * This implements the PoP check to verify the client holds the private
         * key used to sign the cert request.
         */
        tls_uid = est_get_tls_uid(ssl, &uid_len, 0);
        if (tls_uid) {
	    i = memcmp_s(tls_uid, uid_len, bs->data, uid_len, &diff);
            if (i == EOK && !diff) {
                EST_LOG_INFO("PoP is valid");
                rv = EST_ERR_NONE;
            } else {
                EST_LOG_WARN("PoP is not valid");
                rv = EST_ERR_AUTH_FAIL_TLSUID;
            }
            free(tls_uid);
        } else {
            EST_LOG_WARN("Local TLS channel binding info is not available");
            rv = EST_ERR_AUTH_FAIL_TLSUID;
        }
    }

    return rv;
}

/*
 * This function performs a simple sanity check on a PKCS10
 * CSR.  It will check the signature in the CSR.
 * Returns 0 for success, non-zero if the sanity check failed.
 */
int est_server_check_csr (X509_REQ *req) 
{
    EVP_PKEY *pub_key = NULL;
    int rc;

    /*
     * Extract the public key from the CSR
     */
    if ((pub_key = X509_REQ_get_pubkey(req)) == NULL) {
	EST_LOG_ERR("Unable to extract public key from CSR");
	return 1;
    }

    /*
     * Verify the signature in the CSR 
     */
    rc = X509_REQ_verify(req, pub_key);
    EVP_PKEY_free(pub_key);

    /*
     * Check the result
     */
    if (rc < 0) {
	EST_LOG_ERR("CSR signature check failed");
        return 1;
    } else if (rc == 0) {
	EST_LOG_ERR("CSR signature mismatch");
        return 1;
    } else {
        return 0;
    }
}


/*
 * Frees the linked-list containing the attributes in
 * the client CSR.
 */
static void est_server_free_csr_oid_list (EST_OID_LIST *head)
{
    EST_OID_LIST *next_entry;

    if (!head) {
	return;
    }

    next_entry = head->next;
    while (next_entry) {
	free(head);
	head = next_entry;
	next_entry = head->next;
    }
    free(head);
}

/*
 * Adds a new entry to the tail of the list of attributes
 * in the client CSR.
 */
static void est_server_add_oid_to_list (EST_OID_LIST **list, EST_OID_LIST *new_entry) 
{
    EST_OID_LIST *head = *list;

    /*
     * If the list doesn't have a head yet, the new entry
     * simply becomes the head
     */
    if (head == NULL) { 
	*list = new_entry;
    } else {
	/*
	 * Walk the list to find the tail, add the new entry to the end
	 */
	while (head->next) {
	    head = head->next;
	}
	head->next = new_entry;
    }
}

/*
 * This is a recursive routine that walks through an ASN.1 blob
 * looking for ASN.1 object definitions.  For any that are
 * found, the OID for the object is added to the EST_OID_LIST (first argument).
 * The end result of this routine is **list will contain all the OID
 * values for every ASN.1 object in the blob.
 * This code was shamelessly taken from OpenSSL ans1_parse2(), which
 * explains some of the poorly chosen variable names.
 */
static int est_server_csr_asn1_parse (EST_OID_LIST **list, const unsigned char **blob, long length, int offset)
{
    EST_OID_LIST *new_entry;
    const unsigned char *ptr, *ep, *tot, *op, *opp;
    long len;
    int tag, xclass;
    int hl, j, r;
    ASN1_OBJECT *a_object = NULL;
    errno_t safec_rc; 

    ptr = *blob;
    tot = ptr + length;
    op = ptr - 1;
    while ((ptr < tot) && (op < ptr)) {
	op = ptr;
	j = ASN1_get_object(&ptr, &len, &tag, &xclass, length);
	if (j & 0x80) {
	    EST_LOG_ERR("Error in encoding"); 
	    *blob = ptr;
	    return (0);
	}
	hl = ptr - op;
	length -= hl;

	if (j & V_ASN1_CONSTRUCTED) {
	    ep = ptr + len;
	    if (len > length) {
		EST_LOG_ERR("length is greater than %ld",length);
		*blob = ptr;
		return (0);
	    }
	    if ((j == 0x21) && (len == 0)) {
		r = est_server_csr_asn1_parse(list, &ptr, (long)(tot-ptr), offset+(ptr - *blob));
		if (r == 0) { 
		    *blob = ptr;
		    return (0);
		}
		if ((r == 2) || (ptr >= tot)) break;
	    } else {
		while (ptr < ep) {
		    r = est_server_csr_asn1_parse(list, &ptr, (long)len, offset+(ptr - *blob));
		    if (r == 0) { 
			*blob = ptr;
			return (0);
		    }
		}
	    }
	} else if (xclass != 0) {
	    ptr += len;
	} else {
	    if (tag == V_ASN1_OBJECT) {
		opp = op;
		if (d2i_ASN1_OBJECT(&a_object, &opp, len+hl) != NULL) {
		    new_entry = malloc(sizeof(EST_OID_LIST));
		    if (!new_entry) {
			EST_LOG_ERR("malloc failure");
			est_server_free_csr_oid_list(*list);
			if (a_object != NULL) { ASN1_OBJECT_free(a_object); }
			*blob = ptr;
			return (0);
		    }
		    safec_rc = memset_s(new_entry, sizeof(EST_OID_LIST), 0x0, sizeof(EST_OID_LIST));
		    if (safec_rc != EOK) {
		        EST_LOG_INFO("memset_s error 0x%xO\n", safec_rc);
		    }
		    i2t_ASN1_OBJECT(new_entry->oid, EST_MAX_ATTR_LEN, a_object);
		    EST_LOG_INFO("Build CSR OID list: %s", new_entry->oid);
		    est_server_add_oid_to_list(list, new_entry);
		    if (a_object != NULL) {
			ASN1_OBJECT_free(a_object);
			a_object = NULL;
		    }
		} else {
		    EST_LOG_ERR("Bad ASN.1 object");
		    if (a_object != NULL) { ASN1_OBJECT_free(a_object); }
		    *blob = ptr;
		    return (0);
		}
	    } 
	    ptr += len;
	    if ((tag == V_ASN1_EOC) && (xclass == 0)) {
		*blob = ptr;
		return (2);
	    }
	}
	length -= len;
    }
    *blob = ptr;
    return (1);
}

/*
 * Utility function that populates a linked-list containing
 * the OID (or name) of the attributes present in the
 * client CSR.
 */
static EST_ERROR est_server_build_csr_oid_list (EST_OID_LIST **list, char *body, int body_len)
{
    unsigned char *der_data, *der_ptr;
    int der_len;
    int rv;

    /*
     * grab some space to hold the decoded CSR data
     */
    der_ptr = der_data = malloc(body_len*2);
    if (!der_data) {
	EST_LOG_ERR("malloc failed");
        return (EST_ERR_MALLOC);
    }

    /*
     * Decode the CSR data
     */
    der_len = est_base64_decode((char *)body, (char *)der_data, body_len*2);
    if (der_len <= 0) {
        EST_LOG_ERR("Invalid base64 encoded data");
        free(der_data);
        return (EST_ERR_BAD_BASE64);
    }

    rv = est_server_csr_asn1_parse(list, (const unsigned char **)&der_data,
                                   der_len, 0);
    if (!rv) {
        EST_LOG_ERR("Failed to build OID list from client provided CSR");
        est_server_free_csr_oid_list(*list);
        free(der_ptr);
        return (EST_ERR_UNKNOWN);
    }
    free(der_ptr);
    return (EST_ERR_NONE);
}

/*
 * This function checks the locally configured CSR attributes
 * against the attributes in the CSR.  If any attributes are
 * missing from the CSR, then an error is returned.
 */
static EST_ERROR est_server_all_csrattrs_present(EST_CTX *ctx, char *body, int body_len, X509 *peer_cert)
{
    int tag, xclass, j, found_match, nid;
    long len;
    unsigned char *der_ptr, *save_ptr;
    ASN1_OBJECT *a_object;
    int max_len = MAX_CSRATTRS;
    char *csr_data;
    int csr_len;
    long out_len_save;
    unsigned char *der_data;
    int der_len, out_len;
    char tbuf[EST_MAX_ATTR_LEN];
    EST_OID_LIST *csr_attr_oids = NULL;
    EST_OID_LIST *oid_entry;
    int safec_rc;
    int comparator;
    EST_ERROR rv;
    int curr_len;
    const unsigned char *curr_string;    

    EST_LOG_INFO("CSR attributes enforcement is enabled");

    if (!ctx->server_csrattrs && !ctx->est_get_csr_cb) {
        EST_LOG_WARN("CSR attributes enforcement is enabled, but no attributes have been configured");
        return EST_ERR_NONE;
    }

    /*
     * Build the list of attributes present in the CSR.  This list will be
     * used later when we confirm the required attributes are present.
     */
    rv =  est_server_build_csr_oid_list(&csr_attr_oids, body, body_len);
    if (rv != EST_ERR_NONE) {
        return (rv);
    }

    /*
     * Get the CSR attributes configured on the server.  We'll need to
     * look in the CSR to make sure the CSR provided each of these.
     * Use the callback if configured, otherwise use the local copy.
     */
    if (ctx->est_get_csr_cb) {
        csr_data = (char *)ctx->est_get_csr_cb(&csr_len, NULL, peer_cert, ctx->ex_data);
        if (!csr_data) {
            EST_LOG_ERR("Application layer failed to return CSR attributes");
            est_server_free_csr_oid_list(csr_attr_oids);
            return (EST_ERR_CB_FAILED);
        }
    } else {
        csr_data = malloc(ctx->server_csrattrs_len + 1);
        if (!csr_data) {
            EST_LOG_ERR("malloc failure");
            est_server_free_csr_oid_list(csr_attr_oids);
            return (EST_ERR_MALLOC);
        }
        safec_rc = strcpy_s(csr_data, ctx->server_csrattrs_len + 1,
                            (char *)ctx->server_csrattrs);
        if (safec_rc != EOK) {
            EST_LOG_ERR("strcpy_s Safe C error %s(%d)", strerror(safec_rc), safec_rc);
            est_server_free_csr_oid_list(csr_attr_oids);
            free(csr_data);
            return (EST_ERR_UNKNOWN);
        }
        csr_data[ctx->server_csrattrs_len] = 0;
        csr_len = ctx->server_csrattrs_len;
    }
    EST_LOG_INFO("Checking CSR attrs present in CSR: %s", csr_data);

    /*
     * We have the CSR configured on the server and it needs base64 decoding.
     * Check smallest possible base64 case here for now
     * and sanity test will check min/max value for ASN.1 data
     */
    if (csr_len < MIN_CSRATTRS) {
        est_server_free_csr_oid_list(csr_attr_oids);
        free(csr_data);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /*
     * grab some space to hold the decoded CSR data
     */
    der_data = malloc(csr_len*2);
    if (!der_data) {
        EST_LOG_ERR("malloc failed");
        est_server_free_csr_oid_list(csr_attr_oids);
        free(csr_data);
        return (EST_ERR_MALLOC);
    }

    /*
     * Decode the CSR data
     */
    der_len = est_base64_decode(csr_data, (char *)der_data, csr_len*2);
    free(csr_data);
    if (der_len <= 0) {
        EST_LOG_ERR("Invalid base64 encoded data");
        est_server_free_csr_oid_list(csr_attr_oids);
        free(der_data);
        return (EST_ERR_BAD_BASE64);
    }

    /*
     * pointer fun starts here, joy to OpenSSL
     */
    out_len_save = out_len = der_len;
    der_ptr = save_ptr = der_data;

    if (out_len_save > max_len) {
        EST_LOG_ERR("DER length exceeds max");
        est_server_free_csr_oid_list(csr_attr_oids);
        free(der_data);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /* make sure its long enough to be ASN.1 */
    if (der_len < MIN_ASN1_CSRATTRS) {
        EST_LOG_ERR("DER too short");
        est_server_free_csr_oid_list(csr_attr_oids);
        free(der_data);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /*
     * Iterate through the CSR attributes configured on the server
     */
    while (out_len > 0) {
        curr_len = out_len;
        curr_string = der_ptr;

        /*
         * Get the next attributes
         */
        j = ASN1_get_object((const unsigned char**)&der_ptr, &len, &tag, &xclass, out_len);

        EST_LOG_INFO("Sanity: tag=%d, len=%d, j=%d, out_len=%d", tag, len, j, out_len);
        if (j & 0x80) {
            EST_LOG_ERR("Bad ASN1 hex");
            est_server_free_csr_oid_list(csr_attr_oids);
            free(der_data);
            return (EST_ERR_BAD_ASN1_HEX);
        }
        switch (tag) {
            case V_ASN1_OBJECT:
                a_object = d2i_ASN1_OBJECT(NULL, &curr_string, curr_len);
                if (!a_object) {
                    EST_LOG_ERR("a_object is null");
                    est_server_free_csr_oid_list(csr_attr_oids);
                    free(der_data);
                    return (EST_ERR_UNKNOWN);
                }
                der_ptr = (unsigned char *)curr_string;
                
                /*
                 * If this is the challengePassword, no need to check it.
                 * This is already covered when authenticating the client
                 */
                nid = OBJ_obj2nid(a_object);
                if (nid == NID_pkcs9_challengePassword) {
                    ASN1_OBJECT_free(a_object);
                    break;
                }

                i2t_ASN1_OBJECT(tbuf, EST_MAX_ATTR_LEN, a_object);
                EST_LOG_INFO("Looking for attr=%s in the CSR", tbuf);
                ASN1_OBJECT_free(a_object);

                /*
                 * If there were no attributes in the CSR, we can
                 * bail now.
                 */
                if (csr_attr_oids == NULL) {
                    EST_LOG_WARN("CSR did not contain any attributes, CSR will be rejected", tbuf);
                    free(der_data);
                    return (EST_ERR_CSR_ATTR_MISSING);
                }

                found_match = 0;
                oid_entry = csr_attr_oids;
                /*
                 * Iterate through the attributes that are in the CSR
                 */
                while (oid_entry) {
                    EST_LOG_INFO("Comparing %s to %s", tbuf, oid_entry->oid);
                    safec_rc = strcmp_s(
                        oid_entry->oid,
                        EST_MAX_ATTR_LEN,
                        tbuf, &comparator);
                    if (safec_rc != EOK) {
                        EST_LOG_ERR("strcmp_s Safe C error %s(%d)", strerror(safec_rc), safec_rc);
                        est_server_free_csr_oid_list(csr_attr_oids);
                        free(der_data);
                        return (EST_ERR_UNKNOWN);
                    }
                    if (!comparator) {
                        found_match = 1;
                        break;
                    }
                    oid_entry = oid_entry->next;
                }

                if (!found_match) {
                    EST_LOG_WARN("CSR did not contain %s attribute, CSR will be rejected", tbuf);
                    est_server_free_csr_oid_list(csr_attr_oids);
                    free(der_data);
                    return (EST_ERR_CSR_ATTR_MISSING);
                }
                break;
            default:
                /* have to adjust string pointer here, move on to the next item */
                der_ptr += len;
                break;
            case V_ASN1_SET:
            case V_ASN1_SEQUENCE:
                break;
        }
        out_len = out_len_save - (der_ptr - save_ptr);
    }

    /*
     * One file check to ensure we didn't missing something when parsing
     * the locally configured CSR attributes.
     */
    if (out_len != 0) {
        EST_LOG_ERR("DER length not zero (%d)", out_len);
        est_server_free_csr_oid_list(csr_attr_oids);
        free(der_data);
        return (EST_ERR_BAD_ASN1_HEX);
    }

    /*
     * If we're lucky enough to make it this far, then it means all the
     * locally configured CSR attributes were found in the client's CSR.
     */
    est_server_free_csr_oid_list(csr_attr_oids);
    free(der_data);
    return (EST_ERR_NONE);
}

/*
 * This function is used by the server to process an incoming
 * Simple Enroll request from the client.
 */
EST_ERROR est_handle_simple_enroll (EST_CTX *ctx, void *http_ctx,
                                    SSL *ssl, X509 *peer_cert,
                                    const char *ct, char *body,
                                    int body_len, char *path_seg,
                                    EST_ENROLL_REQ_TYPE enroll_req,
                                    unsigned char **returned_cert,
                                    int *returned_cert_len)
{
    int rv, cert_len;
    struct mg_connection *conn = NULL;
    char *user_id = NULL;
    unsigned char *cert;
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;
    X509_REQ *csr = NULL;
    int client_is_ra = 0;
    int reenroll;
    
    /* Performance Timers */
    EST_TIMER enroll_timer;

    if (enroll_req == SIMPLE_ENROLL_REQ) {
        reenroll = 0;
    } else if (enroll_req == REENROLL_REQ) {
        reenroll = 1;
    } else {
        EST_LOG_ERR("Enroll request must be enroll or reenroll");
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (ctx->transport_mode == EST_HTTP) {
        conn = (struct mg_connection*)http_ctx;
        user_id = conn->user_id;
    }
    
    
    if (!reenroll && !ctx->est_enroll_pkcs10_cb) {
        EST_LOG_ERR("Null enrollment callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    if (reenroll && !ctx->est_reenroll_pkcs10_cb) {
        EST_LOG_ERR("Null reenroll callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    /*
     * Make sure the client has sent us a PKCS10 CSR request if in HTTP
     */
    if ((ctx->transport_mode == EST_HTTP) &&
        (strncmp(ct, "application/pkcs10", 18))) {
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_enroll_auth(ctx, http_ctx, ssl, path_seg, reenroll, body,
                            body_len, &csr)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
	/*
	 * this means the user was authorized, either through
	 * HTTP authorization or certificate authorization
	 */
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
        csr = est_server_parse_csr ((unsigned char *)body, body_len,
                                    EST_CSR_DECODE);
        if (!csr) {
            EST_LOG_ERR ("Unable to parse the PKCS10 CSR sent by the client");
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

    if (peer_cert) {
        client_is_ra = est_check_cmcRA (peer_cert);
    }
    EST_LOG_INFO("id-kp-cmcRA present: %d", client_is_ra);

    /*
     * Do the PoP check (Proof of Possession).  The challenge password
     * in the pkcs10 request should match the TLS unique ID.
     * The PoP check is not performed when the client is an RA.
     */
    if (!client_is_ra) {
        rv = est_tls_uid_auth(ctx, ssl, csr);
        if (rv != EST_ERR_NONE) {
            X509_REQ_free(csr);
            return (EST_ERR_AUTH_FAIL_TLSUID);
        }
    }

    /*
     * Check if we need to ensure the client included all the
     * CSR attributes required by the CA.
     */
    if (ctx->enforce_csrattrs) {
        if (EST_ERR_NONE != est_server_all_csrattrs_present(ctx, body, body_len, peer_cert)) {
            X509_REQ_free(csr);
            return (EST_ERR_CSR_ATTR_MISSING);
        }
    }

    /* body now points to the pkcs10 data, pass
     * this to the enrollment routine */

    if (reenroll) {
        if (ctx->transport_mode == EST_HTTP) {
            start_timer(&enroll_timer, ctx, "HTTP est_reenroll_pkcs10_cb");
        } else {
            start_timer(&enroll_timer, ctx, "CoAP est_reenroll_pkcs10_cb");
        }
        rv = ctx->est_reenroll_pkcs10_cb((unsigned char*)body, body_len, 
                                         &cert, (int*)&cert_len,
                                         user_id, peer_cert,
                                         path_seg, ctx->ex_data);
    } else {
        if (ctx->transport_mode == EST_HTTP) {
            start_timer(&enroll_timer, ctx, "HTTP est_enroll_pkcs10_cb");
        } else {
            start_timer(&enroll_timer, ctx, "CoAP est_enroll_pkcs10_cb");
        }
        rv = ctx->est_enroll_pkcs10_cb((unsigned char*)body, body_len, 
                                       &cert, (int*)&cert_len,
                                       user_id, peer_cert,
                                       path_seg, ctx->ex_data);
    }
    stop_timer(&enroll_timer);
    /*
     * For HTTP, build up the response now including the payload that contains
     * the cert
     * For CoAP, return the cert and its length to let the coap specifc code
     * build the response
     */
    if (rv == EST_ERR_NONE && cert_len > 0) {

        /*
         * If the caller wants to get the cert back, then provide it
         */
        if (returned_cert == NULL || returned_cert_len == NULL) {

            free(cert);
            X509_REQ_free(csr);
            EST_LOG_ERR("Null pointers for return cert values");
            return (EST_ERR_INVALID_PARAMETERS);
        }
        
        *returned_cert = cert;
        *returned_cert_len = cert_len;
        
        if (ctx->transport_mode == EST_HTTP) {
            
            /*
             * Send HTTP header
             */
            snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
                     EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
            snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %s%s", EST_HTTP_HDR_CT,
                     EST_HTTP_CT_PKCS7_CO, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
            snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %s%s", EST_HTTP_HDR_CE,
                     EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
            snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX - hdrlen, "%s: %d%s%s", EST_HTTP_HDR_CL,
                     cert_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
            if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
                X509_REQ_free(csr);
                return (EST_ERR_HTTP_WRITE);
            }
            
            /*
             * Send the signed PKCS7 certificate in the body
             */
            if (!mg_write(http_ctx, cert, cert_len)) {
                X509_REQ_free(csr);
                return (EST_ERR_HTTP_WRITE);
            }

        }   
    } else if (rv == EST_ERR_CA_ENROLL_RETRY) {
        /*
         * The CA did not sign the request and has asked the
         * client to retry in the future.  This may occur if
         * the CA is not configured for automatic enrollment.
         * Send the HTTP retry response to the client.
         */
        EST_LOG_INFO("CA server requests retry, possibly it's not setup for auto-enroll");
        X509_REQ_free(csr);
        return EST_ERR_CA_ENROLL_RETRY;
    } else {
        X509_REQ_free(csr);
        return EST_ERR_CA_ENROLL_FAIL;
    }

    X509_REQ_free(csr);
    return EST_ERR_NONE;
}

/*
 * This function is used by the server to process an incoming
 * Server-side key gen Enroll request from the client.
 */
EST_ERROR est_handle_server_keygen (EST_CTX *ctx, void *http_ctx,
                                    SSL *ssl, X509 *peer_cert,
                                    const char *ct, char *body,
                                    int body_len, char *path_seg,
                                    unsigned char **returned_cert,
                                    int *returned_cert_len,
                                    unsigned char **returned_key,
                                    int *returned_key_len) {
    int rv, cert_len;
    EST_ERROR return_code = EST_ERR_UNKNOWN;
    struct mg_connection *conn = NULL;
    char *user_id = NULL;
    unsigned char *cert = NULL, *der_key = NULL, *b64der = NULL;
    char http_hdr[EST_HTTP_HDR_MAX];
    char pvt_key_hdr[EST_HTTP_HDR_MAX];
    char cert_hdr[EST_HTTP_HDR_MAX];
    char final_bndry_hdr[EST_HTTP_HDR_MAX];
    int hdrlen, der_len = 0;
    int pvt_key_hdr_len, cert_hdr_len, final_bndry_hdr_len = 0;
    X509_REQ *csr = NULL;
    int client_is_ra = 0;

    EVP_PKEY *priv_key = NULL;
    int b64der_len = 0;
    BIO *p10out = NULL, *b64 = NULL;
    BUF_MEM *new_body;

    /* Performance Timers */
    EST_TIMER keygen_timer;
    EST_TIMER enroll_timer;

    if (ctx->transport_mode == EST_HTTP) {
        conn = (struct mg_connection*)http_ctx;
        user_id = conn->user_id;
    }

    if (strlen(EST_HTTP_BOUNDARY) > 70) {
        EST_LOG_ERR("EST server boundary length too long");
        return (EST_ERR_BAD_CONTENT_LEN);
    }

    if (!ctx->est_server_keygen_pkcs10_cb) {
        EST_LOG_ERR("Null server-side keygen enrollment callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    if (!ctx->keygen_cb) {
        EST_LOG_ERR("Null keygen callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    /*
     * Make sure the client has sent us a PKCS10 CSR request
     */
    if ((ctx->transport_mode == EST_HTTP) &&
        (strncmp(ct, "application/pkcs10", 18))) { 
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_enroll_auth(ctx, http_ctx, ssl, path_seg, SERVERKEYGEN_REQ, body,
                            body_len, &csr)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
        /*
         * this means the user was authorized, either through
         * HTTP authorization or certificate authorization
         */
        break;
    case EST_HTTP_AUTH_PENDING:
        return_code = EST_ERR_AUTH_PENDING;
        goto free_buffers;
    case EST_CSR_PARSE_FAIL:
        return_code = EST_ERR_BAD_PKCS10;
        goto free_buffers;
    case EST_UNAUTHORIZED:
    default:
        return_code = EST_ERR_AUTH_FAIL;
        goto free_buffers;
    }

    /*
     * Parse the PKCS10 CSR from the client
     */
    if (!csr) {
        csr = est_server_parse_csr((unsigned char *)body, body_len,
                                   EST_CSR_DECODE);
        if (!csr) {
            EST_LOG_ERR("Unable to parse the Server-side Keygen req PKCS10 "
                        "CSR sent by the client");
            return_code = EST_ERR_BAD_PKCS10;
            goto free_buffers;
        }
    }

    /*
     * Generate a key pair
     */
    if (ctx->transport_mode == EST_HTTP) {
        start_timer(&keygen_timer, ctx, "HTTP keygen_cb");
    } else {
        start_timer(&keygen_timer, ctx, "CoAP keygen_cb");
    }
    rv = ctx->keygen_cb(&priv_key);
    stop_timer(&keygen_timer);

    if ((!priv_key) || rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to generate server-side key pair");
        return_code = EST_ERR_NO_KEY;
        goto free_buffers;
    }

    /*
     * Convert PEM key data to DER, then base64 encode
     */
    der_len = i2d_PrivateKey(priv_key, &der_key);
    b64der = malloc(der_len * 2);
    if (b64der == NULL) {
        EST_LOG_INFO("Unable to allocate memory");
        return_code = EST_ERR_MALLOC;
        goto free_buffers;
    }
    b64der_len = est_base64_encode((const char *) der_key, der_len, (char *) b64der, der_len * 2, 1);

    /*
     * Update the CSR
     * Set the public key on the request
     */
    if (!X509_REQ_set_pubkey(csr, priv_key)) {
        EST_LOG_ERR("Unable to set X509 public key");
        return_code = EST_ERR_BAD_PKCS10;
        goto free_buffers;
    }

    /*
     * Sign the CSR
     */
    if (!est_X509_REQ_sign(csr, priv_key, ctx->signing_digest)) {
        EST_LOG_ERR("Unable to sign X509 cert request");
        ossl_dump_ssl_errors();
        return_code = EST_ERR_X509_SIGN;
        goto free_buffers;
    }

    /*
     * Perform a sanity check on the CSR
     */
    if (est_server_check_csr(csr)) {
        EST_LOG_ERR("PKCS10 CSR sent by the client failed sanity check");
        return_code = EST_ERR_BAD_PKCS10;
        goto free_buffers;
    }
    EVP_PKEY_free(priv_key);
    priv_key = NULL;

    /*
     * Replace buf with updated CSR
     */
    body = NULL;

    /*
     * Grab the PKCS10 PEM encoded data
     */
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        EST_LOG_ERR("BIO_new failed");
        ossl_dump_ssl_errors();
        return_code = EST_ERR_MALLOC;
        goto free_buffers;
    }
    p10out = BIO_new(BIO_s_mem());
    if (!p10out) {
        EST_LOG_ERR("BIO_new failed");
        ossl_dump_ssl_errors();
        BIO_free(b64);
        return_code = EST_ERR_MALLOC;
        goto free_buffers;
    }
    p10out = BIO_push(b64, p10out);
    i2d_X509_REQ_bio(p10out, csr);
    (void)BIO_flush(p10out);
    BIO_get_mem_ptr(p10out, &new_body);
    body_len = new_body->length;
    body = new_body->data;

    if (peer_cert) {
        client_is_ra = est_check_cmcRA(peer_cert);
    }
    EST_LOG_INFO("id-kp-cmcRA present: %d", client_is_ra);

    /*
     * Do the PoP check (Proof of Possession).  The challenge password
     * in the pkcs10 request should match the TLS unique ID.
     * The PoP check is not performed when the client is an RA.
     */
    if (!client_is_ra) {
        rv = est_tls_uid_auth(ctx, ssl, csr);
        if (rv != EST_ERR_NONE) {
            return_code = EST_ERR_AUTH_FAIL_TLSUID;
            goto free_buffers;
        }
    }

    /*
     * Check if we need to ensure the client included all the
     * CSR attributes required by the CA.
     */
    if (ctx->enforce_csrattrs) {
        if (EST_ERR_NONE != est_server_all_csrattrs_present(ctx, body, body_len, peer_cert)) {
            return_code = EST_ERR_CSR_ATTR_MISSING;
            goto free_buffers;
        }
    }

    /* 
     * body now points to the pkcs10 data, pass
     * this to the enrollment routine
     */
    if (ctx->transport_mode == EST_HTTP) {
        start_timer(&enroll_timer, ctx, "HTTP est_server_keygen_pkcs10_cb");
    } else {
        start_timer(&enroll_timer, ctx, "CoAP est_server_keygen_pkcs10_cb");
    }
    rv = ctx->est_server_keygen_pkcs10_cb((unsigned char *) body, body_len,
                                          &cert, &cert_len,
                                          &b64der, &b64der_len,
                                          user_id, peer_cert,
                                          path_seg, ctx->ex_data);
    stop_timer(&enroll_timer);

    if (rv == EST_ERR_NONE && cert_len > 0) {

        if (ctx->transport_mode == EST_HTTP) {

            /*
             * Build all headers in order to calculate the correct
             * content-length
             *
             * Build the private key headers,
             * - boundary, ct, ce
             */
            snprintf(pvt_key_hdr, EST_HTTP_HDR_MAX, "--%s%s", EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(pvt_key_hdr, EST_HTTP_HDR_MAX);
            snprintf(pvt_key_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
                    EST_HTTP_CT_PKCS8, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(pvt_key_hdr, EST_HTTP_HDR_MAX);
            snprintf(pvt_key_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s%s", EST_HTTP_HDR_CE,
                    EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(pvt_key_hdr, EST_HTTP_HDR_MAX);
            pvt_key_hdr_len = hdrlen;

            /*
             * Build the certificate headers
             * - boundary, ct, ce
             */
            snprintf(cert_hdr, EST_HTTP_HDR_MAX, "%s--%s%s", EST_HTTP_HDR_EOL, EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(cert_hdr, EST_HTTP_HDR_MAX);
            snprintf(cert_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
                    EST_HTTP_CT_PKCS7_CO, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(cert_hdr, EST_HTTP_HDR_MAX);
            snprintf(cert_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s%s", EST_HTTP_HDR_CE,
                    EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(cert_hdr, EST_HTTP_HDR_MAX);
            cert_hdr_len = hdrlen;

            /*
             * build the final boundary for multipart/mixed content-types
             */
            snprintf(final_bndry_hdr, EST_HTTP_HDR_MAX, "%s--%s--%s%s",
                     EST_HTTP_HDR_EOL, EST_HTTP_BOUNDARY, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(final_bndry_hdr, EST_HTTP_HDR_MAX);
            final_bndry_hdr_len = hdrlen;

            /*
             * Lastly, build the general HTTP headers now that we know the
             * total length of the content
             */
            snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
                    EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
            snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s; boundary=%s%s", EST_HTTP_HDR_CT,
                    EST_HTTP_CT_MULTI_MIXED, EST_HTTP_BOUNDARY,EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
            snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
                    pvt_key_hdr_len+b64der_len + cert_hdr_len+cert_len + final_bndry_hdr_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
            hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);

            /*
             * Now send everything in the proper order
             * - HTTP headers
             * - pvt key hdrs
             * - pvt key
             * - cert_hdrs
             * - cert
             * - final boundary header
             */
            if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }

            /*
             * pvt key headers and the pvt key
             */
            if (!mg_write(http_ctx, pvt_key_hdr, strnlen_s(pvt_key_hdr, EST_HTTP_HDR_MAX))) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }
            if (!mg_write(http_ctx, b64der, b64der_len)) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }

            /*
             * cert headers and the cert
             */
            if (!mg_write(http_ctx, cert_hdr, strnlen_s(cert_hdr, EST_HTTP_HDR_MAX))) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }
            if (!mg_write(http_ctx, cert, cert_len)) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }

            /*
             * Final boundary header
             */
            if (!mg_write(http_ctx, final_bndry_hdr, strnlen_s(final_bndry_hdr, EST_HTTP_HDR_MAX))) {
                return_code = EST_ERR_HTTP_WRITE;
                goto free_buffers;
            }

        } else if (ctx->transport_mode != EST_COAP) {
            EST_LOG_ERR("EST in improper transport mode. Cannot propogate server retry to client.");
            return_code = EST_ERR_BAD_MODE;
            goto free_buffers;
        }
        /* Return the cert and key no matter what transport mode */
        *returned_cert = cert;
        *returned_cert_len = cert_len;
        *returned_key = b64der;
        *returned_key_len = b64der_len;

    } else if (rv == EST_ERR_CA_ENROLL_RETRY) {
        /*
         * The CA did not sign the request and has asked the
         * client to retry in the future.  This may occur if
         * the CA is not configured for automatic enrollment.
         * Send the HTTP retry response to the client.
         */
        EST_LOG_INFO("CA server requests retry, possibly it's not setup for auto-enroll");
        return_code = EST_ERR_CA_ENROLL_RETRY;
        goto free_buffers;
    } else {
        return_code = EST_ERR_CA_ENROLL_FAIL;
        goto free_buffers;
    }
    return_code = EST_ERR_NONE;

    free_buffers:
    if (return_code != EST_ERR_NONE && cert) {
        free(cert);
    }
    if (csr) X509_REQ_free(csr);
    if (p10out) BIO_free_all(p10out);
    if (priv_key) EVP_PKEY_free(priv_key);
    if (return_code != EST_ERR_NONE && b64der) {
        memzero_s(b64der, b64der_len);
        free(b64der);
    }
    if (der_key) {
        memzero_s(der_key, der_len);
        free(der_key);
    }

    return (return_code);
}

/*
 * This function is used by the server to process an incoming
 * csr attributes request from the client.
 */
int est_handle_csr_attrs (EST_CTX *ctx, void *http_ctx, SSL *ssl, X509 *peer_cert,
                          char *path_seg, unsigned char **returned_attrs,
                          int *returned_attrs_len)
{
    int rv = EST_ERR_NONE;
    int pop_present;
    char *csr_data, *csr_data_pop;
    int csr_len, csr_pop_len;

    if (!ctx->server_csrattrs && !ctx->est_get_csr_cb) {
        if (!ctx->server_enable_pop) {
  	        EST_LOG_ERR("Null csr callback");
            return (EST_ERR_HTTP_NO_CONTENT);
        } else {
            csr_data = malloc(EST_CSRATTRS_POP_LEN + 1);
            if (!csr_data) {
                EST_LOG_ERR("Could not malloc csr_data with PoP info");
                return (EST_ERR_MALLOC);
            }
            strcpy_s(csr_data, EST_CSRATTRS_POP_LEN + 1, EST_CSRATTRS_POP);
            csr_data[EST_CSRATTRS_POP_LEN] = 0;
            csr_len = EST_CSRATTRS_POP_LEN;
            /* send the csr attrs back to the client */
            if (ctx->transport_mode == EST_HTTP) {
                return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
            } else if (ctx->transport_mode == EST_COAP) {
                *returned_attrs = (unsigned char *)csr_data;
                *returned_attrs_len = csr_len;
                return (EST_ERR_NONE);
            } else {
                EST_LOG_ERR("EST in improper transport mode. "
                            "Cannot retrieve csr attrs.");
                return (EST_ERR_BAD_MODE);
            }
        }
    }

    /*
     * Invoke CA server callback to retrieve the CSR.  Callback takes priority
     * over saved values in the context.
     * Note: there is no need to authenticate the client (see sec 4.5)
     */
    if (ctx->est_get_csr_cb) {
        csr_data = (char *)ctx->est_get_csr_cb(&csr_len, path_seg, peer_cert, ctx->ex_data);
        rv = est_asn1_parse_attributes(csr_data, csr_len, &pop_present);
        if (csr_len && (rv != EST_ERR_NONE)) {
            if (csr_data) {
                free(csr_data);
                csr_data = NULL;
            }
            EST_LOG_ERR("Cannot parse csr attrs.");
            return rv;
        }
        
        ctx->csr_pop_present = 0;
        if (ctx->server_enable_pop) {
            rv = est_is_challengePassword_present(csr_data, csr_len, &pop_present);
            if (rv != EST_ERR_NONE) {
                if (csr_data) {
                    free(csr_data);
                    csr_data = NULL;
                }
                EST_LOG_ERR("Error during PoP/sanity check");
                return rv;
            }
            ctx->csr_pop_present = pop_present;

            if (!ctx->csr_pop_present) {
                if (csr_len == 0) {
                    csr_data = malloc(EST_CSRATTRS_POP_LEN + 1);
                    if (!csr_data) {
                        EST_LOG_ERR("Could not malloc csr_data");
                        return (EST_ERR_MALLOC);
                    }
                    strcpy_s(csr_data, EST_CSRATTRS_POP_LEN + 1, EST_CSRATTRS_POP);
                    csr_data[EST_CSRATTRS_POP_LEN] = 0;
                    csr_len = EST_CSRATTRS_POP_LEN;
                    /* send the csr attrs back to the client */
                    if (ctx->transport_mode == EST_HTTP) {
                        return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
                    } else if (ctx->transport_mode == EST_COAP) {
                        *returned_attrs = (unsigned char *)csr_data;
                        *returned_attrs_len = csr_len;
                        return (EST_ERR_NONE);
                    } else {
                        EST_LOG_ERR("EST in improper transport mode. "
                                    "Cannot retrieve csr attrs.");
                        return (EST_ERR_BAD_MODE);
                    }
                }
                rv = est_add_challengePassword(csr_data, csr_len, &csr_data_pop, &csr_pop_len);
                if (rv != EST_ERR_NONE) {
                    if (csr_data) {
                        free(csr_data);
                        csr_data = NULL;
                    }
                    EST_LOG_ERR("Error during add PoP");
                    return rv;
                }
                free(csr_data);
                csr_data = csr_data_pop;
                csr_len = csr_pop_len;
            }
        }
    } else {
        csr_data = malloc(ctx->server_csrattrs_len + 1);
        if (!csr_data) {
            EST_LOG_ERR("Could not malloc csr_data using est context info");
            return (EST_ERR_MALLOC);
        }
        strcpy_s(csr_data, ctx->server_csrattrs_len + 1, (char *)ctx->server_csrattrs);
        csr_data[ctx->server_csrattrs_len] = 0;
        csr_len = ctx->server_csrattrs_len;
    }
    /* send the csr attrs back to the client */
    if (ctx->transport_mode == EST_HTTP) {
        return (est_send_csrattr_data(ctx, csr_data, csr_len, http_ctx));
    } else if (ctx->transport_mode == EST_COAP) {
        *returned_attrs = (unsigned char *)csr_data;
        *returned_attrs_len = csr_len;
        return (EST_ERR_NONE);
    } else {
        EST_LOG_ERR("EST in improper transport mode. "
                    "Cannot retrieve csr attrs.");
        return (EST_ERR_BAD_MODE);
    }
}

#if ENABLE_BRSKI
/*
 * This function is used by the server to process an incoming
 * voucher request
 */
static EST_ERROR est_brski_handle_voucher_req (EST_CTX *ctx, void *http_ctx, SSL *ssl,
                                               const char *ct, char *body, int body_len,
                                               char *path_seg)
{
    EST_BRSKI_CALLBACK_RC rv;
    char http_hdr[EST_HTTP_HDR_MAX];
    int hdrlen;
    X509 *peer_cert = NULL;
    char *voucher = NULL;
    int voucher_len = 0;

    if (!ctx->est_brski_voucher_req_cb) {
	EST_LOG_ERR("Null voucher request callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    /*
     * Make sure the client has sent the correct content type for a voucher request
     */
    if ((strncmp(ct, EST_BRSKI_CT_VREQ_SIGNED, sizeof(EST_BRSKI_CT_VREQ_SIGNED))) &&
        (strncmp(ct, EST_BRSKI_CT_VREQ, sizeof(EST_BRSKI_CT_VREQ)))) {
	EST_LOG_ERR("Voucher request contains incorrect Content Type");
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_brski_auth(ctx, http_ctx, ssl, path_seg)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
	/*
	 * this means the user was authorized, either through
	 * HTTP authorization or certificate authorization
	 */
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
     * Get the peer certificate if available.  This
     * identifies the client. The CA may desire
     * this information.
     */
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_WARN("No Client certificate provided");
    }

    /* body now points to the voucher request, pass this to the application's
     * voucher request callback
     */
    rv = ctx->est_brski_voucher_req_cb(body, body_len, &voucher, &voucher_len,
                                       peer_cert);

    /*
     * Peer cert is no longer needed, delete it if we have one
     */
    if (peer_cert) {
        X509_free(peer_cert);
    }

    if (rv == EST_BRSKI_CB_SUCCESS && voucher_len > 0) {
        /*
         * Send HTTP header
         */
        snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
                 EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
        hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CT,
                 EST_BRSKI_CT_VRSP, EST_HTTP_HDR_EOL);
        hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %s%s", EST_HTTP_HDR_CE,
                 EST_HTTP_CE_BASE64, EST_HTTP_HDR_EOL);
        hdrlen = strnlen_s(http_hdr, EST_HTTP_HDR_MAX);
        snprintf(http_hdr + hdrlen, EST_HTTP_HDR_MAX, "%s: %d%s%s", EST_HTTP_HDR_CL,
                 voucher_len, EST_HTTP_HDR_EOL, EST_HTTP_HDR_EOL);
        if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
            free(voucher);
            return (EST_ERR_HTTP_WRITE);
        }
        /*
         * Send the signed PKCS7 certificate in the body
         */
        if (!mg_write(http_ctx, voucher, voucher_len)) {
            free(voucher);
            ossl_dump_ssl_errors();            
            return (EST_ERR_HTTP_WRITE);
        }
    } else if (rv == EST_BRSKI_CB_RETRY) {

        EST_LOG_ERR("EST server: BRSKI: Registrar application layer indicates that a retry-after is required");
        /*
         * The registrar did not provide the voucher at this time, but instead
         * indicated that a retry-after should be sent in response.  This may
         * occur if the application layer registrar logic cannot provide the
         * voucher within a set time frame.  Send the HTTP retry response to
         * the client.
         */
        if (EST_ERR_NONE != est_server_send_http_retry_after(ctx, http_ctx, ctx->brski_retry_period)) { 
            return (EST_ERR_HTTP_WRITE);
        }
        
    } else {
        if (rv == EST_BRSKI_CB_INVALID_PARAMETER) {
            /*
             * Application claims we sent a bad parameter.
             */
            EST_LOG_ERR("Invalid parameter on get voucher callback");
        }
        if (voucher) {
            free(voucher);
        }   
        return (EST_ERR_CA_ENROLL_FAIL);
    }
    if (voucher) {
        free(voucher);
    }
    return (EST_ERR_NONE);
}

/*
 * This function is used by the server to process an incoming
 * voucher status
 */
static EST_ERROR est_brski_handle_voucher_status (EST_CTX *ctx, void *http_ctx, SSL *ssl,
                                                  const char *ct, char *body, int body_len,
                                                  char *path_seg)
{
    EST_BRSKI_CALLBACK_RC rv;
    char http_hdr[EST_HTTP_HDR_MAX];
    X509 *peer_cert;

    if (!ctx->est_brski_voucher_status_cb) {
	EST_LOG_ERR("Null voucher status callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    /*
     * Make sure the client has sent the correct content type for a voucher request
     */
    if (strncmp(ct, EST_BRSKI_CT_STATUS, sizeof(EST_BRSKI_CT_STATUS))) {
	EST_LOG_ERR("Voucher request contains incorrect Content Type");
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_brski_auth(ctx, http_ctx, ssl, path_seg)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
	/*
	 * this means the user was authorized, either through
	 * HTTP authorization or certificate authorization
	 */
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
     * Get the peer certificate if available.  This
     * identifies the client. The CA may desire
     * this information.
     */
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_WARN("No Client certificate provided");
    }

    /* body now points to the voucher status, pass this to the application's
     * voucher status callback
     */
    rv = ctx->est_brski_voucher_status_cb(body, body_len, peer_cert);
    
    /*
     * Peer cert is no longer needed, delete it if we have one
     */
    if (peer_cert) {
        X509_free(peer_cert);
    }

    if (rv == EST_BRSKI_CB_SUCCESS) {
        /*
         * Send HTTP header
         */
        snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
                 EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
        if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
            return (EST_ERR_HTTP_WRITE);
        }
    } else {
        if (rv == EST_BRSKI_CB_INVALID_PARAMETER) {
            /*
             * Application claims we sent a bad parameter.
             */
            EST_LOG_ERR("Invalid parameter on get voucher callback");
        }
        return (EST_ERR_CA_ENROLL_FAIL);
    }
    return (EST_ERR_NONE);
}

/*
 * PDB NOTE:  Once testing is about complete, if this is still effectively
 * identical to voucher_status then merge them and pass in the op code
 *
 * This function is used by the server to process an incoming
 * enroll status
 */
static EST_ERROR est_brski_handle_enroll_status (EST_CTX *ctx, void *http_ctx, SSL *ssl,
                                                 const char *ct, char *body, int body_len,
                                                 char *path_seg)
{
    EST_BRSKI_CALLBACK_RC rv;
    char http_hdr[EST_HTTP_HDR_MAX];
    X509 *peer_cert;

    if (!ctx->est_brski_enroll_status_cb) {
	EST_LOG_ERR("Null enroll status callback");
        return (EST_ERR_NULL_CALLBACK);
    }

    /*
     * Make sure the client has sent the correct content type for a voucher request
     */
    if (strncmp(ct, EST_BRSKI_CT_STATUS, sizeof(EST_BRSKI_CT_STATUS))) {
	EST_LOG_ERR("Voucher request contains incorrect Content Type");
        return (EST_ERR_BAD_CONTENT_TYPE);
    }

    /*
     * Authenticate the client
     */
    switch (est_brski_auth(ctx, http_ctx, ssl, path_seg)) {
    case EST_HTTP_AUTH:
    case EST_SRP_AUTH:
    case EST_CERT_AUTH:
	/*
	 * this means the user was authorized, either through
	 * HTTP authorization or certificate authorization
	 */
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
     * Get the peer certificate if available.  This
     * identifies the client. The CA may desire
     * this information.
     */
    peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        EST_LOG_WARN("No Client certificate provided");
    }

    /* body now points to the voucher status, pass this to the application's
     * voucher status callback
     */
    rv = ctx->est_brski_enroll_status_cb(body, body_len, peer_cert);
    
    /*
     * Peer cert is no longer needed, delete it if we have one
     */
    if (peer_cert) {
        X509_free(peer_cert);
    }

    if (rv == EST_BRSKI_CB_SUCCESS) {
        /*
         * Send HTTP header
         */
        snprintf(http_hdr, EST_HTTP_HDR_MAX, "%s%s%s%s", EST_HTTP_HDR_200_RESP, EST_HTTP_HDR_EOL,
                 EST_HTTP_HDR_STAT_200, EST_HTTP_HDR_EOL);
        if (!mg_write(http_ctx, http_hdr, strnlen_s(http_hdr, EST_HTTP_HDR_MAX))) {
            return (EST_ERR_HTTP_WRITE);
        }
    } else {
        if (rv == EST_BRSKI_CB_INVALID_PARAMETER) {
            /*
             * Application claims we sent a bad parameter.
             */
            EST_LOG_ERR("EST server: BRSKI: Invalid parameter on get voucher callback");
        }
        return (EST_ERR_CA_ENROLL_FAIL);
    }
    return (EST_ERR_NONE);
}
#endif


/*
 * This function should be called by the web server layer when
 * a HTTP request arrives on the listening port of the EST server.
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
int est_http_request (EST_CTX *ctx, void *http_ctx,
                      char *method, char *uri,
                      char *body, int body_len, const char *ct)
{
    SSL *ssl;
    int rc;
    int event_rc;
    EST_OPERATION operation;
    char *path_seg;
    EST_ERROR rv = EST_ERR_NONE;
    EST_ENROLL_REQ_TYPE enroll_req;
    X509 *peer_cert = NULL;
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
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a server, not a client
     */
    if (ctx->est_mode != EST_SERVER) {
        return (EST_ERR_BAD_MODE);
    }

    /*
     * Get the SSL context, which is required for authenticating
     * the client.
     */
    ssl = (SSL*)mg_get_conn_ssl(http_ctx);
    if (!ssl) {
        est_send_http_error(ctx, http_ctx, EST_ERR_NO_SSL_CTX);
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
                "HTTP est_invoke_endpoint_req_event_cb REQ_START");
    est_invoke_endpoint_req_event_cb(ctx, peer_cert, ssl, NULL,
                                     (const char *)uri, EST_ENDPOINT_REQ_START);
    /*
     * Get the PID to identify the thread this request is being handled by when
     * performance timers are enabled.
     */
    if (ctx->perf_timers_enabled) {
        proc_pid = GETPID();
        snprintf(pid_str, MAX_PID_STR_LEN + 1, "%ld", (unsigned long)proc_pid);
    }
    stop_timer_with_id(&event_cb_timer, pid_str);
    rv = est_parse_uri(uri, &operation, (char **)&path_seg);
    if (rv != EST_ERR_NONE) {
        est_send_http_error(ctx, http_ctx, rv);
        X509_free(peer_cert);
        return (rv);
    }
    start_http_req_timer(&http_req_timer, ctx, operation);
    /*
     * See if this is a cacerts request
     */
    if (operation == EST_OP_CACERTS) {
        /* Only GET is allowed */
        if (strncmp(method, "GET", 3)) {
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        rc = est_server_handle_cacerts(ctx, http_ctx, path_seg);
        if (rc != EST_ERR_NONE) {
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (rc);
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * See if this is a simple enrollment request
     */
    else if (operation == EST_OP_SIMPLE_ENROLL ||
             operation == EST_OP_SIMPLE_REENROLL ||
             operation == EST_OP_SERVER_KEYGEN) {
        /* Only POST is allowed */
        if (strncmp(method, "POST", 4)) {
            EST_LOG_WARN("Incoming HTTP request used wrong method\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_CONTENT_TYPE);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_BAD_CONTENT_TYPE);
        }

        if (operation == EST_OP_SERVER_KEYGEN) {
            /*
             * Announce an EST Enroll or Re-Enroll CSR request is taking
             * place now.
             */
            enroll_req = SERVERKEYGEN_REQ;
            if (ctx->enroll_req_event_cb != NULL) {
                start_timer(
                    &event_cb_timer, ctx,
                    "HTTP est_invoke_enroll_req_event_cb SERVERKEYGEN_REQ");
                event_rc = est_invoke_enroll_req_event_cb(ctx, ssl, peer_cert,
                                                          (unsigned char *)body, body_len,
                                                          NULL, path_seg, enroll_req);
                stop_timer_with_id(&event_cb_timer, pid_str);
                if (event_rc != EST_ERR_NONE) {
                    EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
                }
            }      

            rc = est_handle_server_keygen(ctx, http_ctx, ssl, peer_cert,
                                          ct, body, body_len,
                                          path_seg, &returned_cert, &returned_cert_len,
                                          &returned_key, &returned_key_len);


            EST_LOG_INFO("handle server keygen enrollment finished with rc=%d (%s)\n",
                         rc, EST_ERR_NUM_TO_STR(rc));

            /*
             * Announce the response event for this request.
             */
            if (ctx->enroll_rsp_event_cb != NULL) {
                start_timer(
                    &event_cb_timer, ctx,
                    "HTTP est_invoke_enroll_rsp_event_cb SERVERKEYGEN_REQ");
                event_rc = est_invoke_enroll_rsp_event_cb(ctx, ssl, peer_cert,
                                                          (unsigned char *)body, body_len,
                                                          NULL, path_seg, enroll_req,
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
            if (rc == EST_ERR_NONE) {
                free(returned_cert);
                memzero_s(returned_key, returned_key_len);
                free(returned_key);
            }
            
        } else {

            /*
             * At this point, the operation must be an enroll or a re-enroll.
             */
            if (operation == EST_OP_SIMPLE_REENROLL) {
                enroll_req = REENROLL_REQ;
            } else {
                enroll_req = SIMPLE_ENROLL_REQ;
            }

            /*
             * Announce an EST Enroll or Re-Enroll CSR request is taking
             * place now.
             */
            if (ctx->enroll_req_event_cb != NULL) {
                if (enroll_req == REENROLL_REQ) {
                    start_timer(
                        &event_cb_timer, ctx,
                        "HTTP est_invoke_enroll_req_event_cb REENROLL_REQ");
                } else {
                    start_timer(&event_cb_timer, ctx,
                                "HTTP est_invoke_enroll_req_event_cb "
                                "SIMPLE_ENROLL_REQ");
                }
                event_rc = est_invoke_enroll_req_event_cb(ctx, ssl, peer_cert,
                                                          (unsigned char *)body, body_len,
                                                          NULL, path_seg, enroll_req);
                stop_timer_with_id(&event_cb_timer, pid_str);
                if (event_rc != EST_ERR_NONE) {
                    EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
                }
            }            
            
            rc = est_handle_simple_enroll(ctx, http_ctx, ssl, peer_cert,
                                          ct, body, body_len, path_seg,
                                          enroll_req, &returned_cert, &returned_cert_len);
            /*
             * Announce the response event for this request.
             */
            if (ctx->enroll_rsp_event_cb != NULL) {
                if (enroll_req == REENROLL_REQ) {
                    start_timer(
                        &event_cb_timer, ctx,
                        "HTTP est_invoke_enroll_rsp_event_cb REENROLL_REQ");
                } else {
                    start_timer(&event_cb_timer, ctx,
                                "HTTP est_invoke_enroll_rsp_event_cb "
                                "SIMPLE_ENROLL_REQ");
                }
                event_rc = est_invoke_enroll_rsp_event_cb(ctx, ssl, peer_cert,
                                                          (unsigned char *)body, body_len,
                                                          NULL, path_seg, enroll_req,
                                                          returned_cert, returned_cert_len, rc);
                stop_timer_with_id(&event_cb_timer, pid_str);
                if (event_rc != EST_ERR_NONE) {
                    EST_LOG_WARN("Unable to successfully invoke event notification callback\n");
                }
            }
            free(returned_cert);

        }
        if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING) {
            EST_LOG_WARN("Enrollment failed with rc=%d (%s)\n", 
		         rc, EST_ERR_NUM_TO_STR(rc));
            est_send_http_error(ctx, http_ctx, rc);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return rc;
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }

    /*
     * See if this is a CSR attributes request
     */
    else if (operation == EST_OP_CSRATTRS) {
        /* Only GET is allowed */
        if (strncmp(method, "GET", 4)) {
            EST_LOG_WARN("Incoming HTTP request used wrong method\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (EST_ERR_WRONG_METHOD);
        }
        
        rc = est_handle_csr_attrs(ctx, http_ctx, ssl, peer_cert, path_seg, NULL, 0);
        if (rc != EST_ERR_NONE) {
            est_send_http_error(ctx, http_ctx, rc); 
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            stop_timer_with_id(&http_req_timer, pid_str);
            return (rc);
        }
        stop_timer_with_id(&http_req_timer, pid_str);
    }
#if ENABLE_BRSKI
    /*
     * voucher request, voucher status, enroll status
     */
    else if (operation == EST_OP_BRSKI_REQ_VOUCHER    ||
             operation == EST_OP_BRSKI_VOUCHER_STATUS ||
             operation == EST_OP_BRSKI_ENROLL_STATUS) {
        /* POST is referenced in draft so make sure it's POST */
        if (strncmp(method, "POST", 4)) {
            EST_LOG_WARN("Incoming HTTP request used wrong method\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_WRONG_METHOD);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            return (EST_ERR_WRONG_METHOD);
        }
	if (!ct) {
            EST_LOG_WARN("Incoming HTTP header has no Content-Type header\n");
            est_send_http_error(ctx, http_ctx, EST_ERR_BAD_CONTENT_TYPE);
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
	    return (EST_ERR_BAD_CONTENT_TYPE); 
	}

        switch (operation) {
        case EST_OP_BRSKI_REQ_VOUCHER: 
            rc = est_brski_handle_voucher_req(ctx, http_ctx, ssl, ct,
                                              body, body_len,
                                              path_seg);
            break;
        case EST_OP_BRSKI_VOUCHER_STATUS:
            rc = est_brski_handle_voucher_status(ctx, http_ctx, ssl, ct,
                                                 body, body_len,
                                                 path_seg);
            break;
        case EST_OP_BRSKI_ENROLL_STATUS:
            rc = est_brski_handle_enroll_status(ctx, http_ctx, ssl, ct,
                                                body, body_len,
                                                path_seg);
            break;
        default:
            /*
             * We're here because operation was one of the above three, so
             * this should never happen.
             */
            EST_LOG_WARN("BRSKI request processing, invalid path\n");
            rc = EST_ERR_HTTP_NOT_FOUND;
        }
        
        if (rc != EST_ERR_NONE && rc != EST_ERR_AUTH_PENDING) {
            EST_LOG_WARN("Voucher request failed with rc=%d (%s)\n", 
		         rc, EST_ERR_NUM_TO_STR(rc));
	    if (rc == EST_ERR_AUTH_FAIL) {
		    est_send_http_error(ctx, http_ctx, EST_ERR_AUTH_FAIL);
	    } else {
		    est_send_http_error(ctx, http_ctx, EST_ERR_BAD_PKCS10);
	    }
            free(path_seg);
            path_seg = NULL;
            X509_free(peer_cert);
            peer_cert = NULL;
            return rc;
        }
    }
#endif // BRSKI
    /*
     * Send a 500 error if we got to this state, since
     * we already checked if the path legitimate 
     */
    else {
        est_send_http_error(ctx, http_ctx, EST_ERR_UNKNOWN);
    }

    /*
     * Announce the end of the EST endpoint request event.
     */
    start_timer(&event_cb_timer, ctx,
                "HTTP est_invoke_endpoint_req_event_cb REQ_END");
    est_invoke_endpoint_req_event_cb(ctx, peer_cert, ssl, NULL,
                                     (const char *)uri, EST_ENDPOINT_REQ_END);
    stop_timer_with_id(&event_cb_timer, pid_str);
    
    if (peer_cert) {
        X509_free(peer_cert);
        peer_cert = NULL;
    }
    
    free(path_seg);
    path_seg = NULL;
    return (EST_ERR_NONE);
}


/*! @brief est_server_start() is used by an application to start
    the EST server after est_server_init() has been called and
    all the required callback functions have been provided by
    the application.   
 
    @param ctx Pointer to the EST context

    libest uses HTTP code from the Mongoose HTTP server.
    This function allows the application to start the HTTP
    services layer, which is required by EST.
 
    @return EST_ERROR.
 */
EST_ERROR est_server_start (EST_CTX *ctx)
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


/*! @brief est_server_stop() is used by an application to stop
    the EST server.  This should be called prior to est_destroy().
 
    @param ctx Pointer to the EST context

    libest uses HTTP code from the Mongoose HTTP server.
    This function allows the application to stop the HTTP
    services layer.
 
    @return EST_ERROR.
 */
EST_ERROR est_server_stop (EST_CTX *ctx)
{
    EST_MG_CONTEXT *mgctx;

    if (!ctx) {
	EST_LOG_ERR("Null context");
	return (EST_ERR_NO_CTX);
    }

    if (ctx->transport_mode == EST_HTTP) {
        mgctx = (EST_MG_CONTEXT*)ctx->mg_ctx;
        if (mgctx) {
            mg_stop(mgctx);
        }
    } else if (ctx->transport_mode == EST_COAP) {
#if HAVE_LIBCOAP        
        coap_context_t *coap_ctx = ctx->coap_ctx;
        coap_free_context(coap_ctx);
        ctx->coap_ctx = NULL;
#endif
    } else {
        EST_LOG_ERR("Invalid transport mode while attempting to stop server mode");
        return (EST_ERR_BAD_MODE);
    }        
    
    return (EST_ERR_NONE);
}

/*! @brief est_server_init() is used by an application to create
    a context in the EST library when operating as an EST server that
    fronts a CA.  This context is used when invoking other functions in the API.
 
    @param ca_chain     Char array containing PEM encoded CA certs & CRL entries 
    @param ca_chain_len Length of ca_chain char array 
    @param cacerts_resp_chain Char array containing PEM encoded CA certs to include
                              in the /cacerts response
    @param cacerts_resp_chain_len Length of cacerts_resp_chain char array
    @param cert_format Specifies the encoding of the local and external
                       certificate chains (PEM/DER).  
    @param http_realm Char array containing HTTP realm name for HTTP auth
    @param tls_id_cert Pointer to X509 that contains the server's certificate
                    for the TLS layer.
    @param tls_id_key Pointer to EVP_PKEY that contains the private key
                   associated with the server's certificate.

    This function allows an application to initialize an EST server context
    that is used with a CA (not an RA).
    The application must provide the trusted CA certificates to use
    for server operation using the ca_chain parameter.  This certificate
    set should include the explicit trust anchor certificate, any number
    of implicit trust anchor certificates, and any intermediate sub-CA
    certificates required to complete the chain of trust between the
    identity certificate passed into the tls_id_cert parameter and the
    root certificate for that identity certificate.  
    The CA certificates should be encoded using
    the format specified in the cert_format parameter (e.g. PEM) and
    may contain CRL entries that will be used when authenticating
    EST clients connecting to the server.  
    The applications must also provide the HTTP realm to use for 
    HTTP authentication and the server certificate/private key to use
    for the TLS stack to identify the server.
    
    Warning: Including additional intermediate sub-CA certificates that are
             not needed to complete the chain of trust may result in a
	     potential MITM attack.  
 
    @return EST_CTX.
 */
EST_CTX * est_server_init (unsigned char *ca_chain, int ca_chain_len,
                           unsigned char *cacerts_resp_chain, int cacerts_resp_chain_len,
			   EST_CERT_FORMAT cert_format,
                           char *http_realm, 
			   X509 *tls_id_cert, EVP_PKEY *tls_id_key)
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
    if (cert_format != EST_CERT_FORMAT_PEM) {
        EST_LOG_ERR("Only PEM encoding of certificate changes is supported.");
        return NULL;
    }

    /* 
     * Check the length value, it should match.
     */
    len = (int) strnlen_s((char *)ca_chain, EST_CA_MAX);
    if (len != ca_chain_len) {
	EST_LOG_ERR("Length of ca_chain doesn't match ca_chain_len");
        return NULL;
    }
    if (cacerts_resp_chain) {        
        len = (int) strnlen_s((char *)cacerts_resp_chain, EST_CA_MAX);
        if (len != cacerts_resp_chain_len) {
            EST_LOG_ERR("Actual length of cacerts_resp_chain does not match "
                        "passed in length value");
            return NULL;
        }
    }

    if (tls_id_cert == NULL) {
        EST_LOG_ERR("TLS identity cert is empty");
        return NULL;
    }

    if (tls_id_key == NULL) {
        EST_LOG_ERR("Private key associated with TLS identity cert is empty");
        return NULL;
    }
    if (http_realm == NULL) {
        EST_LOG_ERR("EST HTTP realm is NULL");
        return NULL;
    }

    ctx = malloc(sizeof(EST_CTX));
    if (!ctx) {
        EST_LOG_ERR("malloc failed");
        return NULL;
    }
    memzero_s(ctx, sizeof(EST_CTX));
    ctx->est_mode = EST_SERVER;
    ctx->retry_period = EST_RETRY_PERIOD_DEF;
    ctx->require_http_auth = HTTP_AUTH_REQUIRED;
    ctx->server_read_timeout = EST_SSL_READ_TIMEOUT_DEF;
    
    ctx->brski_retry_period = EST_BRSKI_RETRY_PERIOD_DEF;
    /*
     * Load the CA certificates into local memory and retain
     * for future use.  This will be used for /cacerts requests.
     * They are optional parameters.  The alternative is for the
     * app layer to provide a callback and return them on the fly.
     */
    if (cacerts_resp_chain) {   
        if (est_load_ca_certs(ctx, cacerts_resp_chain, cacerts_resp_chain_len)) {
            EST_LOG_ERR("Failed to load CA certificates response buffer");
            free(ctx);
            return NULL;
        }
    }
    if (est_load_trusted_certs(ctx, ca_chain, ca_chain_len)) {  
        EST_LOG_ERR("Failed to load trusted certificate store");
        free(ctx);
        return NULL;
    }

    strcpy_s(ctx->realm, MAX_REALM, http_realm);
    ctx->server_cert = tls_id_cert;
    ctx->server_priv_key = tls_id_key;
    ctx->auth_mode = AUTH_BASIC;
    ctx->server_enable_pop = 1;
    ctx->local_cacerts_processing = 1;

    /* 
     * Create a new ASN object for the id-kp-cmcRA OID.  
     * OpenSSL doesn't define this, so we need to create it
     * ourselves.
     * http://www.openssl.org/docs/crypto/OBJ_nid2obj.html
     */
    if (!o_cmcRA) {
	o_cmcRA = OBJ_txt2obj("1.3.6.1.5.5.7.3.28", 1);
	if (!o_cmcRA) {
	    EST_LOG_WARN("Failed to create OID for id-kp-cmcRA key usage checks");
	}
    }

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

/*! @brief est_server_set_auth_mode() is used by an application to configure
    the HTTP authentication method to use for validating the identity of
    an EST client.
 
    @param ctx   Pointer to the EST context
    @param amode Must be one of the following: AUTH_BASIC, AUTH_DIGEST, AUTH_TOKEN

    This function can optionally be invoked by the application to change the
    default HTTP authentication mode.  The default mode is HTTP Basic
    authentication.  An application may desire to use Digest or Token
    authentication instead, in which case this function can be used to set
    that mode.  This function must be invoked prior to starting the EST
    server.

    @return EST_ERROR.
 */
EST_ERROR est_server_set_auth_mode (EST_CTX *ctx, EST_HTTP_AUTH_MODE amode)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    switch (amode) {
    case AUTH_DIGEST:
        /*
         * Since HTTP digest auth uses MD5, make sure we're not in FIPS mode.
         */
	if (FIPS_mode()) {
	    EST_LOG_ERR("HTTP digest auth not allowed while in FIPS mode");
	    return (EST_ERR_BAD_MODE);
	}
        /* fallthrough */
    case AUTH_BASIC:        
    case AUTH_TOKEN:        
	ctx->auth_mode = amode;
	return (EST_ERR_NONE);
	break;
    default:
        EST_LOG_ERR("Unsupported HTTP authentication mode, only Basic, Digest and Token allowed");
	return (EST_ERR_BAD_MODE);
	break;
    }
}

/*! @brief est_set_ca_enroll_cb() is used by an application to install
    a handler for signing incoming PKCS10 requests.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

        int func(unsigned char*, int, unsigned char**, int*, char*, X509*, char *, void *);

    This function is called by libest when a certificate request
    needs to be signed by the CA server.  The application will need
    to forward the request to the signing authority and return
    the response.  The response should be a PKCS7 signed certificate.
 
    @return EST_ERROR.
 */
EST_ERROR est_set_ca_enroll_cb (EST_CTX *ctx, int (*cb)(unsigned char *pkcs10, int p10_len,
                                                        unsigned char **pkcs7, int *pkcs7_len,
                                                        char *user_id, X509 *peer_cert,
                                                        char *path_seg, void *ex_data))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->est_enroll_pkcs10_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_ca_reenroll_cb() is used by an application to install
    a handler for re-enrolling certificates.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

        int func(unsigned char*, int, unsigned char**, int*, char*, X509*)

    This function is called by libest when a certificate 
    needs to be renewed by the CA server.  The application will need
    to forward the request to the signing authority and return
    the response.  The response should be a PKCS7 signed certificate.
 
    @return EST_ERROR.
 */
EST_ERROR est_set_ca_reenroll_cb (EST_CTX *ctx, int (*cb)(unsigned char *pkcs10, int p10_len,
                                                          unsigned char **pkcs7, int *pkcs7_len,
                                                          char *user_id, X509 *peer_cert,
                                                          char *path_seg, void *ex_data))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->est_reenroll_pkcs10_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_srvr_side_keygen_enroll_cb() is used by an application to install
    a handler for signing incoming PKCS10 requests.

    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

        int func (unsigned char *, int, unsigned char **, int *, unsigned char **,
                  int *, char *, X509 *, char *, void *)

    This function is called by libEST when a server keygen request had been
    made to the server server.  The application will generate a key via this callback

    @return EST_ERROR.
 */
EST_ERROR est_set_server_side_keygen_enroll_cb (EST_CTX *ctx, int (*cb)(unsigned char *pkcs10, int p10_len,
                                                        unsigned char **pkcs7, int *pkcs7_len,
                                                        unsigned char **pkcs8, int *pkcs8_len,
                                                        char *user_id, X509 *peer_cert,
                                                        char *path_seg, void *ex_data))
{
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->est_server_keygen_pkcs10_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_csr_cb() is used by an application to install
    a handler for retrieving the CSR attributes from the
    CA server.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

        unsigned char *(*cb)(int*csr_len, char *path_seg, void *ex_data)

    This function is called by libest when a CSR attributes 
    request is received.  The attributes are provided by the CA
    server and returned as a char array.
 
    @return EST_ERROR.
 */
EST_ERROR est_set_csr_cb (EST_CTX *ctx, unsigned char *(*cb)(int*csr_len, char *path_seg, X509 *peer_cert, void *ex_data))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a server, not a client or proxy
     */
    if (ctx->est_mode != EST_SERVER) {
        return (EST_ERR_BAD_MODE);
    }

    ctx->est_get_csr_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_cacerts_cb() is used by an application to install
    a handler for retrieving the CA certs from the CA server.
 
    @param ctx Pointer to the EST context
    @param cb  Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

        unsigned char *(*cb)(int *csr_len, char *path_seg, void *ex_data)

    This function is called by libest when a CAcerts request 
    is received.  The CA certs chain is provided by the application 
    layer and returned as a char array.
 
    @return EST_ERROR.
 */
EST_ERROR est_set_cacerts_cb (EST_CTX *ctx,
              unsigned char *(*cb)(int*csr_len, char *path_seg, void *ex_data))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a server, not a client or proxy
     */
    if (ctx->est_mode != EST_SERVER) {
        return (EST_ERR_BAD_MODE);
    }

    ctx->est_get_cacerts_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_http_auth_cb() is used by an application to install
    a handler for authenticating EST clients.
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must match the following prototype:

    int (*cb)(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah, X509 *peer_cert,
              char *path_seg, void *ex_data)

    This function is called by libest when performing HTTP authentication.
    libest will pass the EST_HTTP_AUTH_HDR struct to the application,
    allowing the application to hook into a Radius, AAA, or some user
    authentication database.  The X509 certificate from the TLS 
    peer (EST client) is also provided through this callback facility, allowing
    the application layer to check for specific attributes in the 
    X509 certificate such as an 802.1AR device ID.  In addition,
    the path segment string is passed up if there was one in the
    request URI.
 
    @return EST_ERROR.
 */
EST_ERROR est_set_http_auth_cb (EST_CTX *ctx, 
                                int (*cb)(EST_CTX *ctx, EST_HTTP_AUTH_HDR *ah, 
                                          X509 *peer_cert, char *path_seg,
					  void *ex_data))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->est_http_auth_cb = cb;

    return (EST_ERR_NONE);
}

/*! @brief est_set_http_auth_required() is used by an application to define whether
    HTTP authentication should be required in addition to using client certificates.
 
    @param ctx Pointer to the EST context
    @param required Flag indicating that HTTP authentication is required. Set 
    to HTTP_AUTH_REQUIRED value to require HTTP auth.  Set to HTTP_AUTH_NOT_REQUIRED 
    if HTTP auth should occur only when TLS client authentication fails.
 
    @return EST_ERROR.

    The default mode is HTTP_AUTH_REQUIRED.  This means that HTTP authentication
    will be attempted even when TLS client authentication succeeds.  If HTTP
    authentication is only needed when TLS client auth fails, then set this
    to HTTP_AUTH_NOT_REQUIRED.
 */
EST_ERROR est_set_http_auth_required (EST_CTX *ctx, EST_HTTP_AUTH_REQUIRED required)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->require_http_auth = required;

    return (EST_ERR_NONE);
}

/*! @brief est_server_enable_enhanced_cert_auth() is used by an application to
    enable the use of the Enhanced Certificate Authentication mode on the
    server. When this mode is enabled for an HTTP context, http
    authentication is required, and a valid certificate is received during
    authentication the authentication header will be automatically created.
    When the context being used is in CoAP mode and this feature is enabled,
    this feature will always be used during auth.
    The UserID field will be set to the value of a subject field parsed out of
    the cert received. The selection of this field is determined by the
    following decisions which are made in real-time by the server.

    First the server attempts to verify its cert against the manufacturer
    truststores that have been registered via the enhanced cert auth APIs.
    If the client cert verifies against a manufacturer it grabs the field
    registered for that manufacturer from the certificate.

    If the cert was not verified by any of the manufacturers, it is assumed
    that the cert is a part of the local pki domain and should use the
    subject field for the local pki domain.

    If the CSR Check is enabled, the subject field used as the username will be
    compared with with the local pki domain subject field in the CSR to ensure
    that the identifying information will be copied into the newly enrolled
    local PKI domain cert.

    SECURITY ISSUE: The Enhanced Cert Auth CSR Check can be bypassed if there
    are two or more different manufacturer NIDs being used. In this scenario, it
    is possible to masquerade as another device during a local PKI domain
    enrollment. If there is only one unique manufacturer NID then it can be
    ensured that identifying information from the manufacturer cert was copied
    into the local PKI domain and will continue to be copied into all local PKI
    domain CSRs during enrollment.

    Use the est_server_enhanced_cert_auth_add_mfg_info API to add a new
    registered manufacturer to an EST context. This new manufacturer will
    then be used in the auth of a request as described before.

    The password will be set to a user defined value or the default
    Cisco specific password.

    @param ctx Pointer to the EST context
    @param local_pki_subj_field_nid integer name identifier (NID) for the
    subject field that should be obtained from local pki domain certificates
    @param ah_pwd String containing the desired auth header password. If set
    to NULL the default password "cisco" will be used.
    @param csr_check_enabled Flag specifying whether the Enhanced Cert Auth CSR
    copy check should be performed during authentication. The purpose of this
    check is to ensure that the identifying information in the client's peer
    cert gets propagated into the newly enrolled local pki domain cert. If this
    check is on and the information wasn't copied into the csr, the enrollment
    will fail.

    @return EST_ERROR.

    The default mode is ENHANCED_CERT_AUTH_DISABLED. To use Enhanced Certificate
    Authentication mode the user will call this API.
    The user can then also call the est_server_enhanced_cert_auth_add_mfg_info
    API to add a new registered device manufacturer for use with this auth
    feature. If no registered manufacturer is added it will be assumed that all
    devices connecting are part of the local pki domain and use the subject
    field associated with the local PKI domain NID during auth.
    Finally, the user can disable this mode using the
    est_server_disable_enhanced_cert_auth API. Disabling this feature will
    remove all registered manufacturers.
 */
LIBEST_API EST_ERROR est_server_enable_enhanced_cert_auth (
    EST_CTX *ctx, int local_pki_subj_field_nid, const char *ah_pwd,
    EST_ECA_CSR_CHECK_FLAG csr_check_enabled)
{
    EST_ERROR rv = EST_ERR_NONE;
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }
    if (ctx->enhanced_cert_auth_enabled == ENHANCED_CERT_AUTH_ENABLED) {
        EST_LOG_ERR("Enhanced Cert Auth already enabled");
        return (EST_ERR_ALREADY_ENABLED);
    }
    rv = est_server_set_enhcd_cert_auth_local_pki_nid(ctx,
                                                      local_pki_subj_field_nid);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to set enhanced cert auth local PKI domain NID");
        return rv;
    }
    if (!ah_pwd) {
        ah_pwd = EST_SERVER_DEFAULT_ENHCD_CERT_PWD;
    }
    rv = est_server_set_enhcd_cert_auth_pwd(ctx, ah_pwd);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to set enhanced cert auth password");
        return rv;
    }
    switch (csr_check_enabled) {
    case ECA_CSR_CHECK_ON:
    case ECA_CSR_CHECK_OFF:
        ctx->enhanced_cert_auth_csr_check = csr_check_enabled;
        break;
    default:
        EST_LOG_ERR("Invalid value for csr_check_enabled flag");
        return EST_ERR_INVALID_PARAMETERS;
    }
    ctx->enhanced_cert_auth_enabled = ENHANCED_CERT_AUTH_ENABLED;
    EST_LOG_INFO("Enhanced Cert Auth mode enabled");
    return (EST_ERR_NONE);
}

/*! @brief est_server_enhanced_cert_auth_add_mfg_info() is used by an
    application to add a new registered device manufacturer to be used with the
    enhanced cert auth mode. This new manufacturer information and truststore
    will then be used during the auth to determine which subject line field will
    be used for the user.

    @param ctx Pointer to the EST context
    @param mfg_name String containing the name of the device manufacturer
    @param mfg_subj_field_nid Integer name identifier (NID) for the subject
    field that should be obtained from certificates of devices that came from
    this manufacturer
    @param truststore_buf Buffer that contains the truststore to be used to
    identify a device as being from this manufacturer
    @param truststore_buf_len Integer length of the truststore buffer
    @return EST_ERROR

    This API must only be used after the EST context already has enhanced cert
    auth enabled. If no manufacturer is registered using this API it is assumed
    that all requests should use the local pki domain subject field during auth.
 */
LIBEST_API EST_ERROR est_server_enhanced_cert_auth_add_mfg_info (
    EST_CTX *ctx, char *mfg_name, int mfg_subj_field_nid,
    unsigned char *truststore_buf, int truststore_buf_len)
{
    EST_ERROR err = EST_ERR_NONE;
    if (!ctx || !mfg_name || !truststore_buf || !truststore_buf_len) {
        EST_LOG_ERR("One or more of the input parameters were NULL or zero");
        return EST_ERR_INVALID_PARAMETERS;
    }
    if (ctx->enhanced_cert_auth_enabled != ENHANCED_CERT_AUTH_ENABLED) {
        EST_LOG_ERR("Enhanced Cert Auth is not enabled");
        return EST_ERR_INVALID_PARAMETERS;
    }
    if (!ctx->enchd_cert_mfgs_info_list) {
        EST_LOG_INFO("Creating new manufacturer info list.");
        err = est_enhcd_cert_auth_mfg_info_list_create(ctx);
        if (err != EST_ERR_NONE) {
            return err;
        }
    }
    err = est_load_enhcd_cert_auth_manufacturer(
        ctx, mfg_name, mfg_subj_field_nid, truststore_buf, truststore_buf_len);
    return err;
}

/*! @brief est_server_disable_enhanced_cert_auth() is used by an application to
    disable the use of Enhanced Certificate Authentication Mode on the server.
    When this mode is disabled the EST server will revert back to normal
    operation of HTTP Authentication. This means that instead of getting the
    user from the subject line of the received certificate and using a server
    set password, the HTTP Authentication headers received from the client's
    request will be used. In CoAP mode when Enhanced Cert Auth is off all
    successful DTLS connections will skip the auth step and continue on to
    perform the rest of the steps for the EST request.

    @param ctx Pointer to the EST context

    @return EST_ERROR.

    The default mode is ENHANCED_CERT_AUTH_DISABLED. To use Enhanced Certificate
    Authentication mode the user will call the
    est_server_enable_enhanced_cert_auth API. Once enabled the user can then
    disable this mode using the this API. Disabling Enhancecd Cert Auth will
    destroy all manufacturer info and truststores currently registered.
 */
LIBEST_API EST_ERROR est_server_disable_enhanced_cert_auth (EST_CTX *ctx)
{
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (ctx->enhanced_cert_auth_enabled == ENHANCED_CERT_AUTH_DISABLED) {
        EST_LOG_ERR("Enhanced Cert Auth already disabled");
        return (EST_ERR_ALREADY_DISABLED);
    }
    mfg_info_list_destroy(ctx);
    ctx->enhanced_cert_auth_enabled = ENHANCED_CERT_AUTH_DISABLED;
    EST_LOG_INFO("Enhanced Cert Auth mode disabled");
    return (EST_ERR_NONE);
}

/*! @brief est_server_enable_srp() is used by an application to enable 
    the TLS-SRP authentication.  This allows EST clients that provide 
    SRP credentials at the TLS layer to be authenticated by the EST
    server.  This function must be invoked to enable server-side
    SRP support. 

    @param ctx Pointer to the EST context
    @param cb Function address of the application specific SRP verifier handler

    This function should be invoked prior to starting the EST server.   
    This is used to specify the handler for SRP authentication at the TLS
    layer.  When a TLS-SRP cipher suite is negotiated at the TLS layer,
    the handler will be invoked by libest to retrieve the SRP parameters
    for user authentication.  Your application must provide the SRP parameters
    for the user.  
    
    The handler should use the following logic:

    1. Invoke SSL_get_srp_username() to get the SRP user name from the
       TLS layer.
    2. Lookup the user's SRP parameters in the application specific
       user database.  These parameters include the N, g, s, and v 
       parameters.
    3. Invoke SSL_set_srp_server_param() to forward the SRP parameters
       to the TLS layer, allowing the TLS handshake to proceed.
       
    libest includes an example server application that uses this handler
    for SRP support.  This example uses the OpenSSL SRP verifier file capability
    to manage SRP parameters for individual users.  Your application could use
    this approach, or it may utilize another facility for managing user specific
    SRP parameters.  Please refer to RFC 2945 and RFC 5054 for a full understanding
    of SRP.

    @return EST_ERROR.
 */
EST_ERROR est_server_enable_srp (EST_CTX *ctx, int (*cb)(SSL *s, int *ad, void *arg))
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (!cb) {
	EST_LOG_ERR("Null callback");
        return (EST_ERR_INVALID_PARAMETERS);
    }

    ctx->est_srp_username_cb = cb;
    ctx->enable_srp = 1;

    return (EST_ERR_NONE);
}


/*! @brief est_server_enable_pop() is used by an application to enable 
    the proof-of-possession check on the EST server.  This proves the 
    EST client that sent the CSR to the server is in possession of the
    private key that was used to sign the CSR.  This binds the TLS 
    session ID to the CSR.

    Note, if the CSR attributes configured on the server require PoP 
    checking, then there is no need to call this function to enable
    PoP.  The PoP will be enabled automatically under this scenario.
    
    Note, PoP checking is not possible when an EST proxy is used to
    between the EST client and EST server.  Since the proxy will not 
    be in possession of the private key, an EST server would fail the
    PoP check.  However, an EST proxy can enable this feature to ensure 
    the EST client has the signing key.

    @param ctx Pointer to the EST context

    This function may be called at any time.   
 
    @return EST_ERROR.
 */
EST_ERROR est_server_enable_pop (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->server_enable_pop = 1;
    return (EST_ERR_NONE);
}

/*! @brief est_server_disable_pop() is used by an application to disable 
    the proof-of-possession check on the EST server.  Please see
    the documentation for est_server_enable_pop() for more information
    on the proof-of-possession check.

    @param ctx Pointer to the EST context

    This function may be called at any time.   
 
    @return EST_ERROR.
 */
EST_ERROR est_server_disable_pop (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->server_enable_pop = 0;
    return (EST_ERR_NONE);
}

/*! @brief est_server_set_retry_period() is used by an application to  
    change the default retry-after period sent to the EST client when
    the CA server is not configured for auto-enroll.  This retry-after
    value notifies the client about how long it should wait before
    attempting the enroll operation again to see if the CA has 
    approved the original CSR. 
 
    @param ctx Pointer to the EST context
    @param seconds Number of seconds the server will use in the
           retry-after response.

    This function may be called at any time after a context has
    been created.   
 
    @return EST_ERROR.
 */
EST_ERROR est_server_set_retry_period (EST_CTX *ctx, int seconds)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (seconds > EST_RETRY_PERIOD_MAX) {
	EST_LOG_ERR("Maximum retry-after period is %d seconds",
		EST_RETRY_PERIOD_MAX);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (seconds < EST_RETRY_PERIOD_MIN) {
	EST_LOG_ERR("Minimum retry-after period is %d seconds",
		EST_RETRY_PERIOD_MIN);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    ctx->retry_period = seconds;
    return (EST_ERR_NONE);
}

/*! @brief est_server_set_ecdhe_curve() is used by an application to 
    specify the ECC curve that should be used for ephemeral diffie-hellman
    keys during the TLS handshake.  Ephemeral diffie-hellman is enabled
    by libest and provides better forward secrecy.  If the curve
    is not specified by the application using this function, then
    the prime256v1 curve is used as the default curve.  
 
    @param ctx Pointer to the EST context
    @param nid OpenSSL NID value for the desired curve

    This function must be called prior to starting the EST server.  
    The NID values are defined in <openssl/obj_mac.h>.  Typical NID 
    values provided to this function would include:
	
	NID_X9_62_prime192v1
	NID_X9_62_prime256v1
	NID_secp384r1
	NID_secp521r1
 
    @return EST_ERROR.
 */
EST_ERROR est_server_set_ecdhe_curve (EST_CTX *ctx, int nid)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }
    if (nid <= 0) {
	EST_LOG_ERR("Invalid NID value");
        return (EST_ERR_INVALID_PARAMETERS);
    }

    ctx->ecdhe_nid = nid;
    return (EST_ERR_NONE);
}

/*! @brief est_server_set_dh_parms() is used by an application to 
    specify the Diffie-Hellman parameters to be used for single
    use DH key generation during the TLS handshake.  If these 
    parameters are not used, then single-use DH key generation
    is not enabled.  This should be enabled to improve the 
    forward secrecy of the TLS handshake operation.  
    
    The DH parameters provided through this API should not be
    hard-coded in the application.  The parameters should be
    generated at the time of product installation.  Reusing the
    parameters across multiple installations of the product
    results in a vulnerable product.  
 
    @param ctx Pointer to the EST context
    @param parms Pointer to OpenSSL DH parameters

    This function must be called prior to starting the EST server.  
 
    @return EST_ERROR.
 */
EST_ERROR est_server_set_dh_parms (EST_CTX *ctx, DH *parms)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }
    if (!parms) {
        EST_LOG_ERR("Null DH parameters");
        return (EST_ERR_INVALID_PARAMETERS);
    }
    ctx->dh_tmp = DHparams_dup(parms);
    return (EST_ERR_NONE);
}

/*! @brief est_server_init_csrattrs() is used by an application to 
    initialize a fixed set of CSR attributes.  These attributes will
    be used by libest in response to a client CSR attributes
    request.  The attributes must be an ASN.1 base64 encoded character
    string.

    @param ctx Pointer to the EST context
    @param csrattrs Pointer CSR attributes in ASN.1 base64 encoded format,
                    a NULL pointer clears the attributes and length.
    @param csrattrs_len Length of the CSR attributes character string

    The est_get_csr_cb callback function maintains precedence over this
    method for CSR attributes. If est_get_csr_cb is initialized by the
    application it will be used.  If not, then libest will use the
    attributes initialized here.

    This function should be called prior to starting the EST server.  
    PoP configuration(est_server_enable_pop or est_server_disable_pop)
    should be called prior to this function.
    
    @return EST_ERROR.
 */
EST_ERROR est_server_init_csrattrs (EST_CTX *ctx, char *csrattrs, int csrattrs_len)
{
    int csrattrs_pop_len, pop_present, rv;
    char *csrattrs_data_pop = NULL;

    if (ctx == NULL) {
        return (EST_ERR_NO_CTX);
    }

    /*
     * Verify the context is for a server, not a client or proxy
     */
    if (ctx->est_mode != EST_SERVER) {
        return (EST_ERR_BAD_MODE);
    }

    EST_LOG_INFO("Attributes pointer is %p, len=%d", 
		 ctx->server_csrattrs, ctx->server_csrattrs_len);

    /* Free old version if previously initialized */
    if (ctx->server_csrattrs != NULL) {
        free(ctx->server_csrattrs);
        ctx->server_csrattrs = NULL;
        ctx->server_csrattrs_len = 0;
    }

    /* caller just wanted to clear it, so return */
    if (csrattrs == NULL) {
        return (EST_ERR_NONE);
    }

    /*
     * In order to run Client negative unit testing the parameter, 
     * PoP and parse checks all need to be disabled via #define
     * in a couple of places here.
     */

    /* 
     * check smallest possible base64 case here for now 
     * and sanity test will check min/max value for ASN.1 data
     */
    if (csrattrs_len < MIN_CSRATTRS) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /* assume PoP not in CSR attributes */
    ctx->csr_pop_present = 0;
    if (ctx->server_enable_pop) {
        rv = est_is_challengePassword_present(csrattrs, csrattrs_len, &pop_present);
	if (rv != EST_ERR_NONE) {
	    EST_LOG_ERR("Error during PoP/sanity check");
	    return (EST_ERR_INVALID_PARAMETERS);
	}
	ctx->csr_pop_present = pop_present;

	if (!ctx->csr_pop_present) {
	    rv = est_add_challengePassword(csrattrs, csrattrs_len, 
					   &csrattrs_data_pop, &csrattrs_pop_len);
	    if (rv != EST_ERR_NONE) {
		EST_LOG_ERR("Error during add PoP");
		return (EST_ERR_INVALID_PARAMETERS);
	    }
	    csrattrs = csrattrs_data_pop;
	    csrattrs_len = csrattrs_pop_len;
	}
    } else {
        rv = est_asn1_parse_attributes(csrattrs, csrattrs_len, &pop_present);
	if (rv != EST_ERR_NONE) {
	    EST_LOG_ERR("Corrupt CSR Attributes");
	    return (EST_ERR_INVALID_PARAMETERS);
	}
    }    

    ctx->server_csrattrs = malloc(csrattrs_len + 1);
    if (!ctx->server_csrattrs) {
        if (csrattrs_data_pop) {
            free(csrattrs_data_pop);
        }
        return (EST_ERR_MALLOC);
    }
    ctx->server_csrattrs_len = csrattrs_len;

    strcpy_s((char *)ctx->server_csrattrs, csrattrs_len + 1, csrattrs);
    ctx->server_csrattrs[csrattrs_len] = 0;
    if (csrattrs_data_pop) {
      free(csrattrs_data_pop);
    }
    EST_LOG_INFO("Attributes pointer is %p, len=%d", ctx->server_csrattrs, 
		 ctx->server_csrattrs_len);
    return (EST_ERR_NONE);
}

/*! @brief est_server_enable_tls10() is a deprecated function. TLS 1.0
    is a violation of RFC7030 and it is no longer supported by the EST library.
    This function will log an error message and return EST_ERR_BAD_MODE.
    
    @param ctx Pointer to the EST context

    This function must be called prior to starting the EST server.  
 
    @return EST_ERROR.
 */
EST_ERROR est_server_enable_tls10 (EST_CTX *ctx)
{
	EST_LOG_ERR("TLS 1.0 is a violation of RFC7030 and therefore not supported");
        return (EST_ERR_BAD_MODE);

}

/*! @brief est_server_enforce_csrattrs() is used by an application to 
    enable checking of the CSR attributes on the EST server.  When
    enabled, the EST client must provide all the CSR attributes that
    were in the /csrattrs response sent by the server.  The enrollment
    will fail if the client fails to provide all the CSR attributes.
    This setting applies to simple enroll and reenroll operations.
    This setting applies only to server mode and has no bearing on
    proxy mode operation.
    
    @param ctx Pointer to the EST context

    This function must be called prior to starting the EST server.  
 
    @return EST_ERROR.
 */
EST_ERROR est_server_enforce_csrattr (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }
    ctx->enforce_csrattrs = 1;
    return (EST_ERR_NONE);
}

/*! @brief est_server_set_read_timeout() is used by an application to set
    timeout value of server read operations.  Once a socket is opened the
    EST server begins attempting to read from this socket.  This
    timeout value limits the amount of time the client will wait for the
    response.  The default value is set to EST_SSL_READ_TIMEOUT_DEF.

    @param ctx Pointer to the EST context
    @param timeout Integer value representing the read timeout in seconds.
    The minimum value is EST_SSL_READ_TIMEOUT_MIN and the maximum value is
    EST_SSL_READ_TIMEOUT_MAX.
 
    @return EST_ERROR.
 */
EST_ERROR est_server_set_read_timeout (EST_CTX *ctx, int timeout)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (timeout < EST_SSL_READ_TIMEOUT_MIN ||
        timeout > EST_SSL_READ_TIMEOUT_MAX) {
	EST_LOG_ERR("Invalid read timeout value passed: %d ", timeout);
        return (EST_ERR_INVALID_PARAMETERS);
    }
        
    ctx->server_read_timeout = timeout;
    return (EST_ERR_NONE);
}


/*! @brief est_set_brski_voucher_req_cb() is used by an application to install
    a handler for processing incoming BRSKI client voucher requests.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must be defined to be of the brski_voucher_req_cb
    function prototype.

    This function is called by libest when in server mode and receives
    a BRSKI /requestvoucher request.  The callback function will be
    passed the JSON based request from the BRSKI client
    
    @return EST_ERROR_NONE on success, or EST based error
 */
EST_ERROR est_set_brski_voucher_req_cb (EST_CTX *ctx, brski_voucher_req_cb cb)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (cb == NULL) {
        EST_LOG_ERR("EST Server: BRSKI: voucher_req_cb is NULL");
        return EST_ERR_INVALID_PARAMETERS;
    }    
    
    ctx->est_brski_voucher_req_cb = cb;

    return (EST_ERR_NONE);
}


/*! @brief est_set_brski_voucher_status_cb() is used by an application to install
    a handler for processing incoming BRSKI client voucher status indications.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must be defined to be of the brski_voucher_status_cb
    function prototype.

    This function is called by libest when in server mode and receives
    a BRSKI /voucher_status request.  The callback function will be
    passed the JSON based response from the BRSKI client
    
    @return EST_ERROR_NONE on success, or EST based error
 */
EST_ERROR est_set_brski_voucher_status_cb (EST_CTX *ctx, brski_voucher_status_cb cb)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (cb == NULL) {
        EST_LOG_ERR("EST Server: BRSKI: voucher_status_cb is NULL");
        return EST_ERR_INVALID_PARAMETERS;
    }
    
    ctx->est_brski_voucher_status_cb = cb;

    return (EST_ERR_NONE);
}


/*! @brief est_set_brski_enroll_status_cb() is used by an application to install
    a handler for processing incoming BRSKI client certificate status indications.  
 
    @param ctx Pointer to the EST context
    @param cb Function address of the handler

    This function must be called prior to starting the EST server.  The
    callback function must be defined to be of the brski_enroll_status_cb
    function prototype.

    This function is called by libest when in server mode and receives
    a BRSKI /enrollstatus primitive.  The callback function will be
    passed the JSON based status from the BRSKI client
    
    @return EST_ERROR_NONE on success, or EST based error
 */
EST_ERROR est_set_brski_enroll_status_cb (EST_CTX *ctx, brski_enroll_status_cb cb)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (cb == NULL) {
        EST_LOG_ERR("EST Server: BRSKI: enroll_status_cb is NULL");
        return EST_ERR_INVALID_PARAMETERS;
    }        

    ctx->est_brski_enroll_status_cb = cb;

    return (EST_ERR_NONE);
}


/*! @brief est_server_set_brski_retry_period() is used by an application to
    change the default retry-after period sent to the BRSKI pledge when the
    registrar is not able to immediately provide the voucher.  This
    retry-after value notifies the client how long to wait before attempting
    the voucher request operation again to see if the registrar is ready to
    respond with a voucher.
 
    @param ctx Pointer to the EST context
    @param seconds Number of seconds the server will use in the
           retry-after response.

    This function may be called at any time after a context has
    been created.   
 
    @return EST_ERROR.
 */
EST_ERROR est_server_set_brski_retry_period (EST_CTX *ctx, int seconds)
{
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    if (seconds > EST_BRSKI_RETRY_PERIOD_MAX) {
        EST_LOG_ERR("Maximum retry-after period is %d seconds",
                EST_BRSKI_RETRY_PERIOD_MAX);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (seconds < EST_BRSKI_RETRY_PERIOD_MIN) {
        EST_LOG_ERR("Minimum retry-after period is %d seconds",
                EST_BRSKI_RETRY_PERIOD_MIN);
        return (EST_ERR_INVALID_PARAMETERS);
    }

    ctx->brski_retry_period = seconds;
    return (EST_ERR_NONE);
}



/*! @brief est_set_est_err_event_cb() is used by an application to install
    a handler for receiving notification when EST_LOG_ERR() is called with
    EST_LOG_LVL_ERR.

    @param new_est_err_cb Callback function to call when EST_LOG_ERR() called.
                          If NULL, then the callback function reverts to being
                          disabled.

    Because est_log() does not have an EST_CTX argument, only one callback may
    be registered at a time.

    The callback function must be of type est_err_cb_t.

    @return None.
 */
void est_set_est_err_event_cb (est_est_err_event_cb_t new_est_err_cb)
{

    if (est_err_event_cb != NULL) {

        /*
         * If the new cb address is null, then this will disable
         * this callback feature.
         */
        if (new_est_err_cb == NULL) {
            EST_LOG_INFO("EST error callback disabled.");

        } else {
            EST_LOG_INFO("Changing the EST error callback from %p to %p",
                         est_err_event_cb, new_est_err_cb);
        }

    } else {
        EST_LOG_INFO("EST error callback %p enabled.", new_est_err_cb);
    }

    est_err_event_cb = new_est_err_cb;

    return;
}

/*! @brief est_set_ssl_proto_err_event_cb() is used by an application to install
    a handler for receiving notification when an SSL protocol-related error
    occurs. (e.g. ossl_dump_ssl_errors() for OpenSSL errors)

    @param new_ssl_proto_err_cb Callback function to call when an SSL
                                protocol-related error occurs.
                                If NULL, then the callback function reverts to being
                                disabled.

    Because est_log() does not have an EST_CTX argument, only one callback may be
    registered at a time.

    The callback function must be of type ssl_proto_err_cb_t.

    @return None.
 */
void est_set_ssl_proto_err_event_cb (est_ssl_proto_err_event_cb_t new_ssl_proto_err_cb)
{

    if (*ssl_proto_err_event_cb != NULL) {

        /*
         * If the new cb address is null, then this will disable
         * this callback feature.
         */
        if (new_ssl_proto_err_cb == NULL) {
            EST_LOG_INFO("SSL protocol error callback disabled.");

        } else {
            EST_LOG_INFO("Changing the SSL protocol error callback from %p to %p",
                         *ssl_proto_err_event_cb, new_ssl_proto_err_cb);
        }

    } else {
        EST_LOG_INFO("SSL protocol error callback %p enabled.", new_ssl_proto_err_cb);

    }

    ssl_proto_err_event_cb = new_ssl_proto_err_cb;

    return;
}

/*! @brief est_set_enroll_req_event_cb() is used by an application to install
    a handler for receiving notification when an EST enroll request
    occurs.

    @param ctx EST context with which to register.
    @param new_est_enroll_cb Callback function to call when an EST enroll request occurs.
                             If NULL, then the callback function reverts to being
                             disabled.

    The callback function must be of type est_enroll_req_event_cb_t.

    @return None.
 */
void est_set_enroll_req_event_cb (EST_CTX * ctx,
                                  est_enroll_req_event_cb_t new_est_enroll_event_cb)
{

    if (ctx != NULL) {
        if (ctx->enroll_req_event_cb != NULL) {

            /*
             * If the new cb address is null, then this will disable
             * this callback feature.
             */
            if (new_est_enroll_event_cb == NULL) {
                EST_LOG_INFO("EST enroll request event callback disabled.");

            } else {
                EST_LOG_INFO("Changing the EST enroll request event callback from %p to %p",
                             ctx->enroll_req_event_cb, new_est_enroll_event_cb);
            }

        } else {
            EST_LOG_INFO("EST enroll request callback event %p enabled.",
                    new_est_enroll_event_cb);

        }

        ctx->enroll_req_event_cb = new_est_enroll_event_cb;

    } else {
        EST_LOG_ERR("NULL EST context specified to %s\n", __FUNCTION__);

    }
    return;
}

/*! @brief est_set_enroll_rsp_event_cb() is used by an application to install
    a handler for receiving notification when an EST enroll response
    occurs.

    @param ctx EST context with which to register.
    @param new_est_enroll_cb Callback function to call when an EST enroll response occurs.
                             If NULL, then the callback function reverts to being
                             disabled.

    The callback function must be of type est_enroll_rsp_event_cb_t.

    @return None.
 */
void est_set_enroll_rsp_event_cb (EST_CTX * ctx,
                                  est_enroll_rsp_event_cb_t new_est_enroll_event_cb)
{

    if (ctx != NULL) {
        if (ctx->enroll_rsp_event_cb != NULL) {

            /*
             * If the new cb address is null, then this will disable
             * this callback feature.
             */
            if (new_est_enroll_event_cb == NULL) {
                EST_LOG_INFO("EST enroll request event callback disabled.");

            } else {
                EST_LOG_INFO("Changing the EST enroll response event callback from %p to %p",
                             ctx->enroll_rsp_event_cb, new_est_enroll_event_cb);
            }

        } else {
            EST_LOG_INFO("EST enroll response callback event %p enabled.",
                    new_est_enroll_event_cb);

        }

        ctx->enroll_rsp_event_cb = new_est_enroll_event_cb;

    } else {
        EST_LOG_ERR("NULL EST context specified to %s\n", __FUNCTION__);

    }
    return;
}

/*! @brief est_set_enroll_auth_result_event_cb() is used by an application to
    install a handler for receiving notification when an EST enroll
    authentication result is received from the configured authentication
    service.

    @param ctx EST context with which to register.
    @param new_est_enroll_auth_result_cb
                             Callback function to call when an EST enroll
                             authentication result is received. If NULL, then
                             the callback function reverts to being disabled.

    The callback function must be of type est_enroll_auth_result_event_cb_t.

    @return None.
 */
void est_set_enroll_auth_result_event_cb (EST_CTX * ctx,
                     est_enroll_auth_result_event_cb_t new_est_auth_result_cb)
{

    if (ctx != NULL) {
        if (ctx->enroll_auth_result_event_cb != NULL) {

            /*
             * If the new cb address is null, then this will disable
             * this callback feature.
             */
            if (new_est_auth_result_cb == NULL) {
                EST_LOG_INFO("EST enroll auth result event callback disabled.");

            } else {
                EST_LOG_INFO("Changing the EST enroll auth result event callback from %p to %p",
                             ctx->enroll_auth_result_event_cb,
                             new_est_auth_result_cb);
            }

        } else {
            EST_LOG_INFO("EST enroll auth result callback event %p enabled.",
                    new_est_auth_result_cb);

        }

        ctx->enroll_auth_result_event_cb = new_est_auth_result_cb;

    } else {
        EST_LOG_ERR("NULL EST context specified to %s\n", __FUNCTION__);

    }
    return;
}

/*! @brief est_set_endpoint_req_event_cb() is used by an application to install
    a handler for receiving notification when an EST request is received from
    an endpoint.

    @param ctx EST context with which to register.
    @param new_est_endpoint_req_cb
                             Callback function to call when an EST endpoint
                             request is received. If NULL, then the callback
                             function reverts to being disabled.

    The callback function must be of type est_endpoint_req_event_cb_t.

    @return None.
 */
void est_set_endpoint_req_event_cb (EST_CTX * ctx,
                                    est_endpoint_req_event_cb_t new_endpoint_req_cb)
{

    if (ctx != NULL) {
        if (ctx->endpoint_req_event_cb != NULL) {

            /*
             * If the new cb address is null, then this will disable
             * this callback feature.
             */
            if (new_endpoint_req_cb == NULL) {
                EST_LOG_INFO("EST endpoint request event callback disabled.");

            } else {
                EST_LOG_INFO("Changing the EST endpoint request event callback from %p to %p",
                             ctx->endpoint_req_event_cb, new_endpoint_req_cb);
            }

        } else {
            EST_LOG_INFO("EST endpoint request callback event %p enabled.",
                         new_endpoint_req_cb);

        }

        ctx->endpoint_req_event_cb = new_endpoint_req_cb;

    } else {
        EST_LOG_ERR("NULL EST context specified to %s\n", __FUNCTION__);

    }
    return;
}

/*
 * Internal EST function used to invoke the registered callback for EST errors.
 */
void est_invoke_est_err_event_cb (char *format, va_list arg_list)
{
    /*
     * If a callback is registered, call it now.
     */
    if (*est_err_event_cb != NULL) {
        est_err_event_cb(format, arg_list);
    }

    return;
}

/*
 * Internal EST function used to invoke the registered callback for SSL protocol errors.
 */
void est_invoke_ssl_proto_err_event_cb (char *err_msg)
{

    /*
     * If a callback is registered, call it now.
     */
    if (*ssl_proto_err_event_cb != NULL) {
        ssl_proto_err_event_cb(err_msg);
    }

    return;
}


/*
 * Internal function to obtain the subject fields from the peer cert
 * and the CSR.
 */
static
EST_ERROR est_invoke_enroll_get_subjs (EST_CTX *ctx, X509 *peer_cert,
                                       char *id_cert_subj, int id_cert_subj_len,
                                       X509_REQ *csr_x509,
                                       char *csr_subj, int csr_subj_len)
{
    EST_ERROR est_rc;

    *id_cert_subj = '\0';
    *csr_subj = '\0';

    if (peer_cert) {        
        est_rc = est_get_subj_fld_from_cert((void *)peer_cert, EST_CERT,
                                            id_cert_subj, id_cert_subj_len);
        if (est_rc != EST_ERR_NONE) {
            return (est_rc);
        }
    }
    
    est_rc = est_get_subj_fld_from_cert((void *)csr_x509, EST_CSR,
                                        csr_subj, csr_subj_len);
    if (est_rc != EST_ERR_NONE) {
        return (est_rc);
    }    

    /*
     * Assume that the subject will never be an empty string
     */
    if ((peer_cert && *id_cert_subj == '\0') || *csr_subj == '\0') {
        EST_LOG_ERR("Could not obtain subject field from ID cert or CSR");
        return EST_ERR_UNKNOWN;
    }
    
    return EST_ERR_NONE;
}


/*
 * Internal function to obtain the IP address and port num of the remote
 * client.  Called from event handlers before calling the event callbacks and
 * called from the CoAP event handler.
 */
EST_ERROR est_invoke_enroll_get_ip_port (EST_CTX *ctx, SSL *ssl, void *addr_info,
                                         char *src_ipstr, int src_ipstr_len,
                                         int *src_port) 
{
    EST_ERROR est_rc = EST_ERR_NONE;
    int rc;

    src_ipstr[0] = '\0';
    *src_port = 0;
    
    if (ctx->transport_mode == EST_COAP) {
#if HAVE_LIBCOAP
        /*
         * If CoAP, then we need to get the address info
         * from the coap based structure.  libcoap overrides
         * the BIOs that are used by SSL and does not set them
         * up in a way so that we can use them as in normal
         * HTTP mode.
         */
        coap_address_t *coap_addr = (coap_address_t *) addr_info;

        switch (coap_addr->addr.sa.sa_family) {
        case AF_INET:
            *src_port = ntohs(coap_addr->addr.sin.sin_port);
            if (NULL == inet_ntop(coap_addr->addr.sa.sa_family,
                                  &coap_addr->addr.sin.sin_addr,
                                  src_ipstr, src_ipstr_len)) {
                EST_LOG_ERR("Unable to obtain peer v4 IP address");
                est_rc = EST_ERR_SYSCALL;
            }
            break;
        case AF_INET6:
            *src_port = ntohs(coap_addr->addr.sin6.sin6_port);
            if (NULL == inet_ntop(coap_addr->addr.sa.sa_family,
                                  &coap_addr->addr.sin6.sin6_addr,
                                  src_ipstr, src_ipstr_len)) {
                EST_LOG_ERR("Unable to obtain peer v6 IP address");
                est_rc = EST_ERR_SYSCALL;
            }
            break;
        default:
            break;
        }
#else
        /*
         * In this case COAP support has not been enabled in this build of EST,
         * so log it and return an error.
         */
        EST_LOG_ERR("EST over CoAP has not been enabled in this build of libest.");
        return EST_ERR_CLIENT_COAP_MODE_NOT_SUPPORTED;        
#endif        
    } else if (ctx->transport_mode == EST_HTTP) {

        /*
         * Obtain the ip address and port number using the FD from the SSL
         * structure
         */
        struct sockaddr_storage addr;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        socklen_t addr_len = sizeof(addr);        
        int fd;
        
        fd = SSL_get_fd(ssl);
        if (fd == -1) {
            EST_LOG_ERR("Unable to obtain FD from SSL.  Cannot obtain IP address and port number");
            est_rc = EST_ERR_SYSCALL;
        } else {
            rc = getpeername(fd, (struct sockaddr *)&addr, &addr_len);
            if (rc < 0) {
                EST_LOG_ERR("getpeername() failed");
                est_rc = EST_ERR_SYSCALL;
            } else {
                switch (addr.ss_family) {
                case AF_INET:                
                    *src_port = ntohs(addr_in->sin_port);
                    if (NULL == inet_ntop(addr_in->sin_family,
                                          &(addr_in->sin_addr),
                                          src_ipstr, src_ipstr_len)) {
                        EST_LOG_ERR("Unable to obtain peer v4 IP address");
                        est_rc = EST_ERR_SYSCALL;
                    }
                    break;
                case AF_INET6:
                    *src_port = ntohs(addr_in6->sin6_port);
                    if (NULL == inet_ntop(addr_in6->sin6_family,
                                          &(addr_in6->sin6_addr),
                                          src_ipstr, src_ipstr_len)) {
                        EST_LOG_ERR("Unable to obtain peer v6 IP address");
                        est_rc = EST_ERR_SYSCALL;
                    }
                    break;
                default:
                    EST_LOG_ERR("Invalid address family");
                    est_rc = EST_ERR_UNKNOWN;
                    break;
                }
            }
        }
    } else {
        /*
         * invalid transport mode
         */
        EST_LOG_ERR("Transport mode set to invalid mode");
        est_rc = EST_ERR_UNKNOWN;
    }
    return(est_rc);
}
    
/*
 * Invoke the registered callback for EST enroll, reenroll, or server keygen requests.
 */
EST_ERROR est_invoke_enroll_req_event_cb (EST_CTX *ctx, SSL *ssl, X509 *peer_cert,
                                          unsigned char *csr_buf, int csr_len,
                                          void *addr_info, char *path_seg, EST_ENROLL_REQ_TYPE enroll_req)
{
    char id_cert_subj[EST_MAX_CERT_SUBJ_LEN+1];
    char csr_subj[EST_MAX_CERT_SUBJ_LEN+1];
    X509_REQ *csr_x509 = NULL;
    char src_ipstr[INET6_ADDRSTRLEN];
    int src_port = 0;
    EST_ERROR est_rc;
    EST_CSR_BASE64_DECODE decode_mode;
        
    if (ctx != NULL && ctx->enroll_req_event_cb != NULL) {

        /*
         * Gather up all the required information to be sent to the event
         * callback
         *
         * Get the CSR into internal X509 format in order to easily obtain the
         * subject field
         */
        if (ctx->transport_mode == EST_HTTP) {
            decode_mode = EST_CSR_DECODE;
        } else {
            decode_mode = EST_CSR_DECODE_BYPASS;
        }
        csr_x509 = est_server_parse_csr(csr_buf, csr_len, decode_mode);
        if (csr_x509 == NULL) {
            EST_LOG_ERR("Unable to load certificates");
            ossl_dump_ssl_errors();
            return EST_ERR_UNKNOWN;            
        }

        /*
         * Doesn't absolutely need to be done, but better safe than
         * sorry.
         */
        memzero_s(id_cert_subj, EST_MAX_CERT_SUBJ_LEN+1);
        memzero_s(csr_subj, EST_MAX_CERT_SUBJ_LEN+1);

        est_rc = est_invoke_enroll_get_subjs(ctx, peer_cert,
                                             &(id_cert_subj[0]), EST_MAX_CERT_SUBJ_LEN,
                                             csr_x509,
                                             &csr_subj[0], EST_MAX_CERT_SUBJ_LEN);
        if (est_rc != EST_ERR_NONE) {
            EST_LOG_ERR("Could not obtain subject fields from ID certificate of requesting node or from CSR");
        } else {
            
            /*
             * Get the IP address and port number of the client node that sent
             * this request
             */
            memzero_s(src_ipstr, INET6_ADDRSTRLEN+1);
            est_rc = est_invoke_enroll_get_ip_port(ctx, ssl, addr_info,
                                                   &src_ipstr[0], INET6_ADDRSTRLEN,
                                                   &src_port);
            if (est_rc != EST_ERR_NONE) {
                EST_LOG_ERR("Could not obtain IP address or port from requesting node");
            }
        }

        /*
         * Call the application layer callback
         */
        ctx->enroll_req_event_cb(id_cert_subj, peer_cert, csr_subj, csr_x509,
                                 src_ipstr, src_port, path_seg, enroll_req);
        X509_REQ_free(csr_x509);
    }

    return EST_ERR_NONE;
}

/*
 * Invoke the registered callback for EST enroll, reenroll, or server keygen responses.
 */
EST_ERROR est_invoke_enroll_rsp_event_cb (EST_CTX *ctx, SSL *ssl, X509 *peer_cert,
                                          unsigned char *csr_buf, int csr_len,
                                          void *addr_info, char *path_seg, EST_ENROLL_REQ_TYPE enroll_req,
                                          unsigned char *returned_cert, int returned_cert_len,
                                          EST_ERROR rc)
{
    char id_cert_subj[EST_MAX_CERT_SUBJ_LEN+1];
    char csr_subj[EST_MAX_CERT_SUBJ_LEN+1];
    X509_REQ *csr_x509 = NULL;
    char src_ipstr[INET6_ADDRSTRLEN];
    int src_port = 0;
    EST_ERROR est_rc;
    EST_CSR_BASE64_DECODE decode_mode;
   
    if (ctx != NULL && ctx->enroll_rsp_event_cb != NULL) {

        /*
         * Gather up all the required information to be sent to the event
         * callback
         *
         * Get the CSR into internal X509 format in order to easily obtain the
         * subject field
         */
        if (ctx->transport_mode == EST_HTTP) {
            decode_mode = EST_CSR_DECODE;
        } else {
            decode_mode = EST_CSR_DECODE_BYPASS;
        }
        csr_x509 = est_server_parse_csr(csr_buf, csr_len, decode_mode);
        if (csr_x509 == NULL) {
            EST_LOG_ERR("Unable to load certificates");
            ossl_dump_ssl_errors();
            return EST_ERR_UNKNOWN;            
        }
        /*
         * Doesn't absolutely need to be done, but better safe than
         * sorry.
         */
        memzero_s(id_cert_subj, EST_MAX_CERT_SUBJ_LEN+1);
        memzero_s(csr_subj, EST_MAX_CERT_SUBJ_LEN+1);

        est_rc = est_invoke_enroll_get_subjs(ctx, peer_cert,
                                             &(id_cert_subj[0]), EST_MAX_CERT_SUBJ_LEN,
                                             csr_x509,
                                             &csr_subj[0], EST_MAX_CERT_SUBJ_LEN);
        if (est_rc != EST_ERR_NONE) {
            EST_LOG_ERR("Could not obtain subject fields from ID certificate of requesting node or from CSR");
        } else {
            
            /*
             * Get the IP address and port number of the client node that sent
             * this request
             */
            memzero_s(src_ipstr, INET6_ADDRSTRLEN+1);
            est_rc = est_invoke_enroll_get_ip_port(ctx, ssl, addr_info,
                                                   &src_ipstr[0], INET6_ADDRSTRLEN,
                                                   &src_port);
            if (est_rc != EST_ERR_NONE) {
                EST_LOG_ERR("Could not obtain IP address or port from requesting node");
            }
        }
        
        /*
         * Call the application layer callback
         */
        ctx->enroll_rsp_event_cb(id_cert_subj, peer_cert, csr_subj, csr_x509,
                                 src_ipstr, src_port,
                                 returned_cert, returned_cert_len, path_seg,
                                 enroll_req, rc);
        X509_REQ_free(csr_x509);
    }

    return EST_ERR_NONE;
}

/*
 * Internal EST function used to invoke the registered callback for EST
 * enroll, reenroll, or server keygen authentication results.
 */
void est_invoke_enroll_auth_result_event_cb (EST_CTX *ctx, X509 *peer_cert,
                                             char *path_seg, EST_ENROLL_REQ_TYPE enroll_req,
                                             EST_HTTP_AUTH_HDR_RESULT enh_auth_result,
                                             EST_AUTH_STATE rv)
{
    EST_ENHANCED_AUTH_TS_AUTH_STATE enh_auth_ts_state;
    
    /*
     * If a callback is registered, call it now.
     */
    if (ctx != NULL && ctx->enroll_auth_result_event_cb != NULL) {

        /*
         * Map the ECA result down to the success or fail indication of ECA
         * value that is passed to the callback function.
         */
        switch (enh_auth_result) {
        case EST_AUTH_HDR_GOOD:
            enh_auth_ts_state = EST_ENHANCED_AUTH_TS_VALIDATED;
            break;
        case EST_AUTH_HDR_MISSING:
        case EST_AUTH_HDR_BAD:
        case EST_AUTH_ECA_CSR_CHECK_FAIL:
        case EST_AUTH_ECA_CSR_PARSE_FAIL:
        case EST_AUTH_ECA_ERR:
        default:
            enh_auth_ts_state = EST_ENHANCED_AUTH_TS_NOT_VALIDATED;
            break;
        }
        
        ctx->enroll_auth_result_event_cb(peer_cert, path_seg, enroll_req,
                                         enh_auth_ts_state, rv);
    }

    return;
}


/*
 * Internal EST function used to invoke the registered callback for EST
 * endpoint requests.
 */
void est_invoke_endpoint_req_event_cb (EST_CTX *ctx, X509 *peer_cert, SSL *ssl,
                                       void *addr_info, const char *uri,
                                       EST_ENDPOINT_EVENT_TYPE event_type)
{
    char id_cert_subj[EST_MAX_CERT_SUBJ_LEN+1];
    EST_ERROR est_rc;
    char src_ipstr[INET6_ADDRSTRLEN+1];
    int src_port = 0;

    /*
     * If a callback is registered, call it now.
     */
    if (ctx != NULL && ctx->endpoint_req_event_cb != NULL) {

        memzero_s(id_cert_subj, EST_MAX_CERT_SUBJ_LEN+1);        
        memzero_s(src_ipstr, INET6_ADDRSTRLEN+1);
        
        /*
         * If a peer cert is available then retrieve the subject field
         * Then retrieve the ip address and port number.  If either fail
         * continue on and report the values that are available.
         */
        if (peer_cert) {    
            est_rc = est_get_subj_fld_from_cert((void *)peer_cert, EST_CERT,
                                                &id_cert_subj[0], EST_MAX_CERT_SUBJ_LEN);
            if (est_rc != EST_ERR_NONE) {
                EST_LOG_ERR("Could not obtain subject from peer cert");
            }
        }

        if (ssl) {
            est_rc = est_invoke_enroll_get_ip_port(ctx, ssl, addr_info,
                                                   &src_ipstr[0], INET6_ADDRSTRLEN,
                                                   &src_port);
            if (est_rc != EST_ERR_NONE) {
                EST_LOG_ERR("Could not obtain IP address or port from requesting node");
            }
        }
        
        ctx->endpoint_req_event_cb(id_cert_subj, peer_cert, uri,
                                   src_ipstr, src_port,
                                   event_type);
    }

    return;
}
