/*------------------------------------------------------------------
 * est/est_client.c - EST client specific code
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       module.
 *
 * April, 2013
 *
 * Copyright (c) 2013 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-28 few stability improvements; made logging slightly more informative
// 2015-08-13 improved TLS error handling and reporting, introducing general_ssl_error()
// 2014-04-23 est_client_enroll_csr: priv_key can be NULL if CSR is signed
// 2014-04-23 added EST_ERR_NO_CERT; slightly improved logging and spelling
// 2014-06-30 further minor improvements of logging: retry-after is no error

#include "est.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "est_locl.h"
#include "est_ossl_util.h"
#include <openssl/x509v3.h> // TODO cleanup: move general OpenSSL-related functions to est_ossl_util

#define SSL_EXDATA_INDEX_INVALID -1

int e_ctx_ssl_exdata_index = SSL_EXDATA_INDEX_INVALID;

/*****************************************************************************
* EST Client operations
*****************************************************************************/
/*
 * Utility function to set the certificate and private key to use
 * for a SSL context.
 *
 * Returns 0 on success
 */
int est_client_set_cert_and_key (SSL_CTX *ctx, X509 *cert, EVP_PKEY *key)
{

    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        EST_LOG_ERR("Error setting certificate");
        ossl_dump_ssl_errors();
        return 1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) { // TODO bug: for RSA key, OpenSSL yields: error code 42 (EST_ERR_CLIENT_INVALID_KEY) ] [ossl_dump_ssl_errors:245]--> OSSL error: 2147860600:error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch:x509_cmp.c:344:

        EST_LOG_ERR("Unable to set private key");
        ossl_dump_ssl_errors();
        return 1;
    }

    /*
     * Verify the key matches the cert
     */
    if (!SSL_CTX_check_private_key(ctx)) {
        EST_LOG_ERR("Private key does not match the certificate public key");
        ossl_dump_ssl_errors();
        return 1;
    }
    return 0;
}


/*
 * Sign an X509 certificate request using the digest and the key passed.
 * Returns OpenSSL error code from X509_REQ_sign_ctx();
 */
static int est_client_X509_REQ_sign (X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
{
    int ossl_rv;
    EVP_PKEY_CTX *pkctx = NULL;
    EVP_MD_CTX mctx;

    EVP_MD_CTX_init(&mctx);

    if (!EVP_DigestSignInit(&mctx, &pkctx, md, NULL, pkey)) {
        return 0;
    }

    /*
     * We have to set the modified flag on the X509_REQ because
     * OpenSSL keeps a cached copy of the DER encoded data in some
     * cases.  Setting this flag tells OpenSSL to run the ASN
     * encoding again rather than using the cached copy.
     */
    x->req_info->enc.modified = 1; 
    ossl_rv = X509_REQ_sign_ctx(x, &mctx);

    EVP_MD_CTX_cleanup(&mctx);

    return (ossl_rv);
}
/*
 * populate_x509_request will build an x509 request buffer.  It does this by
 * calls into OpenSSL to insert the fields of the x509 header.
 *
 * Parameters:
 *	req:	pointer to the buffer that is to hold the x509 reauest header
 *	pkey:   public key to be placed into the x509 request
 *	cn:     Common Name to be placed into the x509 request
 *      cp:     challenge password to be placed into the x509 header
 *
 * Return value:
 *	EST_ERR_NONE if success
 */
static EST_ERROR populate_x509_request (EST_CTX *ctx, X509_REQ *req, EVP_PKEY *pkey, 
					char *cn, char *cp)
{
    X509_NAME *subj;


    /* setup version number */
    if (!X509_REQ_set_version(req, 0L)) {
        EST_LOG_ERR("Unable to set X509 version");
	ossl_dump_ssl_errors();
        return (EST_ERR_X509_VER);
    }

    /*
     * Add Common Name entry
     */
    subj = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                    (unsigned char*)cn, -1, -1, 0)) {
        EST_LOG_ERR("Unable to set X509 common name");
	ossl_dump_ssl_errors();
        return (EST_ERR_X509_CN);
    }

    /*
     * Add challengePassword attribute if required
     * No need to remove/add attributes here, only the PoP is
     * part of the simple enroll flow.
     */
    if (ctx->csr_pop_required || ctx->client_force_pop) {
	EST_LOG_INFO("Client will include challengePassword in CSR");
        if (!X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword,
                                       MBSTRING_ASC, (unsigned char*)cp, -1)) {
            EST_LOG_ERR("Unable to set X509 challengePassword attribute");
	    ossl_dump_ssl_errors();
            return (EST_ERR_X509_ATTR);
        }
    }
    /*
     * Set the public key on the request
     */
    if (!X509_REQ_set_pubkey(req, pkey)) {
        EST_LOG_ERR("Unable to set public key");
	ossl_dump_ssl_errors();
        return (EST_ERR_X509_PUBKEY);
    }

    return (EST_ERR_NONE);
}


/*
 * This function will generate a PKCS10 request.
 *
 * Parameters:
 *	cn:	Common Name to put into the certificate.
 *	cp:     TLS unique ID for the SSL session, becomes the challenge password
 *	pkey:	Private key to use for signing the request.
 *
 * Return value:
 *	EST_ERR_NONE if success
 */
static EST_ERROR est_generate_pkcs10 (EST_CTX *ctx, char *cn, char *cp, 
	                              EVP_PKEY *pkey, X509_REQ **pkcs10)
{
    X509_REQ *req = NULL;
    EST_ERROR rv;
    int ossl_rv = 0;

    req = X509_REQ_new();
    if (req == NULL) {
        EST_LOG_ERR("Unable to allocate X509_REQ");
        ossl_dump_ssl_errors();
        return (EST_ERR_MALLOC);
    }

    rv = populate_x509_request(ctx, req, pkey, cn, cp);
    if (rv != EST_ERR_NONE) {
        X509_REQ_free(req);
        return (rv);
    }

    /*
     * Sign the request
     */
    ossl_rv = est_client_X509_REQ_sign(req, pkey, ctx->signing_digest);
    if (!ossl_rv) {
        EST_LOG_ERR("Unable to sign X509 cert request");
        X509_REQ_free(req);
        ossl_dump_ssl_errors();
        return (EST_ERR_X509_SIGN);
    }

    *pkcs10 = req;

    return (EST_ERR_NONE);
}


/*
 * This function is a callback used by OpenSSL's verify_cert function.
 * It's called at the end of a cert verification to allow an opportunity to
 * gather more information regarding a failing cert verification, and to
 * possibly change the result of the verification.
 *
 * This callback is similar to the ossl routine, but does not alter
 * the verification result.
 */
// TODO simplify ossl_verify_cb() by calling this function, removing code overlap
static int est_client_cacert_verify_cb (int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    EST_LOG_INFO("enter function: ok=%d cert_error=%d", ok, cert_error);

    if (!ok) {
        EST_LOG_INFO("%svalidation error=%d (%s) at depth=%d; cert subject='%s', issuer='%s",
                     X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
                     cert_error,
                     X509_verify_cert_error_string(cert_error),
                     X509_STORE_CTX_get_error_depth(ctx),
		     current_cert ? current_cert->name : "(no cert)" ,
		     current_cert ? X509_NAME_oneline(X509_get_issuer_name(current_cert), NULL, 0) : "(no cert)");
    }
    return (ok);
}


/*
 * This function will remove CRLs from a received cacert response buffer.
 *
 * Parameters:
 *	ctx:	EST Context representing this session
 *  cacerts:    pointer to the buffer holding the resulting CA certs 
 *  cacerts_len: length of the cacerts buffer
 *       p7:    pointer to the pkcs7 buffer that was received
 *
 * Return value:
 *	EST_ERR_NONE if success
 
 */
static EST_ERROR est_client_remove_crls (EST_CTX *ctx, unsigned char *cacerts,
                                         int *cacerts_len, PKCS7 *p7)
{
    int nid = 0;
    int crls_found = 0;
    BIO *b64_enc = NULL;
    BIO *p7bio_out = NULL;
    int new_cacerts_len = 0;
    char *new_cacerts_buf = NULL;
    int count = 0;    
    
    nid=OBJ_obj2nid(p7->type);
    switch (nid)
        {
        case NID_pkcs7_signed:
            if (p7->d.sign->crl) {
                sk_X509_CRL_pop_free(p7->d.sign->crl, X509_CRL_free);
                p7->d.sign->crl = NULL;
                crls_found = 1;
            }
            break;
        case NID_pkcs7_signedAndEnveloped:
            if (p7->d.signed_and_enveloped->crl) {
                sk_X509_CRL_pop_free(p7->d.signed_and_enveloped->crl, X509_CRL_free);
                p7->d.sign->crl = NULL;
                crls_found = 1;
            }
            break;
        default:
            EST_LOG_ERR("Invalid NID value on PKCS7 structure");
            return (EST_ERR_CACERT_VERIFICATION);            
            break;
        }

    /*
     * If CRLs were removed, then the original PKCS7 buffer needs to be
     * updated.  This will always be base64 encoded.
     * - Allocate the BIOs,
     * - Write the PKCS7 struct back into PEM format,
     * - Get the pointer and length to the new base64 PEM encoded buffer,
     * - and then copy it into the original buffer that was passed in.
     * Since the CRLs are being removed, the new buffer will always be shorter
     * and will fit into the original buffer.
     */
    if (crls_found) {

        EST_LOG_INFO("CRL(s) attached with the CA Certificates.  Removing CRL(s)");
        
        b64_enc = BIO_new(BIO_f_base64());
        if (b64_enc == NULL) {
            EST_LOG_ERR("BIO_new failed");
            ossl_dump_ssl_errors();
            return(EST_ERR_MALLOC);
        }
        p7bio_out = BIO_new(BIO_s_mem());
        if (p7bio_out == NULL) {
            EST_LOG_ERR("Unable to access the CA cert buffer");
            ossl_dump_ssl_errors();
            return(EST_ERR_MALLOC);
        }
        p7bio_out = BIO_push(b64_enc, p7bio_out);
        
        memset(cacerts, 0, *cacerts_len);
        
        count = i2d_PKCS7_bio(p7bio_out, p7);
        if (count == 0) {
            EST_LOG_ERR("PEM_write_bio_PKCS7 failed");
            ossl_dump_ssl_errors();
            BIO_free_all(p7bio_out);            
            return (EST_ERR_CACERT_VERIFICATION);
        }
        (void)BIO_flush(p7bio_out);

        /*
         * BIO_get_mem_data just returns the pointer and length to the data
         * contained in the mem BIO.  Nothing is allocated and passed back
         */
        new_cacerts_len = (int) BIO_get_mem_data(p7bio_out, (char**)&new_cacerts_buf);
        if (new_cacerts_len <= 0) {
            EST_LOG_ERR("Failed to copy PKCS7 data");
            ossl_dump_ssl_errors();
            BIO_free_all(p7bio_out);            
            return (EST_ERR_CACERT_VERIFICATION);
        }
        /*
         * copy the new buffer back into the old buffer
         */
        memcpy(cacerts, new_cacerts_buf, new_cacerts_len);
        *cacerts_len = new_cacerts_len;
    }

    BIO_free_all(p7bio_out);

    return EST_ERR_NONE;
}

/*
 * This function will decode the passed base64 encoded buffer and return the
 * decoded cacerts. If returning EST_ERR_NONE, caller is responsible for
 * freeing the cacerts_decoded buffer
 */
static EST_ERROR b64_decode_cacerts (unsigned char *cacerts, int *cacerts_len,
                                     unsigned char **cacerts_decoded,
                                     int *cacerts_decoded_len)
{
    BIO *in = NULL;
    BIO *b64 = NULL;
    unsigned char *decoded_buf;
    int decoded_buf_len;

    *cacerts_decoded = NULL;
    *cacerts_decoded_len = 0;
    
    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        EST_LOG_ERR("BIO_new failed");
        ossl_dump_ssl_errors();
        return (EST_ERR_MALLOC);
    }    
    /*
     * Decoding will always take up less than the original buffer.
     */
    in = BIO_new_mem_buf(cacerts, *cacerts_len);    
    if (in == NULL) {
        EST_LOG_ERR("Unable to access the CA cert buffer");
        ossl_dump_ssl_errors();
        BIO_free_all(b64);
        return (EST_ERR_MALLOC);
    }
    in = BIO_push(b64, in);    
    decoded_buf = (unsigned char *)malloc(*cacerts_len);
    if (decoded_buf == NULL) {
        EST_LOG_ERR("Unable to allocate CA cert buffer for decode");
        BIO_free_all(in);        
        return (EST_ERR_MALLOC);        
    }
    
    decoded_buf_len = BIO_read(in, decoded_buf, *cacerts_len);
    
    *cacerts_decoded = decoded_buf;
    *cacerts_decoded_len = decoded_buf_len;

    BIO_free_all(in);
    
    return (EST_ERR_NONE);
}

/*
 * If returning EST_ERR_NONE, caller is responsible for freeing the PKCS7 struct
 */
static EST_ERROR create_PKCS7 (unsigned char *cacerts_decoded, int cacerts_decoded_len,
                               PKCS7 **pkcs7out)
{
    BIO *p7bio_in = NULL;
    PKCS7 *pkcs7 = NULL;

    /*
     * Now get the PKCS7 formatted buffer of certificates read into a stack of
     * X509 certs
     */
    p7bio_in = BIO_new_mem_buf(cacerts_decoded, cacerts_decoded_len);
    if (p7bio_in == NULL) {
        EST_LOG_ERR("Unable to access the PKCS7 buffer");
        ossl_dump_ssl_errors();
        return (EST_ERR_MALLOC);
    }
        
    pkcs7 = d2i_PKCS7_bio(p7bio_in,NULL);

    if (pkcs7 == NULL) {
        EST_LOG_ERR("Unable to read in PKCS7 based certificate buffer");
        ossl_dump_ssl_errors();
        BIO_free_all(p7bio_in);   
        return (EST_ERR_LOAD_CACERTS);
    }

    BIO_free_all(p7bio_in);
    *pkcs7out = pkcs7;
    return EST_ERR_NONE;    
}


static EST_ERROR PKCS7_to_stack (PKCS7 *pkcs7, STACK_OF(X509) **stack) 
{
    int nid = 0;

    nid=OBJ_obj2nid(pkcs7->type);
    switch (nid)
        {
        case NID_pkcs7_signed:
            *stack = pkcs7->d.sign->cert;
            break;
        case NID_pkcs7_signedAndEnveloped:
            *stack = pkcs7->d.signed_and_enveloped->cert;
            break;
        default:
            EST_LOG_ERR("Invalid NID value on PKCS7 structure");
            return (EST_ERR_CACERT_VERIFICATION);
            break;
        }

    if (*stack == NULL) {
        EST_LOG_ERR("X509 certs not found within PKCS7 buffer");
        return (EST_ERR_CACERT_VERIFICATION);
    }

    return EST_ERR_NONE;    
}


/*
 * This function is invoked when the CACerts response has been received.  The
 * cert chain is built into a cert store and then each certificate is verified
 * against this store essentially verifying the cert chain against itself to
 * ensure that each intermediate can be verified back to one of the included
 * root certs in the CACerts response.  If CRLs are attached these will be
 * removed and a new PKCS7 buffer is created.
 *
 * Parameters:
 *	ctx:	EST Context representing this session
 *  cacerts:    pointer to the buffer holding the received CA certs 
 *  cacerts_len: length of the cacerts buffer
 *
 * Return value:
 *	EST_ERR_NONE if success
 
 */
static EST_ERROR verify_cacert_resp (EST_CTX *ctx, unsigned char *cacerts,
                                     int *cacerts_len)
{
    EST_ERROR rv = EST_ERR_NONE;
    int failed = 0;
    
    X509_STORE  *trusted_cacerts_store = NULL;
    
    STACK_OF(X509) *stack = NULL;
    X509 *current_cert = NULL;
    int i;
    
    unsigned char *cacerts_decoded = NULL;
    int  cacerts_decoded_len = 0;

    X509_STORE_CTX *store_ctx = NULL;
    PKCS7 *pkcs7 = NULL;
    
    if (ctx == NULL || cacerts == NULL || cacerts_len == 0) {
        EST_LOG_ERR("Invalid parameter. ctx = %x cacerts = %x cacerts_len = %x",
                    ctx, cacerts, cacerts_len);
        return (EST_ERR_INVALID_PARAMETERS);
    }    

    /*
     * - Base64 decode the incoming ca certs buffer,
     * - convert to a PKCS7 structure,
     * - extract out the stack of certs.
     */
    rv = b64_decode_cacerts(cacerts, cacerts_len,
                            &cacerts_decoded, &cacerts_decoded_len);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Base64 decode of received CA certs failed");
        return (rv);
    }
    rv = create_PKCS7(cacerts_decoded, cacerts_decoded_len, &pkcs7);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to build PKCS7 structure from receievd buffer");
        free(cacerts_decoded);
        return (rv);
    }
    rv = PKCS7_to_stack(pkcs7, &stack);    
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Could not obtain stack of ca certs from PKCS7 structure");
        free(cacerts_decoded);
        PKCS7_free(pkcs7);
        return (rv);
    }
    
    /*
     * At this point we have the stack of X509 certs that make up
     * the CA certs response sent from the EST server.
     * - Build a store of "trusted" certs to use in the verify
     * - walk through each cert and verify it 
     *   - Build a store context from the store and the cert to be verified and
     *     call the verify function
     */
    trusted_cacerts_store = X509_STORE_new();
    if (trusted_cacerts_store == NULL) {
        EST_LOG_ERR("Unable to allocate cert store");
        ossl_dump_ssl_errors();
        
        free(cacerts_decoded);
        PKCS7_free(pkcs7);
        
        return (EST_ERR_MALLOC);
    }

    X509_STORE_set_verify_cb(trusted_cacerts_store, est_client_cacert_verify_cb);

    for (i=0; i<sk_X509_num(stack); i++) {
        current_cert = sk_X509_value(stack, i);

        /*
         * Is it self signed?  If so, add it in the trusted store, otherwise,
         * add it to the untrusted store.
         */
	if (X509_check_issued(current_cert, current_cert) == X509_V_OK) {
            EST_LOG_INFO("Adding cert to trusted store (%s)", current_cert->name);
            X509_STORE_add_cert(trusted_cacerts_store, current_cert);
        }
    }

    /*
     * set up a X509 Store Context
     */
    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
        EST_LOG_ERR("Unable to allocate a new store context");
        ossl_dump_ssl_errors();
        
        free(cacerts_decoded);
        PKCS7_free(pkcs7);
        X509_STORE_free(trusted_cacerts_store);
        
        return(EST_ERR_MALLOC);
    }

    for (i=0; i<sk_X509_num(stack); i++) {

        if (!X509_STORE_CTX_init(store_ctx, trusted_cacerts_store, NULL, stack)) {
            EST_LOG_ERR("Unable to initialize the new store context");
            ossl_dump_ssl_errors();

            free(cacerts_decoded);
            PKCS7_free(pkcs7);
            X509_STORE_free(trusted_cacerts_store);
            X509_STORE_CTX_free(store_ctx);
            
            return ( EST_ERR_MALLOC);
        }
        current_cert = sk_X509_value(stack, i);
        EST_LOG_INFO("Adding cert to store (%s)", current_cert->name);
	X509_STORE_CTX_set_cert(store_ctx, current_cert);
        
        if (!X509_verify_cert(store_ctx)) {
            /*
             * this cert failed verification.  Log this and continue on
             */
            EST_LOG_WARN("Certificate failed verification (%s)", current_cert->name);
            failed = 1;
        }
    }

    /*
     * Finally, remove any CRLs that might be attached.
     */
    rv = est_client_remove_crls(ctx, cacerts, cacerts_len, pkcs7);

    free(cacerts_decoded);
    X509_STORE_free(trusted_cacerts_store);
    X509_STORE_CTX_free(store_ctx);
    PKCS7_free(pkcs7);
    
    if (failed) {
        return (EST_ERR_CACERT_VERIFICATION);
    } else {
        return rv;
    }
}


/*
 * This function is registered with SSL to be called during the verification
 * of each certificate in the server's identity cert chain.  The main purpose
 * is to look for the case where the cert could not be verified.  In this case,
 * if the EST client app has registered a callback to receive these untrusted
 * certs, it will be forwarded up to the EST client application.
 *
 * Parameters:
 *	ok:	The status of this certificate from the SSL verify code.
 *   x_ctx:     Ptr to the X509 certificate store structure  
 *
 * Return value:
 *   int: The potentially modified status after processing this certificate. This cane
 *        be modified by the ET client application if they've provided a callback
 *        allowing it to be processed, or modified here in this callback.
 */
static int cert_verify_cb (int ok, X509_STORE_CTX *x_ctx)
{
    SSL    *ssl;
    EST_CTX *e_ctx;
    int     approve;
    int cert_error = 0;
    X509 *current_cert = NULL;

    approve = ok;
    
    if (x_ctx == NULL) {
        EST_LOG_ERR("Invalid X509 context pointer");
        return (approve);
    }    
    
    cert_error = X509_STORE_CTX_get_error(x_ctx);
    current_cert = X509_STORE_CTX_get_current_cert(x_ctx);

    EST_LOG_INFO("entering: Cert passed up from OpenSSL. error = %d (%s) ",
                 cert_error, X509_verify_cert_error_string(cert_error));

    /*
     * Retrieve the pointer to the SSL structure for this connection and then
     * the application specific data stored into the SSL object.  This will be
     * our EST ctx for this EST session.
     */
    if (e_ctx_ssl_exdata_index == SSL_EXDATA_INDEX_INVALID) {
        EST_LOG_ERR("Invalid SSL exdata index for EST context value");
        return (approve);
    }
        
    ssl = (SSL *)X509_STORE_CTX_get_ex_data(x_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl) {
        EST_LOG_ERR("NULL pointer retrieved for SSL session pointer from X509 ctx ex_data");
        return (approve);
    }        
    e_ctx = (EST_CTX *)SSL_get_ex_data(ssl, e_ctx_ssl_exdata_index);
    if (!e_ctx) {
        EST_LOG_ERR("NULL pointer retrieved for EST context from SSL ex_data");
        return (approve);
    }        

    if (!ok) {
        switch (cert_error) {

            /*
             * Cases where we notify the client application:
             *
             * CERT_UNTRUSTED is what is expected, but not what we get in the
             * case where we cannot verify our server's cert.
             * SELF_SIGNED_CERT_IN_CHAIN is what currently results with our server
             * when we cannot verify its cert.
             * UNABLE_TO_GET_CRL is passed up to make sure the application knows
             * that although
             */
        case X509_V_ERR_CERT_UNTRUSTED:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:  
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            
            /*
             * If the application provided a callback then go ahead and pass
             * this cert store up.  If not, then log a warning and return what
             * SSL gave us for a status.
             */            
            if (e_ctx->manual_cert_verify_cb) {
                
                EST_LOG_INFO("EST client application server cert verify function is registered");

                approve = e_ctx->manual_cert_verify_cb(current_cert, cert_error);
                
            } else {
                                
                EST_LOG_INFO("NO EST client application server cert verify function registered");

                if (cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {

                    /*
                     * We've enabled CRL checking in the TLS stack.  If the
                     * application hasn't loaded a CRL, then this verify error
                     * can occur.  The peer's cert is valid, but we can't
                     * confirm if it was revoked.  The app has not provided
                     * a way for us to notify on this, so our only option is
                     * to log a warning and proceed on.
                     */
                    EST_LOG_WARN("No CRL loaded, TLS peer will be allowed.");
                    approve = 1;
                }
            }
            break;

        /* The remainder of these will result in the ok state remaining unchanged
         * and a EST log warning message being logged.
         */
        case X509_V_ERR_NO_EXPLICIT_POLICY:
        case X509_V_ERR_CERT_HAS_EXPIRED:

        /* since we are just checking the certificates, it is
         * ok if they are self signed. But we should still warn
         * the user.
         */
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        case X509_V_ERR_CERT_REVOKED:
        default:
            EST_LOG_WARN("Certificate verify failed (reason = %d) (%s)",
                         cert_error, X509_verify_cert_error_string(cert_error));
            break;
        }
    }
    return (approve);
}


/*
 * This function is used to create and initialize an
 * SSL_CTX that will be used for client and proxy EST operations.
 * The SSL_CTX is stored on the EST_CTX.
 *
 * Parameters:
 *	ctx:	EST Context
 *
 * Return value:
 *	EST_ERROR
 *         EST_ERR_NONE if success
 */
EST_ERROR est_client_init_ssl_ctx (EST_CTX *ctx)
{
    SSL_CTX     *s_ctx;
    X509_VERIFY_PARAM *vpm = NULL;
    EST_ERROR rv = EST_ERR_NONE;

    est_log_version();

    if (ctx == NULL) {
        EST_LOG_ERR("Invalid context pointer");
        return EST_ERR_NO_CTX;
    }
        
    if ((s_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        EST_LOG_ERR("Failed to obtain a new SSL Context");
        ossl_dump_ssl_errors();
        return EST_ERR_SSL_CTX_NEW;
    }

    /*
     * Only TLS 1.1 or above can be used for EST
     */
    SSL_CTX_set_options(s_ctx, SSL_OP_NO_SSLv2 |
                        SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_TLSv1);

    /*
     * limit the cipher suites that are offered
     */
    if (!SSL_CTX_set_cipher_list(s_ctx, EST_CIPHER_LIST)) { 
        EST_LOG_ERR("Failed to set SSL cipher suites");
        ossl_dump_ssl_errors();
        return EST_ERR_SSL_CIPHER_LIST;
    }

    /*
     * Make sure we're verifying the server
     */
    SSL_CTX_set_verify(s_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       cert_verify_cb);

    /*
     * leverage the cert store we already created from the
     * trusted CA chain provided by the application.
     *
     * In either case, the SSL stack will clean up the cert store during the
     * SSL_CTX_free(), so let's remove our reference to it so we don't try to
     * clean it up ourselves later
     */
    SSL_CTX_set_cert_store(s_ctx, ctx->trusted_certs_store);
    ctx->trusted_certs_store = NULL;        

    /*
     * Set up X509 params and assign them to the SSL ctx
     * - Enable CRL checks
     * - Max # of untrusted CA certs that can exist in a chain
     * - ensure that the cert is being used as intended, if
     *   it contains the X509 KeyUsage extension
     */
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == NULL) {
        EST_LOG_ERR("Unable to allocate a verify parameter structure");
        ossl_dump_ssl_errors();
        return (EST_ERR_MALLOC);
    }
        
    /* Enable CRL checks */
    if (ctx->enable_crl) {
	X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK |
                                    X509_V_FLAG_CRL_CHECK_ALL);
    }
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK |
                                X509_V_FLAG_CRL_CHECK_ALL);
    X509_VERIFY_PARAM_set_depth(vpm, EST_TLS_VERIFY_DEPTH);

    X509_VERIFY_PARAM_set_purpose(vpm, X509_PURPOSE_SSL_SERVER);

    SSL_CTX_set1_param(s_ctx, vpm);
    X509_VERIFY_PARAM_free(vpm);

    /*
     * Save the reference to the SSL session
     * This will be used later when matching the EST_CTX to the SSL context
     * in est_ssl_info_cb().
     */
    ctx->ssl_ctx = s_ctx;

    if (e_ctx_ssl_exdata_index == SSL_EXDATA_INDEX_INVALID) {
        e_ctx_ssl_exdata_index = SSL_get_ex_new_index(0, "EST Context", NULL, NULL, NULL);    
    }
    
    return rv;
}

/*
 * This function calculates the digest value to be
 * used in HTTP requests when the server has asked
 * the client to use HTTP digest authentication.
 * It uses the tokens that were parsed from the HTTP
 * server response earlier to calculate the digest.
 */
static unsigned char *est_client_generate_auth_digest (EST_CTX *ctx, char *uri,
                                                       char *user, char *pwd)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_md5();
    uint8_t ha1[EVP_MAX_MD_SIZE];
    unsigned int ha1_len;
    char ha1_str[EST_MAX_MD5_DIGEST_STR_LEN];
    uint8_t ha2[EVP_MAX_MD_SIZE];
    unsigned int ha2_len;
    char ha2_str[EST_MAX_MD5_DIGEST_STR_LEN];
    char nonce_cnt[9] = "00000001";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int d_len;
    unsigned char *result;

    /*
     * Calculate HA1 using username, realm, password, and server nonce
     */
    mdctx = EVP_MD_CTX_create();
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        EST_LOG_ERR("Unable to Initialize digest");
        return NULL;
    }
    EVP_DigestUpdate(mdctx, user, strnlen(user, MAX_UIDPWD));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ctx->realm, strnlen(ctx->realm, MAX_REALM));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, pwd, strnlen(pwd, MAX_UIDPWD));
    EVP_DigestFinal(mdctx, ha1, &ha1_len);
    EVP_MD_CTX_destroy(mdctx);
    est_hex_to_str(ha1_str, ha1, ha1_len);

    /*
     * Calculate HA2 using method, URI,
     */
    mdctx = EVP_MD_CTX_create();
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        EST_LOG_ERR("Unable to Initialize digest");
        return NULL;
    }
    EVP_DigestUpdate(mdctx, "POST", 4);
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, uri, strnlen(uri, MAX_REALM));
    EVP_DigestFinal(mdctx, ha2, &ha2_len);
    EVP_MD_CTX_destroy(mdctx);
    est_hex_to_str(ha2_str, ha2, ha2_len);

    /*
     * Calculate auth digest using HA1, nonce, nonce count, client nonce, qop, HA2
     */
    mdctx = EVP_MD_CTX_create();
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        EST_LOG_ERR("Unable to Initialize digest");
        return NULL;
    }
    EVP_DigestUpdate(mdctx, ha1_str, ha1_len * 2);
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ctx->s_nonce, strnlen(ctx->s_nonce, MAX_NONCE));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, nonce_cnt, strnlen(nonce_cnt, MAX_NC));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ctx->c_nonce, strnlen(ctx->c_nonce, MAX_NONCE));
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, "auth", 4);
    EVP_DigestUpdate(mdctx, ":", 1);
    EVP_DigestUpdate(mdctx, ha2_str, ha2_len * 2);
    EVP_DigestFinal(mdctx, digest, &d_len);
    EVP_MD_CTX_destroy(mdctx);

    result = (unsigned char *)malloc(EST_MAX_MD5_DIGEST_STR_LEN);
    if (result == NULL) {
        EST_LOG_ERR("Unable to allocate memory for digest");
        return NULL;
    }
    
    est_hex_to_str((char *)result, digest, d_len);
    return (result);
}

/*
 * est_client_retrieve_credentials() is used to retrieve the credentials when
 * the server has requested either BASIC or DIGEST mode.  The values needed from
 * the application layer in either mode are the same, username, password, but the
 * API will indicate the mode to the callback in case anything changes.
 */
static void est_client_retrieve_credentials (EST_CTX *ctx, EST_HTTP_AUTH_MODE auth_mode,
                                             char *user, char *pwd) 
{
    EST_HTTP_AUTH_HDR auth_credentials;
    EST_HTTP_AUTH_CRED_RC rc;
    
    /*
     * See if we only have one part of them.  If so, reset the part we
     * have.
     */
    if (ctx->userid[0] != '\0') {
        memset(ctx->userid, 0x0, sizeof(ctx->userid));
    }
            
    if (ctx->password[0] != '\0') {
        memset(ctx->password, 0x0, sizeof(ctx->password));
    }
                
    /*
     * Need to ask the application layer for the credentials
     */
    memset(&auth_credentials, 0x0, sizeof(auth_credentials));
            
    if (ctx->auth_credentials_cb) {
        auth_credentials.mode = auth_mode;
        rc = ctx->auth_credentials_cb(&auth_credentials);
        if (rc == EST_HTTP_AUTH_CRED_NOT_AVAILABLE) {
            EST_LOG_ERR("Attempt to obtain token from application failed.");
        }
    }

    /*
     * Did we get the credentials we expected?  If not, point to a NULL string
     * to generate the header
     */
    if (auth_credentials.user == NULL) {
        user[0] = '\0'; 
    } else if (MAX_UIDPWD < strnlen(auth_credentials.user, MAX_UIDPWD+1)) {
        EST_LOG_ERR("Userid provided is larger than the max of %d", MAX_UIDPWD);
        user[0] = '\0'; 
    } else {
        if (!strncpy(user, auth_credentials.user, MAX_UIDPWD)) {
            EST_LOG_ERR("Invalid User ID provided");
        }
    }
    
    if (auth_credentials.pwd == NULL) {
        pwd[0] = '\0'; 
    } else if (MAX_UIDPWD < strnlen(auth_credentials.pwd, MAX_UIDPWD+1)) {
        EST_LOG_ERR("Password provided is larger than the max of %d", MAX_UIDPWD);
        pwd[0] = '\0'; 
    } else {
        if (!strncpy(pwd, auth_credentials.pwd, MAX_UIDPWD)) {
            EST_LOG_ERR("Invalid User password provided");
        }
    }

    cleanse_auth_credentials(&auth_credentials);    
}

/*
 * This function adds the HTTP authentication header to
 * an outgoing HTTP request, allowing the server to
 * authenticate the EST client.
 *
 * Parameters:
 *	ctx:	    EST context
 *	hdr:        pointer to the buffer to hold the header
 *      uri:        pointer to a buffer that holds the uri to be used in the header
 */
static void est_client_add_auth_hdr (EST_CTX *ctx, char *hdr, char *uri)
{
    int hdr_len;
    unsigned char *digest;
    unsigned char client_random[8];
    char both[MAX_UIDPWD*2+2]; /* both UID and PWD + ":" + /0 */
    char both_b64[2*2*MAX_UIDPWD];
    EST_HTTP_AUTH_HDR auth_credentials;
    EST_HTTP_AUTH_CRED_RC rc;
    char *token = NULL;
    char token_b64[MAX_AUTH_TOKEN_LEN*2];
    char user[MAX_UIDPWD];
    char pwd[MAX_UIDPWD];
    
    hdr_len = (int) strnlen(hdr, EST_HTTP_REQ_TOTAL_LEN);
    if (hdr_len == EST_HTTP_REQ_TOTAL_LEN) {
        EST_LOG_WARN("Authentication header took up the maximum amount in buffer (%d)",
                     EST_HTTP_REQ_TOTAL_LEN);
    }
    
    switch (ctx->auth_mode) {
    case AUTH_BASIC:
        /*
         * make sure we have both parts of the credentials to send.  If we do,
         * then we're operating in the original mode where the app layer
         * provides them up front before they're needed.  If not, then we can
         * now go ask for them from the app layer.
         */
        if (ctx->userid[0] == '\0' && ctx->password[0] == '\0') {

            memset(user, 0, MAX_UIDPWD);
            memset(pwd, 0, MAX_UIDPWD);
            
            est_client_retrieve_credentials(ctx, ctx->auth_mode, user, pwd);

	    /*
	     *If valid userID and password are returned by the application continue building
	     *the HTTP auth header. Otherwise, point the header to a NULL string since
	     *it is not capable of Basic/Digest authentication 
	     */
	    if ((user[0] == '\0' || pwd[0] == '\0') && !(ctx->client_cert)){
	      /*Force hdr to a null string */
	      EST_LOG_ERR("No User ID or Password was provided, not trying another enrollment attempt.");
	      memset(hdr, 0, EST_HTTP_REQ_TOTAL_LEN);	  
	      break;
	    }
            
            /*
             * If a user ID and password are returned, build the string containing both
             */            
            snprintf(both, MAX_UIDPWD*2+2, "%s:%s", user, pwd);
        } else {
            /*
             * Use what was given during configuration through est_client_set_auth
             */
            snprintf(both, MAX_UIDPWD*2+2, "%s:%s", ctx->userid,
                     ctx->password);
        }				    
	  
	  /*
	   * base64 encode the combined string and build the HTTP auth header
	   */
	  est_base64_encode((const unsigned char *)both, strnlen(both, 2*MAX_UIDPWD), both_b64);
	  snprintf(hdr + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len,
		   "Authorization: Basic %s\r\n", both_b64);
	  break;
    
    case AUTH_DIGEST:

        /* Generate a client nonce */
        if (!RAND_bytes(client_random, 8)) {
            EST_LOG_ERR("RNG failure while generating nonce");
            /* Force hdr to a null string */
            memset(hdr, 0, EST_HTTP_REQ_TOTAL_LEN);
            break;
        }
        
        est_hex_to_str(ctx->c_nonce, client_random, 8);

        /*
         * Check to see if the application layer has provided username and password
         * up front during configuration.  If it has not, go retrieve them now, otherwise,
         * copy them into the local buffers to get them ready
         */
        if (ctx->userid[0] == '\0' || ctx->password[0] == '\0') {

            memset(user, 0, MAX_UIDPWD);
            memset(pwd, 0, MAX_UIDPWD);
            
            est_client_retrieve_credentials(ctx, ctx->auth_mode, user, pwd);

	    /*Check to make sure a valid userID and pwd was provided. If not point hdr to a null string*/
	    if ((user[0] == '\0' || pwd[0] == '\0') && !(ctx->client_cert)){
     	      EST_LOG_ERR("No User ID or Password was provided, not trying another enrollment attempt.");
	      /*Force hdr to a null string */
	      memset(hdr, 0, EST_HTTP_REQ_TOTAL_LEN);	    
	      break;
	    }
        } else {
            if (!strncpy(user, ctx->userid, MAX_UIDPWD)) {
                EST_LOG_ERR("Invalid User ID provided");
            }
            if (!strncpy(pwd, ctx->password, MAX_UIDPWD)) {
                EST_LOG_ERR("Invalid User password provided");
            }
        }
        
        digest = est_client_generate_auth_digest(ctx, uri, user, pwd);
        if (digest == NULL) {
            EST_LOG_ERR("Error while generating digest");
            /* Force hdr to a null string */
            memset(hdr, 0, EST_HTTP_REQ_TOTAL_LEN);
            memset(ctx->c_nonce, 0, MAX_NONCE);
            memset(user, 0, MAX_UIDPWD);
            memset(pwd, 0, MAX_UIDPWD);
            break;
        }
            
        snprintf(hdr + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len,
                 "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", cnonce=\"%s\", nc=00000001, qop=\"auth\", response=\"%s\"\r\n",
                user,
                ctx->realm,
                ctx->s_nonce,
                uri,
                ctx->c_nonce,
                digest);
        memset(digest, 0, EST_MAX_MD5_DIGEST_STR_LEN);
        memset(ctx->c_nonce, 0, MAX_NONCE);
        memset(user, 0, MAX_UIDPWD);
        memset(pwd, 0, MAX_UIDPWD);
        free(digest);
        break;
    case AUTH_TOKEN:
        
        EST_LOG_INFO("Server requested Token based authentication");

        memset(&auth_credentials, 0x0, sizeof(auth_credentials));
        
        if (ctx->auth_credentials_cb) {    
            auth_credentials.mode = AUTH_TOKEN;
            rc = ctx->auth_credentials_cb(&auth_credentials);
            if (rc == EST_HTTP_AUTH_CRED_NOT_AVAILABLE) {
                EST_LOG_ERR("Attempt to obtain token from application failed.");
            }
        }

        /*
         * Did we get the credentials we expected?  If not, point to a NULL string
         * to generate the header
         */
        if (auth_credentials.auth_token == NULL) {
            EST_LOG_ERR("Requested token credentials, but application did not provide any.");
            token = "";
        } else {

            /*
             * Make sure the token we were given is not too long.
             * If it is, force it to NULL to cause the auth failure at
             * the server just as if no credentials were provided
             */
            if (MAX_AUTH_TOKEN_LEN < strnlen(auth_credentials.auth_token, MAX_AUTH_TOKEN_LEN+1)) {
                EST_LOG_ERR("Token provided is larger than the max of %d",
                            MAX_AUTH_TOKEN_LEN);
                token = "";
            } else {
                token = auth_credentials.auth_token;
            }
        }


	/*If the token is not valid, point hdr to a null string*/
	if((strncmp(token, "", MAX_AUTH_TOKEN_LEN) == 0) && !(ctx->client_cert)){
	  /* Force hdr to a null string */	  
	  EST_LOG_ERR("No valid token was provided, not trying another enrollment attempt.");
	  memset(hdr, 0, EST_HTTP_REQ_TOTAL_LEN);
	  break;
	}

      /*
       * base64 encode the combined string and build the HTTP auth header
       */

	memset(token_b64, 0, MAX_AUTH_TOKEN_LEN*2);
        est_base64_encode((const unsigned char *)token, strnlen(token, MAX_AUTH_TOKEN_LEN), token_b64);
	
        snprintf(hdr + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len,
                 "Authorization: Bearer %s\r\n", token_b64);

        cleanse_auth_credentials(&auth_credentials);
        
        break;
    default:
        EST_LOG_INFO("No HTTP auth mode set, sending anonymous request");
        break;
    }
}


/*
 * This function is used to build the HTTP header for
 * the CAcerts request flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	hdr:        pointer to the buffer to hold the header
 */
static int est_client_build_cacerts_header (EST_CTX *ctx, char *hdr)
{
    int hdr_len;

    snprintf(hdr, EST_HTTP_REQ_TOTAL_LEN, "GET %s HTTP/1.1\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n",
            EST_CACERTS_URI,
            EST_HTTP_HDR_EST_CLIENT,
            ctx->est_server, ctx->est_port_num);
    hdr_len = (int) strnlen(hdr, EST_HTTP_REQ_TOTAL_LEN);
    if (hdr_len == EST_HTTP_REQ_TOTAL_LEN) {
        EST_LOG_WARN("CA Certs header took up the maximum amount in buffer (%d)",
                     EST_HTTP_REQ_TOTAL_LEN);
    }
    
    return (hdr_len);
}

/*
 * This function is used to build the HTTP header for
 * the CSR attributes request flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	hdr:        pointer to the buffer to hold the header
 */
static int est_client_build_csr_header (EST_CTX *ctx, char *hdr)
{
    int hdr_len;

    snprintf(hdr, EST_HTTP_REQ_TOTAL_LEN,"GET %s HTTP/1.1\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n",
            EST_CSR_ATTRS_URI,
            EST_HTTP_HDR_EST_CLIENT,
            ctx->est_server, ctx->est_port_num);
    est_client_add_auth_hdr(ctx, hdr, EST_SIMPLE_ENROLL_URI);
    hdr_len = (int) strnlen(hdr, EST_HTTP_REQ_TOTAL_LEN);
    if (hdr_len == EST_HTTP_REQ_TOTAL_LEN) {
        EST_LOG_WARN("CSR attributes request header took up the maximum amount in buffer (%d)",
                     EST_HTTP_REQ_TOTAL_LEN);
    }
    return (hdr_len);
}


/*
 * This function does the work for the CSR attributes request flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	ssl:	    SSL context
 */
static EST_ERROR est_client_send_csrattrs_request (EST_CTX *ctx, SSL *ssl,
					     unsigned char **csrattrs, 
					     int *csrattrs_len)
{
    char        *http_data;
    int hdr_len;
    int read_size, write_size;
    unsigned char *csr_attrs_buf = NULL;
    EST_ERROR rv;

    /* assume defeat */
    *csrattrs = NULL;
    *csrattrs_len = 0;
    /*
     * Build the HTTP request
     * - allocate buffer: header, no data, terminating characters
     * - build the header
     * - no data
     * - terminate it
     */    
    http_data = (char *)malloc(EST_HTTP_REQ_TOTAL_LEN);
    if (http_data == NULL) {
        EST_LOG_ERR("Unable to allocate memory for http_data");
        return EST_ERR_MALLOC;
    }
    
    hdr_len = est_client_build_csr_header(ctx, http_data);

    if (hdr_len == 0) {
        EST_LOG_ERR("CSR attributes HTTP header could not be built correctly");
        free(http_data);
        return (EST_ERR_HTTP_CANNOT_BUILD_HEADER);
    }    

    /*
     * terminate the HTTP header
     */
    snprintf(http_data + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len, "\r\n");
    hdr_len += 2;

    /*
     * no data is being sent so go ahead and terminate the HTTP request
     */
    snprintf(http_data + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len, "\r\n");
    hdr_len += 2;


    /*
     * Send the request to the server and wait for a response
     */
    write_size = SSL_write(ssl, http_data, hdr_len);
    if (write_size < 0) {
        EST_LOG_ERR("TLS write error");
	ossl_dump_ssl_errors();
        rv = EST_ERR_SSL_WRITE;
    } else {
        EST_LOG_INFO("TLS wrote %d bytes, attempted %d bytes",
                     write_size, hdr_len);

	/*
         * Try to get the response from the server
         */
        rv = est_io_get_response(ctx, ssl, EST_GET_CSRATTRS,
                                 &csr_attrs_buf, &read_size);
        switch (rv) {
        case EST_ERR_NONE:
	    if (csr_attrs_buf != NULL) {
		*csrattrs = csr_attrs_buf;
		*csrattrs_len = read_size;
            }
            break;
        case EST_ERR_AUTH_FAIL:
        default:
            EST_LOG_ERR("EST request failed: %d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
	    if (csr_attrs_buf) {
                free(csr_attrs_buf);
            }
            break;
        }
    }
    free(http_data);
    return (rv);
}

/*
 * This function is used to build the HTTP header for
 * the Simple Enroll flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	hdr:        pointer to the buffer to hold the header
 *      pkcs10_len: length of the buffer pointed to by hdr 
 *
 * Return value:
 *	Length of the header built, or 0 on error
 */
static int est_client_build_enroll_header (EST_CTX *ctx, char *hdr, int pkcs10_len)
{
    int hdr_len;

    snprintf(hdr, EST_HTTP_REQ_TOTAL_LEN, "POST %s HTTP/1.1\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n"
            "Content-Type: application/pkcs10\r\n"
            "Content-Length: %d\r\n",
            EST_SIMPLE_ENROLL_URI,
            EST_HTTP_HDR_EST_CLIENT,
            ctx->est_server, ctx->est_port_num, pkcs10_len);
    est_client_add_auth_hdr(ctx, hdr, EST_SIMPLE_ENROLL_URI);
    hdr_len = (int) strnlen(hdr, EST_HTTP_REQ_TOTAL_LEN);
    if (hdr_len == EST_HTTP_REQ_TOTAL_LEN) {
        EST_LOG_WARN("Client enroll request header took up the maximum amount in buffer (%d)",
                     EST_HTTP_REQ_TOTAL_LEN);
    }
    
    return (hdr_len);
}

/*
 * This function is used to build the HTTP header for
 * the Simple ReEnroll flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	hdr:        pointer to the buffer to hold the header
 *      pkcs10_len: length of the buffer pointed to by hdr 
 *
 * Return value:
 *	Length of the header built, or 0 on error
 */
static int est_client_build_reenroll_header (EST_CTX *ctx, char *hdr, int pkcs10_len)
{
    int hdr_len;

    snprintf(hdr, EST_HTTP_REQ_TOTAL_LEN, "POST %s HTTP/1.1\r\n"
            "User-Agent: %s\r\n"
            "Connection: close\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n"
            "Content-Type: application/pkcs10\r\n"
            "Content-Length: %d\r\n",
            EST_RE_ENROLL_URI,
            EST_HTTP_HDR_EST_CLIENT,
            ctx->est_server, ctx->est_port_num, pkcs10_len);
    est_client_add_auth_hdr(ctx, hdr, EST_SIMPLE_ENROLL_URI);
    hdr_len = (int) strnlen(hdr, EST_HTTP_REQ_TOTAL_LEN);
    if (hdr_len == EST_HTTP_REQ_TOTAL_LEN) {
        EST_LOG_WARN("Client reenroll request header took up the maximum amount in buffer (%d)",
                     EST_HTTP_REQ_TOTAL_LEN);
    }
    return (hdr_len);
}

/*
 * This function sends the HTTP request for a Simple Enroll
 * The CSR (pkcs10) is already built at this point.  This
 * function simply creates the HTTP header and body and puts
 * it on the wire.  It then waits for a response from the
 * server and copies the response to a buffer provided by
 * the caller
 *
 * Parameters:
 *	ctx:	    EST context
 *	ssl:	    SSL context
 *	bptr:	    pointer containing PKCS10 CSR
 *	pkcs7:	    pointer that will receive the pkcs7 response
 *	pkcs7_len:  length of pkcs7 response
 *	reenroll:   Set to 1 to do a reenroll instead of an enroll
 *
 */
EST_ERROR est_client_send_enroll_request (EST_CTX *ctx, SSL *ssl, BUF_MEM *bptr,
                                    unsigned char *pkcs7, int *pkcs7_len,
				    int reenroll)
{
    char *http_data;
    int hdr_len;
    int write_size;
    unsigned char *enroll_buf = NULL;
    int enroll_buf_len = 0;
    EST_ERROR rv;

    /*
     * Assume the enroll will fail, set return length to zero
     * to be defensive.
     */
    *pkcs7_len = 0;

    /*
     * Build the HTTP request
     * - allocate buffer: header, data, terminating characters
     * - build the header
     * - no data
     * - terminate it
     */    
    http_data = (char *)malloc(EST_HTTP_REQ_TOTAL_LEN);
    if (http_data == NULL) {
        EST_LOG_ERR("Unable to allocate memory for http_data");
        return EST_ERR_MALLOC;
    }

    if (!reenroll) {
	/* Perform a /simpleenroll */
        hdr_len = est_client_build_enroll_header(ctx, http_data, (int) bptr->length);
    } else {
	/* Perform a /simplereenroll */
        hdr_len = est_client_build_reenroll_header(ctx, http_data, (int) bptr->length);
    }

    if (hdr_len == 0) {
        EST_LOG_ERR("Enroll HTTP header could not be built correctly");
        free(http_data);
        return (EST_ERR_HTTP_CANNOT_BUILD_HEADER);
    }
        
    /*
     * terminate the HTTP header
     */
    snprintf(http_data + hdr_len,EST_HTTP_REQ_TOTAL_LEN-hdr_len, "\r\n");
    hdr_len += 2;

    /*
     * Build the HTTP body containing the pkcs10 request
     */
    memcpy(http_data + hdr_len, bptr->data, bptr->length);
    hdr_len += bptr->length;

    /*
     * terminate the HTTP request
     */
    snprintf(http_data + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len,"\r\n");
    hdr_len += 2;


    /*
     * Send the request to the server and wait for a response
     */
    write_size = SSL_write(ssl, http_data, hdr_len);
    if (write_size < 0) {
        EST_LOG_ERR("TLS write error");
	ossl_dump_ssl_errors();
        rv = EST_ERR_SSL_WRITE;
    } else {
        EST_LOG_INFO("TLS wrote %d bytes, attempted %d bytes",
                     write_size, hdr_len);

        /*
         * Try to get the response from the server
         */
        rv = est_io_get_response(ctx, ssl, EST_SIMPLE_ENROLL,
                                 &enroll_buf, &enroll_buf_len);
        switch (rv) {
        case EST_ERR_NONE:
            memcpy(pkcs7, enroll_buf, enroll_buf_len);
            *pkcs7_len = enroll_buf_len;
            break;
        case EST_ERR_AUTH_FAIL:
            EST_LOG_WARN("HTTP auth failure");
            break;
        case EST_ERR_CA_ENROLL_RETRY:
            EST_LOG_INFO("EST request failed with a RETRY AFTER resp");
            break;
        default:
	    EST_LOG_ERR("EST request failed: %d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
            break;
        }
        free(enroll_buf);
    }
    OPENSSL_cleanse(http_data, strnlen(http_data, EST_HTTP_REQ_TOTAL_LEN));
    free(http_data);
    http_data = NULL;
    return (rv);
}

/*
 * This function does a sanity check on the X509
 * prior to attempting to convert the X509 to
 * a CSR for a reenroll operation.
 *
 * Returns an EST_ERROR code
 */
static EST_ERROR est_client_check_x509 (X509 *cert) 
{
    /*
     * Make sure the cert is signed
     */
    if(!cert->signature) {
	EST_LOG_ERR("The certificate provided does not contain a signature.");
	return (EST_ERR_BAD_X509);
    }

    /*
     * Make sure the signature length is not invalid 
     */
    if (cert->signature->length <= 0) {
	EST_LOG_ERR("The certificate provided contains an invalid signature length.");
	return (EST_ERR_BAD_X509);
    }
    return (EST_ERR_NONE);
}

/*
 * This function does a sanity check on the CSR
 * prior to attempting to use the CSR for a
 * simple enroll operation.
 *
 * Returns an EST_ERROR code
 */
static EST_ERROR est_client_check_csr (X509_REQ *csr) 
{
    /*
     * Attempt to get the signature on the CSR
     */
    if(csr->signature && csr->signature->length > 0) {
	EST_LOG_ERR("The CSR provided was already signed.  libest will only accept an unsigned CSR since libest performs the signing operation on the CSR.");
	return (EST_ERR_CSR_ALREADY_SIGNED);
    }
    return (EST_ERR_NONE);
}

/*
 * This function is used to clear any ChallengePassword
 * attributes in an X509 CSR.  This is used because when
 * HTTP authentication is used during the enrollment
 * process, the PoP value will change when the client
 * sends the second HTTP request that contains the HTTP
 * authorization values. Since the CSR is reused between
 * both the initial and secondary requests, we need to
 * clear the PoP value from the CSR before submitting
 * the secondary request.
 */
static void est_client_clear_csr_pop (X509_REQ *csr)
{
    int pos = 0;
    X509_ATTRIBUTE *attr;

    /*
     * The challenge password (PoP) may be in the CSR 
     * more than once.  This should never happen, but
     * we're being defensive.
     */
    while (pos >= 0) {
	/*
	 * Look for the PoP value in the CSR 
	 */
	pos = X509_REQ_get_attr_by_NID(csr, NID_pkcs9_challengePassword, -1);
	if (pos >= 0) {
	    /* 
	     * If found, delete it
	     */
	    attr = X509_REQ_delete_attr(csr, pos);
	    if (attr) {
		/*
		 * There are no docs in OpenSSL that show how
		 * to use X509_REQ_delete_attr.  Going to assume
		 * we need to free the attribute ourselves.  There
		 * do not appear to be any good examples on how
		 * to use this API.
		 */
		X509_ATTRIBUTE_free(attr);
	    }
	}
    }
}


/*
 * This function does the work of converting the X509_REQ* to
 * the base64 encoded DER format as specified in the EST RFC.
 * Once converted to the proper format, this routine will
 * forward the request to the server, check the response,
 * and save the cert on the local context where it can be
 * retrieved later by the application layer.
 */
static EST_ERROR est_client_enroll_req (EST_CTX *ctx, SSL *ssl, X509_REQ *req, 
	                                int *pkcs7_len, int reenroll)
{
    EST_ERROR    rv = EST_ERR_NONE;
    BIO         *p10out = NULL, *b64;
    BUF_MEM     *bptr = NULL;
    unsigned char *recv_buf;
    unsigned char *new_cert_buf;
    int          new_cert_buf_len;

    /*
     * Grab the PKCS10 PEM encoded data
     */
    b64 = BIO_new(BIO_f_base64());
    p10out = BIO_new(BIO_s_mem());
    if (!p10out) {
        EST_LOG_ERR("BIO_new failed");
	ossl_dump_ssl_errors();
        return EST_ERR_MALLOC;
    }
    p10out = BIO_push(b64, p10out);

    /*
     * Encode using DER (ASN.1) 
     */
    req->req_info->enc.modified = 1; 
    i2d_X509_REQ_bio(p10out, req);
    (void)BIO_flush(p10out);
    BIO_get_mem_ptr(p10out, &bptr);

    /*
     * Get the buffer in which to place the entire response from the server
     */
    recv_buf = (unsigned char *)malloc(EST_CA_MAX);
    new_cert_buf = recv_buf; 
    new_cert_buf_len = 0;

    /*
     * Send the PKCS10 as an HTTP request to the EST server
     */
    rv = est_client_send_enroll_request(ctx, ssl, bptr,
                                        new_cert_buf, &new_cert_buf_len, 
					reenroll);
    switch (rv) {

    case EST_ERR_NONE:
        /*
         * Make sure that even though we got a success return code, that we
         * actually received something
         */
        if (new_cert_buf_len == 0) {
            EST_LOG_ERR("Buffer containing newly enrolled client certificate is zero bytes in length");
            rv = EST_ERR_ZERO_LENGTH_BUF;
            break;
        }

        /*
         * Resize the buffer holding the retrieved client certificate and link
         * it into the ctx.  Get rid of the http hdr and any extra space on
         * the back.
         */
        if (ctx->enrolled_client_cert != NULL){
            free(ctx->enrolled_client_cert);
        }
        ctx->enrolled_client_cert = (unsigned char *)malloc(new_cert_buf_len+1);
        if (ctx->enrolled_client_cert == NULL) {
            
            EST_LOG_ERR("Unable to allocate newly enrolled client certificate buffer");
            rv = EST_ERR_MALLOC;
            break;
        }
        ctx->enrolled_client_cert[new_cert_buf_len] = '\0';
        memcpy(ctx->enrolled_client_cert, new_cert_buf, new_cert_buf_len);
        ctx->enrolled_client_cert_len = new_cert_buf_len;

        /*
         * pass back the length of this newly enrolled cert
         */
        *pkcs7_len = ctx->enrolled_client_cert_len;
        
        EST_LOG_INFO("Newly Enrolled Client certificate:\n%s", ctx->enrolled_client_cert);
        EST_LOG_INFO("length: %d", ctx->enrolled_client_cert_len);
        break;

    case EST_ERR_AUTH_FAIL:
        EST_LOG_INFO("HTTP Authorization failed. Requested auth mode = %d", ctx->auth_mode);
        break;

    case EST_ERR_CA_ENROLL_RETRY:
        EST_LOG_INFO("EST enrollment failed with a RETRY AFTER resp");
        break;

    default:
        EST_LOG_ERR("EST enrollment failed, error code is %d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
        break;
    }

    if (recv_buf) {
        free(recv_buf);
    }
    BIO_free_all(p10out);
    return (rv);
}

/*  est_client_enroll_pkcs10() This function implements the Simple Enroll
 *  flow. It signs the CSR that was provided and then sends the CSR
 *  to the EST server and retrieves the pkcs7 response.
 *
 *  Parameters:
 *    ctx    EST context
 *    ssl    SSL context being used for this EST session
 *    csr    Pointer to X509_REQ object containing the PKCS10 CSR
 *    pkcs7_len  pointer to an integer in which the length of the recieved
 *               pkcs7 response is placed.
 *    priv_key Pointer to the private key used to sign the CSR.
 *    reenroll Set to 1 to do a reenroll instead of an enroll
 *
 *  Returns EST_ERROR  
 */
static EST_ERROR est_client_enroll_pkcs10 (EST_CTX *ctx, SSL *ssl, X509_REQ *csr,
                                           int *pkcs7_len, EVP_PKEY *priv_key,
                                           int reenroll)
{
    EST_ERROR    rv = EST_ERR_NONE;
    char        *tls_uid;
    int          ossl_rv;

    /*
     * Make sure the PoP is removed from the CSR before we proceed
     */
    est_client_clear_csr_pop(csr);

    /*
     * Get the PoP value from the TLS session and embed this into
     * the CSR if required.
     */
    if (ctx->csr_pop_required || ctx->client_force_pop) {
	EST_LOG_INFO("Client will include challengePassword in CSR");
        tls_uid = est_get_tls_uid(ssl, 1);
	if (tls_uid) {
	    ossl_rv = X509_REQ_add1_attr_by_NID(csr, NID_pkcs9_challengePassword,
                                                MBSTRING_ASC, (unsigned char*)tls_uid, -1);
	    free(tls_uid);
	    if (!ossl_rv) {
	        EST_LOG_ERR("Unable to set X509 challengePassword attribute");
		ossl_dump_ssl_errors();
		return (EST_ERR_X509_ATTR);
	    }
        } else {
            EST_LOG_ERR("Unable to obtain the TLS UID");
	    return (EST_ERR_AUTH_FAIL_TLSUID);
	}
    }

    /*
     * Sign the CSR
     */
    ossl_rv = est_client_X509_REQ_sign(csr, priv_key, ctx->signing_digest);
    if (!ossl_rv) {
        EST_LOG_ERR("Unable to sign X509 cert request");
        ossl_dump_ssl_errors();
        return (EST_ERR_X509_SIGN);
    }

    rv = est_client_enroll_req(ctx, ssl, csr, pkcs7_len, reenroll);

    return (rv);
}


/*  est_client_enroll_cn() This function implements the Simple Enroll
    flow. It uses the private key to generate a CSR (pkcs10) request.  It
    then sends the request to the EST server and retrieves the pkcs7
    response.  The user of this function simply provides the CommonName
    value to be placed in the PKCS10 CSR.  This is a simplified interface,
    none of the other CSR attributes can be specified.

    @param ctx EST context
    @param ssl SSL context being used for this EST session
    @param cn pointer to the common name that is to be placed in the x509
    request
    @param pkcs7_len pointer to an integer in which the length of the recieved
    pkcs7 response is placed.
    @param pkey The new client public key that is to be enrolled

    @return EST_ERROR 
 */
static EST_ERROR est_client_enroll_cn (EST_CTX *ctx, SSL *ssl, char *cn,
                                         int *pkcs7_len, EVP_PKEY *pkey)
{
    X509_REQ    *pkcs10 = NULL;
    EST_ERROR    rv = EST_ERR_NONE;
    char        *tls_uid;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    /*
     * Attempt to create the PKCS10 certificate request.
     * Get the TLS uid in case we need it during populate.
     */
    tls_uid = est_get_tls_uid(ssl, 1);
    if (tls_uid) {
        rv = est_generate_pkcs10(ctx, cn, tls_uid, pkey, &pkcs10);
        free(tls_uid);
    } else {
        EST_LOG_ERR("Unable to obtain the TLS UID");
        rv = EST_ERR_AUTH_FAIL_TLSUID;
    }

    if (rv == EST_ERR_NONE) {
        rv = est_client_enroll_req(ctx, ssl, pkcs10, pkcs7_len, 0);
    }
    
    if (pkcs10) {
        X509_REQ_free(pkcs10);
    }

    return (rv);
}

/* 
 * The following function was taken from cURL
 *
 * The content that was incorporated were portions of
 * - lib/hostcheck.c
 * - lib/rawstr.c
 *
 * Portable, consistent toupper (remember EBCDIC). Do not use toupper() because
 * its behavior is altered by the current locale. 
 */
static char est_client_Curl_raw_toupper(char in)
{
    switch (in) {
    case 'a':
        return 'A';
    case 'b':
        return 'B';
    case 'c':
        return 'C';
    case 'd':
        return 'D';
    case 'e':
        return 'E';
    case 'f':
        return 'F';
    case 'g':
        return 'G';
    case 'h':
        return 'H';
    case 'i':
        return 'I';
    case 'j':
        return 'J';
    case 'k':
        return 'K';
    case 'l':
        return 'L';
    case 'm':
        return 'M';
    case 'n':
        return 'N';
    case 'o':
        return 'O';
    case 'p':
        return 'P';
    case 'q':
        return 'Q';
    case 'r':
        return 'R';
    case 's':
        return 'S';
    case 't':
        return 'T';
    case 'u':
        return 'U';
    case 'v':
        return 'V';
    case 'w':
        return 'W';
    case 'x':
        return 'X';
    case 'y':
        return 'Y';
    case 'z':
        return 'Z';
    }
    return in;
}

/*
 * The following function was taken from cURL
 *
 * Curl_raw_equal() is for doing "raw" case insensitive strings. This is meant
 * to be locale independent and only compare strings we know are safe for
 * this.  See http://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for
 * some further explanation to why this function is necessary.
 *
 * The function is capable of comparing a-z case insensitively even for
 * non-ascii.
 */

static int est_client_Curl_raw_equal(const char *first, const char *second)
{
    while(*first && *second) {
	if(est_client_Curl_raw_toupper(*first) != est_client_Curl_raw_toupper(*second)) {
	    /* get out of the loop as soon as they don't match */
	    break;
	}
	first++;
	second++;
    }
    /* we do the comparison here (possibly again), just to make sure that if the
       loop above is skipped because one of the strings reached zero, we must not
       return this as a successful match */
    return (est_client_Curl_raw_toupper(*first) == est_client_Curl_raw_toupper(*second));
}

static int est_client_Curl_raw_nequal(const char *first, const char *second, size_t max)
{
    while(*first && *second && max) {
	if(est_client_Curl_raw_toupper(*first) != est_client_Curl_raw_toupper(*second)) {
	    break;
	}
	max--;
	first++;
	second++;
    }
    if(0 == max) {
	return 1; /* they are equal this far */
    }

    return (est_client_Curl_raw_toupper(*first) == est_client_Curl_raw_toupper(*second));
}

/*
 * The following function was taken from cURL
 *
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * http://tools.ietf.org/html/rfc6125#section-6.4.3
 */
#define HOST_NOMATCH 0
#define HOST_MATCH   1
static int est_client_hostmatch(const char *hostname, const char *pattern)
{
    const char *pattern_label_end, *pattern_wildcard, *hostname_label_end;
    int wildcard_enabled;
    size_t prefixlen, suffixlen;
    pattern_wildcard = strchr(pattern, '*');
    if(pattern_wildcard == NULL) {
	return est_client_Curl_raw_equal(pattern, hostname) ? HOST_MATCH : HOST_NOMATCH;
    }
    /* We require at least 2 dots in pattern to avoid too wide wildcard
       match. */
    wildcard_enabled = 1;
    pattern_label_end = strchr(pattern, '.');
    if(pattern_label_end == NULL || strchr(pattern_label_end+1, '.') == NULL ||
	pattern_wildcard > pattern_label_end ||
	est_client_Curl_raw_nequal(pattern, "xn--", 4)) {
	wildcard_enabled = 0;
    }
    if(!wildcard_enabled) {
	return est_client_Curl_raw_equal(pattern, hostname) ? HOST_MATCH : HOST_NOMATCH;
    }
    hostname_label_end = strchr(hostname, '.');
    if(hostname_label_end == NULL || !est_client_Curl_raw_equal(pattern_label_end, hostname_label_end)) {
	return HOST_NOMATCH;
    }
    /* The wildcard must match at least one character, so the left-most
       label of the hostname is at least as large as the left-most label
       of the pattern. */
    if(hostname_label_end - hostname < pattern_label_end - pattern) {
	return HOST_NOMATCH;
    }
    prefixlen = pattern_wildcard - pattern;
    suffixlen = pattern_label_end - (pattern_wildcard+1);
    return (est_client_Curl_raw_nequal(pattern, hostname, prefixlen) &&
	    est_client_Curl_raw_nequal(pattern_wildcard+1, hostname_label_end - suffixlen,
                                       suffixlen) ?  HOST_MATCH : HOST_NOMATCH);
}

/*
 * The following function was taken from cURL for the
 * FQDN check on the server cert
 */
static int est_client_cert_hostcheck(const char *match_pattern, const char *hostname)
{
    /*
     * Sanity check input 
     */
    if(!match_pattern || !*match_pattern || !hostname || !*hostname) { 
	return 0;
    }

#ifdef _MSC_VER
    // normalize names for matching modulo localhost alias
    if (strcmp(match_pattern, "localhost")==0) match_pattern = "127.0.0.1";
    if (strcmp(hostname     , "localhost")==0) hostname      = "127.0.0.1";
#endif

    /*
     * trival case
     */
    if(est_client_Curl_raw_equal(hostname, match_pattern)) {
	return 1;
    }

    if(est_client_hostmatch(hostname,match_pattern) == HOST_MATCH) {
	return 1;
    }
    return 0;
}

/* 
 * This function was taken from cURL and adapted to EST.
 *
 * Quote from RFC2818 section 3.1 "Server Identity"

   If a subjectAltName extension of type dNSName is present, that MUST
   be used as the identity. Otherwise, the (most specific) Common Name
   field in the Subject field of the certificate MUST be used. Although
   the use of the Common Name is existing practice, it is deprecated and
   Certification Authorities are encouraged to use the dNSName instead.

   Matching is performed using the matching rules specified by
   [RFC2459].  If more than one identity of a given type is present in
   the certificate (e.g., more than one dNSName name, a match in any one
   of the set is considered acceptable.) Names may contain the wildcard
   character * which is considered to match any single domain name
   component or component fragment. E.g., *.a.com matches foo.a.com but
   not bar.foo.a.com. f*.com matches foo.com but not bar.com.

   In some cases, the URI is specified as an IP address rather than a
   hostname. In this case, the iPAddress subjectAltName must be present
   in the certificate and must exactly match the IP in the URI.

 */
static EST_ERROR est_client_verifyhost (char *hostname, X509 *server_cert)
{
    int matched = -1;     /* -1 is no alternative match yet, 1 means match and 0
                             means mismatch */
    size_t addrlen = 0;
    STACK_OF(GENERAL_NAME) * altnames;
    struct in6_addr addr_v6;
    struct in_addr addr_v4;
    int addr_is_v4 = 0;
    int addr_is_v6 = 0;
    EST_ERROR res = EST_ERR_NONE;
    int rc;
    int numalts;
    int i, j;
    const GENERAL_NAME *check; 
    const char *altptr; 
    size_t altlen; 
    unsigned char *nulstr; 
    unsigned char *peer_CN; 
    X509_NAME *name; 
    ASN1_STRING *tmp;

    /*
     * Attempt to resolve host name to v4 address 
     */
    rc = inet_pton(AF_INET, hostname, &addr_v4);
    if (rc > 0) {
	addr_is_v4 = 1;
        addrlen = sizeof(struct in_addr);
    } else {
	/*
	 * Try to see if hostname resolves to v6 address
	 */
	rc = inet_pton(AF_INET6, hostname, &addr_v6);
	if (rc > 0) {
	    addr_is_v6 = 1;
	    addrlen = sizeof(struct in6_addr);
	} else {
	    EST_LOG_WARN("SSL: Cannot resolve '%s' to IP address", hostname);
	}
    }

    /* get a "list" of alternative names */
    altnames = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

    if (altnames) {
        /* get amount of alternatives, RFC2459 claims there MUST be at least
           one, but we don't depend on it... */
        numalts = sk_GENERAL_NAME_num(altnames);
        EST_LOG_INFO("Found %d SubjectAlternateNames", numalts);

        /* loop through all alternatives while none has matched */
        for (i = 0; (i < numalts) && (matched != 1); i++) {
            /* get a handle to alternative name number i */
            check = sk_GENERAL_NAME_value(altnames, i);

            /* get data and length */
            altptr = (char*)ASN1_STRING_data(check->d.ia5);
            altlen = (size_t)ASN1_STRING_length(check->d.ia5);

            switch (check->type) {
            case GEN_DNS: /* name/pattern comparison */
                EST_LOG_INFO("Checking FQDN against SAN %s", altptr);
                /* The OpenSSL man page explicitly says: "In general it cannot be
                   assumed that the data returned by ASN1_STRING_data() is null
                   terminated or does not contain embedded nulls." But also that
                   "The actual format of the data will depend on the actual string
                   type itself: for example for and IA5String the data will be ASCII"

                   Gisle researched the OpenSSL sources:
                   "I checked the 0.9.6 and 0.9.8 sources before my patch and
                   it always 0-terminates an IA5String."
                 */
                if ((altlen == strnlen(altptr, EST_MAX_SERVERNAME_LEN)) &&
                    /* if this isn't true, there was an embedded zero in the name
                       string and we cannot match it. */
                    est_client_cert_hostcheck(altptr, hostname)) {
                    matched = 1;
                } else{
                    matched = 0;
                }
                break;

            case GEN_IPADD: /* IP address comparison */
		if (altlen == 4) {
		    EST_LOG_INFO("Comparing FQDN against IPv4 address %s", inet_ntoa(*((struct in_addr *)altptr)));
		}
                /* compare alternative IP address if the data chunk is the same size
                   our server IP address is */
                if ((addr_is_v4) && (altlen == addrlen) && !memcmp(altptr, &addr_v4, altlen)) {
                    matched = 1;
                } else if ((addr_is_v6) && (altlen == addrlen) && !memcmp(altptr, &addr_v6, altlen)) {
                    matched = 1;
                } else{
                    matched = 0;
                }
                break;
            }
        }
        GENERAL_NAMES_free(altnames);
    }

    if (matched == 1) {
        /* an alternative name matched the server hostname */
        EST_LOG_INFO("subjectAltName: %s matched", hostname);
    } else if (matched == 0) {
        /* an alternative name field existed, but didn't match and then
           we MUST fail */
        EST_LOG_INFO("subjectAltName does not match %s", hostname);
        res = EST_ERR_FQDN_MISMATCH;
    } else {
        /* we have to look to the last occurrence of a commonName in the
           distinguished one to get the most significant one. */
        i = -1;

	/* The following is done because of a bug in 0.9.6b */
        nulstr = (unsigned char*)"";
        peer_CN = nulstr;

        name = X509_get_subject_name(server_cert);
        if (name) {
            while ((j = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0) {
                i = j;
            }
        }

        /* we have the name entry and we will now convert this to a string
           that we can use for comparison. Doing this we support BMPstring,
           UTF8 etc. */

        if (i >= 0) {
            tmp = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

            /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
               is already UTF-8 encoded. We check for this case and copy the raw
               string manually to avoid the problem. This code can be made
               conditional in the future when OpenSSL has been fixed. Work-around
               brought by Alexis S. L. Carvalho. */
            if (tmp) {
                if (ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
                    j = ASN1_STRING_length(tmp);
                    if (j >= 0) {
                        peer_CN = (unsigned char *)malloc(j + 1);
                        if (peer_CN) {
                            memcpy(peer_CN, ASN1_STRING_data(tmp), j);
                            peer_CN[j] = '\0';
                        }
                    }
                }else  { /* not a UTF8 name */
                    j = ASN1_STRING_to_UTF8(&peer_CN, tmp);
                }
                if (peer_CN && (strnlen((char*)peer_CN, EST_MAX_SERVERNAME_LEN) != j)) {
                    /* there was a terminating zero before the end of string, this
                       cannot match and we return failure! */
                    EST_LOG_WARN("SSL: illegal cert name field");
                    res = EST_ERR_FQDN_MISMATCH;
                }
            }
        }

        if (peer_CN == nulstr) {
            peer_CN = NULL;
        } else{
            /* convert peer_CN from UTF8 */
#if 0
// UTF8 currently not supported in the first release of libest
            CURLcode rc = Curl_convert_from_utf8(data, peer_CN, strlen(peer_CN));
            /* Curl_convert_from_utf8 calls failf if unsuccessful */
            if (rc) {
                free(peer_CN);
                return EST_ERR_FQDN_MISMATCH;
            }
#endif
        }

        if (res != EST_ERR_NONE) {
            /* error already detected, pass through */
            ;
        } else if (!peer_CN) {
            EST_LOG_WARN("SSL: unable to obtain common name from peer certificate");
            res = EST_ERR_FQDN_MISMATCH;
        }else if (!est_client_cert_hostcheck((const char*)peer_CN, hostname)) {
            EST_LOG_WARN("SSL: FQDN hostname mismatch in server certificate, '%s' does not match "
                      "target host name '%s'", peer_CN, hostname);
            res = EST_ERR_FQDN_MISMATCH;
        }else  {
            EST_LOG_INFO("common name: %s (matched)", peer_CN);
        }
        if (peer_CN) {
            free(peer_CN);
        }
    }
    return res;
}


/*
 * This routine checks the FQDN in the server certificate
 * against the configure server name used to establish
 * the TCP connection with the EST server.
 * This is required per section 3.6 in the EST spec.
 * Note, we only do the FQDN check as defined in RFC 6125.
 * We do not look for the id-kp-cmcRA extended key usage
 * extension in the server cert.  While this is more 
 * restrictive by not allowing FQDN mismatches when the
 * id-kp-cmcRA is present, we currently have no way to
 * determine when we're using the explicit trust anchor to
 * allow this additional flexibility.
 */
static EST_ERROR est_client_check_fqdn (EST_CTX *ctx, SSL *ssl)
{
    X509 *cert;
    EST_ERROR er;

    cert = SSL_get_peer_certificate(ssl);

    if (cert) {
	er = est_client_verifyhost(ctx->est_server, cert);
	X509_free(cert);
	return (er);
    } else if (!cert && ctx->enable_srp) {
	EST_LOG_INFO("No peer certificate, skipping FQDN check since SRP is enabled.");
	return EST_ERR_NONE;
    } else {
	EST_LOG_WARN("Unable to perform FQDN check, no peer certificate.");
	return EST_ERR_FQDN_MISMATCH;
    }
}

static EST_ERROR general_ssl_error(int ssl_err)
{
    EST_ERROR rv = EST_ERR_SSL_CONNECT;
    switch (ERR_peek_error()) {
    case 0:
	if (ssl_err == 0) {
	    EST_LOG_ERR("Server has disconnected violating the protocol");
	    rv = EST_ERR_SOCKET_STOP;
	}
	if (ssl_err == -1) {
	    if (errno != 0) {
		EST_LOG_WARN("SSL_connect resulted in ERRNO %d (%s)", errno, strerror(errno));
	    }
	    if (errno == 104) {
		EST_LOG_WARN("Most likely the server did not accept our authentication");
		rv = EST_ERR_AUTH_FAIL; // EST_ERR_SSL_CONNECT
	    } else {
		rv = EST_ERR_SYSCALL;
	    }
	}
	break;
    case 0x0D0C5006:
	EST_LOG_ERR("Certificate/CRL signature verification failure");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x140740B5:
	EST_LOG_ERR("No ciphers available; this may be due to the server requring SRP but the client not being SRP enabled");
	rv = EST_ERR_SSL_CIPHER_LIST;
	break;
    case 0x14077410:
	EST_LOG_ERR("No shared cipher; this error may be due to the server not being SRP enabled");
	rv = EST_ERR_SSL_CIPHER_LIST;
	break;
    case 0x1407745B:
	EST_LOG_ERR("Bad SRP username");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x1408D173:
	EST_LOG_ERR("Bad SRP parameters");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x14090086:
	EST_LOG_ERR("Server certificate not accepted, likely due to expiration, mismatch with trust anchor, or missing/invalid CRL");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x140943fc:
	EST_LOG_ERR("Decryption failed or bad record mac; this error is likely due to bad SRP password");
	rv = EST_ERR_AUTH_SRP;
	break;
    case 0x14094414:
	EST_LOG_ERR("Server certificate revoked");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x14094415:
	EST_LOG_ERR("Our certificate expired");
	rv = EST_ERR_AUTH_CERT;
	break;
    case 0x14094418:
	EST_LOG_ERR("Our certificate is not accepted, likely due to expiration, mismatch with trust anchor, or missing/invalid CRL"); // OpenSSL said: "Unknown CA"
	rv = EST_ERR_AUTH_CERT;
	break;
    default:
	ossl_dump_ssl_errors();
	break;
    }
    return rv;
}

/*
 * This function will open a TCP socket and establish a TLS session
 * with the EST server.  This should be called after est_client_init().
 *
 * Parameters:
 *	ctx:	    Pointer to EST context for client session
 *      ssl:        pointer to an SSL context structure to return the
 *                  SSL context created,
 * Return value:
 *	EST_ERR_NONE if success
 */
EST_ERROR est_client_connect (EST_CTX *ctx, SSL **ssl)
{
    BIO             *tcp;
    SSL_CTX         *s_ctx;
    EST_ERROR       rv = EST_ERR_NONE;
    int             sock;
    int             rc;
    struct          addrinfo hints, *ai, *aiptr;
    char            portstr[12];
    int             oval = 1;
    
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }

    s_ctx = ctx->ssl_ctx;

    /* 
     * Unfortunately the OpenSSL BIO socket interface doesn't
     * support IPv6.  This precludes us from using BIO_do_connect().
     * We'll need to open a raw socket ourselves and pass that to OpenSSL.
     */
    snprintf(portstr, sizeof(portstr), "%u", ctx->est_port_num);
    memset(&hints, '\0', sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    if ((rc = getaddrinfo(ctx->est_server, portstr, &hints, &aiptr))) {
        EST_LOG_ERR("Unable to lookup hostname %s. %s", 
		ctx->est_server, gai_strerror(rc));
        return (EST_ERR_IP_GETADDR);
    }
    /*
     * Iterate through all the addresses found that match the
     * hostname.  Attempt to connect to them.
     */
    for (ai = aiptr; ai != NULL; ai = ai->ai_next)		{
	/*
	 * Open a socket with this remote address
	 */
	if ((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ) {
	    /* 
	     * If we can't connect, try the next address
	     */
	    continue;
	}
	/*
	 * Enable TCP keep-alive
	 */
	rc = setsockopt(sock, SOL_SOCKET,SO_KEEPALIVE, (char *)&oval, sizeof(oval));
	if (rc < 0) {
	    close(sock);
	    continue;
	}
	/*
	 * Connect to the remote host
	 */
	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 ) {
	    close(sock);
	    continue;
	}
	/* 
	 * Connection has been established. No need to try
	 * any more addresses.
	 */
	break;
    }
    freeaddrinfo(aiptr);
    if (!ai) {
	EST_LOG_ERR("Unable to connect to EST server at address %s", ctx->est_server);
	return (EST_ERR_IP_CONNECT);
    }

    /*
     * Pass the socket to the BIO interface, which OpenSSL uses
     * to create the TLS session.
     */
    tcp = BIO_new_socket(sock, BIO_CLOSE);

    if (!(*ssl = SSL_new(s_ctx))) {
        EST_LOG_ERR("Error creating TLS context");
        ossl_dump_ssl_errors();
        BIO_free_all(tcp);    
        return (EST_ERR_SSL_NEW);
    }

    /*
     * Need to set the EST ctx into the exdata of the SSL session context so
     * that it can be retrieved on a per session basis.
     */
    SSL_set_ex_data(*ssl, e_ctx_ssl_exdata_index, ctx);    

    SSL_set_bio(*ssl, tcp, tcp);
    if (ctx->sess) {
	SSL_set_session(*ssl, ctx->sess);
    }
    int ssl_err = SSL_connect(*ssl);
    int err_code = SSL_get_error(*ssl, ssl_err);
    if (ssl_err <= 0) {
	if (err_code != SSL_ERROR_NONE && err_code != SSL_ERROR_WANT_READ && err_code != SSL_ERROR_WANT_WRITE) {
	    EST_LOG_ERR("SSL_connect error: %d (%s)", err_code, ossl_error_string(err_code));
	}
	switch (err_code) {
	case SSL_ERROR_SSL:
	    usleep(50);  /* In case an EST_ERR_AUTH_CERT error occurred on our side, this delay helps
			    avoiding a race condition causing est_server_handle_request() to obtain:
			    "SSL_accept error: 5 (SSL_ERROR_SYSCALL)" with "ERRNO 104 (Connection reset by peer)"
			    This leads the server to report the too general error EST_ERR_AUTH_FAIL, 
			    while the error code should actually be the more specific EST_ERR_AUTH_CERT,
			    after reporting in the log: "SSL_read error: 1 (SSL_ERROR_SSL)" */
	case SSL_ERROR_SYSCALL:
	    rv = general_ssl_error(ssl_err);
	    break;
	default:
	    ossl_dump_ssl_errors();
	    rv = EST_ERR_SSL_CONNECT;
	    break;
	}
    }
    /*
     * Now that we've established a TLS session with the EST server,
     * we need to verify that the FQDN in the server cert matches
     * the server name we used to establish the connection.
     * This is from section 3.6 in the EST spec.
     */
    if ((EST_ERR_NONE == rv) && est_client_check_fqdn(ctx, *ssl)) {
	/*
	 * The host name did not match, shut down the tunnel and bail
	 */
        EST_LOG_ERR("EST server name did not match FQDN in server certificate.");
	est_client_disconnect(ctx, ssl);
        rv = EST_ERR_FQDN_MISMATCH;
    }

    return rv;
}

/*
 * This function will close the TLS session and the underlying socket.
 *
 * Parameters:
 *	ssl:	    Pointer to SSL context that has been set up for this connection
 *                  to the EST server.
 */
void est_client_disconnect (EST_CTX *ctx, SSL **ssl)
{
    SSL_SESSION *new_sess;
    
    if (!*ssl) {
        return;
    }

    /*
     * if first disconnect, get the session id to cache it away to use for
     * session resumption.
     */
    if (!ctx->sess) {
	ctx->sess = SSL_get1_session(*ssl);
    } else {
        /*
         * if not the first time to disconnect, see if the session id changed.
         * If it did, officially re-obtain it with a get1 call and cache it away
         */
        new_sess = SSL_get0_session(*ssl);
        if (new_sess != ctx->sess) {
            ctx->sess = SSL_get1_session(*ssl);
        }
    }
    
    SSL_shutdown(*ssl);
    SSL_free(*ssl);
    *ssl = NULL;
}


/*
 * This function does the work for the CACerts request flow.
 *
 * Parameters:
 *	ctx:	    EST context
 *	ssl:	    SSL context
 *      ca_certs_len: pointer to the unsigned int that will hold the length of the
 *                    returned CA certs.
 */
static EST_ERROR est_client_send_cacerts_request (EST_CTX *ctx, SSL *ssl,
                                            int *ca_certs_len)
{
    char *http_data;
    int  hdr_len;
    int  write_size;
    EST_ERROR rv;
    unsigned char *ca_certs_buf = NULL;
    int  ca_certs_buf_len = 0;

    /*
     * Build the HTTP request
     * - allocate buffer: header, no data, terminating characters
     * - build the header
     * - no data
     * - terminate it
     */
    http_data = (char *)malloc(EST_HTTP_REQ_TOTAL_LEN);
    if (http_data == NULL) {
        EST_LOG_ERR("Unable to allocate memory for http_data");
        return EST_ERR_MALLOC;
    }
    
    hdr_len = est_client_build_cacerts_header(ctx, http_data);
    /*
     * terminate the HTTP header
     */
    snprintf(http_data + hdr_len, EST_HTTP_REQ_TOTAL_LEN-hdr_len,"\r\n");
    hdr_len += 2;

    /*
     * no data is being sent so go ahead and terminate the HTTP request
     */
    snprintf(http_data + hdr_len,EST_HTTP_REQ_TOTAL_LEN-hdr_len, "\r\n");
    hdr_len += 2;
    
    /*
     * Send the request to the server and wait for a response
     */
    write_size = SSL_write(ssl, http_data, hdr_len);
    if (write_size < 0) {
        EST_LOG_ERR("TLS write error");
	ossl_dump_ssl_errors();
        rv = EST_ERR_SSL_WRITE;
    } else {
        EST_LOG_INFO("TLS wrote %d bytes, attempted %d bytes",
                     write_size, hdr_len);

        /*
         * Try to get the response from the server
         */
        rv = est_io_get_response(ctx, ssl, EST_GET_CACERTS,
                                 &ca_certs_buf, &ca_certs_buf_len);

        switch (rv) {
        case EST_ERR_NONE:
            
            /*
             * Make sure that even though we got a success return code, that we
             * actually received something
             */
            if (ca_certs_buf_len == 0) {
                EST_LOG_ERR("Retrieved CA Cert buf is zero bytes in length");
                rv = EST_ERR_ZERO_LENGTH_BUF;
                break;
            }
            if (ca_certs_buf_len+1 > EST_CA_MAX) {
                EST_LOG_ERR("Retrieved CA Cert buf is larger than maximum allowed");
                rv = EST_ERR_BUF_EXCEEDS_MAX_LEN;
                break;
            }
            
            /*
             * Resize the buffer holding the retrieved CA cert and link it
             * into the ctx.  Get rid of the http hdr and any extra space on
             * the back.
             */
            if (ctx->retrieved_ca_certs != NULL){
                free(ctx->retrieved_ca_certs);
            }
            ctx->retrieved_ca_certs = (unsigned char *)malloc(ca_certs_buf_len+1);
            if (ctx->retrieved_ca_certs == NULL) {
                
                EST_LOG_ERR("Unable to allocate CA certs buffer");
                rv = EST_ERR_MALLOC;
                break;
            }
            
            ctx->retrieved_ca_certs[ca_certs_buf_len] = '\0';
            memcpy(ctx->retrieved_ca_certs, ca_certs_buf, ca_certs_buf_len);
            ctx->retrieved_ca_certs_len = ca_certs_buf_len;

            /*
             * Verify the returned CA cert chain
             */
            rv = verify_cacert_resp(ctx, ctx->retrieved_ca_certs,
                                    &ctx->retrieved_ca_certs_len);
            if (rv != EST_ERR_NONE) {
                EST_LOG_ERR("Returned CACerts chain was invalid");

                free(ctx->retrieved_ca_certs);
                ctx->retrieved_ca_certs = NULL;
                ctx->retrieved_ca_certs_len = 0;
                *ca_certs_len = ctx->retrieved_ca_certs_len;
                break;
            }
            
            /*
             * pass back the length of the retrieved CA cert buffer
             */
            *ca_certs_len = ctx->retrieved_ca_certs_len;
            
            EST_LOG_INFO("CACerts buf:\n%s", ctx->retrieved_ca_certs);
            EST_LOG_INFO("CACerts length: %d", ctx->retrieved_ca_certs_len);
            break;
        case EST_ERR_AUTH_FAIL:
            EST_LOG_ERR("HTTP auth failure");
            break;
        case EST_ERR_CA_ENROLL_RETRY:
            EST_LOG_INFO("EST CACerts request failed with a RETRY AFTER resp");
            break;
        default:
            EST_LOG_ERR("EST CACerts request failed: %d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
            break;
        }
    }
    
    if (http_data) {
        free(http_data);
    }
    if (ca_certs_buf) {
        free(ca_certs_buf);
    }
    
    return (rv);
}


EST_ERROR est_client_set_uid_pw (EST_CTX *ctx, const char *uid, const char *pwd) 
{
    /*
     * If there's a userid, there must be a password, and vice versa.
     * The userid can still be an empty string ( "" ), but it cannot
     * be NULL if there's a password. (3.2.3).
     */
    if (uid != NULL && pwd == NULL) {
        EST_LOG_ERR("User ID provided with no password");
        return EST_ERR_INVALID_PARAMETERS;
    }        
    if (uid == NULL && pwd != NULL) {
        EST_LOG_ERR("Password provided with no user ID");
        return EST_ERR_INVALID_PARAMETERS;
    }

    /*
     * if uid/pwd set, then we're doing basic/digest authentication
     */
    if (uid != NULL) {
	if (strlen(uid) > MAX_UIDPWD-1) {
	    return EST_ERR_INVALID_PARAMETERS;
	}
        strncpy(ctx->userid, uid, MAX_UIDPWD); 
        strncpy(ctx->password, pwd, MAX_UIDPWD);
    }

    return (EST_ERR_NONE);
}

/*
 * Application API
 */

/*! @brief est_client_enroll_csr() performs the simple enroll request with the EST
     server using a PKCS10 CSR provided by the application layer.
 
    @param ctx Pointer to an EST context
    @param csr Pointer to the PKCS10 CSR data, which is defined as an OpenSSL
    X509_REQ.
    @param pkcs7_len Pointer to an integer to hold the length of the PKCS7
    buffer.
    @param priv_key Pointer to the private key that will be used to sign the CSR,
    or NULL if the CSR is already signed.
 
    @return EST_ERROR

    est_client_enroll_csr() connects to the EST server, establishes a SSL/TLS
    connection to the EST server that was configured with the previous call to
    est_client_set_server(), and sends the simple enroll request.  The application
    layer must provide the PKCS10 CSR that will be enrolled.
    If the priv_key argument given is not NULL, then the CSR should not
    need to be signed by the private key, and the EST library will take care of
    signing the CSR.  However, the CSR must contain everything else that is
    required, including the public key.  
    
    The enroll response is stored in the EST context and the length 
    is passed back to the application through the pkcs7_len paramter of this 
    function.  The application can then allocate a correctly sized buffer and 
    call est_client_copy_enrolled_cert() to retrieve the new client certificate 
    from the context.

    Unless the CSR is not already signed, which is indicated by a NULL priv_key,
    the application must provide a pointer to the private key used to sign the CSR.
    This is required by the EST library in the event that the EST server has
    requested the proof-of-possession value be included in the CSR.  The EST library
    will automatically include the proof-of-posession value and sign the CSR
    again.

    Be aware that the X509_REQ data passed to this function must be valid.  Passing
    corrupted CSR data may result in a system crash.  libest utilizes the OpenSSL
    ASN decoding logic to read the X509_REQ data.  OpenSSL does not perform
    safety checks on the X509_REQ data when parsing.  If your application is
    reading externally generated PEM or DER encoded CSR data, then please use
    the est_read_x509_request() helper function to convert the PEM/DER CSR into a
    valid X509_REQ pointer.
 */
EST_ERROR est_client_enroll_csr (EST_CTX *ctx, X509_REQ *csr, int *pkcs7_len, EVP_PKEY *priv_key)
{
    EST_ERROR rv;
    SSL *ssl = NULL;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!csr) {
        return (EST_ERR_NO_CSR);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (priv_key) {
	/*
	 * Do a sanity check on the CSR
	*/
        rv = est_client_check_csr(csr); 
	if (EST_ERR_NONE != rv) {
	    return (rv);
	}
    }
    /*
     * Establish TLS session with the EST server
     */
    rv = est_client_connect(ctx, &ssl);
    if (rv != EST_ERR_NONE) {
        goto err;
    }

    if (priv_key) {
      rv = est_client_enroll_pkcs10(ctx, ssl, csr, pkcs7_len, priv_key, 0);
    } else {
        rv = est_client_enroll_req(ctx, ssl, csr, pkcs7_len, 0);
    }
    est_client_disconnect(ctx, &ssl);
    if (rv == EST_ERR_AUTH_FAIL &&
        (ctx->auth_mode == AUTH_DIGEST ||
         ctx->auth_mode == AUTH_BASIC  ||
         ctx->auth_mode == AUTH_TOKEN)) {

        /*
         * HTTPS digest mode requires the use of MD5.  Make sure we're not
         * in FIPS mode and can use MD5
         */
        if (ctx->auth_mode == AUTH_DIGEST && (FIPS_mode())){
	    EST_LOG_ERR("HTTP digest auth not allowed while in FIPS mode");
	    rv = EST_ERR_BAD_MODE;
            goto err;
        }
        
        /* Try one more time if we're doing Digest auth */
        EST_LOG_INFO("HTTP Auth failed, trying again with digest/basic parameters");
        rv = est_client_connect(ctx, &ssl);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Connection failed on second attempt with basic/digest parameters");
            goto err;
        }
	if (priv_key) {
	  rv = est_client_enroll_pkcs10(ctx, ssl, csr, pkcs7_len, priv_key, 0);
	} else {
	  rv = est_client_enroll_req(ctx, ssl, csr, pkcs7_len, 0);
	}
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Enroll failed on second attempt during basic/digest authentication");
        }
        est_client_disconnect(ctx, &ssl);
    }

err:    
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    return (rv);

}


/*! @brief est_client_enroll() performs the simple enroll request with the EST
     server
 
    @param ctx Pointer to an EST context
    @param cn Pointer to the Common Name value to be used in the enrollment
    request.
    @param pkcs7_len Pointer to an integer to hold the length of the PKCS7
    buffer.
    @param new_public_key Pointer an EVP_PKEY structure that holds the
    client's key pair to be used in the simple enroll request .  The public
    key is included in the Certificate Signing Request (CSR) sent to the CA
    Server, and the private key is used to sign the request.
 
    @return EST_ERROR

    est_client_enroll() connects to the EST server, builds a simple enroll
    request using the Common Name passed in cn, establishes a SSL/TLS
    connection to the EST server that was configured with the previous call to
    est_client_set_server(), and sends the simple enroll request.  The
    response is stored in the EST context and the length is passed back to the
    application through the pkcs7_len parameter of this function.  The
    application can then allocate a correctly sized buffer and call
    est_client_copy_enrolled_cert() to retrieve the new client certificate
    from the context.
 */
EST_ERROR est_client_enroll (EST_CTX *ctx, char *cn, int *pkcs7_len,
                             EVP_PKEY *new_public_key)
{
    EST_ERROR rv;
    SSL *ssl = NULL;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!new_public_key) {
        return (EST_ERR_NO_KEY);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    rv = est_client_connect(ctx, &ssl);
    if (rv != EST_ERR_NONE) {
        goto err;
    }
    rv = est_client_enroll_cn(ctx, ssl, cn, pkcs7_len, new_public_key);
    est_client_disconnect(ctx, &ssl);
    if (rv == EST_ERR_AUTH_FAIL &&
        (ctx->auth_mode == AUTH_DIGEST ||
         ctx->auth_mode == AUTH_BASIC  ||
         ctx->auth_mode == AUTH_TOKEN)) {

        /*
         * HTTPS digest mode requires the use of MD5.  Make sure we're not
         * in FIPS mode and can use MD5
         */
        if (ctx->auth_mode == AUTH_DIGEST && (FIPS_mode())){
	    EST_LOG_ERR("HTTP digest auth not allowed while in FIPS mode");
	    rv = EST_ERR_BAD_MODE;
            goto err;
        }
        
        /* Try one more time if we're doing Digest auth */
        EST_LOG_INFO("HTTP Auth failed, trying again with basic/digest/token parameters");
        rv = est_client_connect(ctx, &ssl);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Connection failed on second attempt with basic/digest/token parameters");
            goto err;
        }
        rv = est_client_enroll_cn(ctx, ssl, cn, pkcs7_len, new_public_key);
        if (rv != EST_ERR_NONE && rv != EST_ERR_CA_ENROLL_RETRY) {
            EST_LOG_ERR("Enroll failed on second attempt during basic/digest authentication");

            /*
             * If we're attempting token mode for the second time, and
             * the server responded with error attributes, log them now
             */
            if (ctx->token_error[0] != '\0' || ctx->token_error_desc[0] != '\0') {
                EST_LOG_ERR("Token Auth mode failed, server provided error information: \n"
                            "   Error = %s\n Error description: %s",
                            ctx->token_error, ctx->token_error_desc);
                ctx->token_error[0] = '\0';
                ctx->token_error_desc[0] = '\0';
            }
        }
        
        est_client_disconnect(ctx, &ssl);
    }

    ctx->auth_mode = AUTH_NONE;

  err:    
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    return (rv);
}

/*! @brief est_client_provision_cert() performs the full sequence of
    EST operations to enroll a new certificate using a trusted message flow.
 
    @param ctx Pointer to an EST context
    @param cn Pointer to the Common Name value to be used in the enrollment
    request.
    @param pkcs7_len Pointer to an integer to hold the length of the PKCS7
    certificate returned from the RA or CA.
    @param ca_cert_len Pointer to an integer to hold the length of the buffer 
    that will hold the new trusted CA certificates.
    @param new_public_key Pointer an EVP_PKEY structure that holds the
    client's key pair to be used in the simple enroll request .  The public
    key is included in the Certificate Signing Request (CSR) sent to the CA
    Server, and the private key is used to sign the request.
 
    @return EST_ERROR

    est_client_provision_cert() connects to the EST server, retrieves the
    latest trusted CA certifictes from the server, retrieves the CSR attributes
    from the server, and sends the simple enroll request to the server to
    provision a new certificate from the RA or CA.  This is a convenience 
    function that is equivalent to invoking the following three functions
    in order:

    est_client_get_cacerts()
    est_client_get_csrattrs()
    est_client_enroll() 

    This function takes a Common Name (CN) as the only entity identifier
    that will be used in the certificate.  If additional X509 attributes
    or extensions are required, then this function should not be used
    to provision a certificate.  The est_client_enroll_csr() function should
    be used when additional X509 attributes are to be included in the
    enroll request. 

    The provisioning response is stored in the EST context and the length is passed 
    back to the application through the pkcs7_len parameter of this function.  The
    application can then allocate a correctly sized buffer and call
    est_client_copy_enrolled_cert() to retrieve the new client certificate
    from the context.

    The provisioning response also includes the latest copy of the trusted
    CA certificates from the EST server.  These should be persisted locally
    by the application for future use.  The ca_cert_len argument will contain the 
    length of the certicates, which can then be retrieved by invoking 
    est_client_copy_cacerts().
 */
EST_ERROR est_client_provision_cert (EST_CTX *ctx, char *cn, 
	                             int *pkcs7_len,
				     int *ca_cert_len,
                                     EVP_PKEY *new_public_key)
{
    EST_ERROR rv;
    unsigned char *new_ta_p7;
    unsigned char *new_ta_pem;
    unsigned char *attr_data = NULL;
    int attr_len;
    int new_ta_len;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    /*
     * Make sure we have non-NULL pointers for the lengths
     */
    if (!pkcs7_len || !ca_cert_len) {
	return (EST_ERR_INVALID_PARAMETERS);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (!new_public_key) {
        return (EST_ERR_NO_KEY);
    }

    /*
     * First, get the latest trust anchor certs from the server.
     */
    rv = est_client_get_cacerts(ctx, ca_cert_len);
    if (rv != EST_ERR_NONE) {
	return rv;
    }
    new_ta_p7 = (unsigned char *)malloc(*ca_cert_len);
    rv = est_client_copy_cacerts(ctx, new_ta_p7);
    if (rv != EST_ERR_NONE) {
	free(new_ta_p7);
	return (rv);
    }

    /*
     * The certs are base64 DER encoded.  We need to convert
     * them to PEM.
     */
    new_ta_len = est_convert_p7b64_to_pem (new_ta_p7, *ca_cert_len, &new_ta_pem);
    free(new_ta_p7);
    if (new_ta_len <= 0) {
	return (EST_ERR_PEM_READ);
    }

    /*
     * We now have the new trust anchor and it's PEM encoded.
     * Let's load it into the current EST context.  All
     * future EST operations will then be using this new
     * trust anchor.
     */
    if (ctx->trusted_certs_store != NULL) {
        X509_STORE_free(ctx->trusted_certs_store);
    }
    rv = est_load_trusted_certs(ctx, new_ta_pem, new_ta_len);
    free(new_ta_pem);
    if (rv != EST_ERR_NONE) {
        return rv;
    }
    
    /*
     * Since we've reset the trust store, mark the client
     * context as initialized.
     */
    ctx->est_client_initialized = 1;

    /*
     * Next we need to get the CSR attributes, which allows libest
     * to know if the challengePassword needs to be included in the
     * CSR.
     */
    rv = est_client_get_csrattrs(ctx, &attr_data, &attr_len);
    if (rv != EST_ERR_NONE) {
	EST_LOG_ERR("Unable to get CSR attributes while provisioning a new certificate");
	return (rv);
    }

    /*
     * Finally, we can attempt to enroll a new certificate using the
     * Common Name provided by the application.
     */
    rv = est_client_enroll(ctx, cn, pkcs7_len, new_public_key);

    return (rv);
}

/*! @brief est_client_reenroll() performs a re-enroll request with the EST
     server using an existing X509 certificate.
 
    @param ctx Pointer to an EST context
    @param cert Pointer to the X509 certificate, which is defined as an OpenSSL
    X509.
    @param pkcs7_len Pointer to an integer to hold the length of the PKCS7
    buffer.
    @param priv_key Pointer to the private key that will be used to sign the CSR.
 
    @return EST_ERROR

    est_client_reenroll() connects to the EST server, establishes a SSL/TLS
    connection to the EST server that was configured with the previous call to
    est_client_set_server(), and sends the re-enroll request.  The application
    layer must provide the X509 certificate that will be enrolled.  This certificate
    should have previously been enrolled with the CA.  The application also
    needs to provide the private key associated with the public key in the
    X509 certificate.  This private key is required to sign the CSR that is
    generated from the X509 certificate. 
    
    The enroll response is stored in the EST context and the length 
    is passed back to the application through the pkcs7_len paramter of this 
    function.  The application can then allocate a correctly sized buffer and 
    call est_client_copy_enrolled_cert() to retrieve the new client certificate 
    from the context.

    The application must provide a pointer to the private key used to sign the CSR.
    This is required by the EST library in the event that the EST server has
    requested the proof-of-possession value be included in the CSR.  The EST library
    will automatically include the proof-of-posession value and sign the CSR
    again.

    Be aware that only the public key and subject name from the X509 certificate
    are included in the re-enroll request sent to the EST server.  The CA is
    responsible for re-applying any X509 extensions that are to be issued with
    the renewed certificate.
 */
EST_ERROR est_client_reenroll (EST_CTX *ctx, X509 *cert, int *pkcs7_len, EVP_PKEY *priv_key)
{
    X509_REQ *req;
    EST_ERROR rv;
    SSL *ssl = NULL;
    int ossl_rv;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!cert) {
        return (EST_ERR_NO_CERT);
    }

    if (!priv_key) {
        return (EST_ERR_NO_KEY);
    }

    if (!ctx->est_client_initialized) {
        return (EST_ERR_CLIENT_NOT_INITIALIZED);
    }

    /*
     * Check the X509 given to us
     */
    rv = est_client_check_x509(cert);
    if (rv != EST_ERR_NONE) {
	return (rv);
    }

    /*
     * Check that the private key matches the public key
     * in the cert.
     */
    if (X509_check_private_key(cert, priv_key) <= 0) {
        return (EST_ERR_CLIENT_INVALID_KEY);
    }

    /*
     * Convert the existing certificate to a CSR
     * This will copy the subject name from the cert into
     * a new CSR.  We pass in NULL for the private key parameter
     * below because we will sign this CSR ourselves later.
     */
    req = X509_to_X509_REQ(cert, NULL, ctx->signing_digest);
    if (!req) {
	EST_LOG_ERR("X509 to CSR conversion failed.");
        ossl_dump_ssl_errors();
        return (EST_ERR_NO_CERT);
    }

    /*
     * Copy the X509 extensions from the old certificate
     * to the CSR.  The CA may or may not retain these, as
     * this behavior depends on policy.  When using the 
     * OpenSSL test CA, set the copy_extensions setting 
     * in the config file to copyall to retain the
     * extensions in the CSR when issuing a new cert.
     */
    if (cert->cert_info && cert->cert_info->extensions) {
	ossl_rv = X509_REQ_add_extensions(req, cert->cert_info->extensions);
	if (!ossl_rv) {
	    EST_LOG_WARN("Failed to copy X509 extensions to the CSR. Your new certificate may not contain the extensions present in the old certificate.");
	}
    }

    /*
     * Establish TLS session with the EST server
     */
    rv = est_client_connect(ctx, &ssl);
    if (rv != EST_ERR_NONE) {
        goto err;
    }

    /*
     * Send the re-enroll request
     */
    rv = est_client_enroll_pkcs10(ctx, ssl, req, pkcs7_len, priv_key, 1);
    est_client_disconnect(ctx, &ssl);
    if (rv == EST_ERR_AUTH_FAIL &&
        (ctx->auth_mode == AUTH_DIGEST ||
         ctx->auth_mode == AUTH_BASIC  ||
         ctx->auth_mode == AUTH_TOKEN)) {

        /*
         * HTTPS digest mode requires the use of MD5.  Make sure we're not
         * in FIPS mode and can use MD5
         */
        if (ctx->auth_mode == AUTH_DIGEST && (FIPS_mode())){
	    EST_LOG_ERR("HTTP digest auth not allowed while in FIPS mode");
	    rv = EST_ERR_BAD_MODE;
            goto err;
        }
        
        /* Try one more time if we're doing Digest auth */
        EST_LOG_INFO("HTTP Auth failed, trying again with digest/basic parameters");
        rv = est_client_connect(ctx, &ssl);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Connection failed on second attempt with basic/digest parameters");
            goto err;
        }
        rv = est_client_enroll_pkcs10(ctx, ssl, req, pkcs7_len, priv_key, 1);
        if (rv != EST_ERR_NONE) {
            EST_LOG_ERR("Reenroll failed on second attempt during basic/digest authentication");
            
            /*
             * If we're attempting token mode for the second time, and
             * the server responded with error attributes, log them now
             */
            if (ctx->token_error[0] != '\0' || ctx->token_error_desc[0] != '\0') {
                EST_LOG_ERR("Token Auth mode failed, server provided error information: \n"
                            "   Error = %s\n Error description: %s",
                            ctx->token_error, ctx->token_error_desc);
                ctx->token_error[0] = '\0';
                ctx->token_error_desc[0] = '\0';
            }            
            
        }
        est_client_disconnect(ctx, &ssl);
    }

err:    
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    X509_REQ_free(req);

    return (rv);

    
}

/*! @brief est_client_copy_enrolled_cert() passes back the client certificate
    that was previously obtained from the EST server by the call to
    est_client_enroll().
 
    @param ctx Pointer to an EST context
    @param cn Pointer to the Common Name value to be used in the enrollment
    request.
    @param pkcs7 Pointer to a pointer that will point to the buffer that
    contains the newly enrolled client certificate.
 
    @return EST_ERROR

    est_client_copy_enrolled_cert() copies the previously obtained client
    certificate from the EST context to the application's buffer.  Once this
    client certificate is copied out of the context it is removed from the
    context.
 */
EST_ERROR est_client_copy_enrolled_cert (EST_CTX *ctx, unsigned char *pkcs7)
{

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (pkcs7 == NULL){
        EST_LOG_ERR("EST Client: Simple Enroll, invalid parameter");
        return EST_ERR_INVALID_PARAMETERS;
    }
         
    if (ctx->enrolled_client_cert == NULL){
        EST_LOG_ERR("No client certificate to copy");
        return(EST_ERR_NO_CERTIFICATE);
    }

    memset(pkcs7, 0, ctx->enrolled_client_cert_len);            
    memcpy(pkcs7, ctx->enrolled_client_cert, ctx->enrolled_client_cert_len);
    
    /*
     * Now that the copy in the context has been handed over,
     * free it up
     */
    free(ctx->enrolled_client_cert);
    ctx->enrolled_client_cert = NULL;
    ctx->enrolled_client_cert_len = 0;

    return (EST_ERR_NONE);
}


/*! @brief est_client_get_cacerts() performs a CAcerts GET request to the EST server
 
    @param ctx Pointer to an EST context
    @param ca_certs_len Pointer to an integer to hold the length of the CA certs
    buffer
 
    @return EST_ERROR

    est_client_get_cacerts() connects to the EST server, builds a CA certs
    request, and sends the GET CA certs request.  The response is placed in a
    buffer allocated and maintained by the EST client library and a pointer to
    this buffer is returned to the calling application.  The returned CA certs
    are in base64 encoded DER format and is stored in a NULL terminated string
    buffer.

    Once the CA certificates are retrieved from the EST server, the ET Client
    library must be reset.  The retrieved CA certificates should now be passed
    into the EST client initialization function as the explicit TA database.
 */
EST_ERROR est_client_get_cacerts (EST_CTX *ctx, int *ca_certs_len)
{
    EST_ERROR rv = EST_ERR_NONE;
    SSL *ssl = NULL;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (ca_certs_len == NULL) {
        EST_LOG_ERR("EST Client: Get CACerts, invalid parameter");
        return EST_ERR_INVALID_PARAMETERS;
    }
    
    rv = est_client_connect(ctx, &ssl);
    if (rv != EST_ERR_NONE) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }        
        return (rv);
    }
    rv = est_client_send_cacerts_request(ctx, ssl, ca_certs_len);
    est_client_disconnect(ctx, &ssl);

    if (ssl) {
        SSL_shutdown(ssl);    
        SSL_free(ssl);
    }
    
    return (rv);
}


/*! @brief est_client_copy_cacerts() copies the previously retrieved CA
    certificates to the application's buffer.
 
    @param ctx Pointer to the current EST context.
    @param ca_certs Pointer to the buffer into which the retrieved CA certificates
    are to be copied. 
 
    @return EST_ERROR

    est_client_copy_cacerts() copies the most recently retrieved CA
    certificates from the EST server.  Once these CA certificates are copied
    to the application's buffer pointed to by ca_certs they are removed from
    the EST client context.

    Once the CA certificates are retrieved by the application, the EST client
    library must be reset.  When this reset is performed, the CA certificates
    retrieved in this est_client_copy_cacerts call should be passed into the
    EST client initialization function as the explicit TA database.
 */
EST_ERROR est_client_copy_cacerts (EST_CTX *ctx, unsigned char *ca_certs)
{

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (ca_certs == NULL) {
        EST_LOG_ERR("EST Client: Get CACerts, invalid parameter");
        return EST_ERR_INVALID_PARAMETERS;
    }
    
    if (ctx->retrieved_ca_certs == NULL) {
        EST_LOG_ERR("No CA certificates to copy");
        return(EST_ERR_NO_CERTIFICATE);
    }

    memset(ca_certs, 0, ctx->retrieved_ca_certs_len);
    memcpy(ca_certs, ctx->retrieved_ca_certs, ctx->retrieved_ca_certs_len);

    /*
     * if the CA certs were obtained, then the client lib needs to be reset.
     */
    ctx->est_client_initialized = 0;
    
    return (EST_ERR_NONE);
}


/*! @brief est_client_get_csrattrs() performs the CSR attributes request to
    the EST server.
 
    @param ctx Pointer to EST context for a client session
    @param csr_data Pointer to a buffer that is to hold the returned CSR
    attributes
    @param csr_len Pointer to an integer that is to hold the length of the CSR
    attributes buffer
 
    @return EST_ERROR

    est_client_get_csrattrs() connects to the EST server, sends the CSR attributes
    request to the server, saves aways the returned CSR attribute data, and then
    disconnects from the EST server.
 */
EST_ERROR est_client_get_csrattrs (EST_CTX *ctx, unsigned char **csr_data, int *csr_len)
{
    EST_ERROR rv;
    int new_csr_len, pop_required = 0;
    SSL *ssl;
    unsigned char *new_csr_data;

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!csr_data) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (!csr_len) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /* assume defeat */
    *csr_data = NULL;
    *csr_len = 0;
    
    /*
     * Connect to the EST server
     */
    rv = est_client_connect(ctx, &ssl);
    if (rv != EST_ERR_NONE) {
        return (rv);
    }

    /*
     * free the current attributes if cached
     */
    if (ctx->retrieved_csrattrs) {
        free(ctx->retrieved_csrattrs);
	ctx->retrieved_csrattrs = NULL;
        ctx->retrieved_csrattrs_len = 0;
    }
    ctx->retrieved_csrattrs_len = 0;
    ctx->retrieved_csrattrs = NULL;

    /*
     * Send the HTTP request to the EST server
     */
    rv = est_client_send_csrattrs_request(ctx, ssl, &new_csr_data, &new_csr_len);
    est_client_disconnect(ctx, &ssl);

    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("CSR request failed, error code is %d (%s)", rv, EST_ERR_NUM_TO_STR(rv));
	if (new_csr_data) {
	    free(new_csr_data);
	}
	return (rv);
    }

    if (new_csr_data == NULL) {
        EST_LOG_INFO("CSR attributes are: NULL");
	return (EST_ERR_NONE);
    }
    /* 
     * have to allocate the new memory prior to 
     * parsing to be sure it is null terminated.
     */
    ctx->retrieved_csrattrs = (unsigned char *)malloc(new_csr_len + 1);
    if (!ctx->retrieved_csrattrs) {
        free(new_csr_data);
	return (EST_ERR_MALLOC);
    }

    ctx->retrieved_csrattrs_len = new_csr_len;
    memcpy(ctx->retrieved_csrattrs, new_csr_data, new_csr_len);
    ctx->retrieved_csrattrs[new_csr_len] = 0;
    EST_LOG_INFO("CSR attributes are(%d): %s", ctx->retrieved_csrattrs_len, 
		 ctx->retrieved_csrattrs);
    free(new_csr_data);

    /* Now make sure the data is valid */
    rv = est_asn1_parse_attributes((char *)ctx->retrieved_csrattrs, ctx->retrieved_csrattrs_len,
				   &pop_required);
    if (rv != EST_ERR_NONE) {
	free(ctx->retrieved_csrattrs);
        ctx->retrieved_csrattrs = NULL;
        ctx->retrieved_csrattrs_len = 0;
    } else {
        *csr_data = ctx->retrieved_csrattrs;
        *csr_len = ctx->retrieved_csrattrs_len;
    }
    ctx->csr_pop_required = pop_required;
    
    return (rv);
}

/*! @brief est_client_enable_srp() is used by an application to enable
    TLS-SRP as the transport, which is used in place of traditional
    TLS.  TLS-SRP allows for secure transport when an X.509 certificate
    is not available or when a trust anchor is not available.
 
    @param ctx EST context obtained from the est_client_init() call.
    @param strength Specifies the SRP strength to use.
    @param uid char buffer containing the user id to be used as the
    SRP user name. 
    @param pwd char buffer containing the passowrd to be used as the
    SRP password.

    This function allows an application to enable TLS-SRP cipher suites,
    which is another form for TLS.  This could be used when the EST client
    does not have an X.509 certificate to identify itself to the EST
    server.  It can also be used by the EST client when a trust anchor
    is not available to authenticate the EST server identity.  
    The EST server must support TLS-SRP when using this API. 

    This function must be invoked after est_client_init() and prior to 
    issuing any EST commands..

    All string parameters are NULL terminated strings.
    
    @return EST_ERROR.  If error, NULL.
*/
EST_ERROR est_client_enable_srp (EST_CTX *ctx, int strength, char *uid, char *pwd) 
{
    X509_STORE *store;
    int rc;

    if (ctx == NULL) {
	EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }    

    if (ctx->ssl_ctx == NULL) {
	EST_LOG_ERR("SSL context has not been initialized");
        return (EST_ERR_NO_SSL_CTX);
    }
    
    if (strength < EST_SRP_STRENGTH_MIN) {
	EST_LOG_ERR("SRP strength must be greater than %d", EST_SRP_STRENGTH_MIN);
        return (EST_ERR_SRP_STRENGTH_LOW);
    }

    if (uid == NULL || uid[0] == 0) {
	EST_LOG_ERR("SRP user ID must be provided");
	return (EST_ERR_INVALID_PARAMETERS);
    }

    if (pwd == NULL || pwd[0] == 0) {
	EST_LOG_ERR("SRP password must be provided");
	return (EST_ERR_INVALID_PARAMETERS);
    }

    /*
     * Enable just the SRP cipher suites.  When SRP is enabled,
     * it's used exclusively.
     *
     * Check if we have a trust anchor configured.  We will
     * enable the DSS and RSA auth cipher suites if we do.
     */
    store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
    if (store && store->objs && sk_X509_OBJECT_num(store->objs) > 0) {
	EST_LOG_INFO("Enabling TLS SRP cipher suites with RSA/DSS");
        rc = SSL_CTX_set_cipher_list(ctx->ssl_ctx, EST_CIPHER_LIST_SRP_AUTH);
    } else {
	EST_LOG_INFO("Enabling TLS SRP cipher suites w/o RSA/DSS");
        rc = SSL_CTX_set_cipher_list(ctx->ssl_ctx, EST_CIPHER_LIST_SRP_ONLY);
    }
    if (!rc) { 
	EST_LOG_ERR("Failed to set SSL SRP cipher suites");
	ossl_dump_ssl_errors();
	return EST_ERR_SSL_CIPHER_LIST;
    }
	
    /* 
     * Set the SRP user name and password.  
     */
    if (!SSL_CTX_set_srp_username(ctx->ssl_ctx, uid)) {
	EST_LOG_ERR("Unable to set SRP username");
	ossl_dump_ssl_errors();
	return EST_ERR_SRP_USERID_BAD;
    }
    if (!SSL_CTX_set_srp_password(ctx->ssl_ctx, pwd)) {
	EST_LOG_ERR("Unable to set SRP password");
	ossl_dump_ssl_errors();
	return EST_ERR_SRP_PWD_BAD;
    }
    SSL_CTX_set_srp_strength(ctx->ssl_ctx, strength);

    ctx->enable_srp = 1;

    EST_LOG_INFO("TLS-SRP enabled");

    return (EST_ERR_NONE);
}


/*! @brief est_client_set_auth() is used by an application to set up the
    authentication parameters to be used.
 
    @param ctx EST context obtained from the est_client_init() call.
    @param uid char buffer containing the user id to be used for basic
    and digest based authentication
    @param pwd char buffer containing the passowrd to be used for basic
    and digest based authentication
    @param client_cert_raw char buffer containing the client application
    certificate.
    @param pkey_raw Private key that can be used with the client cert
    @param pkey_len Length of buffer holding the private key

    This function allows an application to provide the information required
    for authenticating the EST client with the EST server.  Until this call is
    made, the only accepted request is the GET CA Certs.  If the user id is
    provided, a password must also be provided.

    The application may pass the private key (pkey_raw/pkey_len) to be used
    for signing requests to the server, otherwise, only basic or digest based
    authentication will be performed on the TLS session for these requests.
    If the private key is passed, it must contain the private key that matches
    the public key contained in the client_cert parameter.

    All string parameters are NULL terminated strings.
    
    @return EST_ERROR.  If error, NULL.
*/
EST_ERROR est_client_set_auth (EST_CTX *ctx, const char *uid, const char *pwd,
                               X509 *client_cert, EVP_PKEY *client_key)
{
    EST_ERROR rv = EST_ERR_NONE;
    
    if (ctx == NULL) {
	EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }    

    if ((uid || pwd) && ctx->enable_srp) {
	EST_LOG_WARN("http authentication used together with SRP");
    }

    rv = est_client_set_uid_pw(ctx, uid, pwd);
    if (rv != EST_ERR_NONE) {
        return (rv);
    }            

    ctx->auth_mode = AUTH_NONE;

    /*
     * cache away the client cert and the associated private key, then
     * get them loaded into the SSL context so that they'll be used.
     */
    ctx->client_key = client_key;
    ctx->client_cert = client_cert;
    
    /*
     * Load the client cert if it's available
     */
    if (ctx->client_cert && ctx->client_key) {
        if (est_client_set_cert_and_key(ctx->ssl_ctx, ctx->client_cert, ctx->client_key)) {
            EST_LOG_ERR("Unable to load local certificate and private key");
            return EST_ERR_CLIENT_INVALID_KEY;
        }
    } else {
        EST_LOG_WARN("Not using client certificate for TLS session");
    }
    
    return EST_ERR_NONE;
}


/*! @brief est_client_set_auth_cred_cb() is used by an application to register
  its callback function.
    
  @param ctx EST context obtained from the est_client_init() call.
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
EST_ERROR est_client_set_auth_cred_cb (EST_CTX *ctx, auth_credentials_cb callback)
{
    if (ctx == NULL) {
	EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }
    
    ctx->auth_credentials_cb = callback;
    
    return EST_ERR_NONE;
}


/*! @brief est_client_enable_basic_auth_hint() is used by an application to 
    reduce overhead at the TCP and TLS layers when the client knows that
    the EST server is using HTTP Basic Authentication. 
 
    @param ctx Pointer to EST context for a client session

    Normally libest will send an anonymous HTTP request when doing the
    initial request from the EST server.  This function allows an application 
    to improve performance by sending the HTTP Basic Auth header in the initial 
    request sent to the EST server.  This eliminates the need for the server to send
    the HTTP authentication challene response, which eliminates a round-trip
    between the EST client and server.  This function should be called immediately
    after invoking est_client_set_auth().

    Precautions should be taken by your application to ensure this hint is
    only enabled when it is known that the EST server is configured for HTTP
    Basic Authentication.  If the EST server is configured for HTTP Digest
    Authentication, then enabling this hint will cause the EST transaction
    to fail.
 
    @return EST_ERROR
    EST_ERR_NONE - Success.
*/
EST_ERROR est_client_enable_basic_auth_hint (EST_CTX *ctx)
{
    if (ctx == NULL) {
	EST_LOG_ERR("Null context passed");
        return (EST_ERR_NO_CTX);
    }    

    ctx->auth_mode = AUTH_BASIC;
    return (EST_ERR_NONE);
}


/*! @brief est_client_init() is used by an application to create
    a context in the EST library.  This context is used when invoking
    other functions in the client API.
 
    @param ca_chain Required char buffer containing CA certificates as raw byte
    data, to be used for authenticating the EST server
    @param ca_chain_len length of ca_chain char buffer.
    @param cert_format defines the format of the certificates that will be
    passed down during this instantiation of the EST client library.  Currently,
    the only value accepted is EST_CERT_FORMAT_PEM
    @param cert_verify_cb A pointer to a function in the EST client application
    that is called when a received server identity certificate has failed
    verification from the SSL code.  This function takes as input two
    parameters, a pointer to the X509 structure containing the server's
    certificate, and a integer value set to the OpenSSL defined error
    for this certificate.  This callback function returns a 0 if the server's
    identity certificate has been rejected, and any other value if it
    has been approved.

    This function allows an application to initialize an EST client context.
    The application must provide the local CA certificates
    (ca_chain/ca_chain_len) to use for client operation.  The certificates
    provided must be in the format specified by the cert_format parameter.
    Currently, only PEM encoded certificates are supported.  The length
    parameters for the certificates (ca_chain_len) are to be used when DER
    formatted certificates are passed.  The CA certificates may contain CRL
    entries that will be used when authenticating the certificates received
    from the server.
 
    @return EST_CTX.  If error, NULL.
*/
EST_CTX *est_client_init (unsigned char *ca_chain, int ca_chain_len,
                          EST_CERT_FORMAT cert_format,
                          int (*cert_verify_cb)(X509 *, int))
{
    EST_CTX *ctx;
    volatile int len;
    EST_ERROR rv;

    if (cert_format != EST_CERT_FORMAT_PEM) {
        EST_LOG_ERR("Only PEM encoding of certificates is supported.");
        return NULL;
    }
        
    /* 
     * If a CA chain was passed in, then check the length value passed in.  It
     * should match the calculated length of the buffer.  This will verify
     * both that the length value is correct, and that the buffer is properly
     * null terminated.
     */
    if (ca_chain) {    
        len = (int) strnlen((char *)ca_chain, EST_CA_MAX);
        if (len != ca_chain_len) {
            EST_LOG_ERR("Length of ca_chain doesn't match passed ca_chain_len");
            return NULL;
        }
    }
    
    ctx = (EST_CTX *)malloc(sizeof(EST_CTX));
    if (!ctx) {
        EST_LOG_ERR("Unable to allocate memory for EST Context");
        return NULL;
    }
    memset(ctx, 0, sizeof(EST_CTX));
    ctx->est_mode = EST_CLIENT;

    /*
     * Load the local CA certificates into memory and retain
     * for future use.  This will be used for /CACerts requests.
     */
    if (est_load_trusted_certs(ctx, ca_chain, ca_chain_len)) {
        EST_LOG_ERR("Failed to load trusted certificate store");
        est_destroy(ctx);
        return NULL;
    }

    rv = est_client_init_ssl_ctx(ctx);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Failed to initialize SSL context with certificate and private key passed");
        est_destroy(ctx);
        return NULL;
    }

    /*
     * save away the client's callback function that allows for manual verification of
     * the server's identity certificate
     */
    ctx->manual_cert_verify_cb = cert_verify_cb;
    
    /*
     * PDB TODO: change this to be configurable with a default value when the
     * init() API changes to using X509 structures instead of char buffers.
     *
     * For now, hard code the socket read timeout to 10 seconds
     */
    ctx->read_timeout = EST_SSL_READ_TIMEOUT_DEF;

    /*
     * We use SHA-256 as the default hash algorithm
     * for signing the CSR.  This can be changed by the
     * application by using the est_client_set_sign_digest() 
     * function.
     */
    ctx->signing_digest = EVP_sha256(); 

    ctx->retry_after_delay = 0;
    ctx->retry_after_date = 0;
    
    ctx->est_client_initialized = 1;
    return (ctx);
}


/*! @brief est_client_set_server() is called by the application layer to
     specify the address/port of the EST server. It must be called after
     est_client_init() and prior to issuing any EST commands.
 
    @param ctx Pointer to EST context for a client session
    @param server Name of the EST server to connect to.  The ASCII string
    representing the name of the server is limited to 254 characters
    @param port TCP port on the EST server to connect
 
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_INVALID_SERVER_NAME - NULL value passed for EST server name, or
    server name string too long
    EST_ERR_CLIENT_NOT_INITIALIZED - Called before est_client_init()
    EST_ERR_INVALID_PORT_NUM - Invalid port number input, less than zero or
    greater than 65535

    est_client_set_server error checks its input parameters and then stores
    both the hostname and port number into the EST context.
 */
EST_ERROR est_client_set_server (EST_CTX *ctx, const char *server, int port)
{
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    if (server == NULL) {
        return EST_ERR_INVALID_SERVER_NAME;
    }
    
    if (strlen(server) > EST_MAX_SERVERNAME_LEN-1) {
        return EST_ERR_INVALID_SERVER_NAME;
    }
    
    if (port <= 0 || port > 65535) {
        return EST_ERR_INVALID_PORT_NUM;
    }
    
    strncpy(ctx->est_server, server, EST_MAX_SERVERNAME_LEN);

    ctx->est_port_num = port;

    return EST_ERR_NONE;
}

/*! @brief est_client_set_sign_digest() is called by the application layer to
     specify the hash algorithm used to sign the PKCS10 CSR during the
     enroll operation. It must be called after
     est_client_init() and prior to issuing any EST commands.
 
    @param ctx Pointer to EST context for a client session
    @param nid This is the NID value defined in the OpenSSL header file obj_mac.h
               for the desired digest to use for signing.  
 
    @return EST_ERROR
    EST_ERR_NONE - Success.
    EST_ERR_NO_CTX - NULL value passed for EST context
    EST_ERR_INVALID_DIGEST - An unsupported NID was provided.

    libest supports SHA1, SHA224, SHA256, SHA384, and SHA512 digests.  
    SHA256 is the default digest to use for signing.  There's no need
    to invoke this function unless another digest is desired. The
    supported NID values are:
	NID_sha1
	NID_sha224 
	NID_sha256 
	NID_sha384 
	NID_sha512 
    
 */
EST_ERROR est_client_set_sign_digest (EST_CTX *ctx, int nid) 
{
    if (!ctx) {
        return EST_ERR_NO_CTX;
    }

    switch (nid) {
    case NID_sha512:
        ctx->signing_digest = EVP_sha512(); 
        break;
    case NID_sha384:
        ctx->signing_digest = EVP_sha384(); 
        break;
    case NID_sha256:
        ctx->signing_digest = EVP_sha256(); 
        break;
    case NID_sha224:
        ctx->signing_digest = EVP_sha224(); 
        break;
    case NID_sha1:
        ctx->signing_digest = EVP_sha1(); 
        break;
    default:
	return (EST_ERR_INVALID_DIGEST);
        break;
    }

    return (EST_ERR_NONE);
}



/*! @brief est_client_copy_retry_after() copies the retry after value stored
    in this client context.
 
    @param ctx Pointer to the current EST context.
    
    @param retry_delay Pointer to the integer where the retry-after delay secs
    value is copied.  If the server sent a retry-after in delay seconds format
    then it will be passed here.  If it did not, then this value will be zero.
    
    @param retry_time Pointer to the time_t where the retry-after time date
    value is copied.  If the server sent a retry-after in time and date string
    format then this string is converted into a time_t value and passed up
    in this parameter.  This value will only be set if the server sent a time
    and date string response, otherwise, this value is set to zero.
 
    @return EST_ERROR

    When a response is received from the EST server the headers are checked to
    see if the server has included a Retry-After header, indicating that this
    request currently cannot be processed.  If a Retry-After HTTP header is
    included in the received response from the server the delay value is saved
    in the context and an EST error code is given to the application on this
    request indicating that the client must retry the request at a later time.

    The value specified by the server can be in one of two basic formats, a
    string version of a integer value that represents the number of seconds
    the client must wait before retrying the request, and a string containing
    a date and time when the client can retry the request.  The date and time
    string can be in any format specified in RFC 2616.  If the second delay
    value is sent it is converted into an integer and saved in the EST context
    and if the date time string value is sent it is converted into a time_t
    value and saved into the EST context.  The application must then call
    est_client_copy_retry_after() to obtain the amount of time to wait before
    retrying the request.  est_client_copy_retry_after() copies the current
    retry-after value from the client context and returns it to the
    application.  Only one of the two return values will be set with a
    non-zero value.

    NOTE: The processing of a Retry-After value in time/date format is currently
    not supported.  The EST Client will always return only a retry delay
    value in seconds.
 */
EST_ERROR est_client_copy_retry_after (EST_CTX *ctx, int *retry_delay,
                                       time_t *retry_time)
{

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (!ctx->est_client_initialized) {
        return EST_ERR_CLIENT_NOT_INITIALIZED;
    }

    *retry_delay = ctx->retry_after_delay;
    ctx->retry_after_delay = 0;

    *retry_time = ctx->retry_after_date;
    ctx->retry_after_date = 0;
    
    return (EST_ERR_NONE);
}

/*! @brief est_client_force_pop() is used by an application to enable 
    the proof-of-possession generation at the EST client.  This proves
    that the EST client that sent the CSR to the server/proxy is in possession
    of the private key that was used to sign the CSR.  This binds the TLS 
    session ID to the CSR.

    Note, if the CSR attributes configured on the server require PoP 
    checking, then there is no need to call this function to enable
    PoP.  The PoP will be enabled automatically under this scenario
    when the CSR attributes are requested from the server/proxy.
    
    @param ctx Pointer to the EST context

    This function may be called at any time.   
 
    @return EST_ERROR.
 */
EST_ERROR est_client_force_pop (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->client_force_pop = 1;
    return (EST_ERR_NONE);
}

/*! @brief est_client_unforce_pop() is used by an application to disable 
    the proof-of-possession generation at the EST client.  Please see
    the documenation for est_client_force_pop() for more information
    on the proof-of-possession check.

    @param ctx Pointer to the EST context

    This function may be called at any time.   
 
    @return EST_ERROR.
 */
EST_ERROR est_client_unforce_pop (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->client_force_pop = 0;
    return (EST_ERR_NONE);
}


/*! @brief est_client_set_read_timeout() is used by an application to set
    timeout value of read operations.  After the EST client sends a request to
    the EST server it will attempt to read the response from the server.  This
    timeout value limits the amount of time the client will wait for the
    response.

    @param ctx Pointer to the EST context
    @param timeout Integer value representing the read timeout in seconds.
    The minimum value is EST_SSL_READ_TIMEOUT_MIN and the maximum value is
    EST_SSL_READ_TIMEOUT_MAX.
 
    @return EST_ERROR.
 */
EST_ERROR est_client_set_read_timeout (EST_CTX *ctx, int timeout)
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
        
    ctx->read_timeout = timeout;
    return (EST_ERR_NONE);
}
