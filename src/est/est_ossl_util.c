/** @file */
/*------------------------------------------------------------------
 * est_ossl_util.c - Interface between EST server and OpenSSL for
 *                   EST server operations.  Some of this code was taken
 *                   from the OpenSSL /apps directory and modified to work
 *                   with the EST stack, which is why the OpenSSL copyright
 *                   statement is retained here.  
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014, 2016 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* This was written by Gordon Chaffee <chaffee@plateau.cs.berkeley.edu>
 * and donated 'to the cause' along with lots and lots of other fixes to
 * the library. */


#ifndef WIN32
#include <openssl/pem.h>
#include <openssl/err.h>
#else
#include <Ws2tcpip.h>
#endif
#include <stdio.h>
#include <openssl/x509v3.h>
#include "est.h"
#include "est_locl.h"
#include "est_ossl_util.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

/*
 * Extract out the subject field from either a certificate or a
 * CSR.
 * cert_csr - pointer to the OpenSSL structure to be parsed, either
 *            a X509* or a X509_REQ*
 * cert_or_csr - indicates whether it's a cert or a csr
 * name/len - pointer to destination buffer to hold the subj and the
 *            length of the buffer. Name does not have to zeroed out.
 */
EST_ERROR est_get_subj_fld_from_cert (void *cert_csr, EST_CERT_OR_CSR cert_or_csr,
                                      char *name, int len)
{
    X509_NAME *subject_nm;
    BIO *out;
    BUF_MEM *bm;
    errno_t safec_rc;
    int src_len;

    /*
     * Extract the subject name from the X509, read it in through
     * a BIO, and then copy out the data from inside the BIO
     */
    if (cert_or_csr == EST_CSR) {
        subject_nm = X509_REQ_get_subject_name((X509_REQ *)cert_csr);
    } else {
        subject_nm = X509_get_subject_name((X509*) cert_csr);
    }
    
    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        EST_LOG_ERR("BIO_new failed");
        ossl_dump_ssl_errors();
        return(EST_ERR_MALLOC);
    }

    X509_NAME_print_ex(out, subject_nm, 0,
                       XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);

    /*
     * copy out the subject field buffer to be returned
     */
    BIO_get_mem_ptr(out, &bm);
    if (bm->length > len) {
        src_len = len;
    } else {
        src_len = bm->length;
    }
    safec_rc = memcpy_s(name, len, bm->data, src_len);
    if (safec_rc != EOK) {
        EST_LOG_ERR("memcpy_s error 0x%xO\n", safec_rc);
        BIO_free(out);
        return (EST_ERR_SYSCALL);
    }
    if (bm->length < len) {
        name[bm->length] = 0;
    } else {
        name[len] = 0;
    }

    BIO_free(out);
    return (EST_ERR_NONE);
}

/*****************************************************************************************
* Authorization routines
*****************************************************************************************/
int ossl_verify_cb (int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    EST_LOG_INFO("enter function: ok=%d cert_error=%d", ok, cert_error);

    if (!ok) {
        if (current_cert) {
            char *subj = calloc(EST_MAX_CERT_SUBJ_LEN, sizeof(char));
            est_get_subj_fld_from_cert(current_cert, EST_CERT,
                                       &subj[0], EST_MAX_CERT_SUBJ_LEN);
            EST_LOG_INFO("Cert: %s ", subj);
            free(subj);
        }
        EST_LOG_INFO("%serror %d at %d depth lookup:%s\n",
                     X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
                     cert_error,
                     X509_STORE_CTX_get_error_depth(ctx),
                     X509_verify_cert_error_string(cert_error));
        switch (cert_error) {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            /*
             * We've enabled CRL checking in the TLS stack.  If
             * the application hasn't loaded a CRL, then this
             * verify error can occur.  The peer's cert is valid,
             * but we can't confirm if it was revoked.  We'll
             * warn the application.
             */
            EST_LOG_WARN("No CRL loaded, TLS peer will be allowed.");
            ok = 1;
            break;
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
            EST_LOG_WARN("Certificate verify failed (reason=%d)",
                         cert_error);
            break;
        }
        return ok;
    }
    return (ok);
}

/*
 * This function is used to load an X509_STORE using raw
 * data from a buffer.  The data is expected to be PEM
 * encoded.
 *
 * Returns the number of certs added to the store
 */
static int ossl_init_cert_store_from_raw (X509_STORE *store,
                                           unsigned char *raw, int size)
{
    STACK_OF(X509_INFO) * sk = NULL;
    X509_INFO *xi;
    BIO *in;
    int cert_cnt = 0;

    in = BIO_new_mem_buf(raw, size);
    if (in == NULL) {
        EST_LOG_ERR("Unable to open the raw CA cert buffer\n");
        return 0;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (sk == NULL) {
        EST_LOG_ERR("Unable to read PEM encoded certs from BIO");
        BIO_free(in);
        return 0;
    }
    BIO_free(in);

    /* scan over it and pull out the CRL's */
    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
#ifdef HAVE_OLD_OPENSSL
            EST_LOG_INFO("Adding cert to store (%s)", xi->x509->name);
#else
            char *subj = calloc(EST_MAX_CERT_SUBJ_LEN, sizeof(char));
            est_get_subj_fld_from_cert(xi->x509, EST_CERT, &subj[0],
                                       EST_MAX_CERT_SUBJ_LEN);
            EST_LOG_INFO("Cert being added to trust store: %s ", subj);
            free(subj);            
#endif
            X509_STORE_add_cert(store, xi->x509);
	    cert_cnt++;
        }
        if (xi->crl != NULL) {
            EST_LOG_INFO("Adding CRL to store");
            X509_STORE_add_crl(store, xi->crl);
        }
        X509_INFO_free(xi);
    }

    if (sk != NULL) {
        sk_X509_INFO_pop_free(sk, X509_INFO_free);
    }
    return (cert_cnt);
}

/*
 * This function is used to populate an X509_STORE structure,
 * which can be used by the OpenSSL TLS stack to verifying
 * a TLS peer.  The X509_STORE should already have been allocated.
 *
 * Parameters:
 *  store   - Pointer to X509_STORE structure to hold the certs
 *  raw1    - char array containing PEM encoded certs to put
 *            into the store.
 *  size1   - Length of the raw1 char array
 */
EST_ERROR ossl_init_cert_store (X509_STORE *store,
                                unsigned char *raw1, int size1)
{
    X509_STORE_set_flags(store, 0);
    int cnt;

    if (raw1) {
        cnt = ossl_init_cert_store_from_raw(store, raw1, size1);
        if (!cnt) {
            EST_LOG_ERR("Cert count is zero for store");
            return (EST_ERR_NO_CERTS_FOUND);
        }
    }
    return (EST_ERR_NONE);
}

/*
 * This function can be used to output the OpenSSL
 * error buffer.  This is useful when an OpenSSL
 * API call fails and you'd like to provide some
 * detail to the user regarding the cause of the
 * failure.
 */
void ossl_dump_ssl_errors ()
{
    BIO		*e = NULL;
    BUF_MEM	*bptr = NULL;

    e = BIO_new(BIO_s_mem());
    if (!e) {
	EST_LOG_ERR("BIO_new failed");
	return;
    }
    ERR_print_errors(e);
    (void)BIO_flush(e);
    BIO_get_mem_ptr(e, &bptr);
    EST_LOG_WARN("OSSL error: %s", bptr->data); 

#if !(ENABLE_CLIENT_ONLY)
    /*
     * If in server or proxy mode, announce that an SSL protocol error event
     * occurred.
     */
    est_invoke_ssl_proto_err_event_cb(bptr->data);
#endif
    
    BIO_free_all(e);
}


/*! @brief est_convert_p7b64_to_pem() converts the base64 encoded
    PKCS7 response from the EST server into PEM format.   
 
    @param certs_p7 Points to a buffer containing the base64 encoded pkcs7 data.
    @param certs_len Indicates the size of the *certs_p7 buffer.
    @param pem Double pointer that will receive the PEM encoded data. 
 
    Several of the EST message return data that contains base64 encoded PKCS7
    certificates.  This function is used to convert the data to PEM format.
    This function will allocate memory pointed to by the **pem argument.
    The caller is responsible for releasing this memory.  The return value
    is the length of the PEM buffer, or -1 on error.
 
    @return int.
 */
int est_convert_p7b64_to_pem (unsigned char *certs_p7, int certs_len, unsigned char **pem)
{
    X509 *x;
    STACK_OF(X509) *certs = NULL;
    BIO *b64, *in, *out;
    unsigned char *cacerts_decoded = NULL;
    int  cacerts_decoded_len = 0;
    BIO *p7bio_in = NULL;
    PKCS7 *p7=NULL;
    int i, nid;
    unsigned char *pem_data;
    int pem_len;

    /*
     * Base64 decode the incoming ca certs buffer.  Decoding will
     * always take up no more than the original buffer.
     */
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
	EST_LOG_ERR("BIO_new failed");
	return (-1);
    }    
    in = BIO_new_mem_buf(certs_p7, certs_len);    
    if (!in) {
	EST_LOG_ERR("BIO_new failed");
	return (-1);
    }
    in = BIO_push(b64, in);    
    cacerts_decoded = malloc(certs_len);
    if (!cacerts_decoded) {
	EST_LOG_ERR("malloc failed");
	return (-1);
    }
    cacerts_decoded_len = BIO_read(in, cacerts_decoded, certs_len);    
    BIO_free_all(in);
    /*
     * Now get the PKCS7 formatted buffer of certificates read into a stack of
     * X509 certs
     */
    p7bio_in = BIO_new_mem_buf(cacerts_decoded, cacerts_decoded_len);
    if (!p7bio_in) {
        EST_LOG_ERR("BIO_new failed while attempting to create mem BIO");
        ossl_dump_ssl_errors();
        free(cacerts_decoded);
        return (-1);
    }
    p7 = d2i_PKCS7_bio(p7bio_in, NULL);
    if (!p7) {
	EST_LOG_ERR("PEM_read_bio_PKCS7 failed");
	ossl_dump_ssl_errors();
        free(cacerts_decoded);
	return (-1);
    }
    BIO_free_all(p7bio_in);
    free(cacerts_decoded);
    
    /*
     * Now that we've decoded the certs, get a reference
     * to the stack of certs
     */
    nid=OBJ_obj2nid(p7->type);
    switch (nid)
        {
        case NID_pkcs7_signed:
            certs = p7->d.sign->cert;
            break;
        case NID_pkcs7_signedAndEnveloped:
            certs = p7->d.signed_and_enveloped->cert;
            break;
        default:
            EST_LOG_ERR("Invalid NID value on PKCS7 structure");
	    PKCS7_free(p7);
	    return (-1);
            break;
        }

    if (!certs) {
        EST_LOG_ERR("Failed to obtain X509 cert stack from PKCS7 data");
	PKCS7_free(p7);
	return (-1);
    }

    /*
     * Output the certs to a new BIO using the PEM format 
     */
    out = BIO_new(BIO_s_mem());
    if (!out) {
        EST_LOG_ERR("BIO_new failed");
	PKCS7_free(p7);
	return (-1);
    }
    for (i=0; i<sk_X509_num(certs); i++) {
        x=sk_X509_value(certs, i);
	PEM_write_bio_X509(out, x);
	BIO_puts(out, "\n");
    }
    (void)BIO_flush(out);

    /*
     * Now convert the BIO to char*
     */
    pem_len = (int) BIO_get_mem_data(out, (char**)&pem_data);
    if (pem_len <= 0) {
        EST_LOG_ERR("BIO_get_mem_data failed");
	PKCS7_free(p7);
	return (-1);
    }

    *pem = malloc(pem_len + 1);
    if (!*pem) {
        EST_LOG_ERR("malloc failed");
	PKCS7_free(p7);
	return (-1);
    }
    memcpy_s(*pem, pem_len, pem_data, pem_len);   
    (*pem)[pem_len] = 0;  //Make sure it's null termianted
    BIO_free_all(out);
    PKCS7_free(p7);
    return (pem_len);
}

#if ENABLE_BRSKI

char *est_find_ser_num_in_subj(X509 *cert)
{
    X509_NAME *subj = X509_get_subject_name(cert);
    ASN1_STRING *ser_num_asn1 = NULL;
    X509_NAME_ENTRY *entry;
    int i;
    char *ser_num_str;
    
    i = X509_NAME_get_index_by_NID(subj, NID_serialNumber, -1);
    if (i == -1) {
        EST_LOG_ERR("Serial Number element not defined in certificate subject attribute");
        return (NULL);
    }
    
    /*
     * Serial number exists in the subject.  Extract the value and return it
     */
    entry = X509_NAME_get_entry(subj, i);
    ser_num_asn1 = X509_NAME_ENTRY_get_data(entry);
#ifdef HAVE_OLD_OPENSSL
    ser_num_str = (char *)ASN1_STRING_data(ser_num_asn1);
#else
    ser_num_str = (char *)ASN1_STRING_get0_data(ser_num_asn1);
#endif
    EST_LOG_INFO("Found Serial Number.  Serial number = %s", ser_num_str);
    return(ser_num_str);
}
#endif
