/*------------------------------------------------------------------
 * est_ossl_util.c - Interface between EST server and OpenSSL for
 *                   EST server operations.  Some of this code was taken
 *                   from the OpenSSL /apps directory and modified to work
 *                   with the EST stack, which is why the OpenSSL copyright
 *                   statement is retained here.  
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
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
 *    The word 'cryptographic' can be left out if the rouines from the library
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

// 2015-08-28 stability and readabilitly improvement on logging of ossl_verify_cb() 
// 2015-08-13 improved error handling and reporting

#include "est.h"
#include <stdio.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "est_ossl_util.h"
#include "est_locl.h"

char *ossl_error_string(int err_code)
{
    static char *strings[] = {
	"SSL_ERROR_NONE",
	"SSL_ERROR_SSL",
	"SSL_ERROR_WANT_READ",
	"SSL_ERROR_WANT_WRITE",
	"SSL_ERROR_WANT_X509_LOOKUP",
	"SSL_ERROR_SYSCALL",
	"SSL_ERROR_ZERO_RETURN",
	"SSL_ERROR_WANT_CONNECT",
	"SSL_ERROR_WANT_ACCEPT" };
    return (0 <= err_code && err_code < sizeof(strings)/sizeof(*strings) ?
	      strings[err_code] : "unknown SSL error code");
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
        EST_LOG_WARN("%svalidation error=%d (%s) at depth=%d; cert subject='%s', issuer='%s", 
		     X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
		     cert_error, 
		     cert_error == 3 ? "no CRL" : X509_verify_cert_error_string(cert_error),
		     X509_STORE_CTX_get_error_depth(ctx),
		     current_cert ? current_cert->name : "(no cert)" ,
		     current_cert ? X509_NAME_oneline(X509_get_issuer_name(current_cert), NULL, 0) : "(no cert)");
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
        EST_LOG_ERR("Unable to open the raw CA cert buffer");
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
            EST_LOG_INFO("Adding cert to store (%s)", xi->x509->name);
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
    if (bptr->data) {
	EST_LOG_WARN("OpenSSL error: %s", bptr->data);
    }
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
    cacerts_decoded = (unsigned char *)malloc(certs_len);
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
     * the the stack of certs
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
        EST_LOG_ERR("Failed to attain X509 cert stack from PKCS7 data");
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

    *pem = (unsigned char *)malloc(pem_len + 1);
    if (!*pem) {
        EST_LOG_ERR("malloc failed");
	PKCS7_free(p7);
	return (-1);
    }
    memcpy(*pem, pem_data, pem_len);   
    (*pem)[pem_len] = 0;  //Make sure it's null termianted
    BIO_free_all(out);
    PKCS7_free(p7);
    return (pem_len);
}

/*! @brief est_ossl_BIO_copy_data() returns a copy of the contents of the given BIO.
 
    @param out       Pointer to BIO to be read
    @param data_lenp Pointer (or NULL) to variable that will receive the length of the data. 

    This function will allocate memory for the data
    On success, the caller is responsible for freeing this memory.
 
    @return the pointer to the allocated copy, or NULL
 */

unsigned char *est_ossl_BIO_copy_data(BIO *out, int *data_lenp) {
    unsigned char *data, *tdata;
    int data_len;

    data_len = BIO_get_mem_data(out, &tdata);
    data = (unsigned char *)malloc(data_len+1);
    if (data) {
        memcpy(data, tdata, data_len);
	data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
	if (data_lenp) {
	    *data_lenp = data_len;
	}
    } else {
        EST_LOG_ERR("malloc failed");
    }
    return data;
}


int X509_REQ_get_extension(X509_REQ *req, int nid, int lastpos, STACK_OF(X509_EXTENSION) **pexts, 
			   int delete_exts, int *pnid_deleted_exts)
{
	X509_ATTRIBUTE *attr;
	STACK_OF(X509_EXTENSION) *exts;
	ASN1_TYPE *ext = NULL;
	int *pnid, idx, elem, item;
	const unsigned char *p;
	int *ext_nids = X509_REQ_get_extension_nids();

	if (req == NULL)
		return(-2);
	if (req->req_info == NULL || !ext_nids)
		return(-1);
	lastpos++;
	if (lastpos < 0)
		lastpos = 0;
	pnid = ext_nids-1; 
	int pos = -1;
     next_nid:
	if (*++pnid == NID_undef)
    		return -1;
	idx = -1;
    next_attr:
	idx = X509_REQ_get_attr_by_NID(req, *pnid, idx);
	if (idx == -1)
		goto next_nid;
	attr = X509_REQ_get_attr(req, idx);
	elem = -1;
    next_elem:
	elem++;
	ext = NULL;
	if (attr->single == 1&& elem == 0)
		ext = attr->value.single;
	else if (attr->single == 0 && elem < sk_ASN1_TYPE_num(attr->value.set))
		ext = sk_ASN1_TYPE_value(attr->value.set, elem);
	if (!ext)
		goto next_attr;
	if (ext->type != V_ASN1_SEQUENCE)
		goto next_elem;
	p = ext->value.sequence->data;
	exts = (STACK_OF(X509_EXTENSION) *)
		ASN1_item_d2i(NULL, &p, ext->value.sequence->length,
			      ASN1_ITEM_rptr(X509_EXTENSIONS));
	item = -1;
    next_item:
	item = X509v3_get_ext_by_NID(exts, nid, item);
	if (item == -1) {
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		goto next_elem;
	}
	if (++pos < lastpos)
		goto next_item;

	// found
	if (pexts)
		*pexts = exts;
	else
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	if (delete_exts) {
		if (attr->single || sk_ASN1_TYPE_num(attr->value.set) == 1)
			X509_REQ_delete_attr(req, idx);
		else 
			(void)sk_ASN1_TYPE_delete(attr->value.set, elem);
		if (pnid_deleted_exts)
			*pnid_deleted_exts = *pnid;
	}
	return pos;
}


/* The caller is responsible for freeing the string returned. */

unsigned char *ossl_get_extension_value (const X509_EXTENSION *ext)
{
    unsigned char *val = NULL;

    if (ext) {
        BIO *out = BIO_new(BIO_s_mem());
	if (out) {
	    if (!X509V3_EXT_print(out, (X509_EXTENSION *)ext, XN_FLAG_COMPAT, X509_FLAG_COMPAT))
	    {
	        BIO_printf(out, "%16s", "");
		M_ASN1_OCTET_STRING_print(out, ext->value);
	    }
	    val = est_ossl_BIO_copy_data(out, NULL);
	    BIO_free(out);
	}
    }
    return val;
}

/* The caller is responsible for freeing the string returned. */
unsigned char *ossl_get_csr_subject_alt_name (const X509_REQ *csr)
{
    STACK_OF(X509_EXTENSION) *exts;
    // would be incomplete: exts = X509_REQ_get_extensions(csr);
    const X509_EXTENSION *ext = NULL;
    if (X509_REQ_get_extension((X509_REQ *)csr, NID_subject_alt_name, -1, &exts, 0, NULL) >= 0) {
        ext = sk_X509_EXTENSION_value(exts, X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1));
    }
    unsigned char *str = ossl_get_extension_value(ext);
    if (ext)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return str;
}

/* The caller is responsible for freeing the string returned. */
unsigned char *ossl_get_cert_subject_alt_name (const X509 *cert)
{
    const X509_EXTENSION *ext = X509_get_ext((X509 *)cert, X509_get_ext_by_NID((X509 *)cert, NID_subject_alt_name, -1));
    return ossl_get_extension_value(ext);
}

int ossl_name_entries_inclusion (X509_NAME *name1, X509_NAME *name2)
{
    int pos1, pos2;
    for (pos1 = 0; pos1 < X509_NAME_entry_count(name1); pos1++) {
	X509_NAME_ENTRY *ne1 = X509_NAME_get_entry(name1, pos1);
	int found = 0;
	for (pos2 = 0; pos2 < X509_NAME_entry_count(name2); pos2++) {
	    X509_NAME_ENTRY *ne2 = X509_NAME_get_entry(name2, pos2);
	    ASN1_STRING *s1 = X509_NAME_ENTRY_get_data(ne1);
	    ASN1_STRING *s2 = X509_NAME_ENTRY_get_data(ne2);
	    if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne1)) == 
		OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne2)) &&
		s1->length == s2->length && !memcmp(s1->data, s2->data, s1->length)) {
		// This goes wrong if the string types do not match: !ASN1_STRING_cmp(s1, s1)
		found = 1;
		break;
	    }
	}
	if (!found) {
	    return 0;
	}
    }
    return 1;
}

EST_ERROR ossl_check_subjects_agree(const X509_REQ *csr, const X509 *cer)
{
    X509_NAME *subj1 = X509_REQ_get_subject_name((X509_REQ *)csr);
    X509_NAME *subj2 = X509_get_subject_name    ((X509     *)cer);
    EST_ERROR rv = EST_ERR_SUBJECT_MISMATCH;

    char *csr_subject = X509_NAME_oneline(subj1, NULL, 0);
    char *cer_subject = X509_NAME_oneline(subj2, NULL, 0);

    if (!(ossl_name_entries_inclusion (subj1, subj2) &&
	  ossl_name_entries_inclusion (subj2, subj1))) {
	EST_LOG_ERR("Subject name entries disagree for CSR ('%s') and cert ('%s')", 
		    csr_subject ? csr_subject : "(none)", 
		    cer_subject ? cer_subject : "(none)");
	goto cleanup1;
    }

    /* Limitation: Comparing only the first Subject Alternative Names (if present), in the given order. */
    char *csr_subject_alt = (char *)ossl_get_csr_subject_alt_name (csr);
    char *cer_subject_alt = (char *)ossl_get_cert_subject_alt_name(cer);

    if (!cer_subject_alt && !csr_subject_alt) {
        rv = EST_ERR_NONE;
    }
    else if (cer_subject_alt && csr_subject_alt) {
	if (!strcmp(cer_subject_alt, csr_subject_alt)) {
	    rv = EST_ERR_NONE;
	}
    }
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Subject Alternative Names disagree for CSR ('%s') and cert ('%s') with common Subject '%s'", 
		    csr_subject_alt ? csr_subject_alt : "(none)",
		    cer_subject_alt ? cer_subject_alt : "(none)",
		    csr_subject ? csr_subject : "(none)");
    }
    if (csr_subject_alt) free (csr_subject_alt);
    if (cer_subject_alt) free (cer_subject_alt);
 cleanup1:
    if (csr_subject) free (csr_subject);
    if (cer_subject) free (cer_subject);
    return rv;
}
