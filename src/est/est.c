/*------------------------------------------------------------------
 * est/est.c - EST implementation
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       module.
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014 by cisco Systems, Inc.
 * Copyright (c) 2015 Siemens AG
 * License: 3-clause ("New") BSD License
 * All rights reserved.
 **------------------------------------------------------------------
 */

// 2015-08-07 added est_set_log_source() and est_log_prefixed() differentiating log source
// 2015-08-07 simplified logging macros
// 2014-06-25 limited warning for already set ex_data; spelling correction

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#ifndef DISABLE_PTHREADS
#include <pthread.h>
#else
typedef int pthread_t;
#endif
#ifndef DISABLE_BACKTRACE 
#include <execinfo.h>
#endif
#include "est.h"
#include "est_locl.h"
#include "est_ossl_util.h"

static unsigned char hex_chpw[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 
			  0xF7, 0x0D, 0x01, 0x09, 0x07};

const char *EST_ERR_STRINGS[] = {
    "EST_ERR_NONE",
    FOREACH_EST_ERROR(GENERATE_STRING)
};

static void (*est_log_func)(char *, va_list) = NULL;
static EST_LOG_LEVEL est_desired_log_lvl = EST_LOG_LVL_ERR;
static int est_backtrace_enabled = 0;

/*
 * This is our default logger routine, which just
 * dumps log data to stderr.  The application can
 * override this by calling est_init_logger() and
 * passing in a function pointer to a function
 * that implements this prototype.
 */
static void est_logger_stderr (char *format, va_list l)
{
    flockfile(stderr);
    vfprintf(stderr, format, l);
    fflush(stderr);
    funlockfile(stderr);
}

/*
 * Global low-level function to be called to log something
 */
void est_log (EST_LOG_LEVEL lvl, const char *format, ...)
{
    va_list arguments;

    /*
     * check if user is interested in this log message
     */
    if (lvl > est_desired_log_lvl) {
        return;
    }

    /*
     * Pull the arguments from the stack and invoke
     * the logger function
     */
    va_start(arguments, format);
    if (est_log_func != NULL) {
        (*est_log_func)((char *)format, arguments);
    } else {
        est_logger_stderr((char *)format, arguments);
    }
    va_end(arguments);

}

static pthread_t log_source[EST_PROXY+1]; // thread ID
EST_ERROR est_set_log_source (EST_MODE source)
{
    if (EST_SERVER <= source && source <= EST_PROXY) {
#ifndef DISABLE_PTHREADS
	log_source[source] = pthread_self();
#endif
	return EST_ERR_NONE;
    }
    else
	return EST_ERR_INVALID_PARAMETERS;
}

/*
 * Global high-level function to be called to log something
 */
void est_log_prefixed (EST_LOG_LEVEL lvl, const char *func, int line, const char *format, ...)
{
#define LOG_BUF_MAX 10000
    static char log_buf[LOG_BUF_MAX];
    va_list arguments;

    /*
     * check if user is interested in this log message
     */
    if (lvl > est_desired_log_lvl) {
        return;
    }

    char *prefix = "***EST";
    pthread_t self;
#ifndef DISABLE_PTHREADS
    self = pthread_self();
#else
    self = -1;
#endif
#ifndef _WIN32
    if (self == log_source[EST_CLIENT]) prefix = "CLIENT";
    if (self == log_source[EST_SERVER]) prefix = "SERVER";
    if (self == log_source[EST_PROXY ]) prefix = "PROXY ";
#else
    if (self.p == log_source[EST_CLIENT].p) prefix = "CLIENT";
    if (self.p == log_source[EST_SERVER].p) prefix = "SERVER";
    if (self.p == log_source[EST_PROXY ].p) prefix = "PROXY ";
#endif

    if (line != 0) {
	snprintf(log_buf, sizeof(log_buf), "%s [%s][%s:%d]--> ", prefix,
		lvl == EST_LOG_LVL_INFO ? "INFO" :
		lvl == EST_LOG_LVL_WARN ? "WARNING" :
		lvl == EST_LOG_LVL_ERR  ? "ERROR"   : "UNKNOWN",
		func, line);
    } else {
	snprintf(log_buf, sizeof(log_buf), "%s ", prefix);
    }
    int len = strlen(log_buf);
    va_start(arguments, format); // Pull the arguments from the stack
    vsnprintf(log_buf+len, LOG_BUF_MAX-2-len, format, arguments);
    va_end(arguments);
    strcat(log_buf,"\n");

    // mask non-printable garbage
    char *p = log_buf+len-1;
    while(*(++p) != '\0') {
	if (*p >= 0x80 || (*p < ' ' && *p != '\r' && *p != '\n'))
	    *p = '?';
    }

    est_log(lvl, log_buf);
}

void est_log_backtrace (void)
{
#ifndef DISABLE_BACKTRACE
    void* callstack[128];
    char **strs;
    int i, frames;

    /*
     * Spit out a backtrace if this is enabled globally
     */
    if (est_backtrace_enabled) {
        frames = backtrace(callstack, 128);
        strs = backtrace_symbols(callstack, frames);
        for (i = 0; i < frames; ++i) {
	    est_log(0, "%s\n", strs[i]);
            //fprintf(stderr, "%s\n", strs[i]);
        }
	est_log(0, "\n\n");
        free(strs);
    }
#endif
}

/*! @brief est_get_version() allows the application to retrieve
    the libest version string.  Returns a char* array containing
    the full version string value for the library.
 
    @return const char*
 */
const char * est_get_version (void) {
    return EST_VER_STRING; 
}

/*! @brief est_get_api_level() allows the application to retrieve
    the libest API level.  This is a numeric value that
    indicates the API level of the library.  When new versions of
    libest are released and the API changes, this value will be
    incremented.  Applications can use this to determine which capabilities
    in the libest library should or should not be attempted.
 
    @return int
 */
int est_get_api_level (void) {
    return EST_API_LEVEL; 
}

/*
 * Use this to log the libest version to an information
 * log message.  Also logs the compile-time and run-time 
 * OpenSSL versions.
 */
void est_log_version (void)
{
    EST_LOG_INFO("%s (API level %d)", est_get_version(), est_get_api_level());
#ifdef SOURCE_REVISION
    EST_LOG_INFO("Source repository revision# %d", SOURCE_REVISION);
#endif
    EST_LOG_INFO("Compiled against %s", OPENSSL_VERSION_TEXT);
    EST_LOG_INFO("Linking to %s", SSLeay_version(SSLEAY_VERSION));
}



/*
 * Logger initialization routine for EST library
 * This function does not need to be called.
 */
/*! @brief est_init_logger() allows the application to override the 
    default log handler for EST logging messages.
 
    @param lvl Sets the desired logging level to EST_LOG_LEVEL
    @param loggerfunc Sets the callback function to handle logging
 
    This function allows an application that uses EST to provide
    a function for logging EST messages.  EST provides a default handler
    that sends messages to stderr.  Applications may desire to send
    messages to syslog or some other logging facility.  An application
    would provide a function pointer using this method to intercept
    and handle EST log messages.  This setting is global to the library
    and will impact all contexts.
 
    @return EST_ERROR.
 */
EST_ERROR est_init_logger (EST_LOG_LEVEL lvl, void (*loggerfunc)(char *, va_list))
{
    /* Initialize the logger */
    if (loggerfunc) {
        est_log_func = loggerfunc;
    } else {
        /* install our default logger */
        est_log_func = &est_logger_stderr;
    }

    /*
     * Set the desired logging level
     */
    est_desired_log_lvl = lvl;
    return (EST_ERR_NONE);
}


/*! @brief est_enable_backtrace() allows the application to toggle
    whether the stack trace is displayed for WARNING and ERROR
    log messages coming from libest.   
 
    @param enable Set to zero to disable stack traces, non-zero to
                  enable stack traces through the logging facility.
 
    This function allows an application to enable stack traces, which
    may be useful for troubleshooting the libest library.  Stack
    traces are disabled by default.  Call this function with a 
    non-zero argument to enable stack traces for both WARNING and
    ERROR log messages.  This setting is global to the library and
    will impact all contexts.
 
    @return void.
 */
void est_enable_backtrace (int enable)
{
    est_backtrace_enabled = enable;
}

/*! @brief est_read_x509_request() is a helper function that reads
 *  a char* and converts it to an OpenSSL X509_REQ*.  The char* data
 *  can be either PEM or DER encoded.   
 
    @param csr This is the char* that contains the PEM or DER encoded
               X509 CSR.
    @param csr_len This is the length of the csr char*.  DER encoded data
               may contain zeros, which requires the length to be provided
	       by the application layer.
    @param csr_format This parameter specifies the encoding method of the
               csr char* that was provided.  Set this to either EST_CERT_FORMAT_PEM
	       or EST_CERT_FORMAT_DER.
 
    This function converts a PEM or DER encoded char* to the OpenSSL
    X509_REQ structure.  This function will return NULL if the PEM/DER
    data is corrupted or unable to be parsed by the OpenSSL library.
    This function will allocate memory for the X509_REQ data.  You must
    free the memory in your application when it's no longer needed by
    calling X509_REQ_free().
 
    @return X509_REQ*
 */
X509_REQ *est_read_x509_request (unsigned char *csr, int csr_len,
	                         EST_CERT_FORMAT csr_format)
{
    X509_REQ *req = NULL;
    BIO *in;
    unsigned long err;

    if (!csr) {
	EST_LOG_ERR("CSR may not be NULL");
	return (NULL);
    }

    if (csr_len > EST_RAW_CSR_LEN_MAX) {
	EST_LOG_ERR("CSR length is greater than maximum allowed (%d)", EST_RAW_CSR_LEN_MAX);
	return (NULL);
    }

    if (csr_format != EST_CERT_FORMAT_PEM && csr_format != EST_CERT_FORMAT_DER) {
	EST_LOG_ERR("Only PEM and DER encoding formats are supported.");
	return (NULL);
    }

    in = BIO_new_mem_buf(csr, csr_len);
    if (in == NULL) {
        EST_LOG_ERR("Unable to open the CSR memory buffer");
        return (NULL);
    }

    switch (csr_format) {
    case EST_CERT_FORMAT_PEM:
	req = PEM_read_bio_X509_REQ(in,NULL,NULL,NULL);
	break;
    case EST_CERT_FORMAT_DER:
	req = d2i_X509_REQ_bio(in,NULL);
	break;
    default:
	EST_LOG_ERR("Invalid CSR format specified.");
        break;
    }

    /*
     * Check for an error while parsing the input data
     */
    if (!req) {
        EST_LOG_ERR("An error occurred in the OpenSSL library while reading the CSR data.");
	err = ERR_get_error();
	EST_LOG_ERR("OpenSSL error string: %s", ERR_error_string(err, NULL));
    }

    BIO_free_all(in);
    return (req);
}

/*! @brief est_load_key() is a helper function that reads
 *  a char* and converts it to an OpenSSL EVP_PKEY*.  The char* data
 *  can be either PEM or DER encoded.   
 
    @param key This is the char* that contains the PEM or DER encoded
               key pair.
    @param key_len This is the length of the key char*.  DER encoded data
               may contain zeros, which requires the length to be provided
	       by the application layer.
    @param key_format This parameter specifies the encoding method of the
               key char* that was provided.  Set this to either EST_FORMAT_PEM
	       or EST_FORMAT_DER.
 
    This function converts a PEM or DER encoded char* to the OpenSSL
    EVP_PKEY* structure.  This function will return NULL if the PEM/DER
    data is corrupted or unable to be parsed by the OpenSSL library.
    This function will allocate memory for the EVP_PKEY data.  You must
    free the memory in your application when it's no longer needed by
    calling EVP_PKEY_free().
 
    @return EVP_PKEY*
 */
EVP_PKEY *est_load_key (unsigned char *key, int key_len, int format)
{
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;

    if (key == NULL) {
        EST_LOG_ERR("no key data provided");
        return NULL;
    }

    in = BIO_new_mem_buf(key, key_len);
    if (in == NULL) {
        EST_LOG_ERR("Unable to open the provided key buffer");
        return (NULL);
    }

    switch (format) {
    case EST_FORMAT_PEM:
        pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        break;
    case EST_FORMAT_DER:
        pkey = d2i_PrivateKey_bio(in, NULL);
        break;
    default:
        EST_LOG_ERR("Invalid key format");
        BIO_free(in);
        return NULL;
        break;
    }
    BIO_free(in);

    return (pkey);
}



/*
 * This function is used to read the CERTS in a BIO and build a
 * stack of X509* pointers.  This is used during the PEM to
 * PKCS7 conversion process.
 */
static int est_add_certs_from_BIO (STACK_OF(X509) *stack, BIO *in)
{
    int count = 0;
    int ret = -1;

    STACK_OF(X509_INFO) * sk = NULL;
    X509_INFO *xi;


    /* This loads from a file, a stack of x509/crl/pkey sets */
    sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
    if (sk == NULL) {
        EST_LOG_ERR("Unable to read certs from PEM encoded data");
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


/*
 * Converts from PEM to pkcs7 encoded certs.  Optionally
 * applies base64 encoding to the output.  This is used
 * when creating the cached cacerts response.  The returned
 * BIO contains the PKCS7 encoded certs.  The response
 * can optionially be base64 encoded by passing in a
 * non-zero value for the do_base_66 argument.  The caller
 * of this function should invoke BIO_free_all() on the
 * return value to avoid memory leaks.  Note, BIO_free() 
 * will not be sufficient.
 */
static BIO * est_get_certs_pkcs7 (BIO *in, int do_base_64)
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
        EST_LOG_ERR("pkcs7_new failed");
	goto cleanup;
    }
    /*
     * Create the PKCS7 signed object
     */
    if ((p7s = PKCS7_SIGNED_new()) == NULL) {
        EST_LOG_ERR("pkcs7_signed_new failed");
	goto cleanup;
    }
    /*
     * Set the version
     */
    if (!ASN1_INTEGER_set(p7s->version, 1)) {
        EST_LOG_ERR("ASN1_integer_set failed");
	goto cleanup;
    }

    /*
     * Create a stack of X509 certs
     */
    if ((cert_stack = sk_X509_new_null()) == NULL) {
        EST_LOG_ERR("stack malloc failed");
	goto cleanup;
    }

    /*
     * Populate the cert stack
     */
    if (est_add_certs_from_BIO(cert_stack, in) < 0) {
        EST_LOG_ERR("Unable to load certificates");
	ossl_dump_ssl_errors();
	goto cleanup;
    }

    /*
     * Create the BIO which will receive the output
     */
    out = BIO_new(BIO_s_mem());
    if (!out) {
        EST_LOG_ERR("BIO_new failed");
	goto cleanup;
    }

    /*
     * Add the base64 encoder if needed
     */
    if (do_base_64) {
	b64 = BIO_new(BIO_f_base64());
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
        EST_LOG_ERR("PEM_write_bio_PKCS7 failed");
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
 * Takes a raw char array containg the CA certificates, reads the data
 * in loads the certificates on to the context as pkcs7 certs.  This is
 * stored on the EST context and used to respond to the /cacerts request,
 * which requires PKCS7 encoding.
 * This function also loads the x509 store on the context used to
 * verify the peer.
 */
EST_ERROR est_load_ca_certs (EST_CTX *ctx, unsigned char *raw, int size)
{
    BIO *cacerts = NULL;
    BIO *in;
    unsigned char *retval;

    /*
     * Only the server and proxy modes may load the cacerts response
     */
    if (ctx->est_mode == EST_CLIENT) {
	return EST_ERR_BAD_MODE;
    }

    in = BIO_new_mem_buf(raw, size);
    if (in == NULL) {
        EST_LOG_ERR("Unable to open the raw cert buffer");
        return (EST_ERR_LOAD_CACERTS);
    }

    /*
     * convert the CA certs to PKCS7 encoded char array
     * This is used by an EST server to respond to the
     * cacerts request.
     */
    cacerts = est_get_certs_pkcs7(in, 1);
    if (!cacerts) {
        EST_LOG_ERR("est_get_certs_pkcs7 failed");
        BIO_free(in);
        return (EST_ERR_LOAD_CACERTS);
    }

    ctx->ca_certs_len = (int) BIO_get_mem_data(cacerts, (char**)&retval);
    if (ctx->ca_certs_len <= 0) {
        EST_LOG_ERR("Failed to copy PKCS7 data");
        BIO_free_all(cacerts);
        BIO_free(in);
        return (EST_ERR_LOAD_CACERTS);
    }

    ctx->ca_certs = (unsigned char *)malloc(ctx->ca_certs_len);
    if (!ctx->ca_certs) {
        EST_LOG_ERR("malloc failed");
        BIO_free_all(cacerts);
        BIO_free(in);
        return (EST_ERR_LOAD_CACERTS);
    }
    memcpy(ctx->ca_certs, retval, ctx->ca_certs_len);
    BIO_free_all(cacerts);
    BIO_free(in);
    return (EST_ERR_NONE);
}

/*
 * Takes a char array containing the PEM encoded CA certificates,
 * both implicit and explict certs.  These are decoded and loaded
 * into the trusted_certs_store member on the EST context.  This cert
 * store is used by the TLS stack for peer verification at the TLS
 * layer.
 * Note: we do not include defensive code to check for NULL arguments
 *       because this function is not part of the public API.  These
 *       checks should have already been performed.
 */
EST_ERROR est_load_trusted_certs (EST_CTX *ctx, unsigned char *certs, int certs_len)
{
    EST_ERROR rv;

    /*
     * Create the combined cert store on the context
     * This contains both the implicit and explicit certs
     */
    ctx->trusted_certs_store = X509_STORE_new();
    if (ctx->trusted_certs_store == NULL) {
        EST_LOG_ERR("Unable to allocate combined cert store");
        return (EST_ERR_LOAD_TRUST_CERTS);
    }
    X509_STORE_set_verify_cb(ctx->trusted_certs_store, ossl_verify_cb);
    rv = ossl_init_cert_store(ctx->trusted_certs_store, certs, certs_len);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Unable to populate combined cert store");
	return (rv);
    }

    return (EST_ERR_NONE);
}

/*! @brief est_set_ex_data() sets the application specific data
    on the EST context. 
 
    @param ctx Pointer to an EST context
    @param ex_data Pointer to application specific data that will be
                   passed through to the EST callbacks.
 
    @return EST_ERROR

    This function is used to link application specific data to the
    EST_CTX structure.  This can be used by an application to bind
    application specific data to an EST operation.  libest does 
    not use the application specific data.  The *ex_data pointer is
    passed back to the application when libest invokes the 
    enroll, re-enroll, CSR attributes, and HTTP auth callbacks.

    libest will not free the memory referenced by the *ex_data
    parameter when est_destroy() is invoked.  The application is
    responsible for releasing its application specific data. 
 */
EST_ERROR est_set_ex_data (EST_CTX *ctx, void *ex_data)
{
    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }
    if (ctx->ex_data && ex_data) {
	EST_LOG_WARN("ex_data was already set, possible memory leak");
    }
    ctx->ex_data = ex_data;
    return (EST_ERR_NONE);
}

/*! @brief est_get_ex_data() retrieves the application specific data
    on the EST context. 
 
    @param ctx Pointer to an EST context
 
    @return void* 

    This function is used to attain a reference to the application 
    specific data on the EST_CTX structure.  This data should have
    been set by invoking est_set_ex_data() earlier.  Otherwise it
    will return NULL. 
 */
void * est_get_ex_data (EST_CTX *ctx)
{
    if (!ctx) {
        return (NULL);
    }
    return (ctx->ex_data);
}

/*! @brief est_destroy() frees an EST context 
 
    @param ctx Pointer to an EST context
 
    @return EST_ERROR

    This function is used to release all the memory allocated under
    the EST_CTX*.  This should be called last after performing EST
    operations using the context.
 */
EST_ERROR est_destroy (EST_CTX *ctx)
{

    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }

    if (ctx->trusted_certs_store != NULL) {
        X509_STORE_free(ctx->trusted_certs_store);
    }

    if (ctx->ca_certs) {
        free(ctx->ca_certs);
    }

    if (ctx->retrieved_ca_certs) {
        free(ctx->retrieved_ca_certs);
    }

    if (ctx->retrieved_csrattrs) {
        free(ctx->retrieved_csrattrs);
    }

    if (ctx->server_csrattrs) {
        free(ctx->server_csrattrs);
    }

    if (ctx->enrolled_client_cert) {
        free(ctx->enrolled_client_cert);
    }

    if (ctx->ca_chain_raw) {
        free(ctx->ca_chain_raw);
    }

    if (ctx->dh_tmp) {
	DH_free(ctx->dh_tmp);
    }

    /* Only free the SSL context when acting as a client.  When
     * operating as a server, it's expected the web server
     * will free the context */
    if (ctx->ssl_ctx &&
        ((ctx->est_mode == EST_CLIENT)||(ctx->est_mode == EST_PROXY))) {
        /*
         * If the SSL session had been cached, this means that
         * SSL_get1_session() has been called, so now it needs to be explictly
         * freed to get its ref count decrememnted.
         */
        if (ctx->sess) {
            SSL_SESSION_free(ctx->sess);
        }
        SSL_CTX_free(ctx->ssl_ctx);
    }

    if (ctx->est_mode == EST_PROXY) {
        proxy_cleanup(ctx);
    }

    /*
     * And finally free the EST context itself
     */
    free(ctx);
    return (EST_ERR_NONE);
}

/*
 * The following function was taken from Mongoose.  The
 * Mongoose copyright is included to comply with COSI.
 */
// Copyright (c) 2004-2012 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
void est_base64_encode (const unsigned char *src, int src_len, char *dst)
{
    static const char *b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j, a, b, c;

    for (i = j = 0; i < src_len; i += 3) {
        a = src[i];
        b = i + 1 >= src_len ? 0 : src[i + 1];
        c = i + 2 >= src_len ? 0 : src[i + 2];

        dst[j++] = b64[a >> 2];
        dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
        if (i + 1 < src_len) {
            dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
        }
        if (i + 2 < src_len) {
            dst[j++] = b64[c & 63];
        }
    }
    while (j % 4 != 0) {
        dst[j++] = '=';
    }
    dst[j++] = '\0';
}

/*
 * This routine is used to determine whether the BIO_FLAGS_BASE64_NO_NL 
 * option needs to be used when using the OpenSSL
 * base64 decoder.  It takes a string as input and
 * checks if it contains newline characters.
 *
 * Returns 1 if OpenSSL should use the BIO_FLAGS_BASE64_NO_NL option
 * Returns 0 otherwise
 */
static int est_base64_contains_nl (const char *src, int len)
{
    int i;

    if (len < 64) {
	/* 
	 * Any base64 less than 64 bytes shouldn't be a 
	 * problem for OpenSSL since this is the minimum
	 * line length for base64 encoding.
	 */
	return 0;
    }

    /*
     * Start looking for newlines at the 64th position
     */
    for (i = 63; i < len-1; i++) {
	if (src[i] == 0xA) {
	    return 1;
	}
    }
    return 0;
}


/*
 * This routine is used to decode base64 encoded data.
 * Pass in the base64 encoded data and a pointer to a buffer
 * to receive the decoded data.  The length of the decoded 
 * data is returned.  If the return value is zero or negative, then
 * an error occurred.  The dst_size parameter is the maximum
 * allowed size of the decoded data.
 */
int est_base64_decode (const char *src, char *dst, int dst_size)
{
    BIO *b64, *b64in;
    int len;
    int max_in;

    /*
     * Calculate the max size of the base64 encoded data based
     * on the maximum size of the destination buffer.  Base64
     * grows the original data by 4/3.
     */
    max_in = ((dst_size * 4) / 3) + 1;

    /*
     * Get the length of the base64 encoded data.
     */
    len = strnlen(src, max_in); 
    if (len <= 0) {
	return (len);
    }

    b64 = BIO_new(BIO_f_base64());
    b64in = BIO_new_mem_buf((char *)src, len); 
    if (!est_base64_contains_nl (src, len)) {
	/*
	 * Enable the no newlines option if the input
	 * data doesn't contain any newline characters.
	 * It's too bad OpenSSL doesn't do this implicitly.
	 */
        BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
    }
    b64in = BIO_push(b64, b64in);
    len = BIO_read(b64in, dst, dst_size);
    if (len <= 0) {
	EST_LOG_WARN("BIO_read failed while decoding base64 data (%d)", len);
    } else {
        /*
         * Make sure the response is null terminated
         */
        dst[len] = 0;
    }

    BIO_free_all(b64in);
    return (len);
}



/*
 * Given an SSL session, get the TLS unique ID from the
 * peer finished message.  This uses the OpenSSL API
 * to get the 'finished' value from the TLS stack. This 
 * is then encoded using the channel binding rules.  The
 * value is then returned to the call, which can be
 * used for the PoP check.
 */
#define MAX_FINISHED  100
char * est_get_tls_uid (SSL *ssl, int is_client)
{
    char finished[MAX_FINISHED];
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bptr = NULL;
    int len;
    char *rv = NULL;

    /*
     * RFC5929 states the *first* finished message is used
     * to derive the tls-unique-id.  When session resumption
     * is used, the server sends the first finished message.
     * Normally the client sends the first finished messaged.
     */
    if ((is_client && !SSL_session_reused(ssl)) ||
        (!is_client && SSL_session_reused(ssl))) {
        len = (int) SSL_get_finished(ssl, finished, MAX_FINISHED);
    } else {
        len = (int) SSL_get_peer_finished(ssl, finished, MAX_FINISHED);
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    (void)BIO_flush(bio);
    bio = BIO_push(b64, bio);
    BIO_write(bio, finished, len);
    (void)BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    /*
     * Be aware that OpenSSL adds a newline character at the
     * end of the base64 encoded data
     */
    if (bptr->length != EST_TLS_UID_LEN) {
        EST_LOG_WARN("TLS UID length mismatch (%d/%d)", bptr->length,
                     EST_TLS_UID_LEN);
    } else {
        rv = (char *)malloc(EST_TLS_UID_LEN + 1);
        memcpy(rv, bptr->data, EST_TLS_UID_LEN);
        rv[EST_TLS_UID_LEN-1] = '\0';
        EST_LOG_INFO("TLS UID was found");
    }
    BIO_free_all(bio);
    return rv;
}

/*
 * This is a utility function to convert a hex value
 * to a string. This is used with the HTTP digest
 * authentication logic.
 */
void est_hex_to_str (char *dst, unsigned char *src, int len)
{
    static const char *hex = "0123456789abcdef";

    for (; len--; src++) {
        *dst++ = hex[src[0] >> 4];
        *dst++ = hex[src[0] & 0x0f];
    }
    *dst = '\0';
}

/*! @brief est_enable_crl() is used by an application to enable 
    checking of a certificate revocation list when validating the client
    TLS peer certificate during the TLS handshake. When enabled, 
    the ca_chain parameter provided to either est_server_init()
    or est_client_init() should contain both the trusted certificates 
    along with the CRL entries.  The CRL entries should be appened
    at the end.
 
    @param ctx Pointer to the EST context

    CRL checking is disabled by default.  This function must be called 
    after invoking est_server_init() or est_client_init() and prior 
    to performing any EST operations.  Therefore, there is no 'disable' 
    version of this method.  
 
    @return EST_ERROR.
 */
EST_ERROR est_enable_crl (EST_CTX *ctx)
{
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->enable_crl = 1;
    return (EST_ERR_NONE);
}

/*
 * est_asn1_sanity_test - perform a sanity test on the CSR
 * attribute string.  This function operates on an ASN.1 hex
 * string, so it should already be un-based64.
 *
 * return EST_ERROR and the presence of challengePassword
 */
static 
EST_ERROR est_asn1_sanity_test (const unsigned char *string, long out_len, 
				int *pop_present)
{
    int tag, xclass, j, nid;
    long out_len_save = out_len;
    long len;
    const unsigned char *ostring = string;
    ASN1_OBJECT *a_object;
    int max_len = MAX_CSRATTRS;

    /*
     * Assume the challengePassword OID is not present
     */
    *pop_present = 0;

    /* make sure its long enough to be ASN.1 */
    if (out_len < MIN_ASN1_CSRATTRS) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    while (out_len > 0) {
	j = ASN1_get_object(&string, &len, &tag, &xclass, out_len);

	EST_LOG_INFO("Sanity: tag=%d, len=%d, j=%d, out_len=%d", tag, len, j, out_len);
	if (j & 0x80) {
	    return (EST_ERR_BAD_ASN1_HEX);
        }
	switch (tag)
	{
	case V_ASN1_OBJECT:
            a_object = c2i_ASN1_OBJECT(NULL, &string, len);
	    if (a_object != NULL) {
	        nid = OBJ_obj2nid(a_object);
		EST_LOG_INFO("NID=%d", nid);
		if (nid == NID_pkcs9_challengePassword) {
	            EST_LOG_INFO("challengePassword OID found");
		    *pop_present = 1; /* just signifiy it's there */
		    max_len = MAX_CSRATTRS_WITHPOP;
		}
		ASN1_OBJECT_free(a_object);
            }
	    break;
	default:
	    /* have to adjust string pointer here */
	    string += len;
	    break;
	case V_ASN1_SET:
	case V_ASN1_SEQUENCE:
	    break;
	}
	out_len = (out_len_save - (string - ostring));	
    }
    if (out_len != 0) {
        return (EST_ERR_BAD_ASN1_HEX);
    }
    if (out_len_save > max_len) {
        return (EST_ERR_INVALID_PARAMETERS);
    }
    return (EST_ERR_NONE);
}

/*
 * est_is_challengePassword_present - take a base64 
 * encoded ASN.1 string and scan through it to see 
 * if challengePassword is included.
 *
 * return EST_ERROR and the presence of challengePassword
 */
EST_ERROR est_is_challengePassword_present (const char *base64_ptr, int b64_len, int *presence)
{

    /* assume its not there */
    *presence = 0;

    /* just return if no data */
    if ((base64_ptr == NULL) || (b64_len == 0)) {
        return (EST_ERR_NONE);
    }
    return (est_asn1_parse_attributes(base64_ptr, b64_len, presence));
}


/*
 * est_asn1_parse_attributes - base64 decode and sanity test
 * the given attributes string
 *
 * return EST_ERROR and the presence of challengePassword
 */
EST_ERROR est_asn1_parse_attributes (const char *p, int len, int *pop_present)
{
    unsigned char *der_ptr;
    int der_len;
    EST_ERROR rv;

    /* 
     * check smallest possible base64 case here for now 
     * and sanity test will check min/max value for ASN.1 data
     */
    if (len < MIN_CSRATTRS) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    der_ptr = (unsigned char *)malloc(len*2);
    if (!der_ptr) {
        return (EST_ERR_MALLOC);
    }

    der_len = est_base64_decode(p, (char *)der_ptr, len*2);
    if (der_len <= 0) {
        EST_LOG_ERR("Invalid base64 encoded data");
	free(der_ptr);
        return (EST_ERR_BAD_BASE64);
    }

    rv = est_asn1_sanity_test(der_ptr, der_len, pop_present);
    if (rv != EST_ERR_NONE) {
        EST_LOG_ERR("Invalid ASN1 encoded data");
	free(der_ptr);
	return (rv);
    }
    free(der_ptr);
    return (EST_ERR_NONE);
}



/* 
 * est_add_challengePassword - caller has verified that challengePassword 
 * is configured and not included, so add it to the attributes here.
 * No sanity check is needed since est_is_challengePassword_present
 * has already been called.
 */
EST_ERROR est_add_challengePassword (const char *base64_ptr, int b64_len, 
				     char **new_csr, int *pop_len)
{
    unsigned char *der_ptr, *orig_ptr, *new_der = NULL;
    char *csrattrs;
    int der_len, tag, xclass, new_len;
    long len;

    der_ptr = (unsigned char *)malloc(b64_len*2);
    if (!der_ptr) {
        return (EST_ERR_MALLOC);
    }

    der_len = est_base64_decode(base64_ptr, (char *)der_ptr, b64_len*2);
    if (der_len <= 0) {
        EST_LOG_ERR("Malformed base64 data");
	free((void *)der_ptr);
        return (EST_ERR_MALLOC);
    }

    orig_ptr = der_ptr;

    /* grab the first one and do the POP stuff */
    (void)ASN1_get_object((const unsigned char **)&der_ptr, &len, &tag, &xclass, der_len);

    if (tag != V_ASN1_SEQUENCE) {
        EST_LOG_ERR("Malformed ASN.1 Hex, no leanding Sequence");
	free(orig_ptr);
	return (EST_ERR_BAD_ASN1_HEX);
    }

    len = der_ptr - orig_ptr;
    new_len = der_len - (int)len + sizeof(hex_chpw);
	    
    /* remove leading sequence and length and copy to new buffer */
    /* if >= 256 need 4 byte Seq header */
    if ((der_len - len + sizeof(hex_chpw)) >= 256) {
        new_len += 4;
	new_der = (unsigned char *)malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
	*(new_der + 1) = 0x82;
        *(new_der + 2) = (new_len - 4) >> 8;
        *(new_der + 3) = ((new_len - 4) & 0xff);
        memcpy(new_der+4, der_ptr, der_len - len);
	/* if <= 256, but >= 128 need 3 byte Seq header */
    } else if ((der_len - len + sizeof(hex_chpw)) >= 128) {
        new_len += 3;
	new_der = (unsigned char *)malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
        *(new_der + 1) = 0x81;
        *(new_der + 2) = new_len - 3;
        memcpy(new_der+3, der_ptr, der_len - len);
        /* else just need 2 byte header */
    } else {
        new_len += 2;
        new_der = (unsigned char *)malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
        *(new_der + 1) = new_len - 2;
	if ((der_len - len) != 0) {
            memcpy(new_der+2, der_ptr, der_len - len);
	}
    }
    *new_der = 0x30;
    memcpy(new_der + (new_len - sizeof(hex_chpw)), 
	     hex_chpw, sizeof(hex_chpw));

    csrattrs = (char *)malloc(new_len*2);
    if (!csrattrs) {
        free(orig_ptr);
        free(new_der);
	return (EST_ERR_MALLOC);
    }
    est_base64_encode((const unsigned char *)new_der, 
 		       new_len, csrattrs);

    *new_csr = csrattrs;
    *pop_len = (int) strlen(csrattrs);
    EST_LOG_INFO("CSR reconstituted attributes are(%d/%d): %s", b64_len, *pop_len, csrattrs);

    if (new_der) {
        free(new_der);
    }
    if (orig_ptr) {
        free(orig_ptr);
    }
    return (EST_ERR_NONE);
}

/*! @brief est_add_attributes_helper() Add a NID and its character string to
    an X509_REQ as an attribute.
 
    @param req an X509_REQ structure used for the CSR request
    @param nid NID to be added as an attribute
    @param string pointer to the NID string if needed
    @param chtype type of string used with this NID
 
    @return EST_ERROR

    This function is used to add a CSR attribute to a CSR request by the
    EST client.
 */
EST_ERROR est_add_attributes_helper (X509_REQ *req, int nid, void *string, int chtype)
{
    
    if (req == NULL) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (nid == 0) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if (string == NULL) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /* Only MBSTRING_ASC used today, but callers could pass in other values */
    if (chtype == 0) {
        chtype = MBSTRING_ASC;
    }

    if(!X509_REQ_add1_attr_by_NID(req, nid, chtype,
				  (unsigned char *)string, -1)) {
	EST_LOG_WARN("Error adding attribute");
	return (EST_ERR_X509_ATTR);
    }
    return (EST_ERR_NONE);
}

/*! @brief est_decode_attributes_helper() Decode a base64 encoded string
    into DER format(ASN.1 hex).
 
    @param csrattrs pointer to a base64 encoded string
    @param csrattrs_len base64 string length
    @param der_ptr pointer to a pointer to store the DER encoded string
    @param der_len pointer to store the DER string length
 
    @return EST_ERROR

    This function is used decode a base64 encoded CSR attributes string
    into DER format.  It also performs range checking on the input parameters.
 */
EST_ERROR est_decode_attributes_helper (char *csrattrs, int csrattrs_len, 
					unsigned char **der, int *len)
{
    unsigned char *der_ptr;
    int der_len;

    /* just return if no data */
    if ((csrattrs == NULL) || (csrattrs_len == 0)) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    if ((der == NULL) || (len == NULL)) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    /* 
     * check smallest possible base64 case here for now 
     * and sanity test will check min/max value for ASN.1 data
     */
    if (csrattrs_len < MIN_CSRATTRS) {
        return (EST_ERR_INVALID_PARAMETERS);
    }


    der_ptr = (unsigned char *)malloc(csrattrs_len*2);
    if (!der_ptr) {
        return (EST_ERR_MALLOC);
    }

    der_len = est_base64_decode(csrattrs, (char *)der_ptr, csrattrs_len*2);
    if (der_len <= 0) {
        EST_LOG_WARN("Invalid base64 encoded data");
	free(der_ptr);
	return (EST_ERR_BAD_BASE64);
    }

    *der = der_ptr;
    *len = der_len;

    return (EST_ERR_NONE);

}


/*! @brief est_get_attributes_helper() get attributes NID from a DER
    encoded string.
 
    @param der_ptr pointer to a pointer of DER encoded string
    @param der_len pointer to the DER encoded string length
    @param new_nid pointer to storage for NID, if found
 
    @return EST_ERROR

    This function is used to find the next NID in a DER encoded string.
    If no NID is found before reaching the end of the string, then
    new_nid returned as zero and EST_ERR_BAD_ASN1_HEX.
 */
EST_ERROR est_get_attributes_helper (unsigned char **der_ptr, int *der_len, int *new_nid)
{
    int tag, xclass, j, nid = 0;
    int out_len_save;
    long out_len;
    long len;
    const unsigned char *string;
    const unsigned char *ostring;
    ASN1_OBJECT *a_object = NULL;


    if (der_ptr == NULL) {
        return (EST_ERR_INVALID_PARAMETERS);
    }
    string = *der_ptr;
    ostring = *der_ptr;

    if (der_len == NULL) {
        return (EST_ERR_INVALID_PARAMETERS);
    }
    out_len = *der_len;
    out_len_save = *der_len;

    if (new_nid == NULL) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    while (out_len > 0) {
	j = ASN1_get_object(&string, &len, &tag, &xclass, out_len);

	if (j & 0x80) {
	    return (EST_ERR_BAD_ASN1_HEX);
        }
	switch (tag) {

	case V_ASN1_OBJECT:
            a_object = c2i_ASN1_OBJECT(NULL, &string, len);
	    if (a_object != NULL) {
	        nid = OBJ_obj2nid(a_object);
		EST_LOG_INFO("NID=%d", nid);
		*new_nid = nid;
		*der_len = (out_len_save - (int) (string - ostring));
		*der_ptr = (unsigned char *)string;
	        ASN1_OBJECT_free(a_object);
		return (EST_ERR_NONE);
            }
	    break;
	default:
	    /* have to adjust string pointer here */
	    string += len;
	    break;
	case V_ASN1_SET:
	case V_ASN1_SEQUENCE:
	    break;
	}
	out_len = (out_len_save - (string - ostring));	
    }

    return (EST_ERR_NONE);
}


/* 
 * cleanse_auth_credentials - Walk through the auth_credentials structure and
 * overwrite and free each value.
 */
void cleanse_auth_credentials(EST_HTTP_AUTH_HDR *auth_cred)
{

    if (auth_cred == NULL) {
        return;
    }
    
    if (auth_cred->user) {
        OPENSSL_cleanse(auth_cred->user, strnlen(auth_cred->user, MAX_UIDPWD));
        free(auth_cred->user);
        auth_cred->user = NULL;
    }
    
    if (auth_cred->pwd) {
        OPENSSL_cleanse(auth_cred->pwd, strnlen(auth_cred->pwd, MAX_UIDPWD));
        free(auth_cred->pwd);
        auth_cred->pwd = NULL;
    }
    
    if (auth_cred->uri) {
        OPENSSL_cleanse(auth_cred->uri, strnlen(auth_cred->uri, EST_URI_MAX_LEN));
        free(auth_cred->uri);
        auth_cred->uri = NULL;
    }
    
    if (auth_cred->cnonce) {
        OPENSSL_cleanse(auth_cred->cnonce, strnlen(auth_cred->cnonce, MAX_NONCE));
        free(auth_cred->cnonce);
        auth_cred->cnonce = NULL;
    }
    
    if (auth_cred->qop) {
        OPENSSL_cleanse(auth_cred->qop, strnlen(auth_cred->qop, MAX_QOP));
        free(auth_cred->qop);
        auth_cred->qop = NULL;
    }
    
    if (auth_cred->nc) {
        OPENSSL_cleanse(auth_cred->nc, strnlen(auth_cred->nc, MAX_NC));
        free(auth_cred->nc);
        auth_cred->nc = NULL;
    }
    
    if (auth_cred->nonce) {
        OPENSSL_cleanse(auth_cred->nonce, strnlen(auth_cred->nonce,
                                                    MAX_NONCE));
        free(auth_cred->nonce);
        auth_cred->nonce = NULL;
    }
    
    if (auth_cred->response) {
        OPENSSL_cleanse(auth_cred->response, strnlen(auth_cred->response,
                                                       MAX_RESPONSE));
        free(auth_cred->response);
        auth_cred->response = NULL;
    }
    
    if (auth_cred->auth_token) {
        OPENSSL_cleanse(auth_cred->auth_token, strnlen(auth_cred->auth_token,
                                                         MAX_AUTH_TOKEN_LEN));
        free(auth_cred->auth_token);
        auth_cred->auth_token = NULL;
    }        
    
    return;
}
