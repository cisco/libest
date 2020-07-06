/** @file */
/*------------------------------------------------------------------
 * est/est.c - EST implementation
 *
 *	       Assumptions:  - Web server using this module utilizes
 *	                       OpenSSL for HTTPS services.
 *	                     - OpenSSL is linked along with this
 *	                       modulue.
 *
 * November, 2012
 *
 * Copyright (c) 2012-2014, 2016, 2017, 2018, 2019 by cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */


#include <stdlib.h>
#ifdef WIN32
#ifndef DISABLE_BACKTRACE
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif /* DISABLE_BACKTRACE*/
#endif /*WIN32*/
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "est.h"
#include "est_locl.h"
#include "est_ossl_util.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"
#ifdef HAVE_URIPARSER
#include "uriparser/Uri.h"
#endif
#ifndef WIN32
#ifndef DISABLE_BACKTRACE
#include <execinfo.h>
#endif
#else /* DISABLE_BACKTRACE*/
#ifndef DISABLE_BACKTRACE
#include <DbgHelp.h>
#endif  /* DISABLE_BACKTRACE*/
#endif /* WIN32*/

#ifndef ENABLE_CLIENT_ONLY
static char hex_chpw[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 
			  0xF7, 0x0D, 0x01, 0x09, 0x07};
#endif

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
#ifndef WIN32
	flockfile(stderr);
#endif
	vfprintf(stderr, format, l);
	fflush(stderr);
#ifndef WIN32
	funlockfile(stderr);
#endif
}

static void est_log_msg (char *format, ...)
{
    va_list arguments;

    /*
     * Pull the arguments from the stack and invoke
     * the logger function
     */
    va_start(arguments, format);
    if (est_log_func != NULL) {
        (*est_log_func)(format, arguments);
    } else {
        est_logger_stderr(format, arguments);
    }
    va_end(arguments);
}

/*
 * Global function to be called to log something
 */
void est_log (EST_LOG_LEVEL lvl, char *format, ...)
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
        (*est_log_func)(format, arguments);
    } else {
        est_logger_stderr(format, arguments);
    }
    va_end(arguments);

#ifndef ENABLE_CLIENT_ONLY
    /*
     * If appropriate, announce that an EST error event occurred.
     * Make sure this occurs *after* va_end() is called; otherwise
     * a crash will likely occur when the registered callback
     * attempts to use the va_list.
     */
    va_start(arguments, format);
    if (lvl == EST_LOG_LVL_ERR) {
        est_invoke_est_err_event_cb(format, arguments);
    }
    va_end(arguments);
#endif    
}

#ifdef WIN32
#ifndef DISABLE_BACKTRACE
static void printStackTrace(void) {
	unsigned int i;
	void *stack[100];
	unsigned short frames;
	SYMBOL_INFO * symbol;
	HANDLE        process;

	process = GetCurrentProcess();

	SymInitialize(process, NULL, TRUE);

	frames = CaptureStackBackTrace(0, 100, stack, NULL);
	symbol = (SYMBOL_INFO *)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
	symbol->MaxNameLen = 255;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	for (i = 0; i < frames; i++) {
		SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);
		est_log_msg("\n%i: [0x%0X] %s", (frames - i - 1), symbol->Address, symbol->Name);

	}

	free(symbol);
}
#endif /* DISABLE_BACKTRACE */ 
#endif /* WIN32 */

/*
 * Global function to be called to log something
 */
void est_log_backtrace (void)
{
#ifndef DISABLE_BACKTRACE
#ifdef WIN32
	/*
	* Spit out a backtrace if this is enabled globally
	*/
	if (est_backtrace_enabled) {
		printStackTrace();
	}
#else
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
	    est_log_msg("\n%s", strs[i]);
            //fprintf(stderr, "%s\n", strs[i]);
        }
	est_log_msg("\n\n");
        free(strs);
    }
#endif /* WIN32*/
#endif /* DISABLE_BACKTRACE*/
}

/*! @brief est_get_version() allows the application to retrieve
    the libEST version string.  Returns a char* array containing
    the full version string value for the library.
 
    @return const char*
 */
const char * est_get_version (void) {
    return EST_VER_STRING; 
}

/*! @brief est_get_api_level() allows the application to retrieve
    the libEST API level.  This is a numeric value that
    indicates the API level of the library.  When new versions of
    libEST are released and the API changes, this value will be
    incremented.  Applications can use this to determine which capabilities
    in the libEST library should or should not be attempted.
 
    @return int
 */
int est_get_api_level (void) {
    return EST_API_LEVEL; 
}

/*
 * Use this to log the libEST version to an information
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
    log messages coming from libEST.   
 
    @param enable Set to zero to disable stack traces, non-zero to
                  enable stack traces through the logging facility.
 
    This function allows an application to enable stack traces, which
    may be useful for troubleshooting the libEST library.  Stack
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


#ifndef ENABLE_CLIENT_ONLY
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
 * can optionally be base64 encoded by passing in a
 * non-zero value for the do_base_64 argument.  The caller
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
        if (b64 == NULL) {
            EST_LOG_ERR("BIO_new failed while attempting to create base64 BIO");
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
 * Takes a raw char array containing the CA certificates, reads the data
 * in and loads the certificates on to the context as pkcs7 certs.  This is
 * stored on the EST context and used to respond to the /cacerts request,
 * which requires PKCS7 encoding.
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

    ctx->ca_certs = calloc(ctx->ca_certs_len + 1, sizeof(char));
    if (!ctx->ca_certs) {
        EST_LOG_ERR("malloc failed");
        BIO_free_all(cacerts);
        BIO_free(in);
        return (EST_ERR_LOAD_CACERTS);
    }
    memcpy_s(ctx->ca_certs, ctx->ca_certs_len, retval, ctx->ca_certs_len);
    BIO_free_all(cacerts);
    BIO_free(in);
    return (EST_ERR_NONE);
}
#endif

/*
 * Takes a char array containing the PEM encoded CA certificates,
 * both implicit and explicit certs.  These are decoded and loaded
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
    application specific data to an EST operation.  libEST does 
    not use the application specific data.  The *ex_data pointer is
    passed back to the application when libEST invokes the 
    enroll, re-enroll, CSR attributes, and HTTP auth callbacks.

    libEST will not free the memory referenced by the *ex_data
    parameter when est_destroy() is invoked.  The application is
    responsible for releasing its application specific data. 
 */
EST_ERROR est_set_ex_data (EST_CTX *ctx, void *ex_data)
{
    if (!ctx) {
        return (EST_ERR_NO_CTX);
    }
    if (ctx->ex_data) {
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

    if (ctx->uri_path_segment) {
        free(ctx->uri_path_segment);
    }

    if(ctx->brski_retrieved_cacert) {
        free(ctx->brski_retrieved_cacert);
    }

    if(ctx->brski_retrieved_voucher) {
        free(ctx->brski_retrieved_voucher);
    }
    
    if (ctx->client_cert_ser_num) {
        free(ctx->client_cert_ser_num);
    }
#if HAVE_LIBCOAP
    if (ctx->coap_req_array) {
        free(ctx->coap_req_array);
    }
    if(ctx->coap_ctx) {
        coap_free_context(ctx->coap_ctx);
    }
#endif /* HAVE_LIBCOAP */
#ifndef ENABLE_CLIENT_ONLY
    mfg_info_list_destroy(ctx);
#endif
    
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
         * SSL_get1_session() has been called, so now it needs to be explicitly
         * freed to get its ref count decremented.
         */
        if (ctx->sess) {
            SSL_SESSION_free(ctx->sess);
        }
        SSL_CTX_free(ctx->ssl_ctx);
    }

#ifndef ENABLE_CLIENT_ONLY
    if (ctx->est_mode == EST_PROXY) {
        proxy_cleanup(ctx);
    }
#endif
    
    /*
     * And finally free the EST context itself
     */
    free(ctx);
    return (EST_ERR_NONE);
}

/*
 * Counts amount of non whitespace characters in src buffer and
 * also total length of buffer. Instead of traversing the buffer
 * twice for len and len_no_whitespace, just do it this one time.
 */
static void est_base64_str_analyze (const char *src, int *len_no_whitespace,
                                     int *len, unsigned char *contains_newline)
{
    int i = 0;
    int temp = -1;
    *len_no_whitespace = 0;
    while (src[i]) {
        if (!isspace(src[i])) {
            (*len_no_whitespace)++;
        } else if(src[i] == '\n' && temp == -1) {
            temp = i;
        }
        i++;
    }
    /* 
     * Check to make sure that the newline we found was not
     * only the last character
     */
    if(temp != -1 && temp != i - 1) {
        *contains_newline = 1;
    } else {
        *contains_newline = 0;
    }
    *len = i;
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
    int len_no_whitespace;
    int pad;
    int expected_decode_len;
    unsigned char contains_newline;
    int last_non_whitespace_idx;

    /*
     * Get the length of the base64 encoded data and the length without whitespace.
     * Make sure it's not too big
     */
    est_base64_str_analyze(src, &len_no_whitespace, &len, &contains_newline);
    /*
     * First we have to check how many blocks of 4 there should be 
     * if a buffer of this size was being base64 encoded
     * if it was divisible by 3, then divide it by 3 to get the number
     * of 4-byte blocks, if it was not divisible by 3, add an extra block for padding.
     */
    max_in = dst_size % 3
                ? ((dst_size / 3) + 1) * 4
                : (dst_size / 3) * 4;
    if (len_no_whitespace > max_in) {
        EST_LOG_ERR("Source buffer for base64 decode is too large for "
                    "destination buffer. source buf len_no_whitespace = %d, "
                    "max input len = %d, max dest len = %d",
                    len_no_whitespace, max_in, dst_size);
        return 0;
    }

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create base64 BIO");
        ossl_dump_ssl_errors();
        return 0;
    }
    b64in = BIO_new_mem_buf((char *)src, len); 
    if (b64in == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create mem BIO");
        ossl_dump_ssl_errors();
        return 0;
    }
    if (!contains_newline) {
    /*
     * Enable the no newlines option if the input
     * data doesn't contain any newline characters.
     * It's too bad OpenSSL doesn't do this implicitly.
     */
        BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
    }
    /* Base64 decode will not work properly unless length is divisible by 4 */
    if(len_no_whitespace % 4) {
        EST_LOG_ERR("Source buffer length not divisible by 4.");
        return 0;
    }
    /*
     * Before we count the amount of padding we must ignore
     * however much whitespace/newlines there are at the end
     */
    last_non_whitespace_idx = len - 1;
    while(isspace(src[last_non_whitespace_idx]) && last_non_whitespace_idx >= 0) {
        last_non_whitespace_idx--;
    }
    /* Check to make sure index is valid */
    if(last_non_whitespace_idx < 2) {
        EST_LOG_ERR("Index invalid (%d)", last_non_whitespace_idx);
        return 0;
    }
    /* Count how much padding there is */
    if(src[last_non_whitespace_idx] == '=') {
        pad = 1;
        if (src[last_non_whitespace_idx - 1] == '=') {
            pad = 2;
        }
    } else {
        pad = 0;
    }
    
    /* 
     * Calculate final decoded base64 length
     * so we can later check if the lengths match 
     */
    expected_decode_len = ((3 * len_no_whitespace) / 4) - pad;
    b64in = BIO_push(b64, b64in);
    len = BIO_read(b64in, dst, dst_size);
    if (len != expected_decode_len) {
	    EST_LOG_WARN("BIO_read failed while decoding base64 data (%d)", len);
        return 0;
    }

    BIO_free_all(b64in);
    if (len == 0) {
        EST_LOG_WARN("%s: returning a len = %d", __FUNCTION__, len);
    }
    return len;
}

/*
 * This routine is used to encode base64 data.
 * Pass in the unencoded data, the length of the source buffer,
 * and a pointer to a buffer to receive the encoded data.
 * The length of the encoded data is returned.  If the return value
 * is zero, then an error occurred.  The max_dest_len parameter
 * is the maximum allowed size of the encoded data. The nl param
 * is whether new lines are wanted.
 */
int est_base64_encode(const char *src, int actual_src_len, char *dst, int max_dst_len, int nl)
{
    BIO *b64;
    BIO *out;
    int max_src_len;
    int actual_dst_len = 0;
    int write_cnt = 0;
    BUF_MEM *bptr = NULL;

    if (!dst) {
        EST_LOG_ERR("dst is NULL");
        return 0;
    }
    /*
     * When encoding base64, the output will always be larger by a
     * ratio of 3:4.  Determine what the max size can be for the input
     * based on the size of the given output buffer and then make sure that
     * the actual input buffer is not too big.
     */
    max_src_len = ((max_dst_len * 3) / 4) + 1;
    if (actual_src_len > max_src_len) {
        EST_LOG_ERR("Source buffer for base64 encode is loo large for destination buffer. "
                    "max source len = %d, actual_source len = %d",
                    max_src_len, actual_src_len);
	return 0;
    }

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create base64 BIO");
        ossl_dump_ssl_errors();
        return 0;
    }    

    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create mem based BIO");
        ossl_dump_ssl_errors();
        BIO_free_all(b64);
        return 0;
    }
    out = BIO_push(b64, out);

    /*
     * We don't ever insert new lines
     */
    if (!nl) {
        BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);
    }

    /*
     * Write the source buffer through the BIOs and then get a pointer
     * to the resulting memory buffer on the other side to obtain the
     * result.
     */
    write_cnt = BIO_write(out, src, actual_src_len);
    (void)BIO_flush(out);
    BIO_get_mem_ptr(out, &bptr);
    if (write_cnt <= 0) {
	EST_LOG_WARN("BIO_write failed while encoding base64 data (%d)", write_cnt);
    } else {
        /*
         * copy out the resulting base64 encoded string, make sure it's
         * null terminated, and return the length
         */
        memcpy_s(dst, max_dst_len, bptr->data, bptr->length);
        dst[bptr->length] = '\0';
        actual_dst_len = bptr->length;
    }

    BIO_free_all(b64);
    return (actual_dst_len);
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
char * est_get_tls_uid (SSL *ssl, int *uid_len, int is_client)
{
    char finished[MAX_FINISHED];
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bptr = NULL;
    int len;
    char *rv = NULL;
    int version;
    size_t max_len = 0;

    *uid_len = 0;
    
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
    if (b64 == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create base64 BIO");
        ossl_dump_ssl_errors();
	return rv;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        EST_LOG_ERR("BIO_new failed while attempting to create mem based BIO");
        ossl_dump_ssl_errors();
	return rv;
    }
    (void)BIO_flush(bio);
    bio = BIO_push(b64, bio);
    BIO_write(bio, finished, len);
    (void)BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    /*
     * Double check the length of the finish message that was
     * returned.  TLS 1.2 and below it will never be more than 12 bytes.
     * TLS 1.3 it is the size of the hash function used.  We've base64
     * encoded it so we need to account for that, plus...
     * Be aware that OpenSSL adds a newline character at the
     * end of the base64 encoded data
     */
    version = SSL_version(ssl);
    if (version > TLS1_2_VERSION) {
        max_len = EVP_MAX_MD_SIZE*(4/3)+1; /* +1 for the newline */
    } else {
        max_len = EST_TLS_UID_LEN; /* newline is included in this value */
    }

    if (bptr->length > max_len) {
        EST_LOG_ERR("TLS UID length exceeds maximum (%d/%d)", bptr->length,
                    max_len);
    } else {
        rv = calloc(max_len + 1, sizeof(char)); /* +1 for the \0 */
        if (rv == NULL) {
            EST_LOG_ERR("Failed to allocate buffer");
            BIO_free_all(bio);
            return rv;
        }
        /*
         * Need to suppress the newline if it exists.
         */
	if (bptr->data[bptr->length - 1] == '\n') {
	    *uid_len = bptr->length - 1;
        } else {
            *uid_len = bptr->length;
        }
        memcpy_s(rv, max_len, bptr->data, *uid_len);
        EST_LOG_INFO("TLS UID was obtained");
    }
    BIO_free_all(bio);
    return rv;
}

/*
 * This is a utility function to convert a hex value
 * to a string. This is used with the HTTP digest
 * authentication logic and converting a nonce value to
 * a string.
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
    X509_VERIFY_PARAM *vpm;
    
    if (!ctx) {
	EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    /*
     * Client code and server code handle the processing of this
     * flag differently.  The client side looks at the above
     * flag during est_client_init() so there's effectively no way
     * to call this function to set the flag and have it be seen by
     * the code that processes it because you need the context from
     * the est_client_init(), so for client mode, action must be
     * taken right here instead of just setting the flag.
     */
    if (ctx->est_mode == EST_CLIENT) {
        vpm = SSL_CTX_get0_param(ctx->ssl_ctx);
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK |
                                    X509_V_FLAG_CRL_CHECK_ALL);
        SSL_CTX_set1_param(ctx->ssl_ctx, vpm);
    }

    ctx->enable_crl = 1;
    return (EST_ERR_NONE);
}

#if 0
/*
 * This code is taken directly from OpenSSL 1.0.2. At the moment,
 * the CSR attribute logic relies upon it, and it is no longer
 * accessible in OpenSSL 1.1.0.  Until the alternative calls can be
 * figured out for 1.1.0, this code will stay in EST.
 */
ASN1_OBJECT *est_c2i_ASN1_OBJECT (ASN1_OBJECT **a, const unsigned char **pp, long len)
{
    ASN1_OBJECT *ret = NULL;
    const unsigned char *p;
    unsigned char *data;
    int i, length;

    /*
     * Sanity check OID encoding. Need at least one content octet. MSB must
     * be clear in the last octet. can't have leading 0x80 in subidentifiers,
     * see: X.690 8.19.2
     */
    if (len <= 0 || len > INT_MAX || pp == NULL || (p = *pp) == NULL ||
        p[len - 1] & 0x80) {
	EST_LOG_ERR("C2I: invalid object encoding");
/*         ASN1err(ASN1_F_C2I_ASN1_OBJECT, ASN1_R_INVALID_OBJECT_ENCODING); */
        return NULL;
    }
    /* Now 0 < len <= INT_MAX, so the cast is safe. */
    length = (int)len;
    for (i = 0; i < length; i++, p++) {
        if (*p == 0x80 && (!i || !(p[-1] & 0x80))) {
            EST_LOG_ERR("C2I: invalid object encoding");
/*             ASN1err(ASN1_F_C2I_ASN1_OBJECT, ASN1_R_INVALID_OBJECT_ENCODING); */
            return NULL;
        }
    }

    /*
     * only the ASN1_OBJECTs from the 'table' will have values for ->sn or
     * ->ln
     */
    if ((a == NULL) || ((*a) == NULL) ||
        !((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC)) {
        if ((ret = ASN1_OBJECT_new()) == NULL)
            return (NULL);
    } else
        ret = (*a);

    p = *pp;
    /* detach data from object */
    data = (unsigned char *)ret->data;
    ret->data = NULL;
    /* once detached we can change it */
    if ((data == NULL) || (ret->length < length)) {
        ret->length = 0;
        if (data != NULL)
            OPENSSL_free(data);
        data = (unsigned char *)OPENSSL_malloc(length);
        if (data == NULL) {
            EST_LOG_ERR("C2I: malloc failure");            
/*             i = ERR_R_MALLOC_FAILURE; */
            goto err;
        }
        ret->flags |= ASN1_OBJECT_FLAG_DYNAMIC_DATA;
    }
    memcpy(data, p, length);
    /* reattach data to object, after which it remains const */
    ret->data = data;
    ret->length = length;
    ret->sn = NULL;
    ret->ln = NULL;
    /* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
    p += length;

    if (a != NULL)
        (*a) = ret;
    *pp = p;
    return (ret);
 err:
/*     ASN1err(ASN1_F_C2I_ASN1_OBJECT, i); */
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        ASN1_OBJECT_free(ret);
    return (NULL);
}
#endif

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
    int curr_len;
    const unsigned char *curr_string;    

    /*
     * Assume the challengePassword OID is not present
     */
    *pop_present = 0;

    /* make sure its long enough to be ASN.1 */
    if (out_len < MIN_ASN1_CSRATTRS) {
        return (EST_ERR_BAD_ASN1_HEX_TOO_SHORT);
    }

    while (out_len > 0) {
        curr_len = out_len;
        curr_string = string;
        
        j = ASN1_get_object(&string, &len, &tag, &xclass, out_len);
        
	EST_LOG_INFO("Sanity: tag=%d, len=%d, j=%d, out_len=%d", tag, len, j, out_len);
	if (j & 0x80) {
	    return (EST_ERR_BAD_ASN1_HEX);
        }
	switch (tag)
            {
            case V_ASN1_OBJECT:
                a_object = d2i_ASN1_OBJECT(NULL, &curr_string, curr_len);
                if (a_object != NULL) {
                    nid = OBJ_obj2nid(a_object);
                    EST_LOG_INFO("NID=%d", nid);
                    if (nid == NID_pkcs9_challengePassword) {
                        EST_LOG_INFO("challengePassword OID found");
                        *pop_present = 1; /* just signify it's there */
                        max_len = MAX_CSRATTRS_WITHPOP;
                    }
                    string = curr_string;
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
        return (EST_ERR_BAD_ASN1_HEX_TOO_LONG);
    }
    return (EST_ERR_NONE);
}

#ifndef ENABLE_CLIENT_ONLY
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
#endif

/*
 * est_asn1_parse_attributes - base64 decode and sanity test
 * the given attributes string
 *
 * return EST_ERROR and the presence of challengePassword
 */
EST_ERROR est_asn1_parse_attributes (const char *p, int len, int *pop_present)
{
    unsigned char *der_ptr;
    int der_len, rv;

    /* 
     * check smallest possible base64 case here for now 
     * and sanity test will check min/max value for ASN.1 data
     */
    if (len < MIN_CSRATTRS) {
        return (EST_ERR_INVALID_PARAMETERS);
    }

    der_ptr = malloc(len*2);
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
        EST_LOG_ERR("Invalid ASN1 encoded data. rv = %d (%s)", rv,
                    EST_ERR_NUM_TO_STR(rv));
        free(der_ptr);
        return (rv);
    }
    free(der_ptr);
    return (EST_ERR_NONE);
}


#ifndef ENABLE_CLIENT_ONLY
/* 
 * est_add_challengePassword - caller has verified that challengePassword 
 * is configured and not included, so add it to the attributes here.
 * No sanity check is needed since est_is_challengePassword_present
 * has already been called.
 */
EST_ERROR est_add_challengePassword (const char *base64_ptr, int b64_len, 
				     char **new_csr, int *pop_len)
{
    const unsigned char *der_ptr;
    char *orig_ptr, *new_der = NULL, *csrattrs;
    int der_len, tag, xclass, new_len;
    long len;
    int enc_len;

    der_ptr = malloc(b64_len*2);
    if (!der_ptr) {
        return (EST_ERR_MALLOC);
    }

    der_len = est_base64_decode(base64_ptr, (char *)der_ptr, b64_len*2);
    if (der_len <= 0) {
        EST_LOG_ERR("Malformed base64 data");
        free((void *)der_ptr);
        return (EST_ERR_MALLOC);
    }

    orig_ptr = (char *)der_ptr;

    /* grab the first one and do the POP stuff */
    (void)ASN1_get_object(&der_ptr, &len, &tag, &xclass, der_len);

    if (tag != V_ASN1_SEQUENCE) {
        EST_LOG_ERR("Malformed ASN.1 Hex, no leading Sequence");
	free(orig_ptr);
	return (EST_ERR_BAD_ASN1_HEX);
    }

    len = (char *)der_ptr - orig_ptr;
    new_len = der_len - (int)len + sizeof(hex_chpw);
	    
    /* remove leading sequence and length and copy to new buffer */
    /* if >= 256 need 4 byte Seq header */
    if ((der_len - len + sizeof(hex_chpw)) >= 256) {
        new_len += 4;
	new_der = malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
        memzero_s(new_der, new_len);
	*(new_der + 1) = 0x82;
        *(new_der + 2) = (new_len - 4) >> 8;
        *(new_der + 3) = ((new_len - 4) & 0xff);
        memcpy_s(new_der+4, der_len - (unsigned int) len, der_ptr, der_len - (unsigned int)len);
	/* if <= 256, but >= 128 need 3 byte Seq header */
    } else if ((der_len - len + sizeof(hex_chpw)) >= 128) {
        new_len += 3;
	new_der = malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
        memzero_s(new_der, new_len);
        *(new_der + 1) = 0x81;
        *(new_der + 2) = new_len - 3;
        memcpy_s(new_der+3, der_len - ((rsize_t) len), der_ptr, der_len - ((rsize_t) len));
        /* else just need 2 byte header */
    } else {
        new_len += 2;
        new_der = malloc(new_len);
	if (!new_der) {
	    free(orig_ptr);
	    return (EST_ERR_MALLOC);
	}
        memzero_s(new_der, new_len);
        *(new_der + 1) = new_len - 2;
	if ((der_len - len) != 0) {
            memcpy_s(new_der+2, der_len - ((rsize_t) len), der_ptr, der_len - ((rsize_t) len));
	}
    }
    *new_der = 0x30;
    memcpy_s(new_der + (new_len - sizeof(hex_chpw)), sizeof(hex_chpw),
	     hex_chpw, sizeof(hex_chpw));

    csrattrs = malloc(new_len*2);
    if (!csrattrs) {
        free(orig_ptr);
        free(new_der);
	return (EST_ERR_MALLOC);
    }
    memzero_s(csrattrs, new_len*2);
    
    enc_len = est_base64_encode((const char *) new_der, new_len, (char *) csrattrs, new_len * 2, 0);
    if (enc_len <= 0) {
        EST_LOG_ERR("Invalid base64 encoded data");
        free(orig_ptr);
        free(new_der);
        free(csrattrs);
        return (EST_ERR_BAD_BASE64);
    }

    *new_csr = csrattrs;
    *pop_len = (int) strnlen_s(csrattrs, new_len*2);
    EST_LOG_INFO("CSR reconstituted attributes are(%d/%d): %s", b64_len, *pop_len, csrattrs);

    if (new_der) {
        free(new_der);
    }
    if (orig_ptr) {
        free(orig_ptr);
    }
    return (EST_ERR_NONE);
}
#endif

/*! @brief est_X509_REQ_sign() Sign an X509 certificate request
    using the digest and the key passed. Returns OpenSSL error
    code from X509_REQ_sign_ctx();

    @param csr an X509_REQ structure to be signed
    @param pkey key to sign the request with
    @param md the signing digest to be used

    @return int
 */
int est_X509_REQ_sign (X509_REQ *csr, EVP_PKEY *pkey, const EVP_MD *md)
{
    int rv;
    EVP_PKEY_CTX *pkctx = NULL;
#ifdef HAVE_OLD_OPENSSL
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX *mctx = &md_ctx;
    
    EVP_MD_CTX_init(mctx);    
#else
    EVP_MD_CTX *mctx;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        return 0;
    }
#endif

    if (!EVP_DigestSignInit(mctx, &pkctx, md, NULL, pkey)) {
        return 0;
    }

    /*
     * Encode using DER (ASN.1)
     *
     * We have to set the modified flag on the X509_REQ because
     * OpenSSL keeps a cached copy of the DER encoded data in some
     * cases.  Setting this flag tells OpenSSL to run the ASN
     * encoding again rather than using the cached copy.
     */
#ifdef HAVE_OLD_OPENSSL 
    csr->req_info->enc.modified = 1;
#endif
    
    rv = X509_REQ_sign_ctx(csr, mctx);

#ifdef HAVE_OLD_OPENSSL
    EVP_MD_CTX_cleanup(mctx);
#else
    EVP_MD_CTX_free(mctx);
#endif
    
    return (rv);
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


    der_ptr = malloc(csrattrs_len*2);
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
    int curr_len;
    const unsigned char *curr_string;

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
        curr_len = out_len;
        curr_string = string;
        
        j = ASN1_get_object(&string, &len, &tag, &xclass, out_len);

        if (j & 0x80) {
            return (EST_ERR_BAD_ASN1_HEX);
        }
        switch (tag) {

        case V_ASN1_OBJECT:
            a_object = d2i_ASN1_OBJECT(NULL, &curr_string, curr_len);
            if (a_object != NULL) {
                nid = OBJ_obj2nid(a_object);
                EST_LOG_INFO("NID=%d", nid);
                *new_nid = nid;
                *der_len = (out_len_save - (int) (curr_string - ostring));
                *der_ptr = (unsigned char *)curr_string;
                ASN1_OBJECT_free(a_object);
                string = curr_string;
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
        OPENSSL_cleanse(auth_cred->user, strnlen_s(auth_cred->user, MAX_UIDPWD));
        free(auth_cred->user);
        auth_cred->user = NULL;
    }
    
    if (auth_cred->pwd) {
        OPENSSL_cleanse(auth_cred->pwd, strnlen_s(auth_cred->pwd, MAX_UIDPWD));
        free(auth_cred->pwd);
        auth_cred->pwd = NULL;
    }
    
    if (auth_cred->uri) {
        OPENSSL_cleanse(auth_cred->uri, strnlen_s(auth_cred->uri, EST_URI_MAX_LEN));
        free(auth_cred->uri);
        auth_cred->uri = NULL;
    }
    
    if (auth_cred->cnonce) {
        OPENSSL_cleanse(auth_cred->cnonce, strnlen_s(auth_cred->cnonce, MAX_NONCE));
        free(auth_cred->cnonce);
        auth_cred->cnonce = NULL;
    }
    
    if (auth_cred->qop) {
        OPENSSL_cleanse(auth_cred->qop, strnlen_s(auth_cred->qop, MAX_QOP));
        free(auth_cred->qop);
        auth_cred->qop = NULL;
    }
    
    if (auth_cred->nc) {
        OPENSSL_cleanse(auth_cred->nc, strnlen_s(auth_cred->nc, MAX_NC));
        free(auth_cred->nc);
        auth_cred->nc = NULL;
    }
    
    if (auth_cred->nonce) {
        OPENSSL_cleanse(auth_cred->nonce, strnlen_s(auth_cred->nonce,
                                                    MAX_NONCE));
        free(auth_cred->nonce);
        auth_cred->nonce = NULL;
    }
    
    if (auth_cred->response) {
        OPENSSL_cleanse(auth_cred->response, strnlen_s(auth_cred->response,
                                                       MAX_RESPONSE));
        free(auth_cred->response);
        auth_cred->response = NULL;
    }
    
    if (auth_cred->auth_token) {
        OPENSSL_cleanse(auth_cred->auth_token, strnlen_s(auth_cred->auth_token,
                                                         MAX_AUTH_TOKEN_LEN));
        free(auth_cred->auth_token);
        auth_cred->auth_token = NULL;
    }        
    
    return;
}


/*
 * Given an input string, look for the four valid operations
 */
EST_OPERATION est_parse_operation (char *op_path) 
{
    EST_OPERATION operation;

    if (!est_strcasecmp_s(op_path, EST_GET_CACERTS)) {
        operation = EST_OP_CACERTS;
    } else if (!est_strcasecmp_s(op_path, EST_GET_CSRATTRS)) {
        operation = EST_OP_CSRATTRS;
    } else if (!est_strcasecmp_s(op_path, EST_SIMPLE_ENROLL)) {
        operation = EST_OP_SIMPLE_ENROLL;
    } else if (!est_strcasecmp_s(op_path, EST_SIMPLE_REENROLL)) {
        operation = EST_OP_SIMPLE_REENROLL;
    } else if (!est_strcasecmp_s(op_path, EST_SERVER_KEYGEN)) {
        operation = EST_OP_SERVER_KEYGEN;
#if ENABLE_BRSKI
    } else if (!est_strcasecmp_s(op_path, EST_BRSKI_GET_VOUCHER)) {
        operation = EST_OP_BRSKI_REQ_VOUCHER;
    } else if (!est_strcasecmp_s(op_path, EST_BRSKI_VOUCHER_STATUS)) {
        operation = EST_OP_BRSKI_VOUCHER_STATUS;
    } else if (!est_strcasecmp_s(op_path, EST_BRSKI_ENROLL_STATUS)) {
        operation = EST_OP_BRSKI_ENROLL_STATUS;
#endif
    } else {
        operation = EST_OP_MAX;
    }
    
    return (operation);
}

/*
 * Given a URI string, parse it up and return the optional path
 * segment if it exists and the operation value
 */
#ifdef HAVE_URIPARSER
EST_ERROR est_parse_uri (char *uri, EST_OPERATION *operation,
                         char **path_seg) 
{
    /* char *path_seg_end; */
    /* int   path_seg_len = 0; */
    UriParserStateA state;
    UriUriA parsed_uri;
    EST_ERROR rv = EST_ERR_NONE;
    int uriparse_rc;
    errno_t safec_rc;    
    int diff;

    *path_seg = NULL;
    state.uri = &parsed_uri;
    uriparse_rc = uriParseUriA(&state, uri);
    if (uriparse_rc != URI_SUCCESS) {
        uriFreeUriMembersA(state.uri);
        return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    }

    if (parsed_uri.pathHead) {
        
        /*
         * validate the URI
         * - parse the path-prefix (/.well-known/est)
         * - look to see if there is a path segment extension
         * - determine which operation it is
         */        
        UriPathSegmentA *cur_seg = parsed_uri.pathHead;
        char *cur_seg_str = (char *)cur_seg->text.first;
        int cur_seg_len = 0;
        char *segment = NULL;
        
        safec_rc = memcmp_s(cur_seg_str, WELL_KNOWN_SEGMENT_LEN,
                            ".well-known", WELL_KNOWN_SEGMENT_LEN, &diff);
        if (diff || safec_rc != EOK) {
            EST_LOG_ERR("URI path does not start with %s, safec_rc = 0x%xO\n",
                        WELL_KNOWN_SEGMENT, safec_rc);
            uriFreeUriMembersA(state.uri);
            return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
        }
        
        cur_seg = cur_seg->next;
        cur_seg_str = (char *)cur_seg->text.first;
        safec_rc = memcmp_s(cur_seg_str, EST_SEGMENT_LEN,
                            "est", EST_SEGMENT_LEN, &diff);
        if (diff || safec_rc != EOK) {
            EST_LOG_ERR("URI does not contain %s segment 0x%xO\n",
                        EST_SEGMENT, safec_rc);
            uriFreeUriMembersA(state.uri);
            return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
        }
        
        /*
         * This next segment is either a segment extension
         * or it's the operation 
         */
        cur_seg = cur_seg->next;
        cur_seg_str = (char *)cur_seg->text.first;

        /*
         * If there's another segment after this one then use it
         * to find the end, else walk this one for the length
         */
        if (cur_seg->text.afterLast) {
            cur_seg_len = ((char *)cur_seg->text.afterLast) - cur_seg_str;
        } else {
            cur_seg_len = strnlen_s(cur_seg_str, EST_MAX_PATH_SEGMENT_LEN+1);
        }
        if (cur_seg_len > EST_MAX_PATH_SEGMENT_LEN) {
            EST_LOG_ERR("path segment exceeds maximum of %d\n",
                        EST_MAX_PATH_SEGMENT_LEN);
            uriFreeUriMembersA(state.uri);
            return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
        }

        /*
         * See if the current segment needs to be put into its own
         * string
         */
        if ((cur_seg->text.afterLast != NULL) &&
            *(cur_seg->text.afterLast) != '\0') {
            segment = STRNDUP(cur_seg_str, cur_seg_len);
        } else {
            segment = STRNDUP(cur_seg_str, EST_MAX_PATH_SEGMENT_LEN);
        }
        
        /*
         * look to see if the operation path comes next:
         * cacerts, csrattrs, simpleenroll, simplereenroll
         */
        *operation = est_parse_operation(segment);
        if (*operation == EST_OP_MAX) {
            
            /*
             * It wasn't one of the 4 known operations so
             * it must be a path segment.  parse it out.
             *
             * Find the end of the path segment,
             * determine the length,
             * save it away
             */
            /* path_seg_end = (char *)cur_seg->text.afterLast; */
            
            /* if (path_seg_end != NULL) { */
            /*     path_seg_len = path_seg_end - cur_seg_str; */
            /* } */
            
            *path_seg = malloc(cur_seg_len+1);
            if (*path_seg == NULL) {
                free(segment);
                uriFreeUriMembersA(state.uri);
                return (EST_ERR_MALLOC);
            }
            
            safec_rc = memcpy_s(*path_seg, cur_seg_len+1,
                                segment, cur_seg_len);
            if (safec_rc != EOK) {
                EST_LOG_ERR("URI path seg could not copied into the context");
                free(segment);
                free(*path_seg);
                *path_seg = NULL;
                uriFreeUriMembersA(state.uri);                
                return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
            }
            *((*path_seg)+cur_seg_len) = '\0';
            
            /*
             * now that we have the path segment parsed, try
             * for the operation again.  jump over the path segment
             * and the next '/'
             */
            cur_seg_str = cur_seg_str + cur_seg_len + 1;
            *operation = est_parse_operation(cur_seg_str);
            
            if (*operation == EST_OP_MAX) {
                /*
                 * Operation code was suppose to be next but is not
                 */
                free(segment);
                free(*path_seg);
                *path_seg = NULL;
                uriFreeUriMembersA(state.uri);                
                return (EST_ERR_HTTP_BAD_REQ);
            }
        } else {
            /*
             * It was one of the operations, make sure it's the end
             */
            if ((cur_seg->text.afterLast != NULL) &&
                *(cur_seg->text.afterLast) != '\0') {
                EST_LOG_ERR("Invalid path segment: contains an operation value");
                free(segment);
                free(*path_seg);
                *path_seg = NULL;
                *operation = EST_OP_MAX;
                uriFreeUriMembersA(state.uri);
                return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
            }
        }
        free(segment);
        uriFreeUriMembersA(state.uri);        
    }    
    return (rv);
}
#else
EST_ERROR est_parse_uri (char *uri, EST_OPERATION *operation,
                         char **path_seg) 
{
    EST_ERROR rc = EST_ERR_NONE;
    *path_seg = NULL;
    /*
     * Assume that the uri is pointing to
     *   /.well-known/est/<operation>
     */
    if (strncmp(uri, EST_CACERTS_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_CACERTS;
    } else if (strncmp(uri, EST_SIMPLE_ENROLL_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_SIMPLE_ENROLL;
    } else if (strncmp(uri, EST_RE_ENROLL_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_SIMPLE_REENROLL;
    } else if (strncmp(uri, EST_CSR_ATTRS_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_CSRATTRS;
    }  else if (strncmp(uri, EST_KEYGEN_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_SERVER_KEYGEN;
#if ENABLE_BRSKI
    } else if (strncmp(uri, EST_BRSKI_GET_VOUCHER_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_BRSKI_REQ_VOUCHER;
    } else if (strncmp(uri, EST_BRSKI_VOUCHER_STATUS_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_BRSKI_VOUCHER_STATUS;
    } else if (strncmp(uri, EST_BRSKI_ENROLL_STATUS_URI, EST_URI_MAX_LEN) == 0) {
        *operation = EST_OP_BRSKI_ENROLL_STATUS;
#endif        
    } else {
        *operation = EST_OP_MAX;
        rc = EST_ERR_HTTP_INVALID_PATH_SEGMENT;
        
    }
    
    return rc;
}
#endif

#ifdef HAVE_URIPARSER
EST_ERROR est_parse_path_seg (char *path_seg) 
{
    UriParserStateA state;
    UriUriA parsed_uri;
    int uriparse_rc;
    UriPathSegmentA *cur_seg = NULL;
    char *cur_seg_str = NULL;
    EST_OPERATION operation;
    char canned_uri[EST_URI_MAX_LEN];

    /*
     * build out a canned URI to pass to the uriparser library.
     * This will cause the incoming path segment to be in the
     * correct spot within a URI as it gets validated.  Main issue
     * is the possible use of a ':' in the path segment becoming a
     * theme delimiter
     */
    memzero_s(canned_uri, EST_URI_MAX_LEN);
    strcpy_s(canned_uri, EST_URI_MAX_LEN, "/.well-known/est/");
    strcat_s(canned_uri, EST_URI_MAX_LEN, path_seg);

    state.uri = &parsed_uri;
    uriparse_rc = uriParseUriA(&state, canned_uri);
    if (uriparse_rc != URI_SUCCESS) {
        uriFreeUriMembersA(state.uri);
        return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    }

    cur_seg = parsed_uri.pathHead;
    if (cur_seg == NULL) {
        EST_LOG_ERR("No valid path segment in supplied string");
        uriFreeUriMembersA(state.uri);
        return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    }

    cur_seg = cur_seg->next->next;
    cur_seg_str = (char *)cur_seg->text.first;
    operation = est_parse_operation(cur_seg_str);
        /*
         * look to see if the operation path comes next:
         * cacerts, csrattrs, simpleenroll, simplereenroll.
         * If any of the operations occur in this path segment
         * string, then this is a problem.
         */
    if (operation != EST_OP_MAX) {
        EST_LOG_ERR("Path segment string contains an operation value. path segment passed in =  %s\n", cur_seg_str);
        uriFreeUriMembersA(state.uri);
        return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    }

    /*
     * Look to see if there are multiple segments
     */
    if ((char *)cur_seg->next != NULL || *(cur_seg->text.afterLast) != '\0') {
        EST_LOG_ERR("Path segment string contains multiple path segments or more than a path segment");
        uriFreeUriMembersA(state.uri);        
        return (EST_ERR_HTTP_INVALID_PATH_SEGMENT);
    }
    
    uriFreeUriMembersA(state.uri);    
    return (EST_ERR_NONE);
}
#endif

/*
 * Store the path segment into the context.
 */
EST_ERROR est_store_path_segment (EST_CTX *ctx, char *path_segment,
                                  int path_segment_len)
{
    /*
     * reset what might already be cached
     */
    if (ctx->uri_path_segment) {
        free(ctx->uri_path_segment);
        ctx->uri_path_segment = NULL;
    }
    
    ctx->uri_path_segment = malloc(strnlen_s(path_segment, path_segment_len)+1);
    if (ctx->uri_path_segment == NULL) {
        return EST_ERR_MALLOC;
    }
    
    if (EOK != strcpy_s(ctx->uri_path_segment, path_segment_len+1,
                         path_segment)) {
        return EST_ERR_HTTP_INVALID_PATH_SEGMENT;
    }
    ctx->uri_path_segment[path_segment_len] = '\0';

    return EST_ERR_NONE;   
}


int est_strcasecmp_s (char *s1, char *s2)
{
    errno_t safec_rc;
    int diff;
    
    safec_rc = strcasecmp_s(s1, strnlen_s(s1, RSIZE_MAX_STR), s2, &diff);

    if (safec_rc != EOK) {
        /*
         * Log that we encountered a SafeC error
         */
        EST_LOG_INFO("strcasecmp_s error 0x%xO\n", safec_rc);
    } 

    return diff;
}

size_t est_strcspn(const char * str1,const char * str2) 
{
    rsize_t count;
    errno_t safec_rc; 

    if ((str1 != NULL) && (str1[0] == '\0')) {
        return 0; 
    }

    safec_rc = strcspn_s(str1, strnlen_s(str1, RSIZE_MAX_STR),
            str2, RSIZE_MAX_STR, &count);
    if (safec_rc != EOK) {
        EST_LOG_INFO("strcspn_s error 0x%xO\n", safec_rc);
        return 0;
    }

    return count;
}


size_t est_strspn(const char * str1,const char  * str2) 
{
    rsize_t count;
    errno_t safec_rc; 

    if ((str1 != NULL) && (str1[0] == '\0')) {
        return 0; 
    }

    safec_rc = strspn_s(str1, strnlen_s(str1, RSIZE_MAX_STR), 
            str2, RSIZE_MAX_STR, &count);
    if (safec_rc != EOK) {
        EST_LOG_INFO("strspn_s error 0x%xO\n", safec_rc);
        return 0; 
    }

    return count; 

}


// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespaces.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
char *skip_quoted (char **buf, const char *delimiters,
                   const char *whitespace, char quotechar)
{
    char *p, *begin_word, *end_word, *end_whitespace;

    begin_word = *buf;

    end_word = begin_word + est_strcspn(begin_word,delimiters);

    // Check for quotechar
    if (end_word > begin_word) {
        p = end_word - 1;
        while (*p == quotechar) {
            // If there is anything beyond end_word, copy it
            if (*end_word == '\0') {
                *p = '\0';
                break;
            } else {

                rsize_t end_off = (rsize_t) est_strcspn(end_word + 1, delimiters);
                memmove_s(p, end_off + 1, end_word, end_off + 1);
                p += end_off; // p must correspond to end_word - 1
                end_word += end_off + 1;
            }
        }
        for (p++; p < end_word; p++) {
            *p = '\0';
        }
    }

    if (*end_word == '\0') {
        *buf = end_word;
    } else {

        end_whitespace = end_word + 1 + est_strspn(end_word + 1, whitespace);

        for (p = end_word; p < end_whitespace; p++) {
            *p = '\0';
        }

        *buf = end_whitespace;
    }

    return begin_word;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
char *skip (char **buf, const char *delimiters)
{
    return skip_quoted(buf, delimiters, delimiters, 0);
}

/*! @brief est_enable_performance_timers() is used by an application to enable
    the use and output of the libest performance timers for the given est
    context. When enabled these timers will output logs that can be parsed to
    give you performance metrics of different areas of libest as they are
    executed.

    @param ctx Pointer to the EST context

    The libest performance timers is disabled by default.

    @return EST_ERROR.
 */
EST_ERROR est_enable_performance_timers (EST_CTX *ctx)
{
#ifndef WIN32
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->perf_timers_enabled = 1;
    return (EST_ERR_NONE);
#else
    EST_LOG_ERR("Timers are not supported for Windows builds");
    return EST_ERR_UNKNOWN;
#endif
}

/*! @brief est_disable_performance_timers() is used by an application to disable
    the use and output of the libest performance timers for the given est
    context.

    @param ctx Pointer to the EST context

    The libest performance timers is disabled by default.

    @return EST_ERROR.
 */
EST_ERROR est_disable_performance_timers (EST_CTX *ctx)
{
#ifndef WIN32
    if (!ctx) {
        EST_LOG_ERR("Null context");
        return (EST_ERR_NO_CTX);
    }

    ctx->perf_timers_enabled = 0;
    return (EST_ERR_NONE);
#else
    EST_LOG_ERR("Timers are not supported for Windows builds");
    return EST_ERR_UNKNOWN;
#endif
}

/*
 * This function creates and starts an EST performance timer when this
 * functionality is enabled. Pass in the pointer to the timer,the est context,
 * and the tag you would like to print for this timer. If the input parameters
 * were NULL an error will be printed, if a timer was given it will be set to
 * NULL, and a failure (-1) will be returned. If timers are not enabled the tag
 * stored within the timer will remain NULL, but the ctx will be set to signal
 * to stop_timer that timers are disabled. The return is an int that signals
 * success with a 1 and failure with a -1. Note that if the timers are disabled
 * the function returns a success but doesn't create the full timer.
 */
int start_timer (EST_TIMER *timer, EST_CTX *ctx, char *tag) {
#ifndef WIN32
    if (timer) {
        null_timer(timer);
    }
    if (!ctx || !tag || !timer) {
        EST_LOG_ERR("Invalid parameters to start a timer. ctx: (%p) tag: (%p) "
                    "timer: (%p)",
                    ctx, tag, timer);
        return -1;
    }
    timer->ctx = ctx;
    if (!ctx->perf_timers_enabled) {
        return 1;
    }
    gettimeofday(&timer->start, NULL);
    timer->tag = tag;
#endif
    return 1;
}

#if HAVE_LIBCOAP
/*
 * This function creates and starts session, handle request, request gap
 * performance timers for a coap session, as the session is handling different
 * requests. Pass in the est context and coap request node to set the timers on.
 * NOTE: NULL checks of the EST_CTX should be done before making a call to this
 * function, as this function assumes the context is already set.
 */
void start_coap_req_timers (EST_CTX *ctx, coap_req_node_t *req_node) {
#ifndef WIN32
    char *tag;
    if (!req_node) {
        EST_LOG_ERR("NULL request node given when adding timers");
        return;
    }
    if (!ctx->perf_timers_enabled) {
        /* 
         * Add context reference to all timers to tell stop timer that they are
         * disabled 
         */
        req_node->session_timer.ctx = ctx;
        req_node->handle_req_timer.ctx = ctx;
        req_node->session_timer.ctx = ctx;
        return;
    }
    switch (req_node->cur_req) {
    case EST_COAP_REQ_RESET:
        if (!is_started(&(req_node->session_timer))) {
            start_timer(&(req_node->session_timer), ctx, "CoAP session_timer");
            /* capture the starting request gap */
            start_timer(&(req_node->req_gap_timer), ctx, "CoAP req_gap_timer");
        } else {
            /* If the session is started tag is not NULL */
            EST_LOG_WARN(
                "Session timer (%s) told to start when already running",
                req_node->session_timer.tag);
        }
        return;
    case EST_COAP_REQ_CRTS:
        tag = "CoAP handle_req_timer crts";
        break;
    case EST_COAP_REQ_ATT:
        tag = "CoAP handle_req_timer att";
        break;
    case EST_COAP_REQ_SEN:
        tag = "CoAP handle_req_timer sen";
        break;
    case EST_COAP_REQ_SREN:
        tag = "CoAP handle_req_timer sren";
        break;
    case EST_COAP_REQ_SKG:
        tag = "CoAP handle_req_timer skg";
        break;
    default:
        EST_LOG_ERR("Attempted to start timers on invalid EST_COAP_REQ type");
        return;
    }
    if (!is_started(&(req_node->handle_req_timer))) {
        start_timer(&(req_node->handle_req_timer), ctx, tag);
    } else {
        EST_LOG_WARN("Handler timer (%s) told to start when already running",
                     req_node->handle_req_timer.tag);
    }
#endif
}

/*
 * This function stops the handle request, and starts the request gap
 * performance timers for a coap session, to record the amount of time the
 * server is waiting on a session. Pass in the est context and coap request node
 * to enter this state.
 * NOTE: NULL checks of the EST_CTX should be done before making a call to this
 * function, as this function assumes the context is already set.
 */
void enter_wait_coap_req_timers (EST_CTX *ctx, coap_req_node_t *req_node) {
#ifndef WIN32
    char *tag;
    if (!ctx->perf_timers_enabled)  {
        return;
    }
    switch (req_node->cur_req) {
    case EST_COAP_REQ_CRTS:
        tag = "CoAP req_gap_timer crts";
        break;
    case EST_COAP_REQ_ATT:
        tag = "CoAP req_gap_timer att";
        break;
    case EST_COAP_REQ_SEN:
        tag = "CoAP req_gap_timer sen";
        break;
    case EST_COAP_REQ_SREN:
        tag = "CoAP req_gap_timer sren";
        break;
    case EST_COAP_REQ_SKG:
        tag = "CoAP req_gap_timer skg";
        break;
    default:
        EST_LOG_ERR("Attempted to start timers on invalid EST_COAP_REQ type");
        return;
    }
    if (is_started(&(req_node->handle_req_timer))) {
        stop_timer_with_id(&(req_node->handle_req_timer), req_node->key);
    } else {
        /* If the session is started tag is not NULL */
        EST_LOG_WARN("Handler timer (%s) told to stop when it wasn't started",
                     req_node->handle_req_timer.tag);
    }
    if (!is_started(&(req_node->req_gap_timer))) {
        start_timer(&(req_node->req_gap_timer), ctx, tag);
    } else {
        EST_LOG_WARN("Gap timer (%s) told to start when already running",
                     req_node->req_gap_timer.tag);
    }
#endif
}
#endif
/*
 * Start the http_req_timer with the applicable tag. Checks for NULL pointers
 * should be done before calling this function. If timers are disabled this
 * function is a no-op.
 * NOTE: NULL checks of the EST_CTX should be done before making a call to this
 * function, as this function assumes the context is already set.
 */
void start_http_req_timer (EST_TIMER *timer, EST_CTX *est_ctx, EST_OPERATION op)
{
#ifndef WIN32
    char *tag;
    if (!est_ctx->perf_timers_enabled) {
        /* 
         * Add context reference to timer to tell stop timer that this timer is
         * disabled 
         */
        timer->ctx = est_ctx;
        return;
    }
    switch (op) {
    case EST_OP_CACERTS:
        tag = "HTTP cacerts req";
        break;
    case EST_OP_CSRATTRS:
        tag = "HTTP csrattrs req";
        break;
    case EST_OP_SIMPLE_ENROLL:
        tag = "HTTP simpleenroll req";
        break;
    case EST_OP_SIMPLE_REENROLL:
        tag = "HTTP simplereenroll req";
        break;
    case EST_OP_SERVER_KEYGEN:
        tag = "HTTP serverkeygen req";
        break;
    default:
        EST_LOG_ERR(
            "Attempted to start request timer for unsupported req type");
        return;
    }
    start_timer(timer, est_ctx, tag);
#endif
}

/*
 * This function stops the passed in EST performance timer and prints out the
 * log message if performance timers are enabled in the EST context within the
 * timer. This will print out the elapsed time in seconds down to microseconds
 * precision. The return is an int that signals success with a 1 and failure
 * with a -1. Note that if the timers are disabled the function simply returns a
 * success.
 */
int stop_timer (EST_TIMER *timer) {
#ifndef WIN32
    struct timeval diff;
    if (!timer) {
        EST_LOG_ERR("Attempted to stop a NULL timer. timer: (%p)", timer);
        return -1;
    }
    if (!timer->ctx) {
        EST_LOG_ERR("Invalid timer being stopped. timer.ctx: (%p)", timer->ctx);
        return -1;
    }
    if (!timer->ctx->perf_timers_enabled) {
        return 1;
    }
    if (!timer->tag) {
        EST_LOG_ERR("Timer being stopped has no tag. timer.tag: (%p)",
                    timer->tag);
        return -1;
    }
    gettimeofday(&(timer->end), NULL);
    timersub(&(timer->end), &(timer->start), &diff);
    EST_LOG_TIMER("%s => %ld.%06ld seconds", timer->tag, diff.tv_sec,
                  diff.tv_usec);
#endif
    return 1;
}

/*
 * This function stops the passed in EST performance timer and prints out the
 * log message with an appended id string if performance timers are enabled in
 * the EST context within the timer. This will print out the elapsed time in
 * seconds down to microseconds precision. The return is an int that signals
 * success with a 1 and failure with a -1. Note that if the timers are disabled
 * the function simply returns a success.
 */
int stop_timer_with_id (EST_TIMER *timer, char *id) {
#ifndef WIN32
    struct timeval diff;
    if (!timer) {
        EST_LOG_ERR("Attempted to stop a NULL timer. timer: (%p)", timer);
        return -1;
    }
    if (!timer->ctx) {
        EST_LOG_ERR("Invalid timer being stopped. timer.ctx: (%p)", timer->ctx);
        return -1;
    }
    if (!id) {
        EST_LOG_ERR("Asked to print with ID but ID was NULL for timer %s",
                    timer->tag);
        return -1;
    }
    if (!timer->ctx->perf_timers_enabled) {
        return 1;
    }
    if (!timer->tag) {
        EST_LOG_ERR("Timer being stopped has no tag. timer.tag: (%p)",
                    timer->tag);
        return -1;
    }
    gettimeofday(&(timer->end), NULL);
    timersub(&(timer->end), &(timer->start), &diff);
    EST_LOG_TIMER("%s--%s => %ld.%06ld seconds", timer->tag, id, diff.tv_sec,
                  diff.tv_usec);
#endif
    return 1;
}

void null_timer (EST_TIMER *timer) {
#ifndef WIN32
    timer->ctx = NULL;
    timer->tag = NULL;
    timerclear(&(timer->start));
    timerclear(&(timer->end));
#endif
    return;
}
unsigned char is_same_time (struct timeval *time1, struct timeval *time2) {
    /*
     * Some platforms have broken timercmp of == >= <=
     * Use the more portable form 
     */
#ifndef WIN32
    return !timercmp(time1, time2, !=);
#else 
    return 0;
#endif
}
unsigned char is_started (EST_TIMER *timer) {
    /*
     * timer is started if it is initialized and the start time is set
     */
#ifndef WIN32
    return timer->tag && timerisset(&(timer->start));
#else
    return 0;
#endif
}
unsigned char is_stopped (EST_TIMER *timer) {
    /*
     * timer is stopped if it is uninitialized or the end time is set
     */
#ifndef WIN32
    return !timer->tag || timerisset(&(timer->end));
#else
    return 0;
#endif
}

unsigned char is_running (EST_TIMER *timer) {
#ifndef WIN32
    return is_started(timer) && !is_stopped(timer);
#else
    return 0;
#endif
}
