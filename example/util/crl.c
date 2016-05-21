/*------------------------------------------------------------------
 * crl.c - CDP/CRL download related code, taken from openssl/apps/apps.c and slightly extended
 *------------------------------------------------------------------
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include "../server/apps.h"

int load_cert_crl_http(const char *url, BIO *err,
                       X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        if (err)
            BIO_puts(err, "https not supported\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;
    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (!rctx)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;
    if (pcert) {
        do {
            rv = X509_http_nbio(rctx, pcert);
        }
        while (rv == -1);
    } else {
        do {
            rv = X509_CRL_http_nbio(rctx, pcrl);
        } while (rv == -1);
    }

 err:
    if (host)
        OPENSSL_free(host);
    if (path)
        OPENSSL_free(path);
    if (port)
        OPENSSL_free(port);
    if (bio)
        BIO_free_all(bio);
    if (rctx)
        OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        if (bio && err)
            BIO_printf(bio_err, "Error loading %s from '%s'\n",
                       pcert ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

X509_CRL *load_crl(const char *infile, int format)
{
    X509_CRL *x = NULL;
    BIO *in = NULL;

    BIO_printf(bio_err, "\nDEBUG: Loading CRL from '%s' ", infile);
    if (strncmp(infile, "http://", 7))
	format = FORMAT_PEM; // unless http, try loading PEM file

    if (format == FORMAT_HTTP) {
        load_cert_crl_http(infile, bio_err, NULL, &x);
        return x;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile == NULL)
        goto end; // BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
	if (!strncmp(infile, "file:", 5))
	    infile += 5;
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }
    if (format == FORMAT_ASN1)
        x = d2i_X509_CRL_bio(in, NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "bad input format specified for input crl\n");
        goto end;
    }
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load CRL\n");
        ERR_print_errors(bio_err);
        goto end;
    }

 end:
    ERR_clear_error(); // needed to prevent EST_ERR_SYSCALL, e.g., when infile does not exist
    BIO_free(in);
    return (x);
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            char *uptr = (char *)ASN1_STRING_data(uri);
            if (!strncmp(uptr, "http://", 7) || !strncmp(uptr, "file:", 5))
                return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp, const char *default_cdp)
{
    int i;
    X509_CRL *crl = NULL;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr && (crl = load_crl(urlptr, FORMAT_HTTP)))
	    break;
    }
    if (!crl && default_cdp && default_cdp[0])
	crl = load_crl(default_cdp, FORMAT_HTTP);
    return crl;
}

/*
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads, doesn't support non-blocking I/O and doesn't cache
 * anything.
 */

STACK_OF(X509_CRL) *load_crls_from_cdps(X509_STORE_CTX *ctx, X509_NAME *nm, const char *default_cdp)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp, default_cdp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl)
        return NULL;
    crls = sk_X509_CRL_new_null();
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp, default_cdp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    return load_crls_from_cdps(ctx, nm, NULL/* default_cdp */);
}

