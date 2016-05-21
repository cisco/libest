/*------------------------------------------------------------------
 * crl.h - CDP/CRL download related code, taken from openssl/apps/apps.c and slightly extended
 *------------------------------------------------------------------
 */

#ifndef HEADER_CRL_H
#define HEADER_CRL_H

#include <openssl/x509v3.h>

STACK_OF(X509_CRL) *load_crls_from_cdps(X509_STORE_CTX *ctx, X509_NAME *nm, const char *default_cdp);
STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm);

#endif
