/** @file */
/*------------------------------------------------------------------
 * est/est_enhcd_cert_auth.c - EST Enhanced Certificate Auth Feature
 *         Description: This file contains utility functions for the
 *                      Cisco specific Enhanced Certificate Auth
 *                      feature.
 *
 *	       Assumptions:  - OpenSSL is linked along with this
 *	                       module for handling and managing
 *                         certificates.
 *
 * November, 2018
 *
 * Copyright (c) 2018 by Cisco Systems, Inc.
 * All rights reserved.
 **------------------------------------------------------------------
 */

#ifdef WIN32
#include <Ws2tcpip.h>
#endif
#include "est_locl.h"
#include "est_ossl_util.h"
#include "safe_mem_lib.h"
#include "safe_str_lib.h"

/*
 * This function creates the manufacturer info list for the context
 * This manufacturer info list is used in enhanced cert auth mode
 * to build the correct username for the auth.
 */
EST_ERROR est_enhcd_cert_auth_mfg_info_list_create (EST_CTX *ctx)
{
    ctx->enchd_cert_mfgs_info_list = (ENCHD_CERT_MFG_INFO *)calloc(
        (NUM_SUPPORTED_MFG), sizeof(ENCHD_CERT_MFG_INFO));

    if (ctx->enchd_cert_mfgs_info_list == NULL) {
        EST_LOG_ERR("Could not allocate mfg info list.");
        return (EST_ERR_MALLOC);
    }
    return (EST_ERR_NONE);
}

/*
 * This function gets the index of the next open spot in the manufacturer
 * info list. If the manufacturer list is full then the index is set to -1.
 */
static EST_ERROR est_enhcd_cert_get_next_mfg_info_ind (EST_CTX *ctx, int *index)
{
    int i;
    if (!ctx->enchd_cert_mfgs_info_list) {
        EST_LOG_ERR("Manufaturers info list is not created");
        return (EST_ERR_INVALID_PARAMETERS);
    }
    for (i = 0; i < NUM_SUPPORTED_MFG; i++) {
        if (ctx->enchd_cert_mfgs_info_list[i].truststore == NULL) {
            *index = i;
            return (EST_ERR_NONE);
        }
    }
    *index = -1;
    EST_LOG_ERR("The manufacturer info list in the provided est context is "
                "full");
    return (EST_ERR_NONE);
}

/*
 * This function adds a new entry to the manfacturer info list for enhanced cert
 * auth. This function takes a string name that identifies the manufacturer. A
 * subject field NID is passed in to determine which subject field to use as the
 * username during auth. Finally this function takes a char array containing the
 * PEM encoded CA certificates,both implicit and explicit certs. These are
 * decoded and loaded into a X509 store for that manufacturer.
 * When Enhanced Certificate Authentication mode is enabled this cert store
 * will be used to determine whether a request came from a device manufactured
 * by this vendor.
 * Note: we do not include defensive code to check for NULL arguments
 *       because this function is not part of the public API.  These
 *       checks should have already been performed.
 */
EST_ERROR est_load_enhcd_cert_auth_manufacturer (EST_CTX *ctx, char *mfg_name,
                                                 int subject_field_nid,
                                                 unsigned char *certs,
                                                 int certs_len)
{
    EST_ERROR rv;
    int i = -1;
    if (!ctx->enchd_cert_mfgs_info_list) {
        EST_LOG_ERR("Manufaturers info list is not created");
        return (EST_ERR_INVALID_PARAMETERS);
    }
    rv = est_enhcd_cert_get_next_mfg_info_ind(ctx, &i);
    if (rv != EST_ERR_NONE || i < 0) {
        EST_LOG_ERR("Unable to find a spot in the mfgs info list");
        return rv;
    }
    if (strncpy_s(ctx->enchd_cert_mfgs_info_list[i].name, MFG_NAME_MAX_LEN + 1,
                  mfg_name, MFG_NAME_MAX_LEN)) {
        EST_LOG_ERR("SAFEC ERROR: Could not copy manufacturer name");
        return (EST_ERR_UNKNOWN);
    }
    ctx->enchd_cert_mfgs_info_list[i].nid = subject_field_nid;
    ctx->enchd_cert_mfgs_info_list[i].truststore = X509_STORE_new();
    if (ctx->enchd_cert_mfgs_info_list[i].truststore == NULL) {
        EST_LOG_ERR("Unable to allocate Enhanced Cert Auth truststore for "
                    "manufacturer %s",
                    mfg_name);
        return (EST_ERR_MALLOC);
    }
    X509_STORE_set_verify_cb(ctx->enchd_cert_mfgs_info_list[i].truststore,
                             ossl_verify_cb);
    rv = ossl_init_cert_store(ctx->enchd_cert_mfgs_info_list[i].truststore,
                              certs, certs_len);
    if (rv != EST_ERR_NONE) {
        X509_STORE_free(ctx->enchd_cert_mfgs_info_list[i].truststore);
        ctx->enchd_cert_mfgs_info_list[i].truststore = NULL;
        EST_LOG_ERR("Unable to initialize manufacturer truststore for "
                    "manufacturer %s",
                    mfg_name);
        return rv;
    }
    ctx->enchd_cert_mfgs_info_list[i].store_ctx = X509_STORE_CTX_new();
    if (ctx->enchd_cert_mfgs_info_list[i].store_ctx == NULL) {
        EST_LOG_ERR("Unable to allocate a store context for Enhanced Cert "
                    "Auth manufacturer %s",
                    mfg_name);
        ossl_dump_ssl_errors();
        X509_STORE_free(ctx->enchd_cert_mfgs_info_list[i].truststore);
        ctx->enchd_cert_mfgs_info_list[i].truststore = NULL;
        return (EST_ERR_MALLOC);
    }
    return (EST_ERR_NONE);
}

/*
 * This function verifies a X509 certificate against the manufacturer
 * truststores. This allows the caller to determine whether a peer certificate
 * was signed by one of the registered manufacturers, and if so, which one.
 */
EST_ERROR est_enhcd_cert_auth_get_mfg (EST_CTX *ctx, X509 *peer,
                                       STACK_OF (X509) * peer_chain, int *index)
{
    ENCHD_CERT_MFG_INFO *cur_mfg_info;
    EST_ERROR rv = EST_ERR_VALIDATION;
    char *name = NULL;
    int i;
    *index = -1;
    EST_LOG_INFO("Checking if cert was signed by a manufacturer");
    if (!ctx->enchd_cert_mfgs_info_list) {
        EST_LOG_INFO("No manufacturer info list.");
        rv = EST_ERR_NONE;
        goto end;
    }
    for (i = 0; i < NUM_SUPPORTED_MFG; i++) {
        cur_mfg_info = &(ctx->enchd_cert_mfgs_info_list[i]);
        if (cur_mfg_info->truststore && cur_mfg_info->store_ctx) {
            if (!X509_STORE_CTX_init(cur_mfg_info->store_ctx,
                                     cur_mfg_info->truststore, peer,
                                     peer_chain)) {
                EST_LOG_ERR(
                    "Unable to initialize the new store context for Enhanced "
                    "Cert Auth");
                ossl_dump_ssl_errors();
                rv = EST_ERR_MALLOC;
                goto end;
            }
            name = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
            EST_LOG_INFO("Initialized store context with peer (%s)", name);

            rv = X509_verify_cert(cur_mfg_info->store_ctx);
            X509_STORE_CTX_cleanup(cur_mfg_info->store_ctx);
            if (!rv) {
                /*
                 * this cert failed verification.  Log this and continue on
                 */
                EST_LOG_INFO(
                    "Enhanced Cert Auth- Certificate failed verification (%s) "
                    "for manufacturer %s",
                    name, cur_mfg_info->name);
                ossl_dump_ssl_errors();
            } else {
                rv = EST_ERR_NONE;
                *index = i;
                goto end;
            }
            free(name);
            name = NULL;
        }
    }
end:
    if (name) {
        free(name);
    }
    return rv;
}
/*
 * This function will take the given X509_NAME and get the string corresponding
 * to subject field specified by the given NID. If the subject field was not
 * found the returned string will be NULL
 */
static char *find_subject_field_from_x509_name (X509_NAME *name, int nid)
{
    int subj_field_name_index;
    X509_NAME_ENTRY *subj_field_name_entry;
    ASN1_STRING *subj_field_asn1;
    subj_field_name_index = X509_NAME_get_index_by_NID(name, nid, -1);
    if (subj_field_name_index < 0) {
        return NULL;
    }
    subj_field_name_entry = X509_NAME_get_entry(name, subj_field_name_index);
    subj_field_asn1 = X509_NAME_ENTRY_get_data(subj_field_name_entry);
#ifdef HAVE_OLD_OPENSSL
    return (char *)ASN1_STRING_data(subj_field_asn1);
#else
    return (char *)ASN1_STRING_get0_data(subj_field_asn1);
#endif
}
/*
 * This function will take the given cert and get the string corresponding
 * to subject field specified by the given NID. If the subject field was not
 * found, EST_AUTH_ECA_ERR will be returned and an error message will be printed
 * with the NID that wasn't found.
 */
static EST_HTTP_AUTH_HDR_RESULT
get_cert_subject_line_field (X509 *cert, int nid, char **ret_subj_field)
{
    char *subj_field;
    X509_NAME *subj_line_name;
    subj_line_name = X509_get_subject_name(cert);
    subj_field = find_subject_field_from_x509_name(subj_line_name, nid);
    if (subj_field == NULL) {
        EST_LOG_ERR("Could not retrieve subject line field %s (%d) from cert.",
                    OBJ_nid2sn(nid), nid);
        return EST_AUTH_ECA_ERR;
    }
    *ret_subj_field = subj_field;
    return EST_AUTH_HDR_GOOD;
}

/*
 * This function will take the given csr and get the string corresponding
 * to subject field specified by the given NID. If the subject field was not
 * found, EST_AUTH_ECA_ERR will be returned and an error message will be printed
 * with the NID that wasn't found.
 */
static EST_HTTP_AUTH_HDR_RESULT
get_csr_subject_line_field (X509_REQ *csr, int nid, char **ret_subj_field)
{
    char *subj_field;
    X509_NAME *subj_line_name;
    subj_line_name = X509_REQ_get_subject_name(csr);
    subj_field = find_subject_field_from_x509_name(subj_line_name, nid);
    if (subj_field == NULL) {
        EST_LOG_ERR("Could not retrieve subject line field %s (%d) from csr.",
                    OBJ_nid2sn(nid), nid);
        return EST_AUTH_ECA_ERR;
    }
    *ret_subj_field = subj_field;
    return EST_AUTH_HDR_GOOD;
}

/*
 * This function performs the subject field copy check in
 * the CSR. This check is used to ensure that the identifying
 * information for enhanced cert auth continues to be propagated
 * into the newly enrolled certificate.
 *
 * The procedure for this check follows this procedure:
 *  - Check if the peer cert is a manufacturer cert with
 *    the value of mfg_index
 *  If Manufacturer cert:
 *  - Grab the subject field for the manufacturer domain from the
 *    client's certificate
 *  - Compare subject field with the same field in the CSR
 *  - If it matches send an EST_HTTP_AUTH_HDR_RESULT of
 *    EST_AUTH_HDR_GOOD, else it will return EST_AUTH_ECA_CSR_CHECK_FAIL
 *  If local PKI cert:
 *  - iterate over all registered manufacturers:
 *      - Grab the subject field for the manufacturer domain from the
 *        client's certificate
 *      - Compare subject field with the same field in the CSR
 *      - If it matches send an EST_HTTP_AUTH_HDR_RESULT of
 *        EST_AUTH_HDR_GOOD, else continue to the next iteration.
 *  - If none of the manufacturer fields were copied from the local PKI domain
 *    cert to csr then EST_AUTH_ECA_CSR_CHECK_FAIL will be returned.
 *
 * SECURITY ISSUE: The Enhanced Cert Auth CSR Check can be bypassed if there are
 * two or more different manufacturer NIDs being used. In this scenario, it is
 * possible to masquerade as another device during a local PKI domain
 * enrollment. If there is only one unique manufacturer NID then it can be
 * ensured that identifying information from the manufacturer cert was copied
 * into the local PKI domain and will continue to be copied into all local PKI
 * domain CSRs during enrollment.
 *
 * Any invalid paramters or errors will result in a return of EST_AUTH_ECA_ERR
 *
 */
EST_HTTP_AUTH_HDR_RESULT perform_enhanced_cert_auth_csr_check (EST_CTX *ctx,
                                                               X509 *peer,
                                                               X509_REQ *csr,
                                                               int mfg_index)
{
    int subj_field_nid;
    char *cert_subj_field;
    char *csr_subj_field;
    int cert_subj_field_len;
    int csr_subj_field_len;
    int cmp_ind = 0;
    int i;
    ENCHD_CERT_MFG_INFO *cur_mfg_info;
    if (!ctx || !peer || !csr) {
        return EST_AUTH_ECA_ERR;
    }
    if (!ctx->enchd_cert_mfgs_info_list) {
        EST_LOG_INFO("No manufacturer info list created ");
        return EST_AUTH_ECA_CSR_CHECK_FAIL;
    }
    if (mfg_index >= 0) {
        /* Is a manufacturer domain cert */
        subj_field_nid = ctx->enchd_cert_mfgs_info_list[mfg_index].nid;
        if (get_cert_subject_line_field(
                peer, subj_field_nid, &cert_subj_field) != EST_AUTH_HDR_GOOD) {
            /* Error printing happens in search function */
            EST_LOG_INFO("ECA CSR Check: Failure. Cert missing field");
            return EST_AUTH_ECA_CSR_CHECK_FAIL;
        }
        /*
         * Compare against the local pki domain field to check that the
         * credentials are getting moved to the local PKI domain subject field
         */
        if (get_csr_subject_line_field(csr, subj_field_nid, &csr_subj_field) !=
            EST_AUTH_HDR_GOOD) {
            /* Error printing happens in search function */
            EST_LOG_INFO("ECA CSR Check: Failure. CSR missing field");
            return EST_AUTH_ECA_CSR_CHECK_FAIL;
        }
        cert_subj_field_len = strnlen_s(cert_subj_field, MAX_UIDPWD + 1);
        csr_subj_field_len = strnlen_s(csr_subj_field, MAX_UIDPWD + 1);
        if (cert_subj_field_len != csr_subj_field_len) {
            EST_LOG_INFO("ECA CSR Check: Failure. Length Mismatch");
            return EST_AUTH_ECA_CSR_CHECK_FAIL;
        }
        if (strcmp_s(cert_subj_field, cert_subj_field_len, csr_subj_field,
                     &cmp_ind) != EOK) {
            EST_LOG_ERR(
                "SafeC Error during comparison of cert and csr subj fields");
            return EST_AUTH_ECA_ERR;
        }
    } else {
        /* Is a local PKI domain cert */
        for (i = 0; i < NUM_SUPPORTED_MFG; i++) {
            cur_mfg_info = &(ctx->enchd_cert_mfgs_info_list[i]);
            if (cur_mfg_info->truststore && cur_mfg_info->store_ctx) {
                subj_field_nid = cur_mfg_info->nid;
                if (get_cert_subject_line_field(peer, subj_field_nid,
                                                &cert_subj_field) !=
                    EST_AUTH_HDR_GOOD) {
                    /* Error printing happens in search function */
                    EST_LOG_INFO("NID for manufacturer %s was not copied in "
                                 "CSR. Field not in cert",
                                 cur_mfg_info->name);
                    cmp_ind = 1;
                    continue;
                }
                /*
                 * Compare against the local pki domain field to check that the
                 * credentials are getting moved to the local PKI domain subject
                 * field
                 */
                if (get_csr_subject_line_field(csr, subj_field_nid,
                                               &csr_subj_field) !=
                    EST_AUTH_HDR_GOOD) {
                    /* Error printing happens in search function */
                    EST_LOG_INFO("NID for manufacturer %s was not copied in "
                                 "CSR. Field not in CSR",
                                 cur_mfg_info->name);
                    cmp_ind = 1;
                    continue;
                }
                cert_subj_field_len =
                    strnlen_s(cert_subj_field, MAX_UIDPWD + 1);
                csr_subj_field_len = strnlen_s(csr_subj_field, MAX_UIDPWD + 1);
                if (cert_subj_field_len != csr_subj_field_len) {
                    EST_LOG_INFO("NID for manufacturer %s was not copied in "
                                 "CSR. Length mismatch",
                                 cur_mfg_info->name);
                    cmp_ind = 1;
                    continue;
                }
                if (strcmp_s(cert_subj_field, cert_subj_field_len,
                             csr_subj_field, &cmp_ind) != EOK) {
                    EST_LOG_ERR("SafeC Error during comparison of cert and csr "
                                "subj fields");
                }
                if (!cmp_ind) {
                    break;
                }
            }
        }
    }
    
    EST_LOG_INFO("ECA CSR Check: %s.", cmp_ind ? "Failure" : "Success");
    /* If the two fields are the same then we pass the check  */
    return cmp_ind ? EST_AUTH_ECA_CSR_CHECK_FAIL : EST_AUTH_HDR_GOOD;
}

/*
 * This function builds an authentication header in the
 * Enhanced Cert Authentication format. It will fill in
 * the fields on the EST_HTTP_AUTH_HDR struct, which are
 * used later for verifying the user's credentials using
 * HTTP Basic authentication. The ah parameter should
 * already be allocated when calling this function.
 *
 * In this mode, the UserID field in the auth header
 * will be populated by the subject field from the peer
 * certificate specified by the nid parameter.
 *
 * The password field in the auth header will be set to
 * the enhanced cert auth password configured for this
 * EST context(default "cisco")
 *
 * Return either good, or ECA_ERR
 */
EST_HTTP_AUTH_HDR_RESULT build_enhanced_cert_auth_header (EST_CTX *ctx,
                                                          EST_HTTP_AUTH_HDR *ah,
                                                          X509 *peer, int nid)
{
    char *subj_field;
    if (!ah || !ctx || !peer) {
        return EST_AUTH_ECA_ERR;
    }
    ah->mode = AUTH_BASIC;
    if (get_cert_subject_line_field(peer, nid, &subj_field) !=
        EST_AUTH_HDR_GOOD) {
        return EST_AUTH_ECA_ERR;
    }
    ah->user = STRNDUP(subj_field, MAX_UIDPWD + 1);
    if (ah->user == NULL) {
        EST_LOG_ERR("Could not copy user for auth header.");
        return EST_AUTH_ECA_ERR;
    }
    ah->pwd = STRNDUP(ctx->enhcd_cert_auth_pwd, MAX_UIDPWD + 1);
    if (ah->pwd == NULL) {
        EST_LOG_ERR("Could not copy password for auth header.");
        return EST_AUTH_ECA_ERR;
    }
    return EST_AUTH_HDR_GOOD;
}

/*
 * This function will free the truststores within the manufacturer info list
 * Then it frees the manufacturer info list and sets the pointer for the list to
 * NULL in the specified EST context.
 */
void mfg_info_list_destroy (EST_CTX *ctx)
{
    int i;
    if (ctx->enchd_cert_mfgs_info_list) {
        for (i = 0; i < NUM_SUPPORTED_MFG; i++) {
            if (ctx->enchd_cert_mfgs_info_list[i].truststore) {
                X509_STORE_free(ctx->enchd_cert_mfgs_info_list[i].truststore);
            }
            if (ctx->enchd_cert_mfgs_info_list[i].store_ctx) {
                X509_STORE_CTX_free(
                    ctx->enchd_cert_mfgs_info_list[i].store_ctx);
            }
        }
        free(ctx->enchd_cert_mfgs_info_list);
        ctx->enchd_cert_mfgs_info_list = NULL;
    }
}