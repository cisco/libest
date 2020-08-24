/*
 * client.c
 *
 *  Created on: July 1, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014, 2015, 2016 by cisco Systems, Inc.
 * All rights reserved.
 *
 */
#include <stdio.h>
#include <stdint.h>
#include "jest.h"
#include <est/est.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include "safe_mem_lib.h"

#define EST_CLASS_ENROLL_EXCEPTION 			"com/cisco/c3m/est/EnrollException"
#define EST_CLASS_BUFSIZ_EXCEPTION 			"com/cisco/c3m/est/BufferSizeException"
#define EST_CLASS_CACERTS_EXCEPTION 		"com/cisco/c3m/est/CACertsException"
#define EST_CLASS_PKCS10_EXCEPTION 			"com/cisco/c3m/est/PKCS10CreationException"
#define EST_CLASS_RETRY_EXCEPTION			"com/cisco/c3m/est/EnrollRetryAfterException"
#define JAVA_CLASS_INVALID_KEY_EXCEPTION	"java/security/InvalidKeyException"
#define JAVA_CLASS_ILLEGAL_ARG_EXCEPTION	"java/lang/IllegalArgumentException"

#define CHECK_NULL_ARG(arg_name) \
		if (arg_name == NULL ) { \
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION, "NULL argument in JNI layer detected", 0, 0); \
			return (-1); \
		}

#define GET_JNI_BYTE_ARRAY_LEN(env, target, source, min_size, excpt_cls, excpt_msg, cleanup) \
	target = (*env)->GetArrayLength(env, source); \
	/* Check if minimum buffer size is required */ \
	if (target <= min_size) { \
		est_client_raise_exception(env, excpt_cls, excpt_msg, 0, 0); \
		goto cleanup; \
	}

#define GET_JNI_BYTE_ARRAY(env, target, source, excpt_cls, excpt_msg, cleanup) \
	target = (*env)->GetByteArrayElements(env, source, NULL ); \
	if (!target) { \
		est_client_raise_exception(env, excpt_cls, excpt_msg, 0, 0); \
		goto cleanup; \
	}

#define GET_JNI_STRING(env, target, source, excpt_cls, excpt_msg, cleanup) \
	target = (*env)->GetStringUTFChars(env, source, NULL ); \
	if (!target) { \
		est_client_raise_exception(env, excpt_cls, excpt_msg, 0, 0); \
		goto cleanup; \
	}

/*
 * 128KB should be enough as an upper limit on the maximum allowed
 * certificate length.
 */
#define MAX_CERT_LEN	128*1024
/*
 * This is the maximum length of the error string we return when
 * raising an exception.
 */
#define MAX_ERR_DESC	250

/*
 * This is the SRP strength to use when SRP is enabled
 */
#define SRP_BITS		1024

/*
 * This is the default signing algorithm to be used when
 * a new CSR is created and signed by the JNI code
 */
#define SIGNING_ALGORITHM EVP_sha256()

/*
 * This is a configurable value that limits how large of a certificate
 * can be generated.  The Java layer will read this value so it knows
 * how large of a byte array to allocate prior to invoking the JNI
 * methods.  We use 16K as a default, which should be sufficient for
 * most everyone.
 */
static int max_buffer_length = 16*1024;

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
	est_apps_startup();

	/*
	 * Set the default logging level to errors only
	 */
	est_init_logger(EST_LOG_LVL_ERR, NULL );
	return (JNI_VERSION_1_6);
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
	/*
	 * Do our best to avoid those nasty OpenSSL memory leaks
	 */
	est_apps_shutdown();
}

/*
 * This is a generic utility to raise an exception back to Java
 */
static void est_client_raise_exception(JNIEnv *env, char *class, char *desc,
		int err_code, int dump_ossl_errors) {
	jclass newExcCls;
	char error_desc[MAX_ERR_DESC];

	newExcCls = (*env)->FindClass(env, class);
	if (newExcCls == 0) {
		/* Unable to find the new exception class, give up. */
		fprintf(stderr, "\nUnable to find class %s\n", class);
	} else {
		snprintf(error_desc, MAX_ERR_DESC, "%s (code: %d [%s])", desc, err_code, EST_ERR_NUM_TO_STR(err_code));
		(*env)->ThrowNew(env, newExcCls, error_desc);
	}

	if (dump_ossl_errors) {
		ERR_print_errors_fp(stderr);
	}
}

/*
 * Sign an X509 certificate request using the digest and the key passed.
 * Returns OpenSSL error code from X509_REQ_sign_ctx();
 */
static int jni_est_client_X509_REQ_sign (X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
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

    EVP_MD_CTX_init(mctx);

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
    x->req_info->enc.modified = 1;
#endif

    rv = X509_REQ_sign_ctx(x, mctx);

#ifdef HAVE_OLD_OPENSSL
    EVP_MD_CTX_cleanup(mctx);
#else
    EVP_MD_CTX_free(mctx);
#endif

    return (rv);
}

/*
 * Attempts to put OpenSSL into FIPS mode.
 * Returns zero on success, -1 for failure.
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1fips(
		JNIEnv *env, jclass obj) {
	if (!FIPS_mode() && !FIPS_mode_set(1)) {
		ERR_print_errors_fp(stderr);
		return -1;
	} else {
		return 0;
	}
}

/*
 * Sets the libEST log level to 'errors'
 * Returns zero on success
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1errors(
		JNIEnv *env, jclass obj) {
	est_init_logger(EST_LOG_LVL_ERR, NULL );
	return 0;
}

/*
 * Sets the libEST log level to 'warnings'
 * Returns zero on success
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1warnings(
		JNIEnv *env, jclass obj) {
	est_init_logger(EST_LOG_LVL_WARN, NULL );
	return 0;
}

/*
 * Sets the libEST log level to 'info'
 * Returns zero on success
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1info(
		JNIEnv *env, jclass obj) {
	est_init_logger(EST_LOG_LVL_INFO, NULL );
	return 0;
}

/*
 * Gets the configured maximum allowed certificate length
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_get_1max_1cert_1length(
		JNIEnv *env, jclass obj) {
	return max_buffer_length;
}

/*
 * Sets the maximum allowed certificate length allowed
 *
 * Returns zero on success, -1 of failure
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_set_1max_1cert_1length(
		JNIEnv *env, jclass obj, jint new_max) {
	char desc[MAX_ERR_DESC];

	if (new_max > MAX_CERT_LEN || new_max < 0) {
		/*
		 * Raise an exception since the user is trying to set it to an
		 * invalid value.
		 */
		snprintf(desc, MAX_ERR_DESC,
				"Attempt to set new maximum certificate length to an invalid value (%d).  Max allowed is %d.",
				new_max, MAX_CERT_LEN);
		est_client_raise_exception(env, JAVA_CLASS_ILLEGAL_ARG_EXCEPTION,
				desc, 0, 0);
		return -1;
	}
	max_buffer_length = new_max;
	return 0;
}

/*
 * This function will create a new PKCS10 CSR and return it to Java.
 *
 * Returns negative value on failure, otherwise it returns the size of the
 * CSR in bytes.
 *
 * Parameters:
 * 		keypair:  Byte array containing PEM encoded keypair
 * 		subj_name_cn: String containing Common Name to put into the CSR subject name
 * 		subj_name_country: String containing Country Name to put into the CSR subject name
 * 		subj_name_locality: String containing City/Locality to put into the CSR subject name
 * 		subj_name_province: String containing State/Province to put into the CSR subject name
 * 		subj_name_org: String containing Organization Name to put into the CSR subject name
 * 		subj_name_orgunit: String containing Organizational Unit to put into the CSR subject name
 * 		new_csr: Byte array that will receive the newly created CSR
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_PKCS10CertificateRequest_create_1csr(
		JNIEnv *env, jclass obj, jbyteArray keypair, jstring subj_name_cn,
		jstring subj_name_country, jstring subj_name_locality,
		jstring subj_name_province, jstring subj_name_org,
		jstring subj_name_orgunit, jbyteArray new_csr) {
	jbyte *l_new_csr = NULL;
	jbyte *l_keypair = NULL;
	const char *l_subj_name_cn = NULL;
	const char *l_subj_name_country = NULL;
	const char *l_subj_name_locality = NULL;
	const char *l_subj_name_province = NULL;
	const char *l_subj_name_org = NULL;
	const char *l_subj_name_orgunit = NULL;
	X509_REQ *req = NULL;
	X509_NAME *subj = NULL;
	EVP_PKEY *l_pub_key = NULL;
	BIO *out = NULL;
	BUF_MEM *bptr = NULL;
	uint32_t kp_len, new_csr_len;
	int rc;
	int rv = -1;

	GET_JNI_BYTE_ARRAY_LEN(env, kp_len, keypair, 0, JAVA_CLASS_INVALID_KEY_EXCEPTION, "Invalid keypair length", cleanup_req);
	GET_JNI_BYTE_ARRAY(env, l_keypair, keypair, JAVA_CLASS_INVALID_KEY_EXCEPTION, "Null keypair", cleanup_req);

	GET_JNI_BYTE_ARRAY_LEN(env, new_csr_len, new_csr, max_buffer_length-1, EST_CLASS_PKCS10_EXCEPTION, "Invalid length of new_csr buffer", cleanup_req);
	GET_JNI_BYTE_ARRAY(env, l_new_csr, new_csr, EST_CLASS_PKCS10_EXCEPTION, "Null CSR", cleanup_req);

	/*
	 * Get the Subject Name values from JNI
	 */
	GET_JNI_STRING(env, l_subj_name_cn, subj_name_cn, EST_CLASS_PKCS10_EXCEPTION, "NULL Common name", cleanup_req);
	GET_JNI_STRING(env, l_subj_name_country, subj_name_country, EST_CLASS_PKCS10_EXCEPTION, "NULL Country name", cleanup_req);
	GET_JNI_STRING(env, l_subj_name_locality, subj_name_locality, EST_CLASS_PKCS10_EXCEPTION, "NULL Locality name", cleanup_req);
	GET_JNI_STRING(env, l_subj_name_province, subj_name_province, EST_CLASS_PKCS10_EXCEPTION, "NULL Province name", cleanup_req);
	GET_JNI_STRING(env, l_subj_name_org, subj_name_org, EST_CLASS_PKCS10_EXCEPTION, "NULL Organization name", cleanup_req);
	GET_JNI_STRING(env, l_subj_name_orgunit, subj_name_orgunit, EST_CLASS_PKCS10_EXCEPTION, "NULL Organization Unit name", cleanup_req);

	/*
	 * Convert the DER provided key to an EVP_PKEY
	 */
	l_pub_key = est_load_key((unsigned char*) l_keypair, kp_len,
			EST_FORMAT_DER);
	if (l_pub_key == NULL ) {
		est_client_raise_exception(env, JAVA_CLASS_INVALID_KEY_EXCEPTION,
				"Unable to load keypair into OpenSSL EVP_PKEY", 0, 0);
		goto cleanup_req;
	}

	/*
	 * Build the CSR using the subject name and key given to us
	 */
	req = X509_REQ_new();
	if (req == NULL ) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to allocate OpenSSL X509_REQ", 0, 1);
		goto cleanup_req;
	}

	/*
	 * Set the X509 version number
	 */
	if (!X509_REQ_set_version(req, 0L)) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to set X509 version", 0, 1);
		goto cleanup_req;
	}

	/*
	 *  Get reference to subject name entry so we can populate it
	 */
	subj = X509_REQ_get_subject_name(req);
	if (!subj) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to get subject name context from CSR", 0, 1);
		goto cleanup_req;
	}

	/*
	 * Add Common Name entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC,
			(unsigned char*) l_subj_name_cn, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 commonName", 0, 1);
		goto cleanup_req;
	}
	/*
	 * Add Country entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_countryName, MBSTRING_ASC,
			(unsigned char*) l_subj_name_country, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 countryName", 0, 1);
		goto cleanup_req;
	}
	/*
	 * Add Locality entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_localityName, MBSTRING_ASC,
			(unsigned char*) l_subj_name_locality, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 localityName", 0, 1);
		goto cleanup_req;
	}
	/*
	 * Add Province/State name entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_stateOrProvinceName, MBSTRING_ASC,
			(unsigned char*) l_subj_name_province, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 stateOrProvinceName", 0, 1);
		goto cleanup_req;
	}
	/*
	 * Add Organization name entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_organizationName, MBSTRING_ASC,
			(unsigned char*) l_subj_name_org, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 organizationName", 0, 1);
		goto cleanup_req;
	}
	/*
	 * Add Organization Unit name entry
	 */
	rc = X509_NAME_add_entry_by_NID(subj, NID_organizationalUnitName,
			MBSTRING_ASC, (unsigned char*) l_subj_name_orgunit, -1, -1, 0);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add X509 organizationalUnit", 0, 1);
		goto cleanup_req;
	}

	/*
	 * Set the public key on the request
	 */
	if (!X509_REQ_set_pubkey(req, l_pub_key)) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to add public key to CSR", 0, 1);
		goto cleanup_req;
	}

        /*
         * Sign the CSR
         */
        if(!jni_est_client_X509_REQ_sign(req,l_pub_key,SIGNING_ALGORITHM)) {
        	est_client_raise_exception(env, EST_CLASS_PKCS10_EXCEPTION,
                	"Unable to sign the CSR", 0, 1);
        	goto cleanup_req;
	}

	/*
	 * Serialize the CSR using DER encoding, we use an OpenSSL memory
	 * BIO to achieve this.
	 */
	out = BIO_new(BIO_s_mem());
	if (!out) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to allocate BIO", 0, 1);
		goto cleanup_req;
	}
	rc = i2d_X509_REQ_bio(out, req);
	if (!rc) {
		est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,
				"Unable to encode CSR", 0, 1);
		goto cleanup_req;
	}
	(void)BIO_flush(out);
	BIO_get_mem_ptr(out, &bptr);
	if (bptr->length > 0 && bptr->length < max_buffer_length) {
		memcpy_s(l_new_csr, max_buffer_length, bptr->data, bptr->length);
		rv = bptr->length;
	} else {
		if (bptr->length >= max_buffer_length) {
			est_client_raise_exception(env,	EST_CLASS_BUFSIZ_EXCEPTION,	"Invalid CSR buffer length", 0, 0);
		} else {
			est_client_raise_exception(env,	EST_CLASS_PKCS10_EXCEPTION,	"Invalid bptr length", 0, 1);
		}
		goto cleanup_req;
	}

cleanup_req:
	if (out) {
		BIO_free_all(out);
		out = NULL;
	}
	if (req) {
		X509_REQ_free(req);
		req = NULL;
	}
	if (l_pub_key) {
		EVP_PKEY_free(l_pub_key);
		l_pub_key = NULL;
	}

	if (l_subj_name_cn) (*env)->ReleaseStringUTFChars(env, subj_name_cn, l_subj_name_cn);
	if (l_subj_name_country) (*env)->ReleaseStringUTFChars(env, subj_name_country, l_subj_name_country);
	if (l_subj_name_locality) (*env)->ReleaseStringUTFChars(env, subj_name_locality, l_subj_name_locality);
	if (l_subj_name_province) (*env)->ReleaseStringUTFChars(env, subj_name_province, l_subj_name_province);
	if (l_subj_name_org) (*env)->ReleaseStringUTFChars(env, subj_name_org, l_subj_name_org);
	if (l_subj_name_orgunit) (*env)->ReleaseStringUTFChars(env, subj_name_orgunit, l_subj_name_orgunit);
	if (l_keypair) (*env)->ReleaseByteArrayElements(env, keypair, l_keypair, JNI_COMMIT);
	if (l_new_csr) (*env)->ReleaseByteArrayElements(env, new_csr, l_new_csr, JNI_COMMIT);
	return (rv);
}

/*
 * Common routine to enroll a PKCS10 with or without SRP enabled.  This is also used to reenroll
 * an existing X509 certificate.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR.  Should be DER encoded.
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		auth_cert: Existing certificate the client will use to identify itself to the EST server.
 * 		           This argument may be NULL if TLS client auth is not needed.  Should be DER encoded, which
 * 		           is easier to export from Java.
 * 		auth_key: The private key associated with auth_cert.  Should be DER encoded.  We use DER
 * 		          since it's easier to export DER at the Java layer.
 * 		http_user: String containing the HTTP user name to use for the enroll operation
 * 		http_pwd: String containing the HTTP password to use for the enroll operation
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		csr_or_oldcert: Byte array containing either the PEM encoded PKCS10 CSR to use for the enroll operation
 * 		                or the DER encoded X509 certificate to use for the reenroll operation
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 * 		srp_enabled: Use non-zero value to enable SRP auth.
 * 		srp_user: SRP user name to use when srp_enabled is toggled on.
 * 		srp_pwd: SRP password associated with SRP user.
 * 		reenroll: Set to non-zero value to perform a reenroll, otherwise a new enroll is done.
 *
 * 	Return value: Returns -1 on error or the length of the new cert on success
 */
static jint send_enroll_request (
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port,
		jbyteArray auth_cert, jbyteArray auth_key,
		jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray csr_or_oldcert, jbyteArray new_cert,
		jint srp_enabled, jstring srp_user, jstring srp_pwd, jint reenroll) {
	jbyte *l_trust_certs = NULL;
	jbyte *l_keypair = NULL;
	jbyte *l_auth_key = NULL;
	jbyte *l_auth_cert = NULL;
	jbyte *l_csr = NULL;
	jbyte *l_old_cert = NULL;
	jbyte *l_new_cert = NULL;
	const char *l_http_user = NULL;
	const char *l_http_pwd = NULL;
	const char *l_srp_user = NULL;
	const char *l_srp_pwd = NULL;
	const char *l_server_name = NULL;
	uint32_t ta_len;
	uint32_t kp_len, akp_len;
	uint32_t csr_len = 0, old_cert_len = 0, tls_cert_len;
	uint32_t nc_len;
	EST_CTX *ectx = NULL;
	EST_ERROR rv;
	X509_REQ *req = NULL;
	BIO *in = NULL;
	EVP_PKEY *l_priv_key = NULL;
	EVP_PKEY *tls_key = NULL;
	X509 *tls_cert = NULL;
	X509 *old_cert = NULL;
	int pkcs7_len, new_cert_len;
	uint8_t *new_client_cert = NULL;
	uint8_t *new_cert_pem = NULL;
	int ret_val = -1;

	/*
	 * Get the buffer that will hold the new certificate
	 */
	GET_JNI_BYTE_ARRAY_LEN(env, nc_len, new_cert, max_buffer_length-1, EST_CLASS_ENROLL_EXCEPTION, "Invalid length of new_cert buffer, not large enough", cleanup_enroll);
	GET_JNI_BYTE_ARRAY(env, l_new_cert, new_cert, EST_CLASS_ENROLL_EXCEPTION, "No memory to receive new cert, new_cert is NULL", cleanup_enroll);

	/*
	 * Get the trust anchor certs
	 */
	GET_JNI_BYTE_ARRAY_LEN(env, ta_len, trust_certs, 0, EST_CLASS_ENROLL_EXCEPTION, "Invalid length for trust anchor certs", cleanup_enroll);
	GET_JNI_BYTE_ARRAY(env, l_trust_certs, trust_certs, EST_CLASS_ENROLL_EXCEPTION, "NULL trust anchor certs", cleanup_enroll);
	/*
	 * Ensure the array is null terminated.
	 * Reduce ta_len by one to omit null terminator
	 */
	l_trust_certs[ta_len-1] = 0;
	ta_len--;

	/*
	 * Get the private key that will be used to sign the CSR
	 */
	GET_JNI_BYTE_ARRAY_LEN(env, kp_len, keypair, 0, JAVA_CLASS_INVALID_KEY_EXCEPTION, "Invalid keypair length", cleanup_enroll);
	GET_JNI_BYTE_ARRAY(env, l_keypair, keypair, JAVA_CLASS_INVALID_KEY_EXCEPTION, "NULL keypair", cleanup_enroll);

	/*
	 * Check if we'll be using a certificate to identify the EST client
	 */
	if (auth_cert && auth_key) {
		GET_JNI_BYTE_ARRAY_LEN(env, tls_cert_len, auth_cert, 0, EST_CLASS_ENROLL_EXCEPTION, "Invalid TLS client auth certificate length", cleanup_enroll);
		GET_JNI_BYTE_ARRAY(env, l_auth_cert, auth_cert, EST_CLASS_ENROLL_EXCEPTION, "NULL TLS auth certificate, auth_cert is NULL", cleanup_enroll);
		/*
		 * Convert the cert to an X509 object
		 */
		in = BIO_new_mem_buf(l_auth_cert, tls_cert_len);
		if (in == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
					"Unable to allocate BIO", 0, 1);
			goto cleanup_enroll;
		}
		tls_cert = d2i_X509_bio(in, NULL );
		BIO_free_all(in);
		if (tls_cert == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
					"Unable to decode TLS client cert", 0, 1);
			goto cleanup_enroll;
		}

		/*
		 * Load the key associated with the auth cert
		 */
		GET_JNI_BYTE_ARRAY_LEN(env, akp_len, auth_key, 0, JAVA_CLASS_INVALID_KEY_EXCEPTION, "Invalid TLS auth private key length", cleanup_enroll);
		GET_JNI_BYTE_ARRAY(env, l_auth_key, auth_key, JAVA_CLASS_INVALID_KEY_EXCEPTION, "NULL TLS auth private key", cleanup_enroll);
		tls_key = est_load_key((unsigned char*) l_auth_key, akp_len, EST_FORMAT_DER);
		if (tls_key == NULL ) {
			est_client_raise_exception(env, JAVA_CLASS_INVALID_KEY_EXCEPTION,
					"Unable to load TLS auth private key into OpenSSL EVP_PKEY", 0, 0);
			goto cleanup_enroll;
		}
	}

	if (reenroll) {
		/*
		 * Get the old certificate that is about to be renewed
		 */
		GET_JNI_BYTE_ARRAY_LEN(env, old_cert_len, csr_or_oldcert, 0, EST_CLASS_ENROLL_EXCEPTION, "Invalid CSR length", cleanup_enroll);
		GET_JNI_BYTE_ARRAY(env, l_old_cert, csr_or_oldcert, EST_CLASS_ENROLL_EXCEPTION, "NULL CSR", cleanup_enroll);
	} else {
		/*
		 * Get the PKCS10 CSR that will be sent to the EST server
		 */
		GET_JNI_BYTE_ARRAY_LEN(env, csr_len, csr_or_oldcert, 0, EST_CLASS_ENROLL_EXCEPTION, "Invalid CSR length", cleanup_enroll);
		GET_JNI_BYTE_ARRAY(env, l_csr, csr_or_oldcert, EST_CLASS_ENROLL_EXCEPTION, "NULL CSR", cleanup_enroll);
	}

	/*
	 * Get the HTTP user name if it's been provided
	 */
	if (http_user) {
		GET_JNI_STRING(env, l_http_user, http_user, EST_CLASS_ENROLL_EXCEPTION, "NULL HTTP user name", cleanup_enroll);
	}

	/*
	 * Get the HTTP password if it's been provided
	 */
	if (http_pwd) {
		GET_JNI_STRING(env, l_http_pwd, http_pwd, EST_CLASS_ENROLL_EXCEPTION, "NULL HTTP password", cleanup_enroll);
	}

	/*
	 * Get the EST server name
	 */
	GET_JNI_STRING(env, l_server_name, server_name, EST_CLASS_ENROLL_EXCEPTION, "NULL EST server name", cleanup_enroll);

	if (reenroll) {
		/*
		 * Read in the old X509 certificate that will be renewed
		 */
		in = BIO_new_mem_buf(l_old_cert, old_cert_len);
		if (in == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"Unable to allocate BIO", 0, 1);
			goto cleanup_enroll;
		}
		old_cert = d2i_X509_bio(in, NULL );
		BIO_free_all(in);
		in = NULL;
		if (old_cert == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
					"Unable to decode old cert prior to reenroll", 0, 1);
			goto cleanup_enroll;
		}
	} else {
		/*
		 * Read in the PKCS10 CSR that was given to us
		 */
		in = BIO_new_mem_buf(l_csr, csr_len);
		if (in == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"Unable to allocate BIO", 0, 1);
			goto cleanup_enroll;
		}
		req = d2i_X509_REQ_bio(in, NULL );
		BIO_free_all(in);
		if (req == NULL ) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"Unable to decode CSR", 0, 1);
			goto cleanup_enroll;
		}
#if 0
		X509_REQ_print_fp(stderr, req);
#endif
	}

	/*
	 * Convert the DER provided key to an EVP_PKEY
	 */
	l_priv_key = est_load_key((unsigned char*) l_keypair, kp_len,
			EST_FORMAT_DER);
	if (l_priv_key == NULL ) {
		est_client_raise_exception(env, JAVA_CLASS_INVALID_KEY_EXCEPTION,
				"Unable to load keypair into OpenSSL EVP_PKEY", 0, 0);
		goto cleanup_enroll;
	}

	/*
	 * Initialize EST context and configure the server/auth knobs
	 */
	if (ta_len <= 0 && srp_enabled) {
		/*
		 * We're doing SRP w/o a trust anchor.  Need to pass in NULL
		 * for the trusted certs.
		 */
		ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL );
	} else {
		ectx = est_client_init((unsigned char*) l_trust_certs, ta_len, EST_CERT_FORMAT_PEM, NULL );
	}
	if (!ectx) {
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"est_client_init failed", 0, 0);
		goto cleanup_enroll;
	}

	/*
	 * Specify the authentication credentials.  The tls_cert/key may be NULL
	 * when TLS auth isn't enabled from the layer above us.  Same goes
	 * for HTTP auth.
	 */
	rv = est_client_set_auth(ectx, l_http_user, l_http_pwd, tls_cert, tls_key );
	if (rv != EST_ERR_NONE) {
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"est_client_set_auth failed", rv, 0);
		goto cleanup_enroll;
	}

	/*
	 * Check if SRP is enabled, if so, setup the SRP credentials
	 */
    if (srp_enabled) {
    	GET_JNI_STRING(env, l_srp_user, srp_user, EST_CLASS_ENROLL_EXCEPTION, "NULL SRP user name", cleanup_enroll);
    	GET_JNI_STRING(env, l_srp_pwd, srp_pwd, EST_CLASS_ENROLL_EXCEPTION, "NULL SRP password", cleanup_enroll);
    	rv = est_client_enable_srp(ectx, SRP_BITS, (char*)l_srp_user, (char*)l_srp_pwd);
    	if (rv != EST_ERR_NONE) {
    		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
    				"est_client_enable_srp failed", rv, 0);
    		goto cleanup_enroll;
    	}
    }

    rv = est_client_set_server(ectx, l_server_name, port, NULL);
	if (rv != EST_ERR_NONE) {
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"est_client_set_server failed", rv, 0);
		goto cleanup_enroll;
	}

	/*
	 * We enable PoP by default, but will disable it if the user desires
	 */
	if (!disable_pop) {
		rv = est_client_force_pop(ectx);
		if (rv != EST_ERR_NONE) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
					"est_client_force_pop failed", rv, 0);
			goto cleanup_enroll;
		}
	}

	if (reenroll) {
		/*
	     * ReEnroll the old X509 cert with the EST server
	     */
		rv = est_client_reenroll(ectx, old_cert, &pkcs7_len, l_priv_key);
	} else {
		/*
	     * Enroll the CSR with the EST server
	     */
		rv = est_client_enroll_csr(ectx, req, &pkcs7_len, l_priv_key);
	}
	switch (rv) {
	case EST_ERR_CA_ENROLL_RETRY:
		est_client_raise_exception(env, EST_CLASS_RETRY_EXCEPTION,
				"est_client_enroll_csr failed", rv, 0);
		goto cleanup_enroll;
		break;
	case EST_ERR_NONE:
		/* do nothing */
		break;
	default:
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"est_client_enroll_csr failed", rv, 0);
		goto cleanup_enroll;
		break;
	}

	new_client_cert = malloc(pkcs7_len);
	if (new_client_cert == NULL ) {
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"malloc failed", 0, 0);
		goto cleanup_enroll;
	}

	/*
	 * Get a copy of the cert we just enrolled
	 */
	rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
	if (rv != EST_ERR_NONE) {
		est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,
				"est_client_copy_enrolled_cert failed", rv, 0);
		goto cleanup_enroll;
	}

	/*
	 * The certs are base64 DER encoded.  We need to convert them to PEM.
	 * We don't copy directly to l_new_cert here because we still don't know
	 * for certain the new cert isn't too large.
	 */
	new_cert_len = est_convert_p7b64_to_pem(new_client_cert, pkcs7_len,
			&new_cert_pem);

	if (new_cert_len > 0 && new_cert_len < max_buffer_length) {
		memcpy_s(l_new_cert, max_buffer_length, new_cert_pem, new_cert_len);
		ret_val = new_cert_len;
	} else {
		if (new_cert_len >= max_buffer_length) {
			est_client_raise_exception(env, EST_CLASS_BUFSIZ_EXCEPTION,	"Certificate too large to fit in buffer", new_cert_len, 0);
		} else {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION,	"Invalid certificate length", new_cert_len, 1);
		}
		goto cleanup_enroll;
	}

cleanup_enroll:
	if (new_cert_pem) {
		free(new_cert_pem);
		new_cert_pem = NULL;
	}
	if (new_client_cert) {
		free(new_client_cert);
		new_client_cert = NULL;
	}
	if (req) {
		X509_REQ_free(req);
		req = NULL;
	}
	if (ectx) {
		est_destroy(ectx);
		ectx = NULL;
	}
	if (l_priv_key) {
		EVP_PKEY_free(l_priv_key);
		l_priv_key = NULL;
	}
	if (old_cert) {
		X509_free(old_cert);
		old_cert = NULL;
	}
	if (tls_cert) {
		X509_free(tls_cert);
		tls_cert = NULL;
	}
	if (tls_key) {
		EVP_PKEY_free(tls_key);
		tls_key = NULL;
	}

	//Free the JNI resources
	if (l_http_user) (*env)->ReleaseStringUTFChars(env, http_user, l_http_user);
	if (l_http_pwd) (*env)->ReleaseStringUTFChars(env, http_pwd, l_http_pwd);
	if (l_srp_user) (*env)->ReleaseStringUTFChars(env, srp_user, l_srp_user);
	if (l_srp_pwd) (*env)->ReleaseStringUTFChars(env, srp_pwd, l_srp_pwd);
	if (l_server_name) (*env)->ReleaseStringUTFChars(env, server_name, l_server_name);
	if (l_trust_certs) (*env)->ReleaseByteArrayElements(env, trust_certs, l_trust_certs, JNI_COMMIT);
	if (l_keypair) (*env)->ReleaseByteArrayElements(env, keypair, l_keypair, JNI_COMMIT);
	if (l_csr && !reenroll) (*env)->ReleaseByteArrayElements(env, csr_or_oldcert, l_csr, JNI_COMMIT);
	if (l_old_cert && reenroll) (*env)->ReleaseByteArrayElements(env, csr_or_oldcert, l_old_cert, JNI_COMMIT);
	if (l_new_cert) (*env)->ReleaseByteArrayElements(env, new_cert, l_new_cert, JNI_COMMIT);
	if (auth_cert && l_auth_cert) {
		(*env)->ReleaseByteArrayElements(env, auth_cert, l_auth_cert, JNI_COMMIT);
	}
	if (auth_key && l_auth_key) {
		(*env)->ReleaseByteArrayElements(env, auth_key, l_auth_key, JNI_COMMIT);
	}

	return (ret_val);
}

/*
 * Takes as input a PKCS10 cert request and uses EST to enroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		http_user: String containing the HTTP user name to use for the enroll operation
 * 		http_pwd: String containing the HTTP password to use for the enroll operation
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		csr: Byte array containing PEM encoded PKCS10 CSR to use for the enroll operation
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1http_1auth_1enroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port, jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray csr, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(http_user);
	CHECK_NULL_ARG(http_pwd);
	CHECK_NULL_ARG(csr);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			NULL, NULL,
			http_user, http_pwd,
			disable_pop, csr, new_cert,
			0, NULL, NULL, 0);
}

/*
 * Takes as input a PKCS10 cert request and uses EST to enroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		srp_user: String containing the SRP user name to use for the enroll operation
 * 		srp_pwd: String containing the SRP password to use for the enroll operation
 * 		http_user: String containing the HTTP user name to use for the enroll operation (optional)
 * 		http_pwd: String containing the HTTP password to use for the enroll operation (optional)
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		csr: Byte array containing PEM encoded PKCS10 CSR to use for the enroll operation
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1srp_1auth_1enroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port,
		jstring srp_user, jstring srp_pwd,
		jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray csr, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(srp_user);
	CHECK_NULL_ARG(srp_pwd);
	CHECK_NULL_ARG(csr);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			NULL, NULL,
			http_user, http_pwd,
			disable_pop, csr, new_cert,
			1, srp_user, srp_pwd, 0);
}


/*
 * Takes as input a PKCS10 cert request and uses EST to enroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		auth_cert: X509 certificate used to identify the EST client
 * 		auth_key: The private key associated with auth_cert
 * 		http_user: String containing the HTTP user name to use for the enroll operation (optional)
 * 		http_pwd: String containing the HTTP password to use for the enroll operation (optional)
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		csr: Byte array containing PEM encoded PKCS10 CSR to use for the enroll operation
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1tls_1auth_1enroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port,
		jbyteArray auth_cert, jbyteArray auth_key,
		jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray csr, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(auth_cert);
	CHECK_NULL_ARG(auth_key);
	CHECK_NULL_ARG(csr);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			auth_cert, auth_key,
			http_user, http_pwd,
			disable_pop, csr, new_cert,
			0, NULL, NULL, 0);
}

/*
 * Takes as input an existing X509 cert and uses EST to reenroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		http_user: String containing the HTTP user name to use for the reenroll operation
 * 		http_pwd: String containing the HTTP password to use for the reenroll operation
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		old_cert: Byte array containing DER encoded certificate to be renewed
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1http_1auth_1reenroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port, jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray old_cert, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(http_user);
	CHECK_NULL_ARG(http_pwd);
	CHECK_NULL_ARG(old_cert);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			NULL, NULL,
			http_user, http_pwd,
			disable_pop, old_cert, new_cert,
			0, NULL, NULL, 1);
}

/*
 * Takes as input an existing X509 cert and uses EST to reenroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		srp_user: String containing the SRP user name to use for the reenroll operation
 * 		srp_pwd: String containing the SRP password to use for the reenroll operation
 * 		http_user: String containing the HTTP user name to use for the reenroll operation (optional)
 * 		http_pwd: String containing the HTTP password to use for the reenroll operation (optional)
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		old_cert: Byte array containing DER encoded certificate to be renewed
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1srp_1auth_1reenroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port,
		jstring srp_user, jstring srp_pwd,
		jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray old_cert, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(srp_user);
	CHECK_NULL_ARG(srp_pwd);
	CHECK_NULL_ARG(old_cert);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			NULL, NULL,
			http_user, http_pwd,
			disable_pop, old_cert, new_cert,
			1, srp_user, srp_pwd, 1);
}


/*
 * Takes as input an existing X509 cert and uses EST to reenroll the cert.
 * Returns the size of the X509 certificate, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		keypair: Byte array containing the PEM encoded keypair used to sign the CSR
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: Integer containing the TCP port number used by the EST server
 * 		auth_cert: X509 certificate used to identify the EST client
 * 		auth_key: The private key associated with auth_cert
 * 		http_user: String containing the HTTP user name to use for the reenroll operation (optional)
 * 		http_pwd: String containing the HTTP password to use for the reenroll operation (optional)
 * 		disable_pop: Integer value used to indicate if PoP should be disabled
 * 		old_cert: Byte array containing DER encoded certificate to be renewed
 * 		new_cert: Byte array that will receive the newly generated certificate in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1tls_1auth_1reenroll_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs, jbyteArray keypair,
		jstring server_name, jint port,
		jbyteArray auth_cert, jbyteArray auth_key,
		jstring http_user, jstring http_pwd,
		jint disable_pop, jbyteArray old_cert, jbyteArray new_cert) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(keypair);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(auth_cert);
	CHECK_NULL_ARG(auth_key);
	CHECK_NULL_ARG(old_cert);
	CHECK_NULL_ARG(new_cert);

	return send_enroll_request(
			env, obj, trust_certs, keypair,
			server_name, port,
			auth_cert, auth_key,
			http_user, http_pwd,
			disable_pop, old_cert, new_cert,
			0, NULL, NULL, 1);
}

/*
 * Uses libest to send a /cacerts request to the EST server.  Converts response
 * from server to PEM encoded byte array and returns this to Java using the new_certs
 * buffer.
 *
 * Returns the size of the PEM encoded certs buffer, or -1 if an error occurred.
 *
 * Parameters:
 * 		trust_certs: Byte array containing PEM encoded certs to use as the trust anchor for the EST operation
 * 		server_name: String containing the name of the EST server the client will use
 * 		port: int containing the TCP port number used by the EST server
 * 		srp_user: String containing the SRP user name to use for the EST operation
 * 		srp_pwd: String containing the SRP password to use for the EST operation
 * 		new_certs: Byte array that will receive the CA certificates in PEM format
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1cacerts_1request(
		JNIEnv *env, jclass obj, jbyteArray trust_certs,
		jstring server_name, jint port,
		jstring srp_user, jstring srp_pwd,
		jbyteArray new_certs) {
	CHECK_NULL_ARG(trust_certs);
	CHECK_NULL_ARG(server_name);
	CHECK_NULL_ARG(new_certs);

	jbyte *l_trust_certs = NULL;
	jbyte *l_new_certs = NULL;
	const char *l_srp_user = NULL;
	const char *l_srp_pwd = NULL;
	const char *l_server_name = NULL;
	uint32_t ta_len;
	uint32_t nc_len;
	EST_CTX *ectx = NULL;
	EST_ERROR rv;
	int pkcs7_len, ca_certs_len;
	uint8_t *new_ca_certs = NULL;
	uint8_t *new_certs_pem = NULL;
	int ret_val = -1;
	int srp_enabled = 0;

	/*
	 * Get the buffer that will hold the new certificate
	 */
	GET_JNI_BYTE_ARRAY_LEN(env, nc_len, new_certs, max_buffer_length-1, EST_CLASS_CACERTS_EXCEPTION, "Invalid length of new_certs buffer, not large enough", cleanup_cacerts);
	GET_JNI_BYTE_ARRAY(env, l_new_certs, new_certs, EST_CLASS_CACERTS_EXCEPTION, "No memory to receive new certs, new_certs is NULL", cleanup_cacerts);

	/*
	 * Check to see if SRP credentials were provided
	 */
	if (srp_user && srp_pwd) {
		l_srp_user = (*env)->GetStringUTFChars(env, srp_user, NULL );
		l_srp_pwd = (*env)->GetStringUTFChars(env, srp_pwd, NULL );
	}
	if (l_srp_user && l_srp_pwd) {
		srp_enabled = 1;
	}

	/*
	 * Get the trust anchor certs
	 */
	GET_JNI_BYTE_ARRAY_LEN(env, ta_len, trust_certs, 0, EST_CLASS_CACERTS_EXCEPTION, "Invalid length for trust anchor certs", cleanup_cacerts);
	GET_JNI_BYTE_ARRAY(env, l_trust_certs, trust_certs, EST_CLASS_CACERTS_EXCEPTION, "NULL trust anchor certs", cleanup_cacerts);
	if (ta_len <= 1 && !srp_enabled) {
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "Trust anchor may not be null unless SRP is enabled", 0, 0);
		goto cleanup_cacerts;
	}
	/*
	 * Ensure the array is null terminated.
	 * Reduce ta_len by one to omit null terminator
	 */
	l_trust_certs[ta_len-1] = 0;
	ta_len--;

	/*
	 * Get the EST server name
	 */
	GET_JNI_STRING(env, l_server_name, server_name, EST_CLASS_CACERTS_EXCEPTION, "NULL EST server name", cleanup_cacerts);

	/*
	 * Initialize EST context and configure the server/auth knobs
	 */
	if (ta_len <= 0) {
		ectx = est_client_init(NULL, 0, EST_CERT_FORMAT_PEM, NULL);
	} else {
		ectx = est_client_init((unsigned char*) l_trust_certs, ta_len, EST_CERT_FORMAT_PEM, NULL);
	}
	if (!ectx) {
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "est_client_init failed", 0, 0);
		goto cleanup_cacerts;
	}

	rv = est_client_set_server(ectx, l_server_name, port, NULL);
	if (rv != EST_ERR_NONE) {
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "est_client_set_server failed", rv, 0);
		goto cleanup_cacerts;
	}

	if (srp_enabled) {
		rv = est_client_enable_srp(ectx, SRP_BITS, (char*)l_srp_user, (char*)l_srp_pwd);
		if (rv != EST_ERR_NONE) {
			est_client_raise_exception(env, EST_CLASS_ENROLL_EXCEPTION, "est_client_enable_srp failed", rv, 0);
			goto cleanup_cacerts;
		}
	}

	/*
	 * Issue the libest command to retrieve the latest trust anchor certs
	 */
	rv = est_client_get_cacerts(ectx, &pkcs7_len);
	switch (rv) {
	case EST_ERR_NONE:
		/* do nothing */
		break;
	default:
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "est_client_get_cacerts failed", rv, 0);
		goto cleanup_cacerts;
		break;
	}

	new_ca_certs = malloc(pkcs7_len);
	if (new_ca_certs == NULL ) {
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "malloc failed", 0, 0);
		goto cleanup_cacerts;
	}

	/*
	 * Get a copy of the certs we just retrieved
	 */
	rv = est_client_copy_cacerts(ectx, new_ca_certs);
	if (rv != EST_ERR_NONE) {
		est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "est_client_copy_enrolled_cert failed", rv, 0);
		goto cleanup_cacerts;
	}

	/*
	 * The certs are base64 DER encoded.  We need to convert them to PEM.
	 * We don't copy directly to l_new_certs here because we still don't know
	 * for certain the l_new_certs is large enough.
	 */
	ca_certs_len = est_convert_p7b64_to_pem(new_ca_certs, pkcs7_len, &new_certs_pem);

	if (ca_certs_len > 0 && ca_certs_len < max_buffer_length) {
		memcpy_s(l_new_certs, max_buffer_length, new_certs_pem, ca_certs_len);
		ret_val = ca_certs_len;
	} else {
		if (ca_certs_len >= max_buffer_length) {
			est_client_raise_exception(env, EST_CLASS_BUFSIZ_EXCEPTION, "CA certs response too large to fit into buffer", ca_certs_len, 0);
		} else {
			est_client_raise_exception(env, EST_CLASS_CACERTS_EXCEPTION, "Invalid CA certs length", ca_certs_len, 1);
		}
		goto cleanup_cacerts;
	}

cleanup_cacerts:
	if (new_certs_pem) {
		free(new_certs_pem);
		new_certs_pem = NULL;
	}
	if (new_ca_certs) {
		free(new_ca_certs);
		new_ca_certs = NULL;
	}
	if (ectx) {
		est_destroy(ectx);
		ectx = NULL;
	}

	//Free the JNI resources
	if (l_server_name) (*env)->ReleaseStringUTFChars(env, server_name, l_server_name);
	if (l_srp_user) (*env)->ReleaseStringUTFChars(env, srp_user, l_srp_user);
	if (l_srp_pwd) (*env)->ReleaseStringUTFChars(env, srp_pwd, l_srp_pwd);
	if (l_trust_certs) (*env)->ReleaseByteArrayElements(env, trust_certs, l_trust_certs, JNI_COMMIT);
	if (l_new_certs) (*env)->ReleaseByteArrayElements(env, new_certs, l_new_certs, JNI_COMMIT);

	return (ret_val);
}
