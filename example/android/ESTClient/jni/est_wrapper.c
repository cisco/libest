#include <string.h>
#include <jni.h>
#include <android/log.h>
#include "est.h"
#include <openssl/pkcs12.h>
#if 0
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#endif

#define FORMAT_PEM 1  //FIXME

#if 0
void dumpbin2(char *buf, size_t len)
{
    int i;

    fprintf(stderr, "\ndumpbin (%d bytes):\n", len);
    for (i=0;i<len;i++) {
	fprintf(stderr, "%c", buf[i]);
	if (i%32 == 31) fprintf(stderr, "\n");
    }
    fprintf(stderr,"\n");
    fflush(stderr);
}

static char *decode64(unsigned char *input, int *length)
{
  BIO *b64, *bmem;
  int new_len;

  char *buffer = (char *)malloc(*length);
  memset(buffer, 0, *length);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, *length);
  bmem = BIO_push(b64, bmem);

  new_len = BIO_read(bmem, buffer, *length);

  BIO_free_all(bmem);

  *length = new_len;

  return buffer;
}
#endif

/*
 * Converts a PKCS7 cert to PKCS12.
 * returns length of pkcs12 data
 */
static int convert_p7_to_p12 (const char *password, 
			      unsigned char *p7_data, int p7_len, 
			      EVP_PKEY *key,
			      unsigned char *p12_data)
{
	PKCS7 *p7=NULL;
	PKCS12 *p12 = NULL;
	X509 *ucert = NULL;
	STACK_OF(X509) *certs=NULL;
	const EVP_MD *macmd = EVP_sha1();
	BIO *out, *in;
	BIO *b64;
	int p12_len = 0;
	int i;    

	unsigned char *tdata;
//	unsigned char *decoded;

	//__android_log_print(ANDROID_LOG_INFO, "EST:", "PKCS12 password is *%s*", password);

	//dumpbin2(p7_data, p7_len);

//	decoded = decode64(p7_data, &p7_len);

	b64 = BIO_new(BIO_f_base64());
	in = BIO_new_mem_buf(p7_data, p7_len);
//	in = BIO_new_mem_buf(decoded, p7_len);
	in = BIO_push(b64, in);
	p7=d2i_PKCS7_bio(in,NULL);
	//p7=PEM_read_bio_PKCS7(in,NULL,NULL,NULL);
	BIO_free(in);
	if (!p7) {
	    ERR_print_errors_fp(stderr);
	    fflush(stderr);
	    __android_log_print(ANDROID_LOG_INFO, "EST:", "PEM_read_bio_PKCS7 failed");
	    return 0;
	}

	i=OBJ_obj2nid(p7->type);
	switch (i) {
	case NID_pkcs7_signed:
		certs=p7->d.sign->cert;
		break;
	case NID_pkcs7_signedAndEnveloped:
		certs=p7->d.signed_and_enveloped->cert;
		break;
	default:
		break;
	}


	if (certs != NULL) {
	    ucert = sk_X509_value(certs,i);
	} else {
	    __android_log_print(ANDROID_LOG_INFO, "EST:", "certs is null");
	}


	p12 = PKCS12_create((char *)password, "EST Test cert", key, ucert, certs,
				NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 
				NID_pbe_WithSHA1And40BitRC2_CBC, 
				PKCS12_DEFAULT_ITER, -1, 0);

	if (!p12) {
	    __android_log_print(ANDROID_LOG_INFO, "EST:", "PKCS12_create failed");
	    goto export_end;
	}

	PKCS12_set_mac(p12, password, -1, NULL, 0, PKCS12_DEFAULT_ITER, macmd);

	out = BIO_new(BIO_s_mem());
	i2d_PKCS12_bio(out, p12);
	p12_len = BIO_get_mem_data(out, &tdata);
	memcpy(p12_data, tdata, p12_len);
//    __android_log_print(ANDROID_LOG_INFO, "EST:", "%d %d %d %d %d %d %d %d", 
//	    p12_data[100], p12_data[101], p12_data[102], p12_data[103], p12_data[104],
//	    p12_data[105], p12_data[106], p12_data[107]);
	BIO_free(out);


    export_end:

	if (ucert) X509_free(ucert);
	return (p12_len);
}
	


unsigned char* convert_jbytearray(JNIEnv* env, jbyteArray input, unsigned int *out_len){
    unsigned char* handle = NULL;

    if(env != NULL && input != NULL){
        handle = (unsigned char*)(*env)->GetByteArrayElements(env, input, NULL);
        if(out_len != NULL){
            *out_len = (*env)->GetArrayLength(env, input);
        }
    }

    return handle;
}

void release_jbytearray(JNIEnv* env,jbyteArray array, unsigned char* handle, jint mode){
    if(env != NULL && handle != NULL){
        (*env)->ReleaseByteArrayElements(env, array, (jbyte*)handle, mode);
    }
}


/*
 * Generate an RSA key pair and return it
 * 
 * FIXME: need error handling code in this function
 */
static EVP_PKEY * generate_private_key (void)
{
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey;

    /*
     * create an RSA keypair and assign them to a PKEY and return it.
     */
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);    

    pkey = EVP_PKEY_new();
    if (pkey==NULL) {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "Error allocating PKEY structure for new key pair");
        return NULL;
    }
    if (!EVP_PKEY_set1_RSA(pkey, rsa)) {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "Error assigning RSA key pair to PKEY structure");
        return NULL;
    }        
    
    RSA_free(rsa);
    BN_free(bn);
    
    return (pkey);
}

/*
 * This is a simple callback used to override the default
 * logging facility in libest.
 */
static void logger_logcat (char *format, va_list l) 
{
    char buf[1024];
    vsprintf(buf, format, l);
    __android_log_print(ANDROID_LOG_INFO, "ESTnative:", "%s", buf);
}

/*
 * Primary entry point into this JNI library.  This function is used
 * to enroll a new certificate with an EST server.
 * It will return a PKCS12 certificate.
 */
jbyteArray
Java_com_cisco_estclient_ESTActivity_enrollCert( JNIEnv* env,
                                                  jobject thiz,
						  jstring cn,
						  jstring est_uid,
						  jstring est_pwd,
						  jstring server,
						  jint port,
						  jbyteArray cacert)
{
    jboolean isCopy;
    const char * common_name = (*env)->GetStringUTFChars(env, cn, &isCopy);  
    const char * server_name = (*env)->GetStringUTFChars(env, server, &isCopy);  
    const char * est_userid = (*env)->GetStringUTFChars(env, est_uid, &isCopy);  
    const char * est_password = (*env)->GetStringUTFChars(env, est_pwd, &isCopy);  
    jbyte* cacert_handle = (*env)->GetByteArrayElements(env, cacert, 0);
    int ca_len = (*env)->GetArrayLength(env, cacert);
    EST_CTX *ectx = NULL;
    int rv = EST_ERR_UNKNOWN;
    int pkcs7_len;
    unsigned char *pkcs12;
    int pkcs12_len;
    unsigned char* m_cacert = (unsigned char*) cacert_handle;
    EVP_PKEY *m_key = NULL;
    int key_len;
    jbyteArray pkcs12_buf = NULL;
    unsigned char *pkcs12_handle = NULL;
    unsigned char *new_client_cert = NULL;

    char pwd_copy[255];
    int pwd_len = strnlen(est_password, 255);

    __android_log_print(ANDROID_LOG_INFO, "EST:", 
	    "est_init_client cn=%s ca_len=%d sname=%s port=%d uid=%s pwd=%s pwd_len=%d", 
	    common_name, ca_len, server_name, port, est_userid, est_password, pwd_len);
    m_cacert[ca_len-1] = 0;
    ca_len--;

    /* make sure password is null terminated */
    strncpy(pwd_copy, est_password, 255);
    pwd_copy[pwd_len] = 0;

    est_apps_startup();

    pkcs12 = malloc(8092);

    m_key = generate_private_key();

    /*
     * Initialize EST context from libest.a
     */
    est_init_logger(EST_LOG_LVL_INFO, &logger_logcat); 
    ectx = est_client_init(m_cacert, ca_len, EST_CERT_FORMAT_PEM, NULL);
    if (!ectx) {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "est_init_client failed");
	goto cleanup;
    }

    /*
     * Set the local authentication credentials.  We're not using
     * a certificate to identify ourselves to the server.  
     */
    rv = est_client_set_auth(ectx, est_userid, est_password, NULL, NULL);
    if (rv != EST_ERR_NONE) {
        printf("\nUnable to configure client authentication.  Aborting!!!\n");
        printf("EST error code %d (%s)\n", rv, EST_ERR_NUM_TO_STR(rv));
        exit(1);
    }        

    est_client_set_server(ectx, (const char*)server_name, port);

    rv = est_client_enroll(ectx, (char *)common_name, &pkcs7_len, m_key);
    if (rv != EST_ERR_NONE) {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "est_client_enroll rv=%d", rv);
	ERR_print_errors_fp(stderr);
	fflush(stderr);
	goto cleanup;
    }

    new_client_cert = malloc(pkcs7_len);
    if (new_client_cert == NULL){
	__android_log_print(ANDROID_LOG_INFO, "EST:", "malloc failed (p7len=%d)", pkcs7_len);
	goto cleanup;
    }                    
    rv = est_client_copy_enrolled_cert(ectx, new_client_cert);
    if (rv != EST_ERR_NONE) {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "failed to copy new_client_cert");
	goto cleanup;
    }

    pkcs12_len = convert_p7_to_p12(pwd_copy, new_client_cert, pkcs7_len, m_key, pkcs12);
    __android_log_print(ANDROID_LOG_INFO, "EST:", "pkcs12_len=%d", pkcs12_len);
    __android_log_print(ANDROID_LOG_INFO, "EST:", "%d %d %d %d %d %d %d %d", 
	    pkcs12[100], pkcs12[101], pkcs12[102], pkcs12[103], pkcs12[104],
	    pkcs12[105], pkcs12[106], pkcs12[107]);

    pkcs12_buf = (*env)->NewByteArray(env, pkcs12_len);
    pkcs12_handle = convert_jbytearray(env, pkcs12_buf, NULL);
    memcpy(pkcs12_handle, pkcs12, pkcs12_len);
    release_jbytearray(env, pkcs12_buf, pkcs12_handle, 0);
  
cleanup:
    /*
     * Cleanup
     */
    if (new_client_cert) free(new_client_cert);
    free(pkcs12);
    if (m_key) EVP_PKEY_free(m_key);
    if (ectx) est_destroy(ectx);
    (*env)->ReleaseStringUTFChars(env, cn, common_name);  
    (*env)->ReleaseStringUTFChars(env, server, server_name);  
    (*env)->ReleaseStringUTFChars(env, est_uid, est_userid);  
    (*env)->ReleaseStringUTFChars(env, est_pwd, est_password);  
    (*env)->ReleaseByteArrayElements(env, cacert, cacert_handle, 0);

    est_apps_shutdown();

    if (rv == EST_ERR_NONE) {
	return (pkcs12_buf); //(*env)->NewStringUTF(env, "est_client_enroll worked!");
    } else {
	__android_log_print(ANDROID_LOG_INFO, "EST:", "est_client_enroll2 failed");
	return (NULL); 
    }
}


/* This is a hack to display stderr to logcat */
#define STDERR_FILENO 2
void Java_com_cisco_estclient_ESTActivity_nativePipeSTDERRToLogcat(JNIEnv* env,  jobject obj)
{
    int pipes[2];
    pipe(pipes);
    dup2(pipes[1], STDERR_FILENO);
    FILE *inputFile = fdopen(pipes[0], "r");
    char readBuffer[256];
    __android_log_write(ANDROID_LOG_INFO, "EST:", "starting stderr logger");
    while (1) {
        fgets(readBuffer, sizeof(readBuffer), inputFile);
        __android_log_write(ANDROID_LOG_INFO, "stderr", readBuffer);
    }
}
