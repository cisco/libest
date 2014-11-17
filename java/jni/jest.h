/*
 * jest.h
 *
 *  Created on: July 1, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */


#include <jni.h>
/* Header for class com_cisco_c3m_est classes */

#ifndef _Included_com_cisco_c3m_est_ESTClient
#define _Included_com_cisco_c3m_est_ESTClient
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_http_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1http_1auth_1enroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_srp_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1srp_1auth_1enroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jstring, jstring, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_tls_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1tls_1auth_1enroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jbyteArray, jbyteArray, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_http_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1http_1auth_1reenroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_srp_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1srp_1auth_1reenroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jstring, jstring, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_tls_auth_enroll_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1tls_1auth_1reenroll_1request
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jstring, jint, jbyteArray, jbyteArray, jstring, jstring, jint, jbyteArray, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    send_cacerts_request
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_send_1cacerts_1request
  (JNIEnv *, jclass, jbyteArray, jstring, jint, jstring, jstring, jbyteArray);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    enable_fips
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1fips
  (JNIEnv *, jclass);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    enable_logs_errors
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1errors
  (JNIEnv *, jclass);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    enable_logs_warnings
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1warnings
  (JNIEnv *, jclass);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    enable_logs_info
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_enable_1logs_1info
  (JNIEnv *, jclass);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    get_max_cert_length
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_get_1max_1cert_1length
  (JNIEnv *, jclass);

/*
 * Class:     com_cisco_c3m_est_ESTClient
 * Method:    set_max_cert_length
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_ESTClient_set_1max_1cert_1length
  (JNIEnv *, jclass, jint);

/*
 * Class:     com_cisco_c3m_est_PKCS10CertificateRequest
 * Method:    create_csr
 */
JNIEXPORT jint JNICALL Java_com_cisco_c3m_est_PKCS10CertificateRequest_create_1csr
  (JNIEnv *, jclass, jbyteArray, jstring, jstring, jstring, jstring, jstring, jstring, jbyteArray);


#ifdef __cplusplus
}
#endif
#endif
