package com.cisco.c3m.est;

/*
 * PKCS10CertificateRequest.java
 *
 *  Created on: July 1, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 * Note: This class adhers to the javadoc standard.  Be careful when adding comments.
 */

import java.lang.String;
import java.security.KeyPair;
import java.security.InvalidKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 * This class is used to generate a PKCS10 certificate request. It provides the
 * ability to set the Subject Name on the request, along with the public key. If
 * you need to specify additional attributes on the PKCS10 certificate request,
 * then a more feature-rich PKCS10 package is required, such as Bouncy Castle.
 * 
 * @author foleyj
 * 
 */
public class PKCS10CertificateRequest {
	/**
	 * 
	 * @author foleyj
	 * 
	 */
	public enum Encoding {
		PEM, DER
	};

	private byte[] mEncodedDER;

	private String mSubjNameCN;
	private String mSubjNameCountry;
	private String mSubjNameState;
	private String mSubjNameLocality;
	private String mSubjNameOrg;
	private String mSubjNameOrgUnit;

	/**
	 * Instantiates an empty PKCS10CertificateRequest. Use generateNewCSR to
	 * populate the PKCS10 certificate request with a Subject Name and public
	 * key.
	 */
	public PKCS10CertificateRequest() {
	}

	/**
	 * Instantiates a PKCS10CertificateRequest object from DER encoded data.
	 * 
	 * @param data
	 * 		Provide a byte array contain DER encoded PKCS10 data.
	 */
	public PKCS10CertificateRequest(byte[] data) {
		mEncodedDER = data;
	}

	/**
	 * Instantiates a PKCS10CertificateRequest object from an input stream,
	 * which could be used to read a PKCS10 from the file system.
	 * 
	 * @param is
	 * 		Provide an InputStream that references DER encoded PKCS10 data.
	 */
	public PKCS10CertificateRequest(InputStream is) {
		throw new UnsupportedOperationException("Not implemented");
	}

	/**
	 * 
	 * Generates a new PKCS10 certificate request. The Subject Name in the
	 * PKCS10 will be set using the values provided by the caller. A KeyPair
	 * instance containing a public key is required. This public key will be
	 * used in the certificate request. This method does not sign the
	 * certificate request. The resulting certificate request is expected to be
	 * used with EST and will be signed during the enrollment process.
	 * 
	 * @param commonName
	 *		The Common Name to put in the Subject Name
	 * @param countryName
	 *		The Country Name to put in the Subject Name
	 * @param localityName
	 *		The Locality Name (e.g. city) to put in the Subject Name
	 * @param stateOrProvinceName
	 *		The State/Province to put in the Subject Name
	 * @param orgName
	 *		The Organization Name to put in the Subject Name
	 * @param orgUnitName
	 *		The Organizational Unit Name to put in the Subject Name
	 * @param key
	 *		The public key to use in the certificate request
	 * @throws PKCS10CreationException
	 * 		This exception is thrown when an error occurs at the native layer when
	 *      creating the PKCS10 CSR. JEST uses OpenSSL/CiscoSSL to generate
	 *      the CSR.  Check stderr for details on the cause of the error.
	 * @throws InvalidKeyException
	 *      This exception occurs when there is a problem with the key pair used
	 *      to generate the CSR.  Check stderr for details on the cause of the error.
	 * @throws BufferSizeException
	 *		This exception indicates the size of the new CSR buffer was too 
	 *      small.  Use setNativeMaxCertLength() to increase the buffer size.
	 */
	public void generateNewCSR(String commonName, String countryName,
			String localityName, String stateOrProvinceName, String orgName,
			String orgUnitName, KeyPair key) throws PKCS10CreationException,
			InvalidKeyException, BufferSizeException {

		int rc;
		byte[] encodedKey = key.getPrivate().getEncoded();
		byte[] newCsr = new byte[ESTClient.getNativeMaxCertLength()];

		rc = create_csr(encodedKey, commonName, countryName, localityName,
				stateOrProvinceName, orgName, orgUnitName, newCsr);
		if (rc > 0) {
			mEncodedDER = Arrays.copyOf(newCsr, rc);
		} else {
			throw new PKCS10CreationException("CSR generation failed");
		}
	}

	/**
	 * Returns either a DER or PEM encoded byte array of the PKCS10 certificate
	 * request.
	 * 
	 * @param enc 
	 * 		The encoding method to use: DER or PEM.
	 * @return Returns a byte array containing the encoded PKCS10
	 * @throws EncodingException
	 * 		This exception is thrown when neither DER nor PEM encoding is requested.  Only
	 * 		DER and PEM encoding are supported.
	 * @throws IOException
	 * 		This exception occurs when the base64 encoding fails.
	 */
	public byte[] getBytes(Encoding enc) throws EncodingException, IOException {
		if (enc == Encoding.DER) {
			return mEncodedDER;
		} else if (enc == Encoding.PEM) {
			StringBuilder lReq = new StringBuilder();
			byte[] pem = Base64.encode(mEncodedDER);
			String pemstr = new String(pem, Charset.forName("UTF-8"));
			// System.out.println(pemstr);
			lReq.append("-----BEGIN CERTIFICATE REQUEST-----");
			lReq.append(System.getProperty("line.separator"));
			lReq.append(pemstr);
			lReq.append(System.getProperty("line.separator"));
			lReq.append("-----END CERTIFICATE REQUEST-----");
			lReq.append(System.getProperty("line.separator"));
			return (lReq.toString().getBytes(Charset.forName("UTF-8")));
		} else {
			throw new EncodingException(
					"Only PEM and DER encoding are supported");
		}
	}

	/*
	 * Everything below is the JNI layer definitions and mgmt
	 */
	static {
		System.loadLibrary("jest");
	}

	private static native int create_csr(byte[] keypair,
			String subject_name_cn, String subject_name_country,
			String subject_name_locality, String subject_name_province,
			String subject_name_org, String subject_name_orgunit, byte[] new_csr);
}
