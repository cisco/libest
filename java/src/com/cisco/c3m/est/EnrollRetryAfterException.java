package com.cisco.c3m.est;

/*
 * EnrollException.java
 *
 *  Created on: July 1, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

/**
 * This class is used to generate an exception when the EST server is not automatically
 * approving the enrollment of the PKCS10 CSR.  This would occur if the CA is configured
 * to require manual approval of every certificate by a security officer.  When this occurs
 * the EST server will notify the EST client that it should retry the enrollment request
 * at a later time.  This allows time for the security officer to manually approve the 
 * certificate request.  When the EST client retries the enrollment request, the same CSR and
 * key pair should be used.  The application using JEST is responsible for persisting
 * the CSR and key pair between the initial enrollment request and the retry request. 
 * 
 * @author foleyj
 * 
 */
public class EnrollRetryAfterException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 2302815367805705598L;

	public EnrollRetryAfterException(String message) {
        super(message);
    }
}
