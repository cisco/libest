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
 * This class is used to generate exceptions from the libest library in the native
 * layer.  When this exception is thrown, libest logs details about the error to
 * stderr.  There are a large variety of reasons that would generate this exception.
 * These reasons vary from network issues, such as host name resolution failure, to
 * certificate and key pair inconsistency issues.  The libEST documentation provides
 * a detailed description of the various errors that can be generated at the native
 * layer. 
 * 
 * @author foleyj
 * 
 */
public class EnrollException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 9036583857339828180L;

	public EnrollException(String message) {
        super(message);
    }
}
