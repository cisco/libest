package com.cisco.c3m.est;
/*
 * PKCS10CreationException.java
 *
 *  Created on: July 1, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

/**
 * This class is used to generate an exception when there is a problem creating
 * a new PKCS10 CSR. 
 * 
 * @author foleyj
 * 
 */
public class PKCS10CreationException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = -8276158514417428523L;

	public PKCS10CreationException(String message) {
        super(message);
    }
}
