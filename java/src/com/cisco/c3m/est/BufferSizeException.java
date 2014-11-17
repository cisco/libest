package com.cisco.c3m.est;

/*
 * BufferSizeException.java
 *
 *  Created on: Aug 15, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */
/**
 * This class is used to generate an exception when the buffer that's used to 
 * hold the response from the EST server is too small to fit the entire
 * response.  This notifies the application layer that the maximum buffer size
 * should be increased and the request should be tried again.  The setNativeMaxCertLength()
 * method on the ESTClient class is used to increase the maximum buffer size.
 * 
 * @author foleyj
 * 
 */
public class BufferSizeException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3061075711454049221L;

	public BufferSizeException(String message) {
        super(message);
    }
}
