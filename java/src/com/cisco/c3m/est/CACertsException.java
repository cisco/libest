package com.cisco.c3m.est;

/*
 * CACertsException.java
 *
 *  Created on: Aug 12, 2014
 *      Author: foleyj
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

/**
 * This exception indicates a problem occurred in the native layer during 
 * the /cacerts operation.  Details on the error can be found in the
 * stderr output.
 * 
 * @author foleyj
 * 
 */
public class CACertsException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4282714673357869389L;

	public CACertsException(String message) {
        super(message);
    }
}
