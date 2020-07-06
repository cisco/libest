package com.cisco.c3m.est.test.DT;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;

/*
 * Code taken from the web at stackoverflow.com
 *
 */

public class PortFinder {

    /**
     * If you only need the one port you can use this. No need to instantiate the class
     */
    public static int findFreePort() throws IOException {
	ServerSocket socket = new ServerSocket(0);
	try {
	    return socket.getLocalPort();
	} finally {
	    try {
		socket.close();
	    } catch (IOException e) {
	    }
	}
    }

    private static HashSet<Integer> used = new HashSet<Integer>();
    
    /**
     * Finds a port that is currently free and is guaranteed to be different from any of the
     * port numbers previously returned by this PortFinder instance.
     */
    public static synchronized int findUniqueFreePort() throws IOException {
	int port;
	do {
	    port = findFreePort();
	} while (used.contains(port));
	used.add(port);
	return port;
    }

}
