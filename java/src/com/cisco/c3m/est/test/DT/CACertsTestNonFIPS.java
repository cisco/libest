package com.cisco.c3m.est.test.DT;

/*
 * CACertsTestNonFIPS.java
 *
 *  Created on: Sept 23, 2014
 *      Author: sbf
 *
 * Copyright (c) 2014 by cisco Systems, Inc.
 * All rights reserved.
 *
 */

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.cisco.c3m.est.BufferSizeException;
import com.cisco.c3m.est.CACertsException;
import com.cisco.c3m.est.ESTClient;
import com.cisco.c3m.est.EncodingException;
import com.cisco.c3m.est.EnrollException;
import com.cisco.c3m.est.EnrollRetryAfterException;
import com.cisco.c3m.est.PKCS10CertificateRequest;
import com.cisco.c3m.est.PKCS10CreationException;
import com.cisco.c3m.est.ESTClient.NativeLogLevel;

public class CACertsTestNonFIPS {
	private static X509Certificate[] mCerts;
	private static X509Certificate[] mUntrustedCerts;
	private static X509Certificate mUntrustedCert1;
	private static String mTrustDB;
	private static String mUntrustedDB;
	private static String mTestServer = new String("127.0.0.1");
	private static int mTestPort = 0;
	private static KeyPair mKey;
	private PKCS10CertificateRequest mCSR;
	
	private int temp_int1 = 0;

    // The logger and stream handler are needed
    private static final Logger logger = Logger.getLogger(ESTClientTest.class.getName());
    private static StreamHandler shOut = new StreamHandler(System.out, new SimpleFormatter());
    private static StreamHandler shErr = new StreamHandler(System.err, new SimpleFormatter());

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	    System.out.println("Initializing CACertsTestNonFIPS for "+ ESTClient.getVersion() + "...");
            logger.setLevel(Level.INFO);
	    System.out.println("*******************************************************");
	    System.out.println("Running setUpBeforeClass ...");
	    System.out.println("Testing CiscoJEST Version " + ESTClient.getVersion() + " !!!");

	    // Build up a list of strings called "command" to use with the ProcessBuilder class
	    List<String> command = new ArrayList<String>();

	    // use workspace as dir so that the path to the script is not hard coded
	    String dir1 = System.getenv("WORKSPACE");
	    
	    // Add the name of our script
            String script2 = "/java/src/com/cisco/c3m/est/test/DT/dt_start_estserver2.sh";

	    // add what we have so far to the command
	    command.add(dir1 + script2);

	    // get a free tcp port to use for the estserver
	    mTestPort = PortFinder.findUniqueFreePort();

	    // now add the port as a string to the command list as arg1
	    command.add(Integer.toString(mTestPort));
	    // we want the estserver start script to run in the background
	    command.add("&");

	    // create an instance and pass it our command list
	    ProcessBuilder builder2 = new ProcessBuilder(command);

            Process proc2 = builder2.start();
	    // give some time for estservers to get going by sleeping a bit
	    Thread.sleep(4100);
	    
	    
	    /************ Begin From setUp *************************/	    
            /*
	     * Get location of WORKSPACE on local file system
	     */
	    mTrustDB = System.getenv("EST_TRUST");
	    mUntrustedDB = System.getenv("EST_UNTRUSTED");
	    mTestServer = System.getenv("EST_ADDR");
	    mCerts = Helpers.loadTA(mTrustDB);
	    mUntrustedCerts = Helpers.loadTA(mUntrustedDB);
	    mUntrustedCert1 = Helpers.getCert(mUntrustedDB);

	    try {
		/*
		 * Create a new keypair to use with the various tests
		 */
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, rnd);
		System.out.println("Creating new RSA key pair...");
		mKey = keyGen.generateKeyPair();
		assertNotNull(mKey);
	    } catch (Exception e) {
		fail(e.getMessage());
		e.printStackTrace();
		System.out.println("WARNING:  Unable to create RSA key pair, suite will fail!!!!");
	    }
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	    System.out.println("Dev Test CACertsTest has completed ...");
	    /* 
	     *  sleep a few seconds so that junit summary output
	     *  is printed after testcase output
	     */
	    Thread.sleep(3500);
	}

	@Before
	public void setUp() throws Exception {
	    try {
	        /*
		 * Create a PKCS10 CSR that will be used for the various test cases
		 */
		mCSR = new PKCS10CertificateRequest();
		System.out.println("Creating CSR...");
		mCSR.generateNewCSR ("Java EST Client Dev Test", "US", "Raleigh", "NC", "SandTO", "FOR TEST PURPOSES ONLY", mKey);
		assertNotNull(mCSR);
		} catch (InvalidKeyException | PKCS10CreationException e) {
		    fail(e.getMessage());
		    e.printStackTrace();
		    System.out.println("WARNING:  Unable to initialize CSR for all the tests, suite will fail!!!!");
		}
	}

	@After
	public void tearDown() throws Exception {
	}

        /*****   Test cases that will NOT work with FIPS Enabled  ******/

	@Test
	public void testGetCACerts_SRPandTA() {
	/*
	 * This is a basic happy path test case to ensure we can retrieve the CA
	 * certs from the server
	 * 
	 * get cacerts, ipv4, good TA, good srp cred
	 * 
	 * Expect: success getting cacerts
	 * 
	 */
	    System.out.println("Beginning TC2004");
	    ArrayList<X509Certificate> newCACerts = null;
	    ESTClient ec = new ESTClient();
	    
	    assertNotNull(ec);
	    
	    ec.setSRPCredentials("srpuser", "srppwd");
	    ec.setTrustAnchor(mCerts);
	    ec.setServerName(mTestServer);
	    ec.setServerPort(mTestPort);
	    ec.setNativeLogLevel(NativeLogLevel.logFull);
	    
	    /*
	     * Attempt to fetch the latest CA certs from the EST server
	     */
	    try {
		newCACerts = ec.fetchLatestCACerts();
	    } catch (CertificateException | IOException | CACertsException
		     | BufferSizeException e) {
		fail(e.getMessage());
		e.printStackTrace();
	    }
	    
	    assertNotNull(newCACerts);
	    if (newCACerts != null) {
		assertFalse(newCACerts.isEmpty());
	    }

	    for (X509Certificate c : newCACerts) {
		// System.out.println(c.toString());
		System.out.println("Issuer: " + c.getIssuerDN().getName());
		assertNotNull(c.getIssuerDN().getName());
		assertFalse(c.getIssuerDN().getName().equals(""));
	    }
	    System.out.println("Ending TC2004");
	}

	@Test
	public void testGetCACerts_TAandSRPandTLS() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, good TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2005");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();

		ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2005");
	}

	@Test
	public void testGetCACerts_TAandSRPandTLSandHTTP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, good TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2006");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2006");
	}
	
	@Test
	public void testGetCACerts_noTAandSRPandTLSandHTTP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, no TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2007");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2007");
	}
	
	@Test
	public void testGetCACerts_SRPandTLS() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, no TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2008");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2008");
	}
	
	@Test
	public void testGetCACerts_SRP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, no TA, good srp cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2009");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2009");
	}

	@Test
	public void testGetCACerts_unTAandSRPandTLSandHTTP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, untrusted TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2014");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2014");
	}
	
	@Test
	public void testGetCACerts_unTA_SRPandTLS() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, untrusted TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2015");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2015");
	}
	
	@Test
	public void testGetCACerts_unTA_SRP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv4, untrusted TA, good srp cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2016");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2016");
	}
	

	@Test
	public void testGetCACerts_simpleEnroll_SRP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * good http cred, SRP auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2021");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2021");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_SRPwPoP() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv4, good TA, no srp cred
		 * good http cred, SRP auth, PoP on
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2022");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setTrustAnchor(newCACerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2022");
	}
	
	@Test
	public void testGetCACerts_SRPandTAv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server
		 * 
		 * get cacerts, ipv6, good TA, good srp cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2028");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2028");
	}

	@Test
	public void testGetCACerts_TAandSRPandTLSv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, good TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2029");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();

		ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2029");
	}

	@Test
	public void testGetCACerts_TAandSRPandTLSandHTTPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, good TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2030");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2030");
	}
	
	@Test
	public void testGetCACerts_noTAandSRPandTLSandHTTPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, no TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2031");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		//ec.setTrustAnchor(mCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2031");
	}
	
	@Test
	public void testGetCACerts_SRPandTLSv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, no TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2032");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2032");
	}
	
	@Test
	public void testGetCACerts_SRPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, no TA, good srp cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2033");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2033");
	}

	@Test
	public void testGetCACerts_unTAandSRPandTLSandHTTPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, untrusted TA, good srp cred, good TLS cred, good http cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2038");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		ec.setHTTPCredentials("estuser", "estpwd");
		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		// get a good cert to use for tls credentials
		myCert1 = getTrustedCert();
		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2038");
	}
	
	@Test
	public void testGetCACerts_unTA_SRPandTLSv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, untrusted TA, good srp cred, good TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2039");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();
		X509Certificate myCert1 = null;

		assertNotNull(ec);

		// get a good cert to use for tls authentication
		myCert1 = getTrustedCert();

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		ec.setTLSAuthenticationCredentials(myCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2039");
	}
	
	@Test
	public void testGetCACerts_unTA_SRPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server, with srp credentials set for client 
		 * 
		 * get cacerts, ipv6, untrusted TA, good srp cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2040");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		// note - using untrusted trust anchor
		ec.setTrustAnchor(mUntrustedCerts);
		ec.setSRPCredentials("srpuser", "srppwd");
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}

		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		for (X509Certificate c : newCACerts) {
			// System.out.println(c.toString());
			System.out.println("Issuer: " + c.getIssuerDN().getName());
			assertNotNull(c.getIssuerDN().getName());
			assertFalse(c.getIssuerDN().getName().equals(""));
		}
		System.out.println("Ending TC2040");
	}
	

	@Test
	public void testGetCACerts_simpleEnroll_SRPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * good http cred, SRP auth, no PoP
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2045");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.FALSE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2045");
	}
	
	@Test
	public void testGetCACerts_simpleEnroll_SRPwPoPv6() {
		/*
		 * This is a basic happy path test case to ensure we can retrieve the CA
		 * certs from the server.  We then use those certs to do a 
		 * simple enroll.
		 * 
		 * get cacerts + simple enroll, ipv6, good TA, no srp cred
		 * good http cred, SRP auth, PoP on
		 * 
		 * Expect: success getting cacerts and successful enroll
		 * 
		 */
		System.out.println("Beginning TC2046");
		ArrayList<X509Certificate> newCACerts = null;
		X509Certificate newCert = null;
		ESTClient ec = new ESTClient();

		assertNotNull(ec);

		ec.setTrustAnchor(mCerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		
		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (CertificateException | IOException | CACertsException
				| BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
			return;
		}
		assertNotNull(newCACerts);
		if (newCACerts != null) {
			assertFalse(newCACerts.isEmpty());
		}

		
		/*
		 * OK, we have the new trust anchor.  Let's start a new session
		 * using this TA and attempt a simple enroll.
		 */
		ec = new ESTClient();
		assertNotNull(ec);

		ec.setSRPCredentials("srpuser", "srppwd");
		ec.setTrustAnchor(newCACerts);
		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authSRP, mKey, Boolean.TRUE);
		} catch (InvalidKeyException | CertificateException | IOException
				| EncodingException | EnrollException
				| EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCert);
		System.out.println("Ending TC2046");
	}
	

	@Test
	public void testGetCACerts_noTASRPandUntrustedTLS() {
		/*
		 * This is a basic positive testcase
		 *
		 * get cacerts, ipv4, no TA, good srp cred, no http cred, untrusted TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2050");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		//ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		// Use an untrusted cert for the client
		ec.setTLSAuthenticationCredentials(mUntrustedCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCACerts);
		System.out.println("Ending TC2050");
	}
	
	@Test
	public void testGetCACerts_noTASRPandUntrustedTLSv6() {
		/*
		 * This is a basic positive testcase
		 *
		 * get cacerts, ipv6, no TA, good srp cred, no http cred, untrusted TLS cred
		 * 
		 * Expect: success getting cacerts
		 * 
		 */
		System.out.println("Beginning TC2052");
		ArrayList<X509Certificate> newCACerts = null;
		ESTClient ec = new ESTClient();

		// ipv6
		ec.setServerName("ip6-localhost");
		ec.setServerPort(mTestPort);
		ec.setNativeLogLevel(NativeLogLevel.logFull);
		ec.setSRPCredentials("srpuser", "srppwd");

		// Use an untrusted cert for the client
		ec.setTLSAuthenticationCredentials(mUntrustedCert1, mKey);

		/*
		 * Attempt to fetch the latest CA certs from the EST server
		 */
		try {
			newCACerts = ec.fetchLatestCACerts();
		} catch (Exception e) {
			System.out.println("Caught Exception as expected: "
					+ e.getMessage());
			e.printStackTrace();
		}
		assertNotNull(newCACerts);
		System.out.println("Ending TC2052");
	}
	
	
	
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
    /*******************************************************************/
	
	
	/*
	 * This helper routine is used by some testcases using TLS authentication
	 * 
	 *  used like this:  X509Certificate myCert1 = getTrustedCert();
	 * 
	 */
	private X509Certificate getTrustedCert() {
		System.out.println("Beginning getTrustedCert ...");
		ESTClient ec = new ESTClient();
		X509Certificate newCert = null;
		
		assertNotNull(ec);
		
		mCerts = Helpers.loadTA(mTrustDB);
		ec.setTrustAnchor(mCerts);
		ec.setServerName(mTestServer);
		ec.setServerPort(mTestPort);
		ec.setHTTPCredentials("estuser", "estpwd");
		ec.setNativeLogLevel(NativeLogLevel.logFull);

		/*
		 * Attempt to provision a new certificate
		 */
		try {
			newCert = ec.sendSimpleEnrollRequest(mCSR, ESTClient.AuthMode.authHTTPonly, mKey, Boolean.FALSE);
		} catch (InvalidKeyException
				| CertificateException | IOException | EncodingException
				| EnrollException | EnrollRetryAfterException | BufferSizeException e) {
			fail(e.getMessage());
			e.printStackTrace();
		}
		return newCert;
	}

	
	/* ***** End of Class CACertsTestNonFIPS ******** */
}
